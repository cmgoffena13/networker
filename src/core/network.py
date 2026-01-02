import ipaddress
import re
import socket
import struct
import subprocess
import sys
from typing import Optional

import httpx
import structlog
from scapy.all import conf, get_if_addr, sniff
from speedtest import Speedtest, SpeedtestException
from typer import Abort, Exit

from src.cli.console import echo
from src.core.device import get_router_mac
from src.core.packet import PacketHandler
from src.database.network import (
    db_get_latest_network_speed_test,
    db_get_network,
    db_save_network,
    db_save_network_speed_test,
)
from src.exceptions import NetworkNotFoundError
from src.models.network import Network, NetworkSpeedTest

logger = structlog.getLogger(__name__)


def get_wifi_network_name() -> Optional[str]:
    logger.debug("Getting WiFi network name...")
    ssid = None
    if sys.platform == "darwin":  # macOS
        profiler = subprocess.Popen(
            ["system_profiler", "SPAirPortDataType"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        awk = subprocess.Popen(
            ["awk", '/Current Network/ {getline; $1=$1; gsub(":", ""); print; exit}'],
            stdin=profiler.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        profiler.stdout.close()
        stdout, stderr = awk.communicate(timeout=10)
        profiler.wait(timeout=10)
        if awk.returncode == 0 and stdout.strip():
            ssid = stdout.strip()
    elif sys.platform.startswith("linux"):
        result = subprocess.run(
            ["iwgetid", "-r"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            ssid = result.stdout.strip()
    elif sys.platform == "win32":  # Windows
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            match = re.search(r"SSID\s*:\s*(.+)", result.stdout)
            if match:
                ssid = match.group(1).strip()
    logger.debug(f"WiFi network name: {ssid}")
    return ssid


def get_netmask() -> Optional[str]:
    logger.debug("Getting netmask...")
    netmask = None
    interface_name = str(conf.iface)
    if sys.platform == "win32":
        result = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            # Find the interface section and extract subnet mask
            # Format: Subnet Mask . . . . . . . . . . . : 255.255.255.0
            pattern = rf"{re.escape(interface_name)}.*?Subnet Mask[^:]*:\s*(\d+\.\d+\.\d+\.\d+)"
            match = re.search(pattern, result.stdout, re.IGNORECASE | re.DOTALL)
            if match:
                netmask = match.group(1)
    else:
        result = subprocess.run(
            ["ifconfig", interface_name], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            # Look for netmask (format: netmask 0xffffff00 or netmask 255.255.255.0)
            netmask_match = re.search(
                r"netmask\s+(0x[0-9a-fA-F]+|\d+\.\d+\.\d+\.\d+)", result.stdout
            )
            if netmask_match:
                netmask_str = netmask_match.group(1)
                # If it's hex format (common on macOS), convert to dotted decimal
                if netmask_str.startswith("0x"):
                    netmask_int = int(netmask_str, 16)
                    netmask = socket.inet_ntoa(struct.pack("!I", netmask_int))
                else:
                    netmask = netmask_str
    logger.debug(f"Netmask: {netmask}")
    return netmask


def get_network_info() -> Optional[ipaddress.IPv4Network]:
    echo("Finding network...")
    local_ip = get_if_addr(conf.iface)
    netmask = get_netmask()
    if netmask:
        netmask_int = int(ipaddress.IPv4Address(netmask))
        prefix_length = bin(netmask_int).count("1")
        network = ipaddress.IPv4Network(f"{local_ip}/{prefix_length}", strict=False)
        logger.debug(f"Network: {network}")
        echo(f"Network found: {str(network)}")
        return network
    echo("No network found.")
    return None


def get_public_ip() -> Optional[str]:
    logger.debug("Getting public IP...")
    try:
        response = httpx.get("https://api.ipify.org?format=json")
        if response.status_code == 200:
            ip_address = response.json()["ip"]
            logger.debug(f"Public IP: {ip_address}")
            return ip_address
    except Exception as e:
        logger.error(f"Error getting public IP: {e}")
        return None


def get_network(save: bool = False) -> Optional[Network]:
    logger.debug("Getting network info...")
    network_info = get_network_info()
    if not network_info:
        logger.error("No network found")
        raise NetworkNotFoundError("No network found")
    network = Network(
        network_name=get_wifi_network_name(),
        router_mac=get_router_mac(),
        network_address=str(network_info.network_address),
        broadcast_address=str(network_info.broadcast_address),
        netmask=get_netmask(),
        ips_available=network_info.num_addresses - 2,
        public_ip=get_public_ip(),
    )
    if save:
        saved_network = db_save_network(network)
        network = saved_network
        echo("Network info logged to database.")
    else:
        saved_network = db_get_network(network)
        if saved_network:
            network = saved_network
    return network


def monitor_network(filter: str = None, verbose: bool = False) -> None:
    logger.debug("Monitoring network...")
    echo("Starting network monitoring (press Ctrl+C to stop)...")

    packet_handler = PacketHandler(verbose=verbose)

    try:
        sniff(
            iface=str(conf.iface),
            prn=packet_handler.handle_packet,
            store=False,
            filter=filter,
            promisc=True,
        )
    except KeyboardInterrupt:
        raise Abort()
    except Exception:
        raise


def convert_bytes_to_mbps(bytes: int) -> float:
    return round(bytes / 1024 / 1024 * 8, 2)


def test_internet_connectivity(save: bool = False) -> None:
    logger.debug("Testing internet connectivity...")
    try:
        network = get_network()
        st = Speedtest()
        st.get_best_server()
        echo("Measuring download speed...")
        download_speed_bytes = st.download()
        download_speed_mbps = convert_bytes_to_mbps(download_speed_bytes)
        echo(f"Download speed: {download_speed_mbps} Mbps")
        echo("Measuring upload speed...")
        upload_speed_bytes = st.upload()
        upload_speed_mbps = convert_bytes_to_mbps(upload_speed_bytes)
        echo(f"Upload speed: {upload_speed_mbps} Mbps")
        last_network_speed_test = db_get_latest_network_speed_test(network.id)
        if save:
            network_speed_test = NetworkSpeedTest(
                network_id=network.id,
                download_speed_mbps=download_speed_mbps,
                upload_speed_mbps=upload_speed_mbps,
            )
            db_save_network_speed_test(network_speed_test)

        if last_network_speed_test:
            last_download = last_network_speed_test.download_speed_mbps
            last_upload = last_network_speed_test.upload_speed_mbps

            if download_speed_mbps > last_download:
                increase = ((download_speed_mbps - last_download) / last_download) * 100
                echo(f"Download speed has increased by {increase:.1f}%")
            elif download_speed_mbps < last_download:
                decrease = ((last_download - download_speed_mbps) / last_download) * 100
                echo(f"Download speed has decreased by {decrease:.1f}%")

            if upload_speed_mbps > last_upload:
                increase = ((upload_speed_mbps - last_upload) / last_upload) * 100
                echo(f"Upload speed has increased by {increase:.1f}%")
            elif upload_speed_mbps < last_upload:
                decrease = ((last_upload - upload_speed_mbps) / last_upload) * 100
                echo(f"Upload speed has decreased by {decrease:.1f}%")

    except SpeedtestException as e:
        logger.error(f"Speedtest Exception: {e}")
        raise Exit(code=1)
    except Exception as e:
        logger.error(f"Error testing internet connectivity: {e}")
        raise Exit(code=1)
