import ipaddress
import re
import socket
import struct
import subprocess
import sys
from typing import Optional, Tuple

import httpx
import structlog
from scapy.all import DNS, Packet, conf, get_if_addr, sniff
from typer import Abort

from src.cli.console import echo
from src.core.device import get_router_mac
from src.database.device import db_list_devices
from src.database.network import db_save_network
from src.exceptions import NetworkNotFoundError
from src.models.network import Network

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
        ssid_name=get_wifi_network_name(),
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
    return network


def turn_on_promiscuous_mode() -> None:
    logger.debug("Turning on promiscuous mode...")
    subprocess.run(
        ["ifconfig", str(conf.iface), "promisc"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    logger.debug("Promiscuous mode turned on.")


def turn_off_promiscuous_mode() -> None:
    logger.debug("Turning off promiscuous mode...")
    subprocess.run(
        ["ifconfig", str(conf.iface), "-promisc"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    logger.debug("Promiscuous mode turned off.")


def _format_ip_direction(
    src_ip: str, dst_ip: str, local_ips: set, arrow: str = "->"
) -> Tuple[str, str, str]:
    src_is_local = src_ip in local_ips
    dst_is_local = dst_ip in local_ips

    if src_is_local and not dst_is_local:
        # Local -> External
        return (src_ip, arrow, dst_ip)
    elif dst_is_local and not src_is_local:
        # External <- Local (reversed)
        return (dst_ip, "<-", src_ip)
    else:
        # Both local or both external, keep original direction
        return (src_ip, arrow, dst_ip)


def packet_handler(packet: Packet, local_ips: set) -> None:
    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst
        if packet.haslayer("DNS"):
            dns = packet["DNS"]
            if dns.qr == 0:
                query_name = (
                    dns.qd.qname.decode("utf-8").rstrip(".") if dns.qd else "unknown"
                )
                left_ip, arrow, right_ip = _format_ip_direction(
                    src_ip, dst_ip, local_ips
                )
                echo(f"DNS: {left_ip} {arrow} {right_ip} | {query_name}")
        elif packet.haslayer("TCP"):
            src_port = packet["TCP"].sport
            dst_port = packet["TCP"].dport
            left_ip, arrow, right_ip = _format_ip_direction(src_ip, dst_ip, local_ips)
            # If direction was reversed, swap ports too
            if arrow == "<-":
                left_port, right_port = dst_port, src_port
            else:
                left_port, right_port = src_port, dst_port
            echo(f"TCP: {left_ip}:{left_port} {arrow} {right_ip}:{right_port}")
        elif packet.haslayer("UDP"):
            src_port = packet["UDP"].sport
            dst_port = packet["UDP"].dport
            left_ip, arrow, right_ip = _format_ip_direction(src_ip, dst_ip, local_ips)
            # If direction was reversed, swap ports too
            if arrow == "<-":
                left_port, right_port = dst_port, src_port
            else:
                left_port, right_port = src_port, dst_port
            echo(f"UDP: {left_ip}:{left_port} {arrow} {right_ip}:{right_port}")
        elif packet.haslayer("ARP"):
            arp_src = packet["ARP"].psrc
            arp_dst = packet["ARP"].pdst
            left_ip, arrow, right_ip = _format_ip_direction(arp_src, arp_dst, local_ips)
            echo(f"ARP: {left_ip} {arrow} {right_ip}")


def monitor_network(filter: str = None) -> None:
    logger.debug("Monitoring network...")
    echo("Starting network monitoring (press Ctrl+C to stop)...")

    devices = db_list_devices()
    local_ips = {device.ip_address for device in devices}
    logger.debug(f"Local device IPs: {local_ips}")

    def handler(packet: Packet) -> None:
        packet_handler(packet, local_ips)

    try:
        turn_on_promiscuous_mode()
        sniff(iface=str(conf.iface), prn=handler, store=False, filter=filter)
    except KeyboardInterrupt:
        raise Abort()
    finally:
        turn_off_promiscuous_mode()
