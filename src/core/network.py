import ipaddress
import re
import socket
import statistics
import struct
import subprocess
import sys
import time
from threading import Thread
from typing import Optional, Tuple

import httpx
import pendulum
import structlog
from rich.prompt import Prompt
from scapy.all import IP, TCP, UDP, conf, get_if_addr, get_if_list, sniff, sr1
from speedtest import Speedtest, SpeedtestException
from typer import Abort

from src.cli.console import echo
from src.core.device import get_router_mac
from src.core.packet import PacketHandler
from src.database.device import db_get_current_device
from src.database.network import (
    db_get_latest_network_speed_test,
    db_save_network,
    db_save_network_speed_test,
)
from src.exceptions import NetworkNotFoundError
from src.models.network import Network, NetworkSpeedTest
from src.utils import find_command, retry

logger = structlog.getLogger(__name__)


@retry()
def get_wifi_network_name() -> Optional[str]:
    logger.debug("Getting WiFi network name...")
    ssid = None
    if sys.platform == "darwin":  # macOS
        system_profiler = find_command("system_profiler", ["/usr/sbin/system_profiler"])
        awk = find_command("awk", ["/usr/bin/awk"])
        profiler = subprocess.Popen(
            [system_profiler, "SPAirPortDataType"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        awk_proc = subprocess.Popen(
            [awk, '/Current Network/ {getline; $1=$1; gsub(":", ""); print; exit}'],
            stdin=profiler.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        profiler.stdout.close()
        stdout, stderr = awk_proc.communicate(timeout=10)
        profiler.wait(timeout=10)
        if awk_proc.returncode == 0 and stdout.strip():
            ssid = stdout.strip()
    elif sys.platform.startswith("linux"):
        iwgetid = find_command("iwgetid", ["/usr/sbin/iwgetid", "/sbin/iwgetid"])
        result = subprocess.run(
            [iwgetid, "-r"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            ssid = result.stdout.strip()
    elif sys.platform == "win32":  # Windows
        netsh = find_command("netsh", [r"C:\Windows\System32\netsh.exe"])
        result = subprocess.run(
            [netsh, "wlan", "show", "interfaces"],
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
        ipconfig = find_command("ipconfig", [r"C:\Windows\System32\ipconfig.exe"])
        result = subprocess.run([ipconfig], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            # Find the interface section and extract subnet mask
            # Format: Subnet Mask . . . . . . . . . . . : 255.255.255.0
            pattern = rf"{re.escape(interface_name)}.*?Subnet Mask[^:]*:\s*(\d+\.\d+\.\d+\.\d+)"
            match = re.search(pattern, result.stdout, re.IGNORECASE | re.DOTALL)
            if match:
                netmask = match.group(1)
    else:
        if sys.platform == "darwin":
            ifconfig = find_command("ifconfig", ["/sbin/ifconfig"])
        else:
            ifconfig = find_command(
                "ifconfig", ["/sbin/ifconfig", "/usr/sbin/ifconfig"]
            )
        result = subprocess.run(
            [ifconfig, interface_name], capture_output=True, text=True, timeout=5
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


@retry()
def get_public_ip() -> Optional[str]:
    logger.debug("Getting public IP...")
    try:
        response = httpx.get("https://api.ipify.org?format=json")
        if response.status_code == 200:
            ip_address = response.json()["ip"]
            logger.debug(f"Public IP: {ip_address}")
            return ip_address
    except Exception as e:
        raise e


def get_network() -> Network:
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
    network = db_save_network(network)
    logger.debug("Network info logged to database.")
    return network


def get_active_interfaces() -> list[str]:
    active_ifaces = []

    def test_iface(iface: str) -> None:
        def pkt_handler(pkt):
            if pkt:
                active_ifaces.append(iface)
                raise KeyboardInterrupt

        try:
            sniff(iface=iface, prn=pkt_handler, timeout=2, store=0)
        except Exception:
            pass

    threads = []
    for iface in get_if_list():
        if iface.startswith(("en", "ap")):
            t = Thread(target=test_iface, args=(iface,))
            t.start()
            threads.append(t)

    for t in threads:
        t.join(timeout=3)

    return list(set(active_ifaces))


def monitor_network(
    filter: str = None,
    verbose: bool = False,
    exclude_host: bool = False,
    dns: bool = False,
) -> None:
    logger.debug("Monitoring network...")

    echo("Detecting active network interfaces...")
    interfaces = get_active_interfaces()
    if not interfaces:
        interfaces = get_if_list()
        if not interfaces:
            echo("No network interfaces found")
            raise Exception("No network interfaces available")

    if len(interfaces) == 1:
        echo(f"Using default interface: {interfaces[0]}")
        iface = interfaces[0]
    else:
        echo("\nAvailable network interfaces:")
        for idx, interface in enumerate(interfaces, 1):
            echo(f"  {idx}. {interface}")

        while True:
            choice = Prompt.ask(f"\nSelect interface [1-{len(interfaces)}]")
            try:
                idx = int(choice)
                if 1 <= idx <= len(interfaces):
                    iface = interfaces[idx - 1]
                    break
                echo(f"Please enter a number between 1 and {len(interfaces)}")
            except ValueError:
                echo("Please enter a valid number")

    packet_handler = PacketHandler(verbose=verbose, exclude_host=exclude_host)

    filter_parts = []
    if filter:
        filter_parts.append(filter)
    if exclude_host:
        current_device = db_get_current_device()
        if current_device and current_device.ip_address:
            filter_parts.append(f"not host {current_device.ip_address}")
    if dns:
        filter_parts.append("(port 53 or port 5353)")
    final_filter = " and ".join(filter_parts) if filter_parts else None

    filter_msg = f' with filter: "{final_filter}"' if final_filter else ""
    echo(
        f"Starting network monitoring on {iface}{filter_msg} (press Ctrl+C to stop)..."
    )

    try:
        sniff(
            iface=iface,
            prn=packet_handler.handle_packet,
            store=False,
            filter=final_filter,
            promisc=True,
        )
    except KeyboardInterrupt:
        raise Abort()
    except Exception:
        raise


def convert_bytes_to_mbps(bytes: int) -> float:
    return round(bytes / 1024 / 1024 * 8, 2)


def _format_avg_rtt(avg_rtt: float) -> str:
    return_value = f"{avg_rtt:.1f}ms"
    if avg_rtt > 100:
        return_value = f"[red]{avg_rtt:.1f}ms[/red]"
    return return_value


def _traceroute(target_host: str) -> int:
    hostname = target_host.split(":")[0]
    target_ip = socket.gethostbyname(hostname)
    echo(f"Tracing route to: {target_ip} ({hostname})")

    max_hops = 30
    probes = 3
    hops = 0

    for ttl in range(1, max_hops + 1):
        hop_rtts = []
        responses = 0
        last_src = None

        for _ in range(probes):
            pkt = IP(dst=target_ip, ttl=ttl) / TCP(dport=80, flags="S")
            t_start = time.time()
            reply = sr1(pkt, verbose=0, timeout=2)
            rtt = (time.time() - t_start) * 1000

            if reply:
                responses += 1
                hop_rtts.append(rtt)
                last_src = str(reply.src)
                hops = ttl

                if str(reply.src) == target_ip:
                    loss_pct = ((probes - responses) / probes) * 100
                    if hop_rtts and any(rtt for rtt in hop_rtts if rtt is not None):
                        avg_rtt = statistics.mean(
                            [rtt for rtt in hop_rtts if rtt is not None]
                        )
                        formatted_avg = _format_avg_rtt(avg_rtt)
                        echo(
                            f"  {ttl:2d}: {last_src}  Loss: {loss_pct:.0f}%  Avg: {formatted_avg} (target reached)"
                        )
                    else:
                        echo(f"  {ttl:2d}: {last_src}  (target reached)")
                    return ttl
            else:
                hop_rtts.append(None)

        loss_pct = ((probes - responses) / probes) * 100

        if hop_rtts and any(rtt for rtt in hop_rtts if rtt is not None):
            avg_rtt = statistics.mean([rtt for rtt in hop_rtts if rtt is not None])
            formatted_avg = _format_avg_rtt(avg_rtt)
            echo(f"  {ttl:2d}: {last_src}  Loss: {loss_pct:.0f}%  Avg: {formatted_avg}")
        else:
            echo(f"  {ttl:2d}: *  (Firewall)")

            if ttl > 5 and responses == 0:
                return hops

    return hops


@retry()
def speedtest_internet_connectivity(trace: bool = False) -> Tuple[float, float, float]:
    echo("Testing internet speed from current device...")
    st = Speedtest(secure=True)
    best_server = st.get_best_server()
    target_ip = best_server["host"]
    if trace:
        hops = _traceroute(target_ip)
        echo(f"Number of hops: {hops}")
    echo("\nMeasuring download speed...")
    download_speed_bytes = st.download()
    download_speed_mbps = convert_bytes_to_mbps(download_speed_bytes)
    echo(f"Download speed: {download_speed_mbps} Mbps")
    echo("Measuring upload speed...")
    upload_speed_bytes = st.upload()
    upload_speed_mbps = convert_bytes_to_mbps(upload_speed_bytes)
    echo(f"Upload speed: {upload_speed_mbps} Mbps")
    ping_time_ms = st.results.ping
    echo(f"Ping time: {ping_time_ms} ms")
    return download_speed_mbps, upload_speed_mbps, ping_time_ms


def test_internet_connectivity(trace: bool = False) -> None:
    try:
        network = get_network()
        current_device = db_get_current_device()
        if not current_device:
            echo("Current device not found. Please scan the network first.")
            return
        download_speed_mbps, upload_speed_mbps, ping_time_ms = (
            speedtest_internet_connectivity(trace=trace)
        )
        network_speed_test = NetworkSpeedTest(
            network_id=network.id,
            device_id=current_device.id,
            download_speed_mbps=download_speed_mbps,
            upload_speed_mbps=upload_speed_mbps,
            ping_time_ms=ping_time_ms,
        )

        last_network_speed_test = db_get_latest_network_speed_test(
            network.id, current_device.id
        )

        db_save_network_speed_test(network_speed_test)
        logger.debug("Network speed test saved to database.")
        if last_network_speed_test:
            echo("\n")
            created_at = pendulum.instance(
                last_network_speed_test.created_at
            ).in_timezone(pendulum.local_timezone())
            days_ago = (pendulum.now() - created_at).days
            days_ago_str = (
                f"({days_ago} day{'s' if days_ago != 1 else ''} ago)"
                if days_ago > 0
                else "(today)"
            )
            echo(
                f"Last network speed test for device {current_device.id} on {created_at.format('YYYY-MM-DD hh:mm:ss A')} {days_ago_str}"
            )
            last_ping_time = last_network_speed_test.ping_time_ms
            last_download = last_network_speed_test.download_speed_mbps
            last_upload = last_network_speed_test.upload_speed_mbps

            if download_speed_mbps > last_download:
                increase = ((download_speed_mbps - last_download) / last_download) * 100
                echo(
                    f"Download speed has increased by {increase:.1f}% "
                    f"(from {last_download} Mbps to {download_speed_mbps} Mbps)"
                )
            elif download_speed_mbps < last_download:
                decrease = ((last_download - download_speed_mbps) / last_download) * 100
                echo(
                    f"Download speed has decreased by {decrease:.1f}% "
                    f"(from {last_download} Mbps to {download_speed_mbps} Mbps)"
                )

            if upload_speed_mbps > last_upload:
                increase = ((upload_speed_mbps - last_upload) / last_upload) * 100
                echo(
                    f"Upload speed has increased by {increase:.1f}% "
                    f"(from {last_upload} Mbps to {upload_speed_mbps} Mbps)"
                )
            elif upload_speed_mbps < last_upload:
                decrease = ((last_upload - upload_speed_mbps) / last_upload) * 100
                echo(
                    f"Upload speed has decreased by {decrease:.1f}% "
                    f"(from {last_upload} Mbps to {upload_speed_mbps} Mbps)"
                )

            if ping_time_ms > last_ping_time:
                increase = ((ping_time_ms - last_ping_time) / last_ping_time) * 100
                echo(
                    f"Ping time has increased by {increase:.1f}% "
                    f"(from {last_ping_time} ms to {ping_time_ms} ms)"
                )
            elif ping_time_ms < last_ping_time:
                decrease = ((last_ping_time - ping_time_ms) / last_ping_time) * 100
                echo(
                    f"Ping time has decreased by {decrease:.1f}% "
                    f"(from {last_ping_time} ms to {ping_time_ms} ms)"
                )

    except SpeedtestException as e:
        logger.error(f"Speedtest Exception: {e}")
        raise e
    except Exception as e:
        raise e
