import ipaddress
import re
import socket
import struct
import subprocess
import sys
from typing import Optional

import httpx
import structlog
from scapy.all import conf, get_if_addr

from src.cli.console import echo

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


def _get_netmask() -> Optional[str]:
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


def get_network() -> Optional[ipaddress.IPv4Network]:
    logger.debug("Getting network...")
    echo("Finding network...")
    local_ip = get_if_addr(conf.iface)
    netmask = _get_netmask()
    if netmask:
        netmask_int = int(ipaddress.IPv4Address(netmask))
        prefix_length = bin(netmask_int).count("1")
        network = ipaddress.IPv4Network(f"{local_ip}/{prefix_length}", strict=False)
        logger.debug(f"Network: {network}")
        echo(f"Network found: {str(network)}")
        return network
    logger.debug("No network found")
    echo("No network found")
    return None


def get_public_ip() -> Optional[str]:
    logger.debug("Getting public IP...")
    try:
        response = httpx.get("https://api.ipify.org?format=json")
        if response.status_code == 200:
            return response.json()["ip"]
    except Exception as e:
        logger.error(f"Error getting public IP: {e}")
        return None
