import ipaddress
import platform
import signal
import socket
from time import sleep
from typing import List, Optional, Tuple

import httpx
import structlog
from scapy.all import ARP, IP, TCP, UDP, Ether, conf, get_if_hwaddr, sr, srp
from tqdm import tqdm
from typer import Abort, Exit

from src.cli.console import echo
from src.database.device import (
    db_get_device_by_mac_address,
    db_save_device,
)
from src.database.device_port import db_list_device_ports, db_save_device_ports
from src.models.device import Device
from src.models.device_port import DevicePort
from src.models.network import Network
from src.protocol import Protocol
from src.settings import config

logger = structlog.getLogger(__name__)


def get_mac_vendor_name(
    mac_address: str,
) -> Optional[str]:
    oui = mac_address[:8]
    logger.debug(f"Getting vendor name for OUI: {oui}")
    vendor_name = None

    try:
        url = f"https://api.maclookup.app/v2/macs/{oui}/company/name"
        response = httpx.get(url, timeout=10)

        if response.status_code == 200:
            vendor_name = response.text.strip()
            logger.debug(f"Vendor name for {mac_address}: {vendor_name}")
            sleep(0.6)  # Rate limit is 2 requests per second
            if vendor_name == "*NO COMPANY*" and len(mac_address) > 1:
                second_hex = mac_address[1].upper()
                if second_hex in ("2", "6", "A", "E"):
                    logger.debug(
                        f"MAC {mac_address} appears to be dynamic (second hex: {second_hex})"
                    )
                    vendor_name = "Dynamic MAC"
        else:
            logger.warning(
                f"Unexpected response from maclookup.app: {response.status_code}"
            )
    except Exception as e:
        logger.error(f"Error getting vendor name for {mac_address}: {e}")
        raise Exit(code=1)

    return vendor_name


def get_router_mac() -> Optional[str]:
    logger.debug("Getting router MAC address...")
    router_mac = None

    route = conf.route.route("0.0.0.0")
    router_ip = route[2]

    if router_ip:
        arp_request = ARP(pdst=router_ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

        answered, unanswered = srp(arp_request_broadcast, timeout=2, verbose=False)

        if answered:
            router_mac = answered[0][1].hwsrc
            logger.debug(f"Router MAC address: {router_mac}")
        else:
            logger.debug("No router MAC address found")

    return router_mac


def get_current_device_ip() -> Optional[str]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            return ip
    except Exception:
        return None


def get_current_device_info(ip_address: str, network_id: int) -> Device:
    try:
        hostname = socket.gethostname()
        os_name = platform.system()
        device_name = f"{hostname} ({os_name})"

        mac_address = get_if_hwaddr(conf.iface)
        vendor_name = get_mac_vendor_name(mac_address)

        device = Device(
            network_id=network_id,
            mac_address=mac_address,
            mac_vendor=vendor_name,
            ip_address=ip_address,
            device_name=device_name,
            current_device=True,
            is_router=False,
        )

        logger.debug(
            f"Current device info: {device_name}, IP: {ip_address}, MAC: {mac_address}"
        )
    except Exception as e:
        logger.error(f"Error getting current device info: {e}")
        raise Exit(code=1)
    return device


def get_devices_on_network(network: Network, save: bool = False) -> List[Device]:
    echo(f"Getting devices on network: {str(network.network_address)}...")
    devices = []

    netmask_int = int(ipaddress.IPv4Address(network.netmask))
    prefix_length = bin(netmask_int).count("1")
    network_range = f"{network.network_address}/{prefix_length}"

    arp_request = ARP(pdst=network_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered, unanswered = srp(arp_request_broadcast, timeout=2, verbose=False)

    echo(f"Found {len(answered)} devices on network: {network.network_address}")
    echo(f"Gathering device information...")

    current_ip = get_current_device_ip()
    seen_ips = set()

    for sent, received in answered:
        ip = received.psrc
        mac = received.hwsrc
        seen_ips.add(ip)

        if mac == network.router_mac:
            is_router = True
        else:
            is_router = False

        is_current_device = current_ip is not None and ip == current_ip

        if is_current_device:
            device = get_current_device_info(ip, network.id)
        else:
            vendor_name = get_mac_vendor_name(mac)
            device = Device(
                network_id=network.id,
                mac_address=mac,
                mac_vendor=vendor_name,
                ip_address=ip,
                is_router=is_router,
                current_device=False,
            )
        if save:
            device = db_save_device(device)
        else:
            saved_device = db_get_device_by_mac_address(device.mac_address, network.id)
            if not saved_device:
                echo(f"New device detected: {device.mac_address} ({device.ip_address})")
            else:
                device = saved_device
        devices.append(device)

    if current_ip and current_ip not in seen_ips:
        current_device = get_current_device_info(current_ip, network.id)
        if save:
            current_device = db_save_device(current_device)
        else:
            saved_current_device = db_get_device_by_mac_address(
                current_device.mac_address, network.id
            )
            if not saved_current_device:
                echo(
                    f"New current device detected: {current_device.mac_address} ({current_device.ip_address})"
                )
            else:
                current_device = saved_current_device
        devices.append(current_device)

    if save:
        echo("Devices info logged to database.")
    return devices


def get_open_ports(
    device: Device, save: bool = False
) -> List[Tuple[DevicePort, Optional[str], Optional[str]]]:
    device_ports = []
    ports = list(range(1, 65536))
    total_batches = (
        len(ports) + config.PORT_SCAN_BATCH_SIZE - 1
    ) // config.PORT_SCAN_BATCH_SIZE

    interrupted = False

    def signal_handler(signum, frame):
        nonlocal interrupted
        interrupted = True
        echo("\nPort scan interrupted...")

    original_handler = signal.signal(signal.SIGINT, signal_handler)

    echo("Press Ctrl+C to interrupt the scan(s)...")
    try:
        echo(
            f"Scanning device (MAC: {device.mac_address}, Name: {device.device_name}, ID: {device.id}) for open ports..."
        )
        with tqdm(
            total=total_batches,
            colour="green",
            bar_format="{percentage:3.0f}%|{bar}| ETA [{remaining}]  ",
        ) as pbar:
            for index in range(0, len(ports), config.PORT_SCAN_BATCH_SIZE):
                if interrupted:
                    break

                batch = ports[index : index + config.PORT_SCAN_BATCH_SIZE]
                batch_num = (index // config.PORT_SCAN_BATCH_SIZE) + 1
                logger.debug(
                    f"Processing batch {batch_num}/{total_batches} (ports {batch[0]}-{batch[-1]})"
                )
                tcp_packets = [
                    IP(dst=device.ip_address) / TCP(dport=port, flags="S")
                    for port in batch
                ]
                answered, unanswered = sr(tcp_packets, timeout=1, verbose=False)
                for sent, received in answered:
                    if interrupted:
                        break
                    if received.haslayer(TCP) and received[TCP].flags == 18:
                        port = received[TCP].sport
                        device_port = DevicePort(
                            device_id=device.id,
                            port_number=port,
                            protocol=Protocol.TCP,
                        )
                        device_ports.append(device_port)
                        logger.debug(f"Found open TCP port: {port} on device.")

                if interrupted:
                    break

                udp_packets = [
                    IP(dst=device.ip_address) / UDP(dport=port) for port in batch
                ]
                answered, unanswered = sr(udp_packets, timeout=0.5, verbose=False)
                for sent, received in answered:
                    if interrupted:
                        break
                    if received.haslayer(UDP):
                        port = received[UDP].sport
                        device_port = DevicePort(
                            device_id=device.id,
                            port_number=port,
                            protocol=Protocol.UDP,
                        )
                        device_ports.append(device_port)
                        logger.debug(f"Found open UDP port: {port} on device.")
                pbar.update(1)

        if interrupted:
            signal.signal(signal.SIGINT, original_handler)
            raise Abort()
        else:
            echo(f"Found {len(device_ports)} open ports on device.")

        if save:
            db_save_device_ports(device_ports, device.id)
            echo("Open ports saved to database.")
            result = db_list_device_ports(device.id)
        else:
            result = [(dp, None, None) for dp in device_ports]

    except Abort:
        raise
    except Exception:
        raise Exit(code=1)
    finally:
        signal.signal(signal.SIGINT, original_handler)

    return result
