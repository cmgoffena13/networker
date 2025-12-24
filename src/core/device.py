import ipaddress
from time import sleep
from typing import List, Optional, Tuple

import httpx
import structlog
from scapy.all import ARP, IP, TCP, UDP, Ether, conf, sr, srp
from tqdm import tqdm
from typer import Abort, Exit

from src.cli.console import echo
from src.database.device import db_save_device
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
    try:
        url = f"https://api.maclookup.app/v2/macs/{oui}/company/name"
        response = httpx.get(url, timeout=10)

        if response.status_code == 200:
            vendor_name = response.text.strip()
            logger.debug(f"Vendor name for {mac_address}: {vendor_name}")
            sleep(0.6)  # Rate limit is 2 requests per second
            return vendor_name if vendor_name else None
        else:
            logger.warning(
                f"Unexpected response from maclookup.app: {response.status_code}"
            )
            return None
    except Exception as e:
        logger.error(f"Error getting vendor name for {mac_address}: {e}")
        return None


def get_router_mac() -> Optional[str]:
    logger.debug("Getting router MAC address...")
    route = conf.route.route("0.0.0.0")
    router_ip = route[2]

    if not router_ip:
        return None

    # Send ARP request to get MAC address
    arp_request = ARP(pdst=router_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    # Send and receive ARP response
    answered, _ = srp(arp_request_broadcast, timeout=2, verbose=False)

    if answered:
        logger.debug(f"Router MAC address: {answered[0][1].hwsrc}")
        return answered[0][1].hwsrc

    logger.debug("No router MAC address found")
    return None


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
    for sent, received in answered:
        ip = received.psrc
        mac = received.hwsrc
        if mac == network.router_mac:
            is_router = True
        else:
            is_router = False

        vendor_name = get_mac_vendor_name(mac)
        device = Device(
            network_id=network.id,
            mac_address=mac,
            mac_vendor=vendor_name,
            ip_address=ip,
            is_router=is_router,
        )
        if save:
            device = db_save_device(device)
        devices.append(device)

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
    try:
        echo(
            f"Scanning device (MAC: {device.mac_address}, Name: {device.device_name}, ID: {device.id}) for open ports..."
        )
        with tqdm(
            total=total_batches,
            colour="green",
            bar_format="{percentage:3.0f}%|{bar}| ETA [{remaining}]\t\t",
        ) as pbar:
            for index in range(0, len(ports), config.PORT_SCAN_BATCH_SIZE):
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
                    if received.haslayer(TCP) and received[TCP].flags == 18:
                        port = received[TCP].sport
                        device_port = DevicePort(
                            device_id=device.id,
                            port_number=port,
                            protocol=Protocol.TCP,
                        )
                        device_ports.append(device_port)
                        logger.debug(f"Found open TCP port: {port} on device.")
                udp_packets = [
                    IP(dst=device.ip_address) / UDP(dport=port) for port in batch
                ]
                answered, unanswered = sr(udp_packets, timeout=0.5, verbose=False)
                for sent, received in answered:
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
        echo(f"Found {len(device_ports)} open ports on device.")
        if save:
            db_save_device_ports(device_ports, device.id)
            echo("Open ports saved to database.")
            result = db_list_device_ports(device.id)
        else:
            result = [(dp, None, None) for dp in device_ports]
    except KeyboardInterrupt:
        raise Abort()
    except Exception as e:
        logger.error(f"Error getting open ports for device: {device.mac_address}: {e}")
        raise Exit(code=1)
    return result
