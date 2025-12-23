import ipaddress
import time
from typing import List, Optional

import httpx
import structlog
from scapy.all import ARP, Ether, conf, srp

from src.cli.console import echo
from src.database.device import db_save_device
from src.models.device import Device
from src.models.network import Network

logger = structlog.getLogger(__name__)


def get_vendor_name(mac_address: str, api_key: Optional[str] = None) -> Optional[str]:
    oui = mac_address[:8]
    logger.debug(f"Getting vendor name for OUI: {oui}")
    try:
        url = f"https://api.maclookup.app/v2/macs/{oui}/company/name"
        params = {}
        if api_key:
            params["apiKey"] = api_key

        response = httpx.get(url, params=params, timeout=10)

        if response.status_code == 200:
            vendor_name = response.text.strip()
            logger.debug(f"Vendor name for {mac_address}: {vendor_name}")
            time.sleep(0.6)  # Rate limit is 2 requests per second
            return vendor_name if vendor_name else None
        elif response.status_code == 400:
            logger.warning(f"Invalid MAC address format: {mac_address}")
            return None
        elif response.status_code == 401:
            logger.warning("Invalid API key for maclookup.app")
            return None
        elif response.status_code == 409:
            logger.warning("Rate limit exceeded for maclookup.app")
            return None
        elif response.status_code == 429:
            logger.warning("Rate limit exceeded for maclookup.app")
            return None
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
    logger.debug(f"Getting devices on network: {network.network_address}...")
    echo(f"Getting devices on network: {str(network.network_address)}...")
    devices = []

    netmask_int = int(ipaddress.IPv4Address(network.netmask))
    prefix_length = bin(netmask_int).count("1")
    network_range = f"{network.network_address}/{prefix_length}"

    arp_request = ARP(pdst=network_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered, unanswered = srp(arp_request_broadcast, timeout=2, verbose=False)
    for sent, received in answered:
        ip = received.psrc
        mac = received.hwsrc
        if mac == network.router_mac:
            is_router = True
        else:
            is_router = False

        vendor_name = get_vendor_name(mac)
        device = Device(
            network_id=network.id,
            device_mac=mac,
            device_ip=ip,
            is_router=is_router,
            vendor_name=vendor_name,
        )
        devices.append(device)
    logger.debug(f"Found {len(devices)} devices on network: {network.network_address}")
    echo(f"Found {len(devices)} devices.")
    if save:
        logger.debug("Saving devices...")
        for device in devices:
            db_save_device(device)
        echo("Devices info logged to database.")
        logger.debug("Devices saved")
    return devices
