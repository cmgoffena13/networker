import json
from typing import Optional

import structlog
from typer import Abort, Exit, Option, Typer

from src.cli.console import console, display_port_info, echo
from src.core.device import get_devices_on_network, get_open_ports
from src.core.network import get_network, monitor_network
from src.database.device_inference import db_infer_device_type
from src.database.network import db_list_networks, db_update_network
from src.logging_conf import set_log_level
from src.utils import lower_string

logger = structlog.getLogger(__name__)
network_typer = Typer(help="Network commands")


@network_typer.command("init", help="Initialize the network and devices information")
def init(
    verbose: bool = Option(
        False, "--verbose", "-v", help="Enable verbose (DEBUG) logging"
    ),
):
    if verbose:
        set_log_level("DEBUG")
    try:
        network = get_network(save=True)
        get_devices_on_network(network, save=True)
    except Exception as e:
        logger.error(f"Error initializing network: {e}")
        raise Exit(code=1)


@network_typer.command("scan", help="Scan the network for open ports on devices")
def scan(
    save: bool = Option(
        False, "--save", "-s", help="Save the network scan results to the database"
    ),
    verbose: bool = Option(
        False, "--verbose", "-v", help="Enable verbose (DEBUG) logging"
    ),
):
    if verbose:
        set_log_level("DEBUG")
    try:
        network = get_network(save=save)
        devices = get_devices_on_network(network, save=save)
        echo("\nPress Ctrl+C to interrupt scanning and exit...")
        for device in devices:
            device_ports = get_open_ports(device, save=save)
            device_port_objects = [dp for dp, _, _ in device_ports]
            device_inference, device_inference_match = db_infer_device_type(
                device_port_objects, device.id, save=save
            )
            echo(
                f"Device {device.id} Inference: {device_inference}, Match: {device_inference_match}"
            )
            for device_port, service_name, description in device_ports:
                echo(display_port_info(device_port, service_name, description))
    except Abort:
        raise
    except Exception as e:
        logger.error(f"Error scanning network: {e}")
        raise Exit(code=1)


@network_typer.command("list", help="List information on networks stored")
def list(
    verbose: bool = Option(
        False, "--verbose", "-v", help="Enable verbose (DEBUG) logging"
    ),
):
    if verbose:
        set_log_level("DEBUG")
    try:
        networks = db_list_networks()
        echo(f"Listing {len(networks)} networks...")
        for network in networks:
            echo(f"Network: {network.model_dump_json(indent=2)}")
    except Exception as e:
        logger.error(f"Error listing networks: {e}")
        raise Exit(code=1)


@network_typer.command("update", help="Update the network information")
def update(
    network_id: int = Option(..., "--id", "-i", help="Network ID to update"),
    data: str = Option(
        ...,
        "--data",
        "-d",
        help='JSON dictionary of fields to update (e.g., \'{"network_name": "my network"}\')',
    ),
    verbose: bool = Option(
        False, "--verbose", "-v", help="Enable verbose (DEBUG) logging"
    ),
):
    if verbose:
        set_log_level("DEBUG")

    try:
        kwargs = json.loads(data)
    except json.JSONDecodeError as e:
        logger.error(f"Error: Invalid JSON - {e.msg}")
        console.print(
            'Example: --data \'{"network_name": "my network"}\'', style="yellow"
        )
        raise Exit(code=1)

    try:
        updated_network = db_update_network(network_id, **kwargs)
        echo(f"Network {network_id} updated successfully")
        echo(f"Updated network: {updated_network.model_dump_json(indent=2)}")
    except Exception as e:
        logger.error(f"Error updating network: {e}")
        raise Exit(code=1)


@network_typer.command("monitor", help="Monitor network traffic")
def monitor(
    filter: Optional[str] = Option(
        None, "--filter", "-f", help="Filter network traffic", callback=lower_string
    ),
    verbose: bool = Option(
        False, "--verbose", "-v", help="Enable verbose (DEBUG) logging"
    ),
):
    if verbose:
        set_log_level("DEBUG")
    try:
        monitor_network(filter=filter, verbose=verbose)
    except Exception as e:
        error_msg = str(e).lower()
        if "cannot set filter" in error_msg:
            echo(error_msg)
            echo("Use BPF (Berkeley Packet Filter) syntax.")
            echo("Examples:")
            echo("  - 'udp port 5353' (for UDP port 5353)")
            echo("  - 'tcp port 80' (for TCP port 80)")
            echo("  - 'host 192.168.1.1' (for specific host)")
            echo("  - 'arp' (for ARP packets)")
            echo("  - 'icmp' (for ICMP packets)")
            echo("  - 'udp port 5353 or tcp port 80' (for multiple conditions)")
        logger.error(f"Error monitoring network: {e}")
        raise Exit(code=1)
