import structlog
from typer import Exit, Option, Typer

from src.cli.console import display_port_info, echo
from src.core.device import get_devices_on_network, get_open_ports
from src.core.network import get_network, monitor_network
from src.database.device_inference import db_infer_device_type
from src.database.network import db_list_networks
from src.logging_conf import set_log_level

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


@network_typer.command("monitor", help="Monitor network traffic")
def monitor(
    filter: str = Option(None, "--filter", "-f", help="Filter network traffic"),
    verbose: bool = Option(
        False, "--verbose", "-v", help="Enable verbose (DEBUG) logging"
    ),
):
    if verbose:
        set_log_level("DEBUG")
    try:
        monitor_network(filter=filter)
    except Exception as e:
        logger.error(f"Error monitoring network: {e}")
        raise Exit(code=1)
