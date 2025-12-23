import structlog
from typer import Exit, Option, Typer

from src.cli.console import display_port_info, echo
from src.core.device import get_devices_on_network, get_open_ports
from src.core.network import get_network
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
    log: bool = Option(False, "--log", "-l", help="Log the network scan results"),
    verbose: bool = Option(
        False, "--verbose", "-v", help="Enable verbose (DEBUG) logging"
    ),
):
    if verbose:
        set_log_level("DEBUG")
    try:
        network = get_network(save=log)
        devices = get_devices_on_network(network, save=log)
        for device in devices:
            device_ports = get_open_ports(device, save=log)
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
