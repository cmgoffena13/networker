from typer import Option, Typer

from src.cli.console import echo
from src.core.device import get_devices_on_network
from src.core.network import get_network
from src.database.network import db_list_networks
from src.logging_conf import set_log_level

network_typer = Typer(help="Network commands")


@network_typer.command("init", help="initialize the network and devices information")
def init(
    verbose: bool = Option(
        False, "--verbose", "-v", help="Enable verbose (DEBUG) logging"
    ),
):
    if verbose:
        set_log_level("DEBUG")
    network = get_network(save=True)
    get_devices_on_network(network, save=True)


@network_typer.command("scan", help="Scan the network for open ports on devices")
def scan(
    log: bool = Option(False, "--log", "-l", help="Log the network scan results"),
    verbose: bool = Option(
        False, "--verbose", "-v", help="Enable verbose (DEBUG) logging"
    ),
):
    if verbose:
        set_log_level("DEBUG")
    network = get_network(save=log)
    get_devices_on_network(network, save=log)


@network_typer.command("list", help="list information on networks stored")
def list(
    verbose: bool = Option(
        False, "--verbose", "-v", help="Enable verbose (DEBUG) logging"
    ),
):
    if verbose:
        set_log_level("DEBUG")
    networks = db_list_networks()
    for network in networks:
        echo(f"Network: {network.model_dump_json(indent=2)}")
