from typer import Option, Typer

from src.core.device import get_devices_on_network
from src.core.network import get_network

network_typer = Typer(help="Network commands")


@network_typer.command("init", help="initialize the network and devices information")
def init():
    network = get_network(save=True)
    get_devices_on_network(network, save=True)


@network_typer.command("scan", help="Scan the network for open ports on devices")
def scan(log: bool = Option(False, "--log", "-l", help="Log the network scan results")):
    network = get_network(save=log)
    get_devices_on_network(network, save=log)


@network_typer.command("list", help="list information on networks stored")
def list():
    pass
