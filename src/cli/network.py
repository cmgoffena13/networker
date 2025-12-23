from typer import Option, Typer

from src.core.device import get_devices_on_network
from src.core.network import get_network

network = Typer(help="Network commands")


@network.command("init", help="Initialize the network and devices")
def init():
    get_network(save=True)
    get_devices_on_network(network, save=True)


@network.command("scan", help="Scan the network for open ports on devices")
def scan(log: bool = Option(False, "--log", "-l", help="Log the network scan results")):
    network = get_network(save=log)
    get_devices_on_network(network, save=log)


@network.command("list", help="list information on networks stored")
def list():
    pass
