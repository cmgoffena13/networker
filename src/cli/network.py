from typer import Typer

from src.cli.console import echo

network = Typer(help="Network commands")


@network.command("scan", help="Scan the network for devices")
def scan():
    echo(f"Scanning network...")
