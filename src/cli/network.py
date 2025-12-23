from typer import Typer

from src.cli.console import echo

network = Typer(help="Network commands")


@network.command()
def scan():
    echo(f"Scanning network...")
