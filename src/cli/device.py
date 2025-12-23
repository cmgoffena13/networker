from typer import Typer

from src.cli.console import echo

device = Typer(help="Device commands")


@device.command()
def scan():
    echo(f"Scanning device...")
