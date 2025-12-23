from typer import Typer

from src.cli.console import echo

device = Typer(help="Device commands")


@device.command("scan", help="Scan the device for open ports")
def scan():
    echo(f"Scanning device...")


@device.command("list", help="list information on devices stored")
def list():
    pass
