from typer import Typer

device_typer = Typer(help="Device commands")


@device_typer.command("scan", help="Scan the device for open ports")
def scan():
    pass


@device_typer.command("list", help="list information on devices stored")
def list():
    pass
