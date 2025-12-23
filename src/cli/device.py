from typer import Typer

device = Typer(help="Device commands")


@device.command("scan", help="Scan the device for open ports")
def scan():
    pass


@device.command("list", help="list information on devices stored")
def list():
    pass
