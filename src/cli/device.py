from typer import Option, Typer

from src.logging_conf import set_log_level

device_typer = Typer(help="Device commands")


@device_typer.command("scan", help="Scan the device for open ports")
def scan(
    verbose: bool = Option(
        False, "--verbose", "-v", help="Enable verbose (DEBUG) logging"
    ),
):
    if verbose:
        set_log_level("DEBUG")
    pass


@device_typer.command("list", help="list information on devices stored")
def list(
    verbose: bool = Option(
        False, "--verbose", "-v", help="Enable verbose (DEBUG) logging"
    ),
):
    if verbose:
        set_log_level("DEBUG")
    pass
