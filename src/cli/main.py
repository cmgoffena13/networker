import ctypes
import logging
import os
import sys

from rich.logging import RichHandler
from typer import Typer

from src.cli.console import console, echo
from src.cli.device import device_typer
from src.cli.inference import inference_typer
from src.cli.network import register_base_network_commands
from src.logging_conf import setup_logging

app = Typer(help="Networker CLI - Interact with your local area network (LAN)")
register_base_network_commands(app)
app.add_typer(device_typer, name="device")
app.add_typer(inference_typer, name="inference")


def _is_root() -> bool:
    is_admin = False
    if sys.platform == "win32":
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            is_admin = False
    else:
        is_admin = os.geteuid() == 0
    return is_admin


def main() -> None:
    if not _is_root():
        if sys.platform == "win32":
            echo(
                "[yellow]Warning:[/yellow] Not running as administrator. Networker requires administrator privileges.",
            )
            echo(
                "Please run in an admin terminal.",
            )
        else:
            echo(
                "[yellow]Warning:[/yellow] Not running as root. Networker requires root privileges.",
            )
            echo(
                "Please run with [bold]sudo networker <command>[/bold]",
            )
        return

    setup_logging()
    root_logger = logging.getLogger("src")
    for handler in root_logger.handlers:
        if isinstance(handler, RichHandler):
            handler.console = console
            handler.show_time = False
            handler.show_path = False
            handler.highlighter = None
    app()


if __name__ == "__main__":
    main()
