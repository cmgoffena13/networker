import logging

from rich.logging import RichHandler
from typer import Exit, Option, Typer

from src.cli.console import console, echo
from src.cli.device import device_typer
from src.cli.inference import inference_typer
from src.cli.network import register_base_network_commands
from src.database.db import get_db_path
from src.logging_conf import setup_logging
from src.utils import check_root_and_warn, get_version

app = Typer(help="Networker CLI - Interact with your local area network (LAN)")


@app.callback(no_args_is_help=True)
def main_menu(
    version: bool = Option(False, "--version", help="Show CLI version and exit"),
    info: bool = Option(False, "--info", help="Show general CLI info and exit"),
) -> None:
    if version:
        echo(f"Networker version: {get_version()}")
        raise Exit(code=0)
    if info:
        echo(f"Database: {get_db_path()}")
        raise Exit(code=0)


register_base_network_commands(app)
app.add_typer(device_typer, name="device")
app.add_typer(inference_typer, name="inference")


def main() -> None:
    if not check_root_and_warn():
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
