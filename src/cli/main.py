import logging

from rich.logging import RichHandler
from typer import Typer

from src.cli.console import console
from src.cli.device import device
from src.cli.network import network
from src.db import init_db
from src.logging_conf import setup_logging

app = Typer(help="Networker CLI - Interact with your local network")
app.add_typer(network, name="network")
app.add_typer(device, name="device")


@app.command()
def init():
    init_db(init=True)


def main() -> None:
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
