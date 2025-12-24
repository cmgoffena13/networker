import logging

from rich.logging import RichHandler
from typer import Option, Typer

from src.cli.console import console, echo
from src.cli.device import device_typer
from src.cli.network import network_typer
from src.database.db import init_db
from src.logging_conf import set_log_level, setup_logging

app = Typer(help="Networker CLI - Interact with your local network")
app.add_typer(network_typer, name="network")
app.add_typer(device_typer, name="device")


@app.command("init", help="Initialize the sqlite database and seed lookup data")
def init(
    verbose: bool = Option(
        False, "--verbose", "-v", help="Enable verbose (DEBUG) logging"
    ),
):
    if verbose:
        set_log_level("DEBUG")
    echo("Initializing database...")
    init_db(init=True)
    echo("Database initialized and seeded lookup data")


def main() -> None:
    setup_logging(log_level="WARNING")
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
