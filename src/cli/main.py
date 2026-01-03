import logging

from rich.logging import RichHandler
from sqlalchemy import inspect
from typer import Typer

from src.cli.console import console, echo
from src.cli.device import device_typer
from src.cli.inference import inference_typer
from src.cli.network import register_base_network_commands
from src.database.db import engine, init_db
from src.logging_conf import setup_logging

app = Typer(help="Networker CLI - Interact with your local network")
register_base_network_commands(app)
app.add_typer(device_typer, name="device")
app.add_typer(inference_typer, name="inference")


def _auto_init_db() -> None:
    inspector = inspect(engine)
    existing_tables = inspector.get_table_names()

    if not existing_tables:
        echo("Initializing database...")
        init_db(reset=False)
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
    _auto_init_db()
    app()


if __name__ == "__main__":
    main()
