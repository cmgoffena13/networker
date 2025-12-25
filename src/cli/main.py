import logging

from rich.logging import RichHandler
from sqlalchemy import inspect
from typer import Abort, Option, Typer, confirm

from src.cli.console import console, echo
from src.cli.device import device_typer
from src.cli.inference import inference_typer
from src.cli.network import network_typer
from src.database.db import engine, init_db
from src.logging_conf import set_log_level, setup_logging

app = Typer(help="Networker CLI - Interact with your local network")
app.add_typer(network_typer, name="network")
app.add_typer(device_typer, name="device")
app.add_typer(inference_typer, name="inference")


@app.command("init", help="Initialize the sqlite database and seed lookup data")
def init(
    verbose: bool = Option(
        False, "--verbose", "-v", help="Enable verbose (DEBUG) logging"
    ),
):
    if verbose:
        set_log_level("DEBUG")

    inspector = inspect(engine)
    existing_tables = inspector.get_table_names()

    if existing_tables:
        echo("Warning: The database already contains tables.")
        echo("This operation will DROP ALL EXISTING TABLES and recreate them.")
        echo("All existing data will be lost!")
        if not confirm("Are you sure you want to continue?", default=False):
            echo("Database initialization cancelled.")
            raise Abort()

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
