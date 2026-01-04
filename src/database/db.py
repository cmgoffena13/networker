import shutil
import sqlite3
import sys
from pathlib import Path

import pendulum
import structlog
from pydantic_extra_types.pendulum_dt import Date, DateTime
from sqlmodel import create_engine

from src.cli.console import echo
from src.models import *

logger = structlog.getLogger(__name__)


def _register_pendulum_adapters():
    sqlite3.register_adapter(pendulum.DateTime, lambda val: val.isoformat(" "))
    sqlite3.register_adapter(pendulum.Date, lambda val: val.format("YYYY-MM-DD"))
    sqlite3.register_adapter(
        DateTime, lambda val: val.in_timezone("UTC").isoformat(" ")
    )
    sqlite3.register_adapter(Date, lambda val: val.format("YYYY-MM-DD"))


def get_db_path():
    """Get the path to the user's database file.

    On first run, copies the schema database to the user's config directory.
    """
    if getattr(sys, "frozen", False):
        base_path = sys._MEIPASS
    else:
        base_path = Path(__file__).parent.parent

    schema_db = base_path / "data" / "networker_base.db"

    config_dir = Path.home() / ".config" / "networker"
    config_dir.mkdir(parents=True, exist_ok=True)
    user_db = config_dir / "networker.db"

    if not user_db.exists() and schema_db.exists():
        shutil.copy2(schema_db, user_db)
        echo(f"Created user database: {user_db}")
        logger.debug(f"Copied schema database from {schema_db} to {user_db}")

    return user_db


def create_new_engine():
    _register_pendulum_adapters()
    db_path = get_db_path()
    db_url = f"sqlite:///{db_path}"
    return create_engine(db_url)


engine = create_new_engine()
