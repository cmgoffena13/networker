from pathlib import Path

import polars as pl
import structlog
from sqlmodel import Session, SQLModel, create_engine

from src.models import *
from src.protocol import Protocol

logger = structlog.getLogger(__name__)

engine = create_engine("sqlite:///database.db")


def db_seed_ports():
    logger.debug("Inserting ports...")
    script_dir = Path(__file__).parent
    ports_file = script_dir / "seeds" / "output" / "ports.csv"

    if not ports_file.exists():
        logger.error(f"Ports file not found: {ports_file}")
        raise FileNotFoundError(f"Ports seed file not found: {ports_file}")

    ports_df = pl.read_csv(ports_file)
    port_objects = []

    for row in ports_df.iter_rows(named=True):
        port = Port(
            port_number=row["port_number"],
            protocol=Protocol(row["protocol"]),
            service_name=row["service_name"],
            description=row["description"],
        )
        port_objects.append(port)

    with Session(engine) as session:
        session.add_all(port_objects)
        try:
            session.commit()
        except Exception:
            session.rollback()
            raise


def init_db(init: bool = False):
    logger.debug("Initializing database...")
    if init:
        logger.debug("Dropping all tables...")
        SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    if init:
        db_seed_ports()
    logger.debug("Database initialized")
