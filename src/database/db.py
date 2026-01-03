import shutil
import sqlite3
import sys
from pathlib import Path

import pendulum
import polars as pl
import structlog
from pydantic_extra_types.pendulum_dt import Date, DateTime
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlmodel import Session, SQLModel, create_engine

from src.models import *
from src.models.device_inference import DeviceInference
from src.protocol import Protocol

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
        logger.debug(f"Copied schema database from {schema_db} to {user_db}")

    return user_db


def create_new_engine():
    _register_pendulum_adapters()
    db_path = get_db_path()
    return create_engine(f"sqlite:///{db_path}")


engine = create_new_engine()


def db_seed_ports(engine: Engine):
    logger.debug("Inserting ports...")
    script_dir = Path(__file__).parent.parent
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


def db_seed_device_inferences(engine: Engine):
    logger.debug("Inserting device inferences...")

    inferences = [
        DeviceInference(
            tcp_port_numbers=[445, 3389],
            inference="Windows",
            inference_reasoning="SMB and RDP are used for Windows",
        ),
        DeviceInference(
            tcp_port_numbers=[53, 80, 443, 5000, 7547],
            inference="Router",
            inference_reasoning="DNS + Web Server + UPnP + ISP Remote Management",
        ),
        DeviceInference(
            tcp_port_numbers=[7000, 8009, 5541],
            udp_port_numbers=[5353],
            inference="macOS AirPlay Receiver",
            inference_reasoning="RTSP AirPlay control + Cast discovery + AirPlay session port",
        ),
        DeviceInference(
            tcp_port_numbers=[9100],
            inference="Printer",
            inference_reasoning="Printer port",
        ),
        DeviceInference(
            tcp_port_numbers=[548],
            udp_port_numbers=[5353],
            inference="macOS",
            inference_reasoning="Bonjour/Zeroconf discovery + AFP file sharing",
        ),
        DeviceInference(
            tcp_port_numbers=[49152, 62078],
            inference="iOS Device",
            inference_reasoning="Temporary local app connections and Apple Sync port",
        ),
        DeviceInference(
            udp_port_numbers=[5353],
            inference="iOS Device",
            inference_reasoning="Persistent Bonjour/mDNS (all Apple mobile)",
        ),
        DeviceInference(
            tcp_port_numbers=[22, 111, 2049],
            inference="Linux Server",
            inference_reasoning="SSH + NFS + Samba",
        ),
        DeviceInference(
            tcp_port_numbers=[1433],
            inference="Microsoft SQL Server",
            inference_reasoning="MSSQL default instance port",
        ),
        DeviceInference(
            tcp_port_numbers=[5432],
            inference="PostgreSQL",
            inference_reasoning="PostgreSQL standard query port",
        ),
        DeviceInference(
            tcp_port_numbers=[6379],
            inference="Redis",
            inference_reasoning="Redis in-memory database port",
        ),
        DeviceInference(
            tcp_port_numbers=[3306],
            inference="MySQL/MariaDB",
            inference_reasoning="MySQL standard query port",
        ),
    ]

    with Session(engine) as session:
        session.exec(text("DELETE FROM device_inferences"))
        session.add_all(inferences)
        try:
            session.commit()
        except Exception:
            session.rollback()
            raise


def init_db(reset: bool = False):
    logger.debug("Initializing database...")
    if reset:
        logger.debug("Dropping all tables...")
        SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    db_seed_ports(engine=engine)
    db_seed_device_inferences(engine=engine)
    logger.debug("Database initialized")


def create_base_db():
    data_dir = Path(__file__).parent.parent / "data"
    base_engine = create_engine(f"sqlite:///{data_dir}/networker_base.db")
    SQLModel.metadata.drop_all(base_engine)
    SQLModel.metadata.create_all(base_engine)
    db_seed_ports(engine=base_engine)
    db_seed_device_inferences(engine=base_engine)


def update_inferences(engine: Engine):
    db_seed_device_inferences(engine=engine)
