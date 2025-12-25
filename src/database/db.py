from pathlib import Path

import polars as pl
import structlog
from sqlalchemy import text
from sqlmodel import Session, SQLModel, create_engine

from src.models import *
from src.models.device_inference import DeviceInference
from src.protocol import Protocol

logger = structlog.getLogger(__name__)

engine = create_engine("sqlite:///networker.db")


def db_seed_ports():
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


def db_seed_device_inferences():
    logger.debug("Inserting device inferences...")

    inferences = [
        DeviceInference(
            tcp_port_numbers=[445, 3389],
            inference="Windows",
            inference_reasoning="SMB and RDP are used for Windows",
        ),
        DeviceInference(
            tcp_port_numbers=[53, 80, 443],
            inference="Switch",
            inference_reasoning="DNS + Web Server",
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


def init_db(init: bool = False):
    logger.debug("Initializing database...")
    if init:
        logger.debug("Dropping all tables...")
        SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    if init:
        db_seed_ports()
        db_seed_device_inferences()
    logger.debug("Database initialized")
