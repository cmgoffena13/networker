from pathlib import Path

import polars as pl
import structlog
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
            port_number=53,
            protocol=Protocol.TCP,
            inference="Router",
            inference_reasoning="Port 53 is used for DNS Servers",
        ),
        DeviceInference(
            port_number=161,
            protocol=Protocol.UDP,
            inference="Router",
            inference_reasoning="Port 161 is used for SNMP",
        ),
        DeviceInference(
            port_number=5000,
            protocol=Protocol.TCP,
            inference="macOS",
            inference_reasoning="Port 5000 is used for desktop Airplay",
        ),
        DeviceInference(
            port_number=548,
            protocol=Protocol.TCP,
            inference="macOS",
            inference_reasoning="Port 548 is used for Apple Filing Protocol (AFP)",
        ),
        DeviceInference(
            port_number=7000,
            protocol=Protocol.TCP,
            inference="iPhone/iPad",
            inference_reasoning="Port 7000 is used for mobile device Airplay",
        ),
        DeviceInference(
            port_number=62078,
            protocol=Protocol.TCP,
            inference="iPhone/iPad",
            inference_reasoning="Port 62078 is used for wifi sync",
        ),
        DeviceInference(
            port_number=22,
            protocol=Protocol.TCP,
            inference="Linux",
            inference_reasoning="Port 22 is used for SSH",
        ),
        DeviceInference(
            port_number=3389,
            protocol=Protocol.TCP,
            inference="Windows",
            inference_reasoning="Port 3389 is used for Remote Desktop Protocol (RDP)",
        ),
        DeviceInference(
            port_number=445,
            protocol=Protocol.TCP,
            inference="Windows",
            inference_reasoning="Port 445 is used for Server Message Block (SMB)",
        ),
        DeviceInference(
            port_number=9100,
            protocol=Protocol.TCP,
            inference="Printer",
            inference_reasoning="Port 9100 is used for Printers",
        ),
    ]

    with Session(engine) as session:
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
