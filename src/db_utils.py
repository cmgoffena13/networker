from pathlib import Path

import polars as pl
import structlog
from sqlalchemy import select
from sqlmodel import Session

from src.db import engine
from src.models.device import Device
from src.models.device_port import DevicePort
from src.models.network import Network
from src.models.port import Port
from src.protocol import Protocol

logger = structlog.getLogger(__name__)


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


def db_save_device_port(device_port: DevicePort):
    logger.debug(f"Saving device port: {device_port}")
    with Session(engine) as session:
        statement = select(DevicePort).where(
            DevicePort.device_id == device_port.device_id,
            DevicePort.port_number == device_port.port_number,
            DevicePort.protocol == device_port.protocol,
        )
        existing = session.exec(statement).first()

        if existing:
            session.add(existing)
            try:
                session.commit()
            except Exception:
                session.rollback()
                raise
        else:
            session.add(device_port)
            try:
                session.commit()
            except Exception:
                session.rollback()
                raise


def db_save_device(device: Device) -> Device:
    logger.debug(f"Saving device: {device}")
    with Session(engine) as session:
        statement = select(Device).where(
            Device.network_id == device.network_id,
            Device.device_mac == device.device_mac,
        )
        existing = session.exec(statement).first()

        if existing:
            existing.device_ip = device.device_ip
            existing.is_router = device.is_router
            session.add(existing)
            try:
                session.commit()
                session.refresh(existing)
                return existing
            except Exception:
                session.rollback()
                raise
        else:
            session.add(device)
            try:
                session.commit()
                session.refresh(device)
                return device
            except Exception:
                session.rollback()
                raise


def db_save_network(network: Network) -> Network:
    logger.debug(f"Saving network: {network}")
    with Session(engine) as session:
        statement = select(Network).where(
            Network.ssid_name == network.ssid_name,
            Network.router_mac == network.router_mac,
        )
        existing = session.exec(statement).first()

        if existing:
            existing.network_address = network.network_address
            existing.public_ip = network.public_ip
            existing.broadcast_address = network.broadcast_address
            existing.netmask = network.netmask
            existing.ips_available = network.ips_available
            session.add(existing)
            try:
                session.commit()
                session.refresh(existing)
                return existing
            except Exception:
                session.rollback()
                raise
        else:
            session.add(network)
            try:
                session.commit()
                session.refresh(network)
                return network
            except Exception:
                session.rollback()
                raise
