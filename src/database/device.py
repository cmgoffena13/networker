from typing import Any, List, Optional

import structlog
from pendulum import now
from sqlmodel import Session, delete, select

from src.cli.console import echo
from src.database.db import engine
from src.exceptions import DeviceNotFoundError
from src.models.device import Device
from src.models.device_port import DevicePort
from src.models.network import NetworkSpeedTest

logger = structlog.getLogger(__name__)


def db_save_device(device: Device) -> Device:
    logger.debug(f"Saving device to database: {device}")
    with Session(engine) as session:
        statement = select(Device).where(
            Device.network_id == device.network_id,
            Device.mac_address == device.mac_address,
        )
        existing = session.exec(statement).first()

        if existing:
            logger.debug(f"Device already exists in database, updating...")
            device_data = device.model_dump(
                exclude_none=True,
                exclude={
                    "id",
                    "device_name",
                    "network_id",
                    "mac_address",
                    "created_at",
                },
            )
            for key, value in device_data.items():
                if hasattr(existing, key):
                    setattr(existing, key, value)
            existing.updated_at = now()
            session.add(existing)
            try:
                session.commit()
                session.refresh(existing)
            except Exception:
                session.rollback()
                raise
            return existing
        else:
            echo(
                f"New device detected: {device.mac_address} ({device.ip_address})",
                bold=True,
            )
            session.add(device)
            try:
                session.commit()
                session.refresh(device)
            except Exception:
                session.rollback()
                raise
            return device


def db_update_device(id: int, **kwargs: Any) -> Device:
    logger.debug(f"Updating device id {id} in database with kwargs: {kwargs}")
    with Session(engine) as session:
        statement = select(Device).where(
            Device.id == id,
        )
        existing = session.exec(statement).first()
        if existing:
            for key, value in kwargs.items():
                if hasattr(existing, key):
                    setattr(existing, key, value)
            existing.updated_at = now()
            session.add(existing)
            try:
                session.commit()
                session.refresh(existing)
            except Exception:
                session.rollback()
                raise
            return existing
        else:
            raise DeviceNotFoundError(f"Device not found: {id}")


def db_list_devices() -> List[Device]:
    logger.debug("Listing all devices from database...")
    with Session(engine) as session:
        return session.exec(select(Device)).all()


def db_get_current_device() -> Optional[Device]:
    logger.debug("Getting current device from database...")
    with Session(engine) as session:
        current_device_id = session.exec(
            select(Device.id).where(Device.current_device == True)
        ).first()
        return session.exec(
            select(Device).where(Device.id == current_device_id)
        ).first()


def db_get_device(id: int) -> Device:
    logger.debug(f"Getting device from database by id: {id}...")
    with Session(engine) as session:
        return session.exec(select(Device).where(Device.id == id)).first()


def db_get_device_by_mac_address(mac_address: str, network_id: int) -> Optional[Device]:
    logger.debug(
        f"Getting device from database by mac address {mac_address} and network id {network_id}..."
    )
    with Session(engine) as session:
        return session.exec(
            select(Device).where(
                Device.mac_address == mac_address, Device.network_id == network_id
            )
        ).first()


def db_delete_device(device_id: int) -> None:
    logger.debug(f"Deleting device id {device_id} from database...")
    with Session(engine) as session:
        try:
            session.exec(delete(DevicePort).where(DevicePort.device_id == device_id))
            session.exec(
                delete(NetworkSpeedTest).where(NetworkSpeedTest.device_id == device_id)
            )
            session.exec(delete(Device).where(Device.id == device_id))
            session.commit()
            logger.debug(f"Device id {device_id} deleted from database")
        except Exception:
            session.rollback()
            raise
