from typing import Any, List

import structlog
from pendulum import now
from sqlmodel import Session, select

from src.cli.console import echo
from src.database.db import engine
from src.exceptions import DeviceNotFoundError
from src.models.device import Device

logger = structlog.getLogger(__name__)


def db_save_device(device: Device) -> Device:
    logger.debug(f"Saving device: {device}")
    with Session(engine) as session:
        statement = select(Device).where(
            Device.network_id == device.network_id,
            Device.mac_address == device.mac_address,
        )
        existing = session.exec(statement).first()

        if existing:
            logger.debug(f"Device already exists, updating...")
            device_data = device.model_dump(
                exclude_none=True,
                exclude={"id", "network_id", "mac_address", "created_at"},
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
            echo(f"New device detected: {device.mac_address} ({device.ip_address})")
            session.add(device)
            try:
                session.commit()
                session.refresh(device)
            except Exception:
                session.rollback()
                raise
            return device


def db_update_device(id: int, **kwargs: Any) -> Device:
    logger.debug(f"Updating device id: {id} with kwargs: {kwargs}")
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
    with Session(engine) as session:
        return session.exec(select(Device)).all()


def db_get_device(id: int) -> Device:
    with Session(engine) as session:
        return session.exec(select(Device).where(Device.id == id)).first()


def db_check_device_exists(device: Device, network_id: int) -> bool:
    logger.debug(
        f"Checking if device {device.mac_address} exists on network {network_id}..."
    )
    with Session(engine) as session:
        statement = select(Device).where(
            Device.network_id == network_id,
            Device.mac_address == device.mac_address,
        )
        existing = session.exec(statement).first()

        if existing:
            logger.debug(f"Device already exists with id: {existing.id}")
            return True
        else:
            logger.debug("Device is new!")
            return False
