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
            Device.device_mac == device.device_mac,
        )
        existing = session.exec(statement).first()

        if existing:
            existing.device_ip = device.device_ip
            existing.device_name = device.device_name
            existing.vendor_name = device.vendor_name
            existing.is_router = device.is_router
            existing.updated_at = now()
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
                return existing
            except Exception:
                session.rollback()
                raise
        else:
            raise DeviceNotFoundError(f"Device not found: {id}")


def db_list_devices() -> List[Device]:
    with Session(engine) as session:
        statement = select(Device)
        devices = session.exec(statement).all()
        return devices
