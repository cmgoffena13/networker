import structlog
from pendulum import now
from sqlmodel import Session, select

from src.database.db import engine
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
