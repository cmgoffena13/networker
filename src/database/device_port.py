import structlog
from sqlalchemy import select
from sqlmodel import Session

from src.database.db import engine
from src.models.device_port import DevicePort

logger = structlog.getLogger(__name__)


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
