from typing import List

import structlog
from sqlmodel import Session, delete

from src.database.db import engine
from src.models.device_port import DevicePort

logger = structlog.getLogger(__name__)


def db_save_device_ports(device_ports: List[DevicePort], device_id: int):
    logger.debug(f"Saving open device ports for device: {device_id}")
    with Session(engine) as session:
        savepoint = session.begin_nested()
        try:
            session.exec(delete(DevicePort).where(DevicePort.device_id == device_id))

            session.add_all(device_ports)

            savepoint.commit()
            session.commit()
        except Exception:
            savepoint.rollback()
            session.rollback()
            raise
