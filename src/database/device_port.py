from typing import List, Optional, Tuple

import structlog
from sqlmodel import Session, delete, select

from src.database.db import engine
from src.models.device_port import DevicePort
from src.models.port import Port

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


def db_list_device_ports(
    device_id: int,
) -> List[Tuple[DevicePort, Optional[str], Optional[str]]]:
    logger.debug(f"Listing open device ports for device: {device_id}")
    with Session(engine) as session:
        return session.exec(
            select(DevicePort, Port.service_name, Port.description)
            .outerjoin(
                Port,
                (DevicePort.port_number == Port.port_number)
                & (DevicePort.protocol == Port.protocol),
            )
            .where(DevicePort.device_id == device_id)
        ).all()
