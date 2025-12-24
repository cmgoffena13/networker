from typing import List

import structlog
from pendulum import now
from sqlalchemy import func
from sqlmodel import Session, select

from src.database.db import engine
from src.database.device import db_update_device
from src.models.device_inference import DeviceInference
from src.models.device_port import DevicePort

logger = structlog.getLogger(__name__)


def db_infer_device_type(
    device_ports: List[DevicePort], device_id: int, save: bool = False
):
    logger.debug(f"Inferring device type for device ID: {device_id}")
    with Session(engine) as session:
        if not save:
            all_inferences = session.exec(select(DeviceInference)).all()
            matching_inferences = []
            for device_port in device_ports:
                for inference in all_inferences:
                    if (
                        inference.port_number == device_port.port_number
                        and inference.protocol == device_port.protocol
                    ):
                        matching_inferences.append(inference.inference)

            if matching_inferences:
                inferences_str = ",".join(matching_inferences)
                return inferences_str
            else:
                logger.debug(f"No inferences found for device ID: {device_id}")
                return None
        else:
            result = session.exec(
                select(
                    func.group_concat(DeviceInference.inference).label("inferences"),
                )
                .select_from(DevicePort)
                .join(
                    DeviceInference,
                    (DevicePort.port_number == DeviceInference.port_number)
                    & (DevicePort.protocol == DeviceInference.protocol),
                )
                .where(DevicePort.device_id == device_id)
            ).first()

            if result:
                db_update_device(device_id, device_inference=result, updated_at=now())
                logger.debug(
                    f"Updated device {device_id} with device_inference: {result}"
                )
                return result
            else:
                logger.debug(f"No inferences found for device ID: {device_id}")
                return None
