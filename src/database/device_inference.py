from typing import List, Optional, Set, Tuple

import structlog
from pendulum import now
from sqlmodel import Session, select

from src.database.db import engine
from src.database.device import db_update_device
from src.models.device_inference import DeviceInference
from src.models.device_port import DevicePort
from src.protocol import Protocol

logger = structlog.getLogger(__name__)


def score_inference(
    inference: DeviceInference, tcp_ports: Set[int], udp_ports: Set[int]
) -> float:
    """
    Score: (percent_match * num_ports_matched)
    Higher = better match
    """
    tcp_sig = set(inference.tcp_port_numbers or [])
    udp_sig = set(inference.udp_port_numbers or [])

    tcp_matched = len(tcp_sig & tcp_ports)
    udp_matched = len(udp_sig & udp_ports)
    total_matched = tcp_matched + udp_matched
    total_sig_ports = len(tcp_sig) + len(udp_sig)

    if total_sig_ports == 0:
        return 0.0

    percent_match = total_matched / total_sig_ports
    score = percent_match * total_matched

    # Tiebreaker: prefer longer signatures
    tiebreaker = total_sig_ports * 0.01

    return score + tiebreaker


def db_infer_device_type(
    device_ports: List[DevicePort], device_id: int, save: bool = False
) -> Tuple[Optional[str], Optional[float]]:
    logger.debug(f"Inferring device type from database for device ID {device_id}")
    tcp_ports = {dp.port_number for dp in device_ports if dp.protocol == Protocol.TCP}
    udp_ports = {dp.port_number for dp in device_ports if dp.protocol == Protocol.UDP}

    with Session(engine) as session:
        all_inferences = session.exec(select(DeviceInference)).all()

        best_inference: Optional[DeviceInference] = None
        best_score = 0.0

        for inference in all_inferences:
            score = score_inference(inference, tcp_ports, udp_ports)
            if score > best_score:
                best_score = score
                best_inference = inference

        if best_inference and best_score > 0.1:
            tcp_sig = set(best_inference.tcp_port_numbers or [])
            udp_sig = set(best_inference.udp_port_numbers or [])
            total_matched = len(tcp_sig & tcp_ports) + len(udp_sig & udp_ports)
            total_sig_ports = len(tcp_sig) + len(udp_sig)
            match_percentage = (
                total_matched / total_sig_ports if total_sig_ports > 0 else 0.0
            )

            if save and best_inference:
                db_update_device(
                    device_id,
                    device_inference=best_inference.inference,
                    inference_match=match_percentage,
                    updated_at=now(),
                )
                logger.debug(
                    f"Updated device {device_id} in database with inference: {best_inference.inference} (match: {match_percentage:.2%}, score: {best_score:.2f})"
                )
            return (best_inference.inference, match_percentage)

        logger.debug(f"No inferences found in database for device ID {device_id}")
        return (None, None)


def db_list_inferences() -> List[DeviceInference]:
    logger.debug("Listing all inferences from database...")
    with Session(engine) as session:
        return session.exec(select(DeviceInference)).all()
