from typing import List

import structlog
from pendulum import now
from sqlmodel import Session, select

from src.cli.console import echo
from src.database.db import engine
from src.models.network import Network

logger = structlog.getLogger(__name__)


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
            session.add(network)
            try:
                session.commit()
                session.refresh(network)
                return network
            except Exception:
                session.rollback()
                raise


def db_list_networks() -> List[Network]:
    with Session(engine) as session:
        return session.exec(select(Network)).all()
