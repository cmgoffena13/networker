from typing import List, Optional

import structlog
from pendulum import now
from sqlmodel import Session, select

from src.database.db import engine
from src.models.network import Network

logger = structlog.getLogger(__name__)


def db_save_network(network: Network) -> Network:
    logger.debug(f"Saving network: {network}")
    with Session(engine) as session:
        statement = select(Network).where(
            Network.router_mac == network.router_mac,
            Network.public_ip == network.public_ip,
        )
        existing = session.exec(statement).first()

        if existing:
            logger.debug(f"Network already exists, updating...")
            network_data = network.model_dump(
                exclude_none=True,
                exclude={"id", "router_mac", "public_ip", "created_at"},
            )
            for key, value in network_data.items():
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
            session.add(network)
            try:
                session.commit()
                session.refresh(network)
            except Exception:
                session.rollback()
                raise
            return network


def db_get_network(network: Network) -> Optional[Network]:
    with Session(engine) as session:
        return session.exec(
            select(Network).where(
                Network.router_mac == network.router_mac,
                Network.public_ip == network.public_ip,
            )
        ).first()


def db_list_networks() -> List[Network]:
    with Session(engine) as session:
        return session.exec(select(Network)).all()
