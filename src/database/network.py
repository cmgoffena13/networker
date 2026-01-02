from typing import Any, List, Optional

import structlog
from pendulum import now
from sqlmodel import Session, select

from src.database.db import engine
from src.exceptions import NetworkNotFoundError
from src.models.network import Network, NetworkSpeedTest

logger = structlog.getLogger(__name__)


def db_save_network(network: Network) -> Network:
    logger.debug(f"Saving network: {network}")
    with Session(engine) as session:
        statement = select(Network).where(
            Network.router_mac == network.router_mac,
        )
        existing = session.exec(statement).first()

        if existing:
            logger.debug(f"Network already exists, updating...")
            network_data = network.model_dump(
                exclude_none=True,
                exclude={"id", "network_name", "router_mac", "created_at"},
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
            )
        ).first()


def db_list_networks() -> List[Network]:
    with Session(engine) as session:
        return session.exec(select(Network)).all()


def db_update_network(id: int, **kwargs: Any) -> Network:
    logger.debug(f"Updating network id: {id} with kwargs: {kwargs}")
    with Session(engine) as session:
        statement = select(Network).where(
            Network.id == id,
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
            raise NetworkNotFoundError(f"Network not found: {id}")


def db_save_network_speed_test(
    network_speed_test: NetworkSpeedTest,
) -> NetworkSpeedTest:
    logger.debug(f"Saving network speed test: {network_speed_test}")
    with Session(engine) as session:
        session.add(network_speed_test)
        try:
            session.commit()
        except Exception:
            session.rollback()
            raise


def db_get_latest_network_speed_test(network_id: int) -> Optional[NetworkSpeedTest]:
    with Session(engine) as session:
        return session.exec(
            select(NetworkSpeedTest)
            .where(
                NetworkSpeedTest.network_id == network_id,
            )
            .order_by(NetworkSpeedTest.id.desc())
        ).first()
