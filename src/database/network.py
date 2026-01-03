import ipaddress
from typing import Any, List, Optional

import structlog
from pendulum import now
from sqlalchemy import func
from sqlmodel import Session, delete, select

from src.cli.console import echo
from src.database.db import engine
from src.exceptions import NetworkNotFoundError
from src.models.device import Device
from src.models.device_port import DevicePort
from src.models.network import Network, NetworkSpeedTest

logger = structlog.getLogger(__name__)


def db_save_network(network: Network) -> Network:
    logger.debug(f"Saving network to database: {network}")
    with Session(engine) as session:
        statement = select(Network).where(
            Network.router_mac == network.router_mac,
        )
        existing = session.exec(statement).first()

        if existing:
            logger.debug(f"Network already exists in database, updating...")
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
                logger.debug(f"Network id {existing.id} updated in database")
            except Exception:
                session.rollback()
                raise
            return existing
        else:
            netmask_int = int(ipaddress.IPv4Address(network.netmask))
            prefix_length = bin(netmask_int).count("1")
            echo(
                f"New network detected: {network.network_address}/{prefix_length}",
                bold=True,
            )
            session.add(network)
            try:
                session.commit()
                session.refresh(network)
                logger.debug(f"Network id {network.id} saved to database")
            except Exception:
                session.rollback()
                raise
            return network


def db_get_network(network: Network) -> Optional[Network]:
    logger.debug("Getting network from database...")
    with Session(engine) as session:
        return session.exec(
            select(Network).where(
                Network.router_mac == network.router_mac,
            )
        ).first()


def db_list_networks() -> List[Network]:
    logger.debug("Listing all networks from database...")
    with Session(engine) as session:
        return session.exec(select(Network)).all()


def db_update_network(id: int, **kwargs: Any) -> Network:
    logger.debug(f"Updating network id {id} in database with kwargs: {kwargs}")
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
                logger.debug(f"Network id {existing.id} updated in database")
            except Exception:
                session.rollback()
                raise
            return existing
        else:
            raise NetworkNotFoundError(f"Network not found: {id}")


def _cleanup_network_speed_tests(network_id: int, device_id: int) -> None:
    logger.debug("Checking for network speed test cleanup...")
    with Session(engine) as session:
        count_result = session.exec(
            select(func.count(NetworkSpeedTest.id)).where(
                NetworkSpeedTest.network_id == network_id,
                NetworkSpeedTest.device_id == device_id,
            )
        ).one()

        if count_result and count_result > 100:
            logger.debug(
                f"Cleaning up network speed tests for network id {network_id} and device id {device_id}..."
            )
            subquery = (
                select(NetworkSpeedTest.id)
                .where(
                    NetworkSpeedTest.network_id == network_id,
                    NetworkSpeedTest.device_id == device_id,
                )
                .order_by(NetworkSpeedTest.id.desc())
                .limit(100)
                .subquery()
            )
            min_id = session.exec(select(func.min(subquery.c.id))).one()

            session.exec(
                delete(NetworkSpeedTest).where(
                    NetworkSpeedTest.network_id == network_id,
                    NetworkSpeedTest.device_id == device_id,
                    NetworkSpeedTest.id < min_id,
                )
            )
            try:
                session.commit()
            except Exception:
                session.rollback()
                raise
            logger.debug(
                f"Deleted old network speed test records for network id {network_id} and device id {device_id} (keeping records with id >= {min_id})"
            )


def db_save_network_speed_test(
    network_speed_test: NetworkSpeedTest,
) -> None:
    logger.debug(f"Saving network speed test to database: {network_speed_test}")
    with Session(engine) as session:
        session.add(network_speed_test)
        try:
            session.commit()
            logger.debug(f"Network speed test saved to database")
        except Exception:
            session.rollback()
            raise

    _cleanup_network_speed_tests(
        network_speed_test.network_id, network_speed_test.device_id
    )


def db_get_latest_network_speed_test(
    network_id: int, device_id: int
) -> Optional[NetworkSpeedTest]:
    logger.debug(
        f"Getting latest network speed test from database for network id {network_id} and device id {device_id}..."
    )
    with Session(engine) as session:
        network_speed_test_id = session.exec(
            select(NetworkSpeedTest.id)
            .where(
                NetworkSpeedTest.network_id == network_id,
                NetworkSpeedTest.device_id == device_id,
            )
            .order_by(NetworkSpeedTest.id.desc())
        ).first()
        return session.exec(
            select(NetworkSpeedTest).where(NetworkSpeedTest.id == network_speed_test_id)
        ).first()


def db_delete_network(network_id: int) -> None:
    logger.debug(
        f"Deleting network id {network_id} and associated data from database..."
    )
    with Session(engine) as session:
        try:
            device_ids = session.exec(
                select(Device.id).where(Device.network_id == network_id)
            ).all()
            if device_ids:
                session.exec(
                    delete(DevicePort).where(DevicePort.device_id.in_(device_ids))
                )
            session.exec(
                delete(NetworkSpeedTest).where(
                    NetworkSpeedTest.network_id == network_id
                )
            )
            session.exec(delete(Device).where(Device.network_id == network_id))
            session.exec(delete(Network).where(Network.id == network_id))
            session.commit()
            logger.debug(f"Network id {network_id} deleted from database")
        except Exception:
            session.rollback()
            raise


def db_get_network_by_id(network_id: int) -> Optional[Network]:
    logger.debug(f"Getting network from database by id: {network_id}...")
    with Session(engine) as session:
        return session.exec(select(Network).where(Network.id == network_id)).first()
