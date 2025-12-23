from typing import Any, List, Optional

import httpx
import structlog
from pendulum import now
from sqlmodel import Session, select

from src.cli.console import echo
from src.database.db import engine
from src.exceptions import DeviceNotFoundError
from src.models.device import Device

logger = structlog.getLogger(__name__)


def get_vendor_name(mac_address: str, api_key: Optional[str] = None) -> Optional[str]:
    oui = mac_address[:8]
    logger.debug(f"Getting vendor name for OUI: {oui}")
    try:
        url = f"https://api.maclookup.app/v2/macs/{oui}/company/name"
        params = {}
        if api_key:
            params["apiKey"] = api_key

        response = httpx.get(url, params=params, timeout=10)

        if response.status_code == 200:
            vendor_name = response.text.strip()
            logger.debug(f"Vendor name for {mac_address}: {vendor_name}")
            return vendor_name if vendor_name else None
        elif response.status_code == 400:
            logger.warning(f"Invalid MAC address format: {mac_address}")
            return None
        elif response.status_code == 401:
            logger.warning("Invalid API key for maclookup.app")
            return None
        elif response.status_code == 409:
            logger.warning("Rate limit exceeded for maclookup.app")
            return None
        elif response.status_code == 429:
            logger.warning("Rate limit exceeded for maclookup.app")
            return None
        else:
            logger.warning(
                f"Unexpected response from maclookup.app: {response.status_code}"
            )
            return None
    except Exception as e:
        logger.error(f"Error getting vendor name for {mac_address}: {e}")
        return None


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
            if not existing.vendor_name:
                existing.vendor_name = get_vendor_name(existing.device_mac)
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
            if not device.vendor_name:
                device.vendor_name = get_vendor_name(device.device_mac)
            session.add(device)
            try:
                session.commit()
                session.refresh(device)
                return device
            except Exception:
                session.rollback()
                raise


def db_update_device(id: int, **kwargs: Any) -> Device:
    logger.debug(f"Updating device id: {id} with kwargs: {kwargs}")
    with Session(engine) as session:
        statement = select(Device).where(
            Device.id == id,
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
                return existing
            except Exception:
                session.rollback()
                raise
        else:
            raise DeviceNotFoundError(f"Device not found: {id}")


def db_list_devices() -> List[Device]:
    echo("Listing devices...")
    with Session(engine) as session:
        statement = select(Device)
        devices = session.exec(statement).all()
        return devices
