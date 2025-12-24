import json

import structlog
from typer import Exit, Option, Typer

from src.cli.console import (
    console,
    display_port_info,
    echo,
    format_device_with_ports_json,
)
from src.core.device import get_open_ports
from src.database.device import db_get_device, db_list_devices, db_update_device
from src.database.device_inference import db_infer_device_type
from src.database.device_port import db_list_device_ports
from src.logging_conf import set_log_level

logger = structlog.getLogger(__name__)

device_typer = Typer(help="Device commands")


@device_typer.command("scan", help="Scan the device for open ports")
def scan(
    save: bool = Option(False, "--save", "-s", help="Save the device scan results"),
    verbose: bool = Option(
        False, "--verbose", "-v", help="Enable verbose (DEBUG) logging"
    ),
    device_id: int = Option(..., "--id", "-i", help="Device ID to scan for open ports"),
):
    if verbose:
        set_log_level("DEBUG")
    try:
        device = db_get_device(device_id)
        device_ports = get_open_ports(device, save=save)
        device_port_objects = [dp for dp, _, _ in device_ports]
        device_inference, device_inference_match = db_infer_device_type(
            device_port_objects, device.id, save=save
        )
        echo(
            f"Device {device.id} Inference: {device_inference}, Match: {device_inference_match:.2%}"
        )
        for device_port, service_name, description in device_ports:
            echo(display_port_info(device_port, service_name, description))
    except Exception as e:
        logger.error(f"Error scanning device: {e}")
        raise Exit(code=1)


@device_typer.command("list", help="List information on devices stored")
def list(
    verbose: bool = Option(
        False, "--verbose", "-v", help="Enable verbose (DEBUG) logging"
    ),
):
    if verbose:
        set_log_level("DEBUG")
    try:
        devices = db_list_devices()
        echo(f"Listing {len(devices)} devices...")
        for device in devices:
            device_ports = db_list_device_ports(device.id)
            echo(format_device_with_ports_json(device, device_ports))
    except Exception as e:
        logger.error(f"Error listing devices: {e}")
        raise Exit(code=1)


@device_typer.command("update", help="Update the device information")
def update(
    device_id: int = Option(..., "--id", "-i", help="Device ID to update"),
    data: str = Option(
        ...,
        "--data",
        "-d",
        help='JSON dictionary of fields to update (e.g., \'{"device_name": "my device"}\')',
    ),
    verbose: bool = Option(
        False, "--verbose", "-v", help="Enable verbose (DEBUG) logging"
    ),
):
    if verbose:
        set_log_level("DEBUG")

    try:
        kwargs = json.loads(data)
    except json.JSONDecodeError as e:
        logger.error(f"Error: Invalid JSON - {e.msg}")
        console.print(
            'Example: --data \'{"device_name": "my device"}\'', style="yellow"
        )
        raise Exit(code=1)

    try:
        updated_device = db_update_device(device_id, **kwargs)
        echo(f"Device {device_id} updated successfully")
        echo(f"Updated device: {updated_device.model_dump_json(indent=2)}")
    except Exception as e:
        logger.error(f"Error updating device: {e}")
        raise Exit(code=1)
