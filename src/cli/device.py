import json

import structlog
from typer import Abort, Exit, Option, Typer, confirm

from src.cli.console import (
    console,
    display_port_info,
    echo,
    format_device_with_ports_json,
)
from src.core.device import scan_device_for_open_ports
from src.database.device import (
    db_delete_device,
    db_get_device,
    db_list_devices,
    db_update_device,
)
from src.database.device_port import db_list_device_ports
from src.logging_conf import set_log_level

logger = structlog.getLogger(__name__)

device_typer = Typer(help="Device commands")


@device_typer.command("scan", help="Scan the device for open ports")
def scan(
    save: bool = Option(
        False, "--save", "-s", help="Save the device scan results to the database"
    ),
    verbose: bool = Option(
        False, "--verbose", "-v", help="Enable verbose (DEBUG) logging"
    ),
    device_id: int = Option(..., "--id", "-i", help="Device ID to scan for open ports"),
):
    if verbose:
        set_log_level("DEBUG")
    try:
        device = db_get_device(device_id)
        echo("\nPress Ctrl+C to interrupt scanning and exit...")
        scan_device_for_open_ports(device, save=save)
    except Abort:
        raise
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


@device_typer.command("delete", help="Delete a device and all associated data")
def delete(
    device_id: int = Option(..., "--id", "-i", help="Device ID to delete"),
    verbose: bool = Option(
        False, "--verbose", "-v", help="Enable verbose (DEBUG) logging"
    ),
):
    if verbose:
        set_log_level("DEBUG")
    try:
        device = db_get_device(device_id)
        if not device:
            echo(f"Device {device_id} not found")
            raise Exit(code=1)

        echo(f"Warning: This will delete device {device_id} and all associated data:")
        echo("  - All device port records")
        echo("  - All network speed test records")
        echo("  - The device record")
        if not confirm("Are you sure you want to continue?", default=False):
            echo("Device deletion cancelled.")
            raise Abort()

        db_delete_device(device_id)
        echo(f"Device {device_id} deleted successfully")
    except Abort:
        raise
    except Exception as e:
        logger.error(f"Error deleting device: {e}")
        raise Exit(code=1)
