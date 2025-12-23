import structlog
from typer import Exit, Option, Typer

from src.cli.console import display_port_info, echo
from src.database.device import db_get_device
from src.database.device_port import db_list_device_ports
from src.logging_conf import set_log_level

logger = structlog.getLogger(__name__)

device_port_typer = Typer(help="Open Port commands")


@device_port_typer.command("list", help="List all open ports for a device")
def list(
    verbose: bool = Option(
        False, "--verbose", "-v", help="Enable verbose (DEBUG) logging"
    ),
    device_id: int = Option(..., "--id", "-i", help="Device ID to list open ports for"),
):
    if verbose:
        set_log_level("DEBUG")
    try:
        device = db_get_device(device_id)
        device_ports = db_list_device_ports(device_id)
        device_name = device.device_name or "Unknown"
        echo(
            f"Listing the {len(device_ports)} open ports for device (MAC: {device.device_mac}, Name: {device_name}, ID: {device.id})..."
        )
        for device_port, service_name, description in device_ports:
            echo(display_port_info(device_port, service_name, description))
    except Exception as e:
        logger.error(f"Error listing ports: {e}")
        raise Exit(code=1)
