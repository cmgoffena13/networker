import structlog
from typer import Exit, Option, Typer

from src.cli.console import echo
from src.database.device_port import db_list_device_ports
from src.logging_conf import set_log_level

logger = structlog.getLogger(__name__)

device_port_typer = Typer(help="Open port commands")


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
        device_ports = db_list_device_ports(device_id)
        echo(f"Listing {len(device_ports)} open ports for device: {device_id}")
        for device_port, service_name in device_ports:
            service_info = f" - {service_name}" if service_name else ""
            echo(
                f"Open Port: {device_port.port_number} ({device_port.protocol.value}){service_info}"
            )
    except Exception as e:
        logger.error(f"Error listing ports: {e}")
        raise Exit(code=1)
