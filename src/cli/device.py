import json

from typer import Exit, Option, Typer

from src.cli.console import console, echo
from src.database.device import db_list_devices, db_update_device
from src.logging_conf import set_log_level

device_typer = Typer(help="Device commands")


@device_typer.command("scan", help="Scan the device for open ports")
def scan(
    verbose: bool = Option(
        False, "--verbose", "-v", help="Enable verbose (DEBUG) logging"
    ),
):
    if verbose:
        set_log_level("DEBUG")
    pass


@device_typer.command("list", help="list information on devices stored")
def list(
    verbose: bool = Option(
        False, "--verbose", "-v", help="Enable verbose (DEBUG) logging"
    ),
):
    if verbose:
        set_log_level("DEBUG")
    devices = db_list_devices()
    for device in devices:
        echo(f"Device: {device.model_dump_json(indent=2)}")


@device_typer.command("update", help="update the device information")
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
        console.print(f"Error: Invalid JSON - {e.msg}", style="red")
        console.print(
            'Example: --data \'{"device_name": "my device"}\'', style="yellow"
        )
        raise Exit(code=1)

    try:
        updated_device = db_update_device(device_id, **kwargs)
        echo(f"Device {device_id} updated successfully")
        echo(f"Updated device: {updated_device.model_dump_json(indent=2)}")
    except Exception as e:
        console.print(f"Error updating device: {e}", style="red")
        raise Exit(code=1)
