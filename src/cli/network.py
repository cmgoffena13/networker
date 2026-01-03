import json
import shutil
import sys
from pathlib import Path
from typing import Optional

import structlog
from typer import Abort, Exit, Option, Typer, confirm

from src.cli.console import console, echo
from src.core.device import get_devices_on_network, scan_device_for_open_ports
from src.core.network import get_network, monitor_network, test_internet_connectivity
from src.database.db import get_db_path
from src.database.network import (
    db_delete_network,
    db_get_network_by_id,
    db_list_networks,
    db_update_network,
)
from src.logging_conf import set_log_level
from src.utils import lower_string

logger = structlog.getLogger(__name__)


def register_base_network_commands(app: Typer) -> None:
    """Register network commands directly on the main app"""

    @app.command("scan", help="Scan the network for devices")
    def scan(
        verbose: bool = Option(
            False, "--verbose", "-v", help="Enable verbose (DEBUG) logging"
        ),
        ports: bool = Option(
            False, "--ports", "-p", help="Scan the network for open ports on devices"
        ),
    ):
        if verbose:
            set_log_level("DEBUG")
        try:
            network = get_network()
            devices = get_devices_on_network(network)
            if ports:
                echo("\nPress Ctrl+C to interrupt scanning and exit...")
                for device in devices:
                    scan_device_for_open_ports(device)
        except Abort:
            raise
        except Exception as e:
            logger.exception(f"Error scanning network: {e}")
            raise Exit(code=1)

    @app.command("list", help="List information on networks stored")
    def list(
        verbose: bool = Option(
            False, "--verbose", "-v", help="Enable verbose (DEBUG) logging"
        ),
    ):
        if verbose:
            set_log_level("DEBUG")
        try:
            networks = db_list_networks()
            echo(f"Listing {len(networks)} networks...")
            for network in networks:
                echo(f"Network: {network.model_dump_json(indent=2)}")
        except Exception as e:
            logger.exception(f"Error listing networks: {e}")
            raise Exit(code=1)

    @app.command("update", help="Update the network information")
    def update(
        network_id: int = Option(..., "--id", "-i", help="Network ID to update"),
        data: str = Option(
            ...,
            "--data",
            "-d",
            help='JSON dictionary of fields to update (e.g., \'{"network_name": "my network"}\')',
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
                'Example: --data \'{"network_name": "my network"}\'', style="yellow"
            )
            raise Exit(code=1)

        try:
            updated_network = db_update_network(network_id, **kwargs)
            echo(f"Network {network_id} updated successfully")
            echo(f"Updated network: {updated_network.model_dump_json(indent=2)}")
        except Exception as e:
            logger.exception(f"Error updating network: {e}")
            raise Exit(code=1)

    @app.command("monitor", help="Monitor network traffic.")
    def monitor(
        filter: Optional[str] = Option(
            None,
            "--filter",
            "-f",
            help="Filter network traffic. Ex 'tcp port 80'",
            callback=lower_string,
        ),
        verbose: bool = Option(
            False, "--verbose", "-v", help="Enable verbose (DEBUG) logging"
        ),
        exclude_host: bool = Option(
            False,
            "--exclude-host",
            "-e",
            help="Exclude the host from the network traffic",
        ),
        dns: bool = Option(False, "--dns", "-d", help="Monitor DNS traffic"),
    ):
        if verbose:
            set_log_level("DEBUG")
        try:
            monitor_network(
                filter=filter, verbose=verbose, exclude_host=exclude_host, dns=dns
            )
        except Exception as e:
            error_msg = str(e).lower()
            if "cannot set filter" in error_msg:
                echo(error_msg)
                echo("Use BPF (Berkeley Packet Filter) syntax.")
                echo("Examples:")
                echo("  - 'udp port 5353' (for UDP port 5353)")
                echo("  - 'tcp port 80' (for TCP port 80)")
                echo("  - 'host 192.168.1.1' (for specific host)")
                echo("  - 'not host 192.168.1.1' (for all hosts except 192.168.1.1)")
                echo("  - 'arp' (for ARP packets)")
                echo("  - 'icmp' (for ICMP packets)")
                echo("  - 'udp port 5353 or tcp port 80' (for multiple conditions)")
            logger.exception(f"Error monitoring network: {e}")
            raise Exit(code=1)

    @app.command("test", help="Test internet connectivity")
    def test(
        verbose: bool = Option(
            False, "--verbose", "-v", help="Enable verbose (DEBUG) logging"
        ),
        trace: bool = Option(
            False, "--trace", "-t", help="Trace the internet connectivity test"
        ),
    ):
        if verbose:
            set_log_level("DEBUG")
        try:
            test_internet_connectivity(trace=trace)
        except Exception as e:
            logger.exception(f"Error testing internet connectivity: {e}")
            raise Exit(code=1)

    @app.command("delete", help="Delete a network and all associated data")
    def delete(
        network_id: int = Option(..., "--id", "-i", help="Network ID to delete"),
        verbose: bool = Option(
            False, "--verbose", "-v", help="Enable verbose (DEBUG) logging"
        ),
    ):
        if verbose:
            set_log_level("DEBUG")
        try:
            network = db_get_network_by_id(network_id)
            if not network:
                echo(f"Network {network_id} not found")
                raise Exit(code=1)

            echo(
                f"Warning: This will delete network {network_id} and all associated data:"
            )
            echo("  - All device port records")
            echo("  - All network speed test records")
            echo("  - All device records")
            echo("  - The network record")
            if not confirm("Are you sure you want to continue?", default=False):
                echo("Network deletion cancelled.")
                raise Abort()

            db_delete_network(network_id)
            echo(f"Network {network_id} deleted successfully")
        except Abort:
            raise
        except Exception as e:
            logger.exception(f"Error deleting network: {e}")
            raise Exit(code=1)

    @app.command("reset", help="Reset the database. Deletes information.")
    def reset(
        verbose: bool = Option(
            False, "--verbose", "-v", help="Enable verbose (DEBUG) logging"
        ),
    ):
        if verbose:
            set_log_level("DEBUG")

        echo("Warning: This operation will DROP ALL EXISTING TABLES and recreate them.")
        echo("All existing data will be lost!")
        if not confirm("Are you sure you want to continue?", default=False):
            echo("Database reset cancelled.")
            raise Abort()

        echo("Resetting database...")
        user_db_path = get_db_path()
        if getattr(sys, "frozen", False):
            base_path = Path(sys._MEIPASS)
        else:
            base_path = Path(__file__).parent.parent
        schema_db = base_path / "data" / "networker_base.db"
        user_db_path.unlink(missing_ok=True)
        shutil.copy2(schema_db, user_db_path)
        echo("Database reset")
