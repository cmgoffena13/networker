import json
from typing import Optional

import structlog
from typer import Abort, Exit, Option, Typer, confirm

from src.cli.console import console, echo
from src.core.device import get_devices_on_network, scan_device_for_open_ports
from src.core.network import get_network, monitor_network, test_internet_connectivity
from src.database.db import init_db
from src.database.network import db_list_networks, db_update_network
from src.logging_conf import set_log_level
from src.utils import lower_string

logger = structlog.getLogger(__name__)


def register_base_network_commands(app: Typer) -> None:
    """Register network commands directly on the main app"""

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
        init_db(reset=True)
        echo("Database reset and seeded lookup data")

    @app.command("scan", help="Scan the network for devices")
    def scan(
        save: bool = Option(
            False, "--save", "-s", help="Save the network scan results to the database"
        ),
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
            network = get_network(save=save)
            devices = get_devices_on_network(network, save=save)
            if ports:
                echo("\nPress Ctrl+C to interrupt scanning and exit...")
                for device in devices:
                    scan_device_for_open_ports(device, save=save)
        except Abort:
            raise
        except Exception as e:
            logger.error(f"Error scanning network: {e}")
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
            logger.error(f"Error listing networks: {e}")
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
            logger.error(f"Error updating network: {e}")
            raise Exit(code=1)

    @app.command("monitor", help="Monitor network traffic")
    def monitor(
        filter: Optional[str] = Option(
            None, "--filter", "-f", help="Filter network traffic", callback=lower_string
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
            logger.error(f"Error monitoring network: {e}")
            raise Exit(code=1)

    @app.command("test", help="Test internet connectivity")
    def test(
        verbose: bool = Option(
            False, "--verbose", "-v", help="Enable verbose (DEBUG) logging"
        ),
        save: bool = Option(
            False,
            "--save",
            "-s",
            help="Save the internet connectivity test results to the database",
        ),
    ):
        if verbose:
            set_log_level("DEBUG")
        try:
            test_internet_connectivity(save=save)
        except Exception as e:
            logger.error(f"Error testing internet connectivity: {e}")
            raise Exit(code=1)
