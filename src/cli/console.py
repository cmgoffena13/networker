from typing import Optional

from rich.console import Console
from rich.theme import Theme

from src.models.device_port import DevicePort

matrix_theme = Theme(
    {
        "logging.level.debug": "bold green",
        "logging.level.info": "bold green",
        "logging.level.warning": "bold yellow",
        "logging.level.error": "bold red",
        "logging.level.critical": "bold red",
        "log.message": "green",
    }
)
console = Console(theme=matrix_theme)


def echo(message: str, **kwargs):
    console.print(message, style="green", **kwargs)


def display_port_info(
    device_port: DevicePort,
    service_name: Optional[str] = None,
    description: Optional[str] = None,
) -> str:
    service_info = f" - {service_name}" if service_name else ""
    desc_info = f" ({description})" if description else ""
    return f"Open Port: {device_port.port_number} ({device_port.protocol.value}){service_info}{desc_info}"
