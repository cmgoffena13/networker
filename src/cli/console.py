import json
from typing import List, Optional, Tuple

from rich.console import Console
from rich.theme import Theme

from src.models.device import Device
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


def format_device_with_ports_json(
    device: Device,
    device_ports: List[Tuple[DevicePort, Optional[str], Optional[str]]],
) -> str:
    device_dict = device.model_dump()
    ports_list = [
        {
            "port_number": dp.port_number,
            "protocol": dp.protocol.value,
            "service_name": service_name,
            "description": description,
        }
        for dp, service_name, description in device_ports
    ]
    device_dict = dict(sorted(device_dict.items()))
    device_dict["open_ports"] = ports_list
    return json.dumps(device_dict, indent=2, default=str)
