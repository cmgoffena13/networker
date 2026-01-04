import ctypes
import os
import shutil
import sys
import time
import tomllib
from functools import wraps
from pathlib import Path
from typing import Optional

import structlog

from src.cli.console import echo

logger = structlog.getLogger(__name__)


def retry(attempts: int = 3, delay: float = 0.25, backoff: float = 2.0):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            wait = delay
            for index in range(attempts):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if index == attempts - 1:
                        raise e
                    logger.warning(
                        f"Retrying {func.__name__} (attempt {index + 2}/{attempts}) after {type(e).__name__}: {e}"
                    )
                    time.sleep(wait)
                    wait *= backoff

        return wrapper

    return decorator


def lower_string(value: Optional[str]) -> Optional[str]:
    return value.lower() if value else None


def find_command(cmd: str, default_paths: list[str] = None) -> str:
    """Find the full path to a system command.

    Tries shutil.which() first, then falls back to default_paths if provided.
    This is useful for frozen/compiled executables where PATH may not be set correctly.
    """
    path = shutil.which(cmd)
    if path:
        return path

    if default_paths:
        for default_path in default_paths:
            if shutil.which(default_path):
                return default_path

    return cmd


def get_version() -> str:
    if getattr(sys, "frozen", False):
        base_path = Path(sys._MEIPASS)
        pyproject_path = base_path / "pyproject.toml"
        if not pyproject_path.exists():
            exe_path = Path(
                sys.executable if hasattr(sys, "executable") else sys.argv[0]
            )
            pyproject_path = exe_path.parent / "pyproject.toml"
    else:
        pyproject_path = Path(__file__).parent.parent / "pyproject.toml"

    if not pyproject_path.exists():
        raise FileNotFoundError(f"Could not find pyproject.toml at {pyproject_path}")

    with open(pyproject_path, "rb") as f:
        pyproject = tomllib.load(f)
    return pyproject["project"]["version"]


def check_root_and_warn() -> bool:
    """Check if running as root/admin and warn if not.

    Returns True if running as root/admin, False otherwise.
    If not root, displays a warning message and returns False.
    """
    is_admin = False
    if sys.platform == "win32":
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            is_admin = False
    else:
        is_admin = os.geteuid() == 0

    if not is_admin:
        if sys.platform == "win32":
            echo(
                "[yellow]Warning:[/yellow] Not running as administrator. Networker requires administrator privileges.",
            )
            echo(
                "Please run in an admin terminal.",
            )
        else:
            echo(
                "[yellow]Warning:[/yellow] Not running as root. Networker requires root privileges.",
            )
            echo(
                "Please run with [bold]sudo networker <command>[/bold]",
            )

    return is_admin
