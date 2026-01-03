import shutil
import time
from functools import wraps
from typing import Optional

import structlog

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
