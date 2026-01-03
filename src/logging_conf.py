import logging
import warnings
from logging.config import dictConfig

import structlog

from src.settings import config


def setup_logging(log_level: str = None):
    if log_level is None:
        log_level = config.LOG_LEVEL

    warnings.filterwarnings(
        "ignore",
        message=".*Pydantic serializer warnings.*",
        category=UserWarning,
        module="pydantic.main",
    )
    warnings.filterwarnings(
        "ignore",
        message=".*MAC address to reach destination not found. Using broadcast.*",
        module="scapy.arch",
    )
    warnings.filterwarnings(
        "ignore",
        message=".*Socket.*failed with.*maximum recursion depth exceeded.*",
    )
    logging.getLogger("scapy").setLevel(logging.ERROR)

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.stdlib.render_to_log_kwargs,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    handlers = {
        "default": {
            "class": "rich.logging.RichHandler",
            "level": log_level,
            "formatter": "console",
            "show_path": False,
        },
    }

    formatters = {
        "console": {
            "class": "logging.Formatter",
            "datefmt": "%Y-%m-%dT%H:%M:%S",
            "format": "%(name)s:%(lineno)d - %(message)s",
        }
    }

    # Declare src logger as the root logger
    # Any other loggers will be children of src and inherit the settings
    loggers = {
        "src": {
            "level": log_level,
            "handlers": list(handlers.keys()),
            "propagate": False,
        }
    }

    dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": formatters,
            "handlers": handlers,
            "loggers": loggers,
        }
    )


def set_log_level(level: str):
    """Update the logging level dynamically after setup_logging has been called."""

    root_logger = logging.getLogger("src")
    root_logger.setLevel(level)

    # Update all handlers
    for handler in root_logger.handlers:
        handler.setLevel(level)
