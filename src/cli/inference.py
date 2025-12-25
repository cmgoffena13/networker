import structlog
from typer import Exit, Option, Typer

from src.cli.console import echo
from src.database.db import db_seed_device_inferences
from src.database.device_inference import db_list_inferences
from src.logging_conf import set_log_level

logger = structlog.getLogger(__name__)

inference_typer = Typer(help="Inference commands")


@inference_typer.command("list", help="List all inferences")
def list(
    verbose: bool = Option(
        False, "--verbose", "-v", help="Enable verbose (DEBUG) logging"
    ),
):
    if verbose:
        set_log_level("DEBUG")
    try:
        inferences = db_list_inferences()
        echo(f"Listing {len(inferences)} inferences...")
        for inference in inferences:
            echo(f"Inference: {inference.model_dump_json(indent=2)}")
    except Exception as e:
        logger.error(f"Error listing inferences: {e}")
        raise Exit(code=1)


@inference_typer.command("update", help="Update inferences by deleting and re-seeding")
def update(
    verbose: bool = Option(
        False, "--verbose", "-v", help="Enable verbose (DEBUG) logging"
    ),
):
    if verbose:
        set_log_level("DEBUG")
    try:
        db_seed_device_inferences()
        echo("Inferences updated successfully")
    except Exception as e:
        logger.error(f"Error updating inferences: {e}")
        raise Exit(code=1)
