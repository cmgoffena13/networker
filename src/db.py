import structlog
from sqlmodel import Session, SQLModel, create_engine

from src.models import *

logger = structlog.getLogger(__name__)

engine = create_engine("sqlite:///database.db")


def init_db(init: bool = False):
    logger.debug("Initializing database...")
    if init:
        logger.debug("Dropping all tables...")
        SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    if init:
        from src.db_utils import db_seed_ports

        db_seed_ports()
    logger.debug("Database initialized")
