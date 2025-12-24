from pydantic_extra_types.pendulum_dt import DateTime
from sqlalchemy import Column, text
from sqlalchemy import DateTime as DateTimeTZ
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.schema import PrimaryKeyConstraint
from sqlmodel import Field, SQLModel

from src.protocol import Protocol


class DeviceInference(SQLModel, table=True):
    __tablename__ = "device_inferences"

    port_number: int = Field(le=65535)
    protocol: Protocol = Field(sa_column=Column(SQLEnum(Protocol)))
    inference: str = Field(max_length=255)
    inference_reasoning: str = Field(max_length=255)
    created_at: DateTime = Field(
        sa_column=Column(
            DateTimeTZ(timezone=False),
            nullable=False,
            server_default=text("CURRENT_TIMESTAMP"),
        ),
    )

    __table_args__ = (PrimaryKeyConstraint("port_number", "protocol"),)
