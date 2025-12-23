from typing import Optional

from pydantic_extra_types.pendulum_dt import DateTime
from sqlalchemy import Column, text
from sqlalchemy import DateTime as DateTimeTZ
from sqlalchemy import Enum as SQLEnum
from sqlmodel import Field, PrimaryKeyConstraint, SQLModel

from src.protocol import Protocol


class Port(SQLModel, table=True):
    __tablename__ = "ports"

    port_number: int = Field(le=65535)
    protocol: Protocol = Field(sa_column=Column(SQLEnum(Protocol)))
    service_name: Optional[str] = Field(max_length=255)
    description: Optional[str] = Field(max_length=255)
    created_at: DateTime = Field(
        sa_column=Column(
            DateTimeTZ(timezone=False),
            nullable=False,
            server_default=text(
                "CURRENT_TIMESTAMP"
            ),  # Have Postgres generate the timestamp
        ),
    )

    __table_args__ = (
        PrimaryKeyConstraint("port_number", "protocol", name="pk_port_number_protocol"),
    )
