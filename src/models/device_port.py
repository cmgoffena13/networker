from typing import Optional

from pydantic_extra_types.pendulum_dt import DateTime
from sqlalchemy import Column, text
from sqlalchemy import DateTime as DateTimeTZ
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.schema import Index
from sqlmodel import Field, SQLModel

from src.protocol import Protocol


class DevicePort(SQLModel, table=True):
    __tablename__ = "device_ports"

    id: int | None = Field(default=None, primary_key=True, nullable=False)
    device_id: int = Field(foreign_key="devices.id")
    port_number: int = Field(le=65535)
    protocol: Protocol = Field(sa_column=Column(SQLEnum(Protocol)))
    created_at: DateTime = Field(
        sa_column=Column(
            DateTimeTZ(timezone=False),
            nullable=False,
            server_default=text("CURRENT_TIMESTAMP"),
        ),
    )
    updated_at: Optional[DateTime] = Field(
        sa_column=Column(
            DateTimeTZ(timezone=False),
            nullable=True,
        )
    )

    __table_args__ = (
        Index(
            "ix_port_number_protocol",
            "port_number",
            "protocol",
        ),
        Index(
            "idx_device_id",
            "device_id",
        ),
    )
