from typing import Optional

from pydantic_extra_types.pendulum_dt import DateTime
from sqlalchemy import Column, text
from sqlalchemy import DateTime as DateTimeTZ
from sqlalchemy.schema import Index
from sqlmodel import Field, SQLModel


class Device(SQLModel, table=True):
    __tablename__ = "devices"

    id: int | None = Field(default=None, primary_key=True, nullable=False)
    network_id: int = Field(foreign_key="networks.id")
    device_mac: str = Field(max_length=12)
    device_ip: str = Field(max_length=16)
    is_router: bool = Field(default=False)
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
            onupdate=text("CURRENT_TIMESTAMP"),
        )
    )

    __table_args__ = (
        Index("idx_network_id_device_mac", "network_id", "device_mac", unique=True),
    )
