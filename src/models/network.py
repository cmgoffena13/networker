from typing import Optional

from pydantic_extra_types.pendulum_dt import DateTime
from sqlalchemy import Column, text
from sqlalchemy import DateTime as DateTimeTZ
from sqlalchemy.schema import Index
from sqlmodel import Field, SQLModel


class Network(SQLModel, table=True):
    __tablename__ = "networks"

    id: int | None = Field(default=None, primary_key=True, nullable=False)
    ssid_name: str = Field(max_length=255)
    router_mac: str = Field(max_length=12)
    network_address: str = Field(max_length=16)
    public_ip: str = Field(max_length=16)
    broadcast_address: str = Field(max_length=16)
    netmask: str = Field(max_length=16)
    ips_available: int = Field(ge=0)
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
        Index("ux_name_router_mac", "ssid_name", "router_mac", unique=True),
    )
