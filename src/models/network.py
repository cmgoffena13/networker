from typing import Optional

from pydantic_extra_types.pendulum_dt import DateTime
from sqlalchemy import Column, text
from sqlalchemy import DateTime as DateTimeTZ
from sqlalchemy.schema import Index
from sqlmodel import Field, SQLModel


class Network(SQLModel, table=True):
    __tablename__ = "networks"

    id: int | None = Field(default=None, primary_key=True, nullable=False)
    network_name: str = Field(max_length=255)
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
        )
    )

    __table_args__ = (Index("ux_router_mac", "router_mac", unique=True),)


class NetworkSpeedTest(SQLModel, table=True):
    __tablename__ = "network_speed_tests"

    id: int | None = Field(default=None, primary_key=True, nullable=False)
    network_id: int = Field(foreign_key="networks.id")
    download_speed_mbps: float = Field(ge=0)
    upload_speed_mbps: float = Field(ge=0)
    created_at: DateTime = Field(
        sa_column=Column(
            DateTimeTZ(timezone=False),
            nullable=False,
            server_default=text("CURRENT_TIMESTAMP"),
        ),
    )
