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
    mac_address: str = Field(max_length=12)
    ip_address: str = Field(max_length=16)
    is_router: bool = Field(default=False)
    device_name: Optional[str] = Field(max_length=255)
    mac_vendor: Optional[str] = Field(max_length=255)
    snmp_system_desc: Optional[str] = Field(max_length=255)
    os_fingerprint_vendor: Optional[str] = Field(max_length=255)
    os_fingerprint_family: Optional[str] = Field(max_length=255)
    os_fingerprint_type: Optional[str] = Field(max_length=255)
    os_fingerprint_accuracy: Optional[int] = Field(ge=0, le=100)
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
        Index("idx_network_id_mac_address", "network_id", "mac_address", unique=True),
    )
