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
    mac_vendor: Optional[str] = Field(max_length=255)
    ip_address: str = Field(max_length=45)
    is_router: bool = Field(default=False)
    device_name: Optional[str] = Field(max_length=255)
    device_inference: Optional[str] = Field(max_length=255)
    inference_match: Optional[float] = Field(ge=0, le=1)
    current_device: bool = Field(default=False)
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
        Index("idx_current_device", "current_device", "id"),
    )
