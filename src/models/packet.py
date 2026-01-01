from typing import Optional

from pydantic_extra_types.pendulum_dt import DateTime
from sqlalchemy import JSON, Column
from sqlalchemy import Enum as SQLEnum
from sqlmodel import BigInteger, Field, SQLModel

from src.protocol import Protocol


class Packet(SQLModel, table=True):
    __tablename__ = "packets"

    id: int | None = Field(
        sa_column=Column(BigInteger, nullable=False, primary_key=True, default=None),
    )
    timestamp: DateTime
    request: bool
    source_mac: str = Field(max_length=12)
    destination_mac: str = Field(max_length=12)
    ethernet_type: str = Field(max_length=8)

    source_ip: Optional[str] = Field(max_length=45, nullable=True)
    source_port: Optional[int] = Field(le=65535, nullable=True)

    destination_ip: Optional[str] = Field(max_length=45, nullable=True)
    destination_port: Optional[int] = Field(le=65535, nullable=True)

    transport_protocol: Protocol = Field(sa_column=Column(SQLEnum(Protocol)))
    application_protocol: Optional[str] = Field(max_length=20, nullable=True)

    additional_data: Optional[dict] = Field(sa_column=Column(JSON, nullable=True))
    payload_hex: Optional[str] = Field(max_length=16384, nullable=True)
    payload_length: int = Field(default=0)
