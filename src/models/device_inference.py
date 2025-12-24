from typing import List, Optional

from pydantic_extra_types.pendulum_dt import DateTime
from sqlalchemy import JSON, Column, text
from sqlalchemy import DateTime as DateTimeTZ
from sqlmodel import Field, SQLModel


class DeviceInference(SQLModel, table=True):
    __tablename__ = "device_inferences"

    id: int | None = Field(default=None, primary_key=True, nullable=False)
    tcp_port_numbers: Optional[List[int]] = Field(
        sa_column=Column(JSON, nullable=True), le=65535
    )
    udp_port_numbers: Optional[List[int]] = Field(
        sa_column=Column(JSON, nullable=True), le=65535
    )
    inference: str = Field(max_length=255)
    inference_reasoning: str = Field(max_length=255)
    created_at: DateTime = Field(
        sa_column=Column(
            DateTimeTZ(timezone=False),
            nullable=False,
            server_default=text("CURRENT_TIMESTAMP"),
        ),
    )
