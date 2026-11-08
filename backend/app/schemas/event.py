from uuid import UUID, uuid4

from pydantic import AwareDatetime, BaseModel, Field


class SecurityEvent(BaseModel):
    schema_version: str = "1.0"

    event_id: UUID = Field(default_factory=uuid4)
    device_id: UUID | None = None

    timestamp: AwareDatetime

    source: str = Field(min_length=1, max_length=100)
    hostname: str = Field(min_length=1, max_length=255)
    event_type: str = Field(min_length=1, max_length=100)

    src_ip: str | None = None

    message: str = Field(min_length=1, max_length=65536)

    raw_event: dict = Field(default_factory=dict)
