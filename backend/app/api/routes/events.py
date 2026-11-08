from typing import Any

import redis
from fastapi import APIRouter, Depends, HTTPException

from app.api.security import verify_ingest_device, verify_ingest_key
from app.schemas.event import SecurityEvent
from app.windows_normalizer import normalize_windows_event
from app.services.device_service import update_device_last_seen

from app.core.config import get_redis_config

router = APIRouter(
    tags=["events"],
    dependencies=[Depends(verify_ingest_key)],
)

STREAM_NAME = "intelsoc:events"


@router.post("/events", status_code=202)
def receive_event(event: SecurityEvent):
    client = redis.Redis(**get_redis_config())

    try:
        stream_id = client.xadd(
            STREAM_NAME,
            {"payload": event.model_dump_json()},
        )

        return {
            "status": "queued",
            "event_id": str(event.event_id),
            "stream_id": stream_id.decode(),
        }

    except redis.RedisError:
        raise HTTPException(
            status_code=503,
            detail="Event queue unavailable",
        )

    finally:
        client.close()


@router.post("/events/windows", status_code=202)
def receive_windows_events(
    records: list[dict[str, Any]],
    device: dict = Depends(verify_ingest_device),
):
    """Receive raw Windows events from Fluent Bit."""

    if not records:
        raise HTTPException(
            status_code=422,
            detail="Windows event batch cannot be empty",
        )

    try:
        normalized_events = []

        for record in records:
            normalized = normalize_windows_event(record)
            normalized["device_id"] = device["device_id"]

            normalized_events.append(
                SecurityEvent.model_validate(normalized)
            )

    except (ValueError, TypeError) as error:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid Windows event: {error}",
        ) from error

    for event in normalized_events:
        receive_event(event)
       
    update_device_last_seen(device["device_id"])

    return {
        "status": "queued",
        "accepted": len(normalized_events),
    }


@router.post("/events/linux", status_code=202)
def receive_linux_events(
    records: list[dict[str, Any]],
    device: dict = Depends(verify_ingest_device),
):
    """Receive raw Linux journal events from Fluent Bit."""

    from app.linux_normalizer import normalize_linux_event

    if not records:
        raise HTTPException(
            status_code=422,
            detail="Linux event batch cannot be empty",
        )

    try:
        normalized_events = []

        for record in records:
            normalized = normalize_linux_event(record)
            normalized["device_id"] = device["device_id"]

            normalized_events.append(
                SecurityEvent.model_validate(normalized)
            )

    except (ValueError, TypeError) as error:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid Linux event: {error}",
        ) from error

    for event in normalized_events:
        receive_event(event)
    update_device_last_seen(device["device_id"])
    
    return {
        "status": "queued",
        "accepted": len(normalized_events),
    }
