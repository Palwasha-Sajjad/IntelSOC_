from typing import Any

import redis
from fastapi import APIRouter, Depends, HTTPException

from app.api.security import verify_ingest_device, verify_ingest_key
from app.schemas.event import SecurityEvent
from app.windows_normalizer import normalize_windows_event
from app.services.device_service import update_device_last_seen

from app.core.config import get_redis_config
from app.linux_audit_normalizer import normalize_linux_audit_event
from app.linux_normalizer import normalize_linux_event


router = APIRouter(
    tags=["events"],
    dependencies=[Depends(verify_ingest_key)],
)

STREAM_NAME = "intelsoc:events"


def _require_device_platform(device: dict, expected: str) -> None:
    """Reject cross-platform use of a registered endpoint identity."""

    if str(device.get("platform") or "").strip().casefold() != expected:
        raise HTTPException(
            status_code=403,
            detail=f"Device is not registered as {expected}",
        )


def _queue_events(events: list[SecurityEvent]) -> list[bytes]:
    """Queue one validated batch atomically to avoid partial acceptance."""

    client = redis.Redis(**get_redis_config())

    try:
        with client.pipeline(transaction=True) as pipe:
            for event in events:
                pipe.xadd(
                    STREAM_NAME,
                    {"payload": event.model_dump_json()},
                )
            return pipe.execute()

    except redis.RedisError as error:
        raise HTTPException(
            status_code=503,
            detail="Event queue unavailable",
        ) from error

    finally:
        client.close()


@router.post("/events", status_code=202)
def receive_event(event: SecurityEvent):
    stream_ids = _queue_events([event])

    return {
        "status": "queued",
        "event_id": str(event.event_id),
        "stream_id": stream_ids[0].decode(),
    }


@router.post("/events/windows", status_code=202)
def receive_windows_events(
    records: list[dict[str, Any]],
    device: dict = Depends(verify_ingest_device),
):
    """Receive raw Windows events from Fluent Bit."""

    _require_device_platform(device, "windows")

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

    _queue_events(normalized_events)

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

    _require_device_platform(device, "linux")

    if not records:
        raise HTTPException(
            status_code=422,
            detail="Linux event batch cannot be empty",
        )

    try:
        normalized_events = []

        for record in records:
            if "log" in record:
                normalized = normalize_linux_audit_event(
                    record,
                    hostname=device["hostname"],
                )
            else:
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

    _queue_events(normalized_events)

    update_device_last_seen(device["device_id"])
    
    return {
        "status": "queued",
        "accepted": len(normalized_events),
    }
