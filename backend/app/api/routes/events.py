import redis

from fastapi import APIRouter, HTTPException

from app.schemas.event import SecurityEvent

from typing import Any

from app.windows_normalizer import normalize_windows_event

router = APIRouter(tags=["events"])

STREAM_NAME = "intelsoc:events"


@router.post("/events", status_code=202)
def receive_event(event: SecurityEvent):

    client = redis.Redis(
        host="127.0.0.1",
        port=6380,
        socket_connect_timeout=3,
        socket_timeout=3,
    )

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
            detail="Event queue unavailable"
        )

    finally:
        client.close()


@router.post("/events/windows", status_code=202)
def receive_windows_events(records: list[dict[str, Any]]):
    """Receive raw Windows events from Fluent Bit."""

    if not records:
        raise HTTPException(
            status_code=422,
            detail="Windows event batch cannot be empty",
        )

    # Validate the entire batch before queueing anything.
    try:
        normalized_events = [
            SecurityEvent.model_validate(
                normalize_windows_event(record)
            )
            for record in records
        ]
    except (ValueError, TypeError) as error:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid Windows event: {error}",
        ) from error

    # Reuse our existing Redis ingestion function.
    queued_events = [
        receive_event(event)
        for event in normalized_events
    ]

    return {
        "status": "queued",
        "accepted": len(queued_events),
        "events": queued_events,
    }

