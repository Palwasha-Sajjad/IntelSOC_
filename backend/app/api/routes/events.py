import redis

from fastapi import APIRouter, HTTPException

from app.schemas.event import SecurityEvent


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
