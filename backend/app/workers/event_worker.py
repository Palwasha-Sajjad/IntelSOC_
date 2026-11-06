import json
import os
from pathlib import Path

import psycopg
import redis
from dotenv import load_dotenv
from pydantic import ValidationError

from app.schemas.event import SecurityEvent

ROOT = Path(__file__).resolve().parents[3]
load_dotenv(ROOT / ".env")

STREAM = "intelsoc:events"
GROUP = "intelsoc-storage"
CONSUMER = "worker-1"
DLQ_STREAM = "intelsoc:events:dlq"


def save_event(payload):
    """Validate a security event and commit it to PostgreSQL."""
    event = SecurityEvent.model_validate_json(payload)

    with psycopg.connect(
        host="127.0.0.1",
        port=5433,
        dbname="intelsoc",
        user="intelsoc",
        password=os.environ["POSTGRES_PASSWORD"],
        connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO security_events (
                    event_id, schema_version, event_time,
                    source, hostname, event_type,
                    src_ip, message, raw_event
                )
                VALUES (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s::jsonb
                )
                ON CONFLICT (event_id) DO NOTHING
                """,
                (
                    event.event_id,
                    event.schema_version,
                    event.timestamp,
                    event.source,
                    event.hostname,
                    event.event_type,
                    event.src_ip,
                    event.message,
                    json.dumps(event.raw_event),
                ),
            )

    # The connection context has committed the transaction at this point.
    print(f"Processed event: {event.event_id}", flush=True)


def process_message(client, stream_id, fields):
    """Save an event, or atomically transfer an invalid event to the DLQ."""
    try:
        save_event(fields["payload"])
    except (ValidationError, KeyError) as error:
        # Keep the original message if either operation fails.
        with client.pipeline(transaction=True) as pipe:
            pipe.xadd(
                DLQ_STREAM,
                {
                    "original_stream_id": stream_id,
                    "payload": fields.get("payload", ""),
                    "error_type": type(error).__name__,
                },
            )
            pipe.xack(STREAM, GROUP, stream_id)
            pipe.execute()

        print(f"Invalid event moved to DLQ: {stream_id}", flush=True)
        return "dlq"

    # Only acknowledge after PostgreSQL has committed successfully.
    client.xack(STREAM, GROUP, stream_id)
    return "saved"


def main():
    client = redis.Redis(
        host="127.0.0.1",
        port=6380,
        decode_responses=True,
        socket_connect_timeout=5,
        socket_timeout=5,
    )

    try:
        try:
            client.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
            print("Consumer group created", flush=True)
        except redis.exceptions.ResponseError as error:
            if "BUSYGROUP" not in str(error):
                raise

        print("IntelSOC worker started", flush=True)

        while True:
            # Recover messages pending for this same consumer.
            batches = client.xreadgroup(
                GROUP, CONSUMER, {STREAM: "0"}, count=10
            )

            if not batches or not any(messages for _, messages in batches):
                # No pending events; wait up to one second for new ones.
                batches = client.xreadgroup(
                    GROUP, CONSUMER, {STREAM: ">"}, count=10, block=1000
                )

            for _, messages in batches:
                for stream_id, fields in messages:
                    process_message(client, stream_id, fields)
    finally:
        client.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nWorker stopped")
