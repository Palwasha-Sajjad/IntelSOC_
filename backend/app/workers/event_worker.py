import os
from pathlib import Path

import psycopg
import redis
from dotenv import load_dotenv

from app.schemas.event import SecurityEvent


ROOT = Path(__file__).resolve().parents[3]
load_dotenv(ROOT / ".env")

STREAM = "intelsoc:events"
GROUP = "intelsoc-storage"
CONSUMER = "worker-1"


def save_event(payload):
    event = SecurityEvent.model_validate_json(payload)

    # PostgreSQL commits before we acknowledge Redis.
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
                    event.model_dump_json(),
                ),
            )

    print(f"Saved event: {event.event_id}", flush=True)


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
            client.xgroup_create(
                STREAM, GROUP, id="0", mkstream=True
            )
            print("Consumer group created")

        except redis.exceptions.ResponseError as error:
            if "BUSYGROUP" not in str(error):
                raise

        print("IntelSOC worker started")

        while True:
            # Recover messages pending for this same worker.
            batches = client.xreadgroup(
                GROUP, CONSUMER,
                {STREAM: "0"},
                count=10,
            )


            if not batches or not any(messages for _, messages in batches):
                # No pending messages. Read new events.
                batches = client.xreadgroup(
                    GROUP, CONSUMER,
                    {STREAM: ">"},
                    count=10,
                    block=1000,
                )


            for _, messages in batches:
                for stream_id, fields in messages:
                    save_event(fields["payload"])

                    # Acknowledge only after database commit.
                    client.xack(STREAM, GROUP, stream_id)

    finally:
        client.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nWorker stopped")
