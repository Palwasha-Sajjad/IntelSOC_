import os
from pathlib import Path

import psycopg
import redis

from dotenv import load_dotenv
from fastapi import APIRouter
from fastapi.responses import JSONResponse


router = APIRouter(tags=["services"])

# Load the IntelSOC root .env file
ROOT = Path(__file__).resolve().parents[4]
load_dotenv(ROOT / ".env")


@router.get("/services/status")
def check_services():
    postgresql_status = "disconnected"
    redis_status = "disconnected"

    # Check PostgreSQL
    try:
        with psycopg.connect(
            host="127.0.0.1",
            port=5433,
            dbname="intelsoc",
            user="intelsoc",
            password=os.environ["POSTGRES_PASSWORD"],
            connect_timeout=3,
        ) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")

        postgresql_status = "connected"

    except (psycopg.Error, OSError, KeyError):
        pass

    # Check Redis
    try:
        with redis.Redis(
            host="127.0.0.1",
            port=6380,
            socket_connect_timeout=3,
            socket_timeout=3,
        ) as client:
            client.ping()

        redis_status = "connected"

    except (redis.RedisError, OSError):
        pass

    ready = (
        postgresql_status == "connected"
        and redis_status == "connected"
    )

    return JSONResponse(
        status_code=200 if ready else 503,
        content={
            "status": "ready" if ready else "unavailable",
            "postgresql": postgresql_status,
            "redis": redis_status,
        },
    )