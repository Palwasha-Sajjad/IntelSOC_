
import os
from pathlib import Path

import psycopg
import redis
from dotenv import load_dotenv
from app.core.config import get_postgres_config, get_redis_config

# Find the main IntelSOC folder.
ROOT = Path(__file__).resolve().parents[2]

# Load the database password securely from .env.
load_dotenv(ROOT / ".env")


def check_postgresql():
    password = os.getenv("POSTGRES_PASSWORD")

    if not password:
        raise ValueError("POSTGRES_PASSWORD is missing")

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            result = cursor.fetchone()

    print("PostgreSQL connected:", result == (1,))


def check_redis():
    client = redis.Redis(**get_redis_config())
    
    print("Redis connected:", client.ping())
    client.close()


if __name__ == "__main__":
    try:
        check_postgresql()
        check_redis()
        print("IntelSOC services are ready!")

    except Exception as error:
        print("Connection check failed:", type(error).__name__)
        raise SystemExit(1)
