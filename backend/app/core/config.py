import os


def get_postgres_config() -> dict:
    """Return PostgreSQL connection settings for IntelSOC."""
    return {
        "host": os.getenv("POSTGRES_HOST", "127.0.0.1"),
        "port": int(os.getenv("POSTGRES_PORT", "5433")),
        "dbname": os.getenv("POSTGRES_DB", "intelsoc"),
        "user": os.getenv("POSTGRES_USER", "intelsoc"),
        "password": os.environ["POSTGRES_PASSWORD"],
    }


def get_redis_config() -> dict:
    """Return Redis connection settings for IntelSOC."""
    return {
        "host": os.getenv("REDIS_HOST", "127.0.0.1"),
        "port": int(os.getenv("REDIS_PORT", "6380")),
        "decode_responses": False,
    }
