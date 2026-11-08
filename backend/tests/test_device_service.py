from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest

from app.services.device_service import (
    get_device_by_id,
    register_device,
    validate_platform,
)


def test_validate_platform_accepts_windows_and_linux():
    assert validate_platform("windows") == "windows"
    assert validate_platform("linux") == "linux"


def test_validate_platform_normalizes_case():
    assert validate_platform("Windows") == "windows"
    assert validate_platform("LINUX") == "linux"


def test_validate_platform_rejects_unknown_platform():
    with pytest.raises(ValueError, match="Unsupported platform"):
        validate_platform("macos")


def test_register_device_returns_active_device(monkeypatch):
    captured = {}
    created_at = datetime.now(timezone.utc)

    class FakeCursor:
        def execute(self, sql, params):
            captured["sql"] = sql
            captured["params"] = params

        def fetchone(self):
            return (
                captured["params"][0],
                "LAB-WIN-01",
                "windows",
                "active",
                created_at,
                None,
            )

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    class FakeConnection:
        def cursor(self):
            return FakeCursor()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setenv(
        "POSTGRES_PASSWORD",
        "test-only-password",
    )

    import app.services.device_service as device_service

    monkeypatch.setattr(
        device_service.psycopg,
        "connect",
        lambda **kwargs: FakeConnection(),
    )

    device = register_device(
        hostname="LAB-WIN-01",
        platform="windows",
    )

    UUID(str(device["device_id"]))

    assert device["hostname"] == "LAB-WIN-01"
    assert device["platform"] == "windows"
    assert device["status"] == "active"
    assert device["last_seen_at"] is None

    assert "INSERT INTO registered_devices" in captured["sql"]
    assert "certificate_common_name" not in captured["sql"]
    assert "certificate_fingerprint" not in captured["sql"]


def test_register_device_rejects_empty_hostname():
    with pytest.raises(ValueError, match="Hostname cannot be empty"):
        register_device(
            hostname="   ",
            platform="windows",
        )


def test_get_device_by_id_returns_device(monkeypatch):
    device_id = uuid4()
    created_at = datetime.now(timezone.utc)

    class FakeCursor:
        def execute(self, sql, params):
            self.sql = sql
            self.params = params

        def fetchone(self):
            return (
                device_id,
                "LAB-LINUX-01",
                "linux",
                "active",
                created_at,
                None,
            )

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    class FakeConnection:
        def cursor(self):
            return FakeCursor()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    import app.services.device_service as device_service

    monkeypatch.setenv(
        "POSTGRES_PASSWORD",
        "test-only-password",
    )

    monkeypatch.setattr(
        device_service.psycopg,
        "connect",
        lambda **kwargs: FakeConnection(),
    )

    device = get_device_by_id(device_id)

    assert device["device_id"] == device_id
    assert device["hostname"] == "LAB-LINUX-01"
    assert device["platform"] == "linux"
    assert device["status"] == "active"


def test_get_device_by_id_returns_none_when_missing(monkeypatch):
    class FakeCursor:
        def execute(self, sql, params):
            pass

        def fetchone(self):
            return None

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    class FakeConnection:
        def cursor(self):
            return FakeCursor()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    import app.services.device_service as device_service

    monkeypatch.setenv(
        "POSTGRES_PASSWORD",
        "test-only-password",
    )

    monkeypatch.setattr(
        device_service.psycopg,
        "connect",
        lambda **kwargs: FakeConnection(),
    )

    assert get_device_by_id(uuid4()) is None
