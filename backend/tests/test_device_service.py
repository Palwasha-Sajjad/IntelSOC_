from uuid import UUID

import pytest

from app.services.device_service import (
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


def test_register_device_returns_pending_device(monkeypatch):
    captured = {}

    class FakeCursor:
        def execute(self, sql, params):
            captured["sql"] = sql
            captured["params"] = params

        def fetchone(self):
            return (
                captured["params"][0],
                "LAB-WIN-01",
                "windows",
                "intelsoc-device-test",
                None,
                "pending",
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
        certificate_common_name="intelsoc-device-test",
    )

    UUID(str(device["device_id"]))

    assert device["hostname"] == "LAB-WIN-01"
    assert device["platform"] == "windows"
    assert device["certificate_common_name"] == "intelsoc-device-test"
    assert device["certificate_fingerprint"] is None
    assert device["status"] == "pending"

    assert "INSERT INTO registered_devices" in captured["sql"]


def test_activate_device_sets_fingerprint_and_active_status(monkeypatch):
    from uuid import uuid4

    from app.services.device_service import activate_device

    device_id = uuid4()
    fingerprint = "AA" * 32
    captured = {}

    class FakeCursor:
        def execute(self, sql, params):
            captured["sql"] = sql
            captured["params"] = params

        def fetchone(self):
            return (
                device_id,
                "LAB-WIN-01",
                "windows",
                "intelsoc-device-test",
                fingerprint,
                "active",
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

    device = activate_device(
        device_id=device_id,
        certificate_fingerprint=fingerprint,
    )

    assert device["device_id"] == device_id
    assert device["certificate_fingerprint"] == fingerprint
    assert device["status"] == "active"

    assert "UPDATE registered_devices" in captured["sql"]


def test_validate_device_identity_accepts_matching_active_device():
    from uuid import uuid4

    from app.services.device_service import validate_device_identity

    device_id = uuid4()

    device = {
        "device_id": device_id,
        "hostname": "LAB-WIN-01",
        "platform": "windows",
        "certificate_common_name": "intelsoc-device-test",
        "certificate_fingerprint": "AA" * 32,
        "status": "active",
    }

    result = validate_device_identity(
        device=device,
        submitted_device_id=str(device_id),
        certificate_common_name="intelsoc-device-test",
        certificate_fingerprint="AA" * 32,
    )

    assert result is True


def test_validate_device_identity_rejects_pending_device():
    from uuid import uuid4

    from app.services.device_service import validate_device_identity

    device_id = uuid4()

    device = {
        "device_id": device_id,
        "hostname": "LAB-WIN-01",
        "platform": "windows",
        "certificate_common_name": "intelsoc-device-test",
        "certificate_fingerprint": None,
        "status": "pending",
    }

    assert validate_device_identity(
        device=device,
        submitted_device_id=str(device_id),
        certificate_common_name="intelsoc-device-test",
        certificate_fingerprint="AA" * 32,
    ) is False


def test_validate_device_identity_rejects_wrong_certificate():
    from uuid import uuid4

    from app.services.device_service import validate_device_identity

    device_id = uuid4()

    device = {
        "device_id": device_id,
        "hostname": "LAB-WIN-01",
        "platform": "windows",
        "certificate_common_name": "intelsoc-device-test",
        "certificate_fingerprint": "AA" * 32,
        "status": "active",
    }

    assert validate_device_identity(
        device=device,
        submitted_device_id=str(device_id),
        certificate_common_name="different-device",
        certificate_fingerprint="BB" * 32,
    ) is False


def test_get_device_by_id_returns_device(monkeypatch):
    from uuid import uuid4

    from app.services.device_service import get_device_by_id

    device_id = uuid4()

    class FakeCursor:
        def execute(self, sql, params):
            self.sql = sql
            self.params = params

        def fetchone(self):
            return (
                device_id,
                "LAB-LINUX-01",
                "linux",
                "intelsoc-device-linux01",
                "CC" * 32,
                "active",
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
    from uuid import uuid4

    from app.services.device_service import get_device_by_id

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
