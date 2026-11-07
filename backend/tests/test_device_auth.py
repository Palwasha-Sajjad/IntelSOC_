from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.api import security


def test_verify_registered_device_accepts_active_device(monkeypatch):
    device_id = uuid4()

    device = {
        "device_id": device_id,
        "hostname": "LAB-WIN-01",
        "platform": "windows",
        "status": "active",
    }

    monkeypatch.setattr(
        security,
        "get_device_by_id",
        lambda value: device,
    )

    result = security.verify_registered_device(
        submitted_device_id=str(device_id),
    )

    assert result["device_id"] == device_id
    assert result["status"] == "active"


def test_verify_registered_device_rejects_missing_device_id():
    with pytest.raises(HTTPException) as error:
        security.verify_registered_device(
            submitted_device_id=None,
        )

    assert error.value.status_code == 401


def test_verify_registered_device_rejects_unknown_device(monkeypatch):
    monkeypatch.setattr(
        security,
        "get_device_by_id",
        lambda value: None,
    )

    with pytest.raises(HTTPException) as error:
        security.verify_registered_device(
            submitted_device_id=str(uuid4()),
        )

    assert error.value.status_code == 401


def test_verify_registered_device_rejects_inactive_device(monkeypatch):
    device_id = uuid4()

    device = {
        "device_id": device_id,
        "hostname": "LAB-LINUX-01",
        "platform": "linux",
        "status": "pending",
    }

    monkeypatch.setattr(
        security,
        "get_device_by_id",
        lambda value: device,
    )

    with pytest.raises(HTTPException) as error:
        security.verify_registered_device(
            submitted_device_id=str(device_id),
        )

    assert error.value.status_code == 401