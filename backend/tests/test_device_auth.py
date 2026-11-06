from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.api import security


def test_verify_registered_device_accepts_matching_identity(monkeypatch):
    device_id = uuid4()

    device = {
        "device_id": device_id,
        "hostname": "LAB-WIN-01",
        "platform": "windows",
        "certificate_common_name": "intelsoc-device-win01",
        "certificate_fingerprint": "AA" * 32,
        "status": "active",
    }

    monkeypatch.setattr(
        security,
        "get_device_by_id",
        lambda value: device,
    )

    monkeypatch.setattr(
        security,
        "validate_device_identity",
        lambda **kwargs: True,
    )

    result = security.verify_registered_device(
        submitted_device_id=str(device_id),
        certificate_common_name="intelsoc-device-win01",
        certificate_fingerprint="AA" * 32,
    )

    assert result["device_id"] == device_id
    assert result["status"] == "active"


def test_verify_registered_device_rejects_missing_headers():
    with pytest.raises(HTTPException) as error:
        security.verify_registered_device(
            submitted_device_id=None,
            certificate_common_name=None,
            certificate_fingerprint=None,
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
            certificate_common_name="unknown-device",
            certificate_fingerprint="BB" * 32,
        )

    assert error.value.status_code == 401


def test_verify_registered_device_rejects_identity_mismatch(monkeypatch):
    device_id = uuid4()

    device = {
        "device_id": device_id,
        "hostname": "LAB-LINUX-01",
        "platform": "linux",
        "certificate_common_name": "intelsoc-device-linux01",
        "certificate_fingerprint": "CC" * 32,
        "status": "active",
    }

    monkeypatch.setattr(
        security,
        "get_device_by_id",
        lambda value: device,
    )

    monkeypatch.setattr(
        security,
        "validate_device_identity",
        lambda **kwargs: False,
    )

    with pytest.raises(HTTPException) as error:
        security.verify_registered_device(
            submitted_device_id=str(device_id),
            certificate_common_name="wrong-device",
            certificate_fingerprint="DD" * 32,
        )

    assert error.value.status_code == 401
