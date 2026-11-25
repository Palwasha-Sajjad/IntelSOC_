from datetime import datetime, timezone
from uuid import uuid4

import psycopg
import pytest

from fastapi.testclient import TestClient

from app.main import app
from app.api import rbac
from app.api.routes import user_management
from app.api.routes.auth import SESSION_COOKIE
from app.services.auth_session_service import InvalidSession


TOKEN = "f" * 43
USER_ID = uuid4()

HEADERS = {
    "Cookie": f"{SESSION_COOKIE}={TOKEN}"
}

ENDPOINTS = [
    "/api/v1/users",
    f"/api/v1/users/{USER_ID}",
]


def sample_user():
    now = datetime.now(timezone.utc)

    return {
        "user_id": USER_ID,
        "username": "test_user",
        "email": "test@example.com",
        "role": "viewer",
        "status": "invited",
        "created_by": None,
        "created_at": now,
        "updated_at": now,
        "last_login_at": None,
        "password_changed_at": None,
    }


@pytest.fixture
def client(monkeypatch):

    def validate(token):
        if token != TOKEN:
            raise InvalidSession()

        return {
            "user_id": uuid4(),
            "role": "administrator",
            "status": "active",
        }

    monkeypatch.setattr(rbac, "validate_session", validate)

    with TestClient(
        app,
        base_url="https://intelsoc.test",
    ) as test_client:
        yield test_client


@pytest.mark.parametrize("endpoint", ENDPOINTS)
def test_missing_session(client, endpoint):
    assert client.get(endpoint).status_code == 401


@pytest.mark.parametrize("endpoint", ENDPOINTS)
@pytest.mark.parametrize("role", ["viewer", "analyst"])
def test_unauthorized_roles(client, monkeypatch, endpoint, role):

    monkeypatch.setattr(
        rbac,
        "validate_session",
        lambda token: {
            "role": role,
            "status": "active",
        },
    )

    def blocked(**kwargs):
        raise AssertionError("Unauthorized database access")

    monkeypatch.setattr(user_management, "list_users", blocked)
    monkeypatch.setattr(user_management, "get_user", blocked)

    response = client.get(endpoint, headers=HEADERS)

    assert response.status_code == 403


def test_admin_lists_users(client, monkeypatch):

    monkeypatch.setattr(
        user_management,
        "list_users",
        lambda **kwargs: [sample_user()],
    )

    response = client.get(
        "/api/v1/users",
        headers=HEADERS,
    )

    assert response.status_code == 200
    assert response.json()[0]["username"] == "test_user"


def test_admin_reads_user_details(client, monkeypatch):

    monkeypatch.setattr(
        user_management,
        "get_user",
        lambda **kwargs: sample_user(),
    )

    response = client.get(
        f"/api/v1/users/{USER_ID}",
        headers=HEADERS,
    )

    assert response.status_code == 200
    assert response.json()["user_id"] == str(USER_ID)


@pytest.mark.parametrize("endpoint", ENDPOINTS)
def test_sensitive_fields_excluded(client, monkeypatch, endpoint):

    user = {
        **sample_user(),
        "password_hash": "sensitive-hash",
        "token_hash": "sensitive-token",
        "session_token": "sensitive-session",
    }

    monkeypatch.setattr(
        user_management,
        "list_users",
        lambda **kwargs: [user],
    )

    monkeypatch.setattr(
        user_management,
        "get_user",
        lambda **kwargs: user,
    )

    response = client.get(endpoint, headers=HEADERS)

    assert response.status_code == 200

    data = response.json()

    if isinstance(data, list):
        data = data[0]

    assert set(data) == set(sample_user())


def test_user_filters(client, monkeypatch):

    calls = []

    def retrieve(**kwargs):
        calls.append(kwargs)
        return []

    monkeypatch.setattr(user_management, "list_users", retrieve)

    response = client.get(
        "/api/v1/users",
        headers=HEADERS,
        params={
            "limit": 10,
            "offset": 5,
            "role": "viewer",
            "status": "invited",
        },
    )

    assert response.status_code == 200

    assert calls == [{
        "limit": 10,
        "offset": 5,
        "role": "viewer",
        "status": "invited",
    }]


@pytest.mark.parametrize("params", [
    {"limit": 0},
    {"limit": 101},
    {"offset": -1},
    {"offset": 100001},
    {"role": "superadmin"},
    {"status": "unknown"},
])
def test_invalid_parameters(client, monkeypatch, params):

    def blocked(**kwargs):
        raise AssertionError("Invalid request reached database")

    monkeypatch.setattr(user_management, "list_users", blocked)

    response = client.get(
        "/api/v1/users",
        headers=HEADERS,
        params=params,
    )

    assert response.status_code == 422


def test_unknown_user(client, monkeypatch):

    monkeypatch.setattr(
        user_management,
        "get_user",
        lambda **kwargs: None,
    )

    response = client.get(
        f"/api/v1/users/{USER_ID}",
        headers=HEADERS,
    )

    assert response.status_code == 404


def test_invalid_user_id(client):

    response = client.get(
        "/api/v1/users/invalid-uuid",
        headers=HEADERS,
    )

    assert response.status_code == 422


@pytest.mark.parametrize("endpoint", ENDPOINTS)
def test_storage_error_sanitized(client, monkeypatch, endpoint):

    def fail(**kwargs):
        raise psycopg.OperationalError("sensitive-database-error")

    monkeypatch.setattr(user_management, "list_users", fail)
    monkeypatch.setattr(user_management, "get_user", fail)

    response = client.get(endpoint, headers=HEADERS)

    assert response.status_code == 503
    assert "sensitive-database-error" not in response.text


@pytest.mark.parametrize("endpoint", ENDPOINTS)
def test_legacy_admin_key_rejected(client, monkeypatch, endpoint):

    monkeypatch.setenv(
        "INTELSOC_ADMIN_API_KEY",
        "test-legacy-key",
    )

    response = client.get(
        endpoint,
        headers={
            "X-IntelSOC-Admin-Key": "test-legacy-key",
        },
    )

    assert response.status_code == 401


from unittest.mock import Mock

from app.services.user_management_service import (
    DuplicateUserError,
    UserManagementForbidden,
)

from app.services.auth_invitation_service import (
    InvitationNotAllowed,
    InvitationUserNotFound,
)

from app.services.email_service import EmailConfigurationError


ORIGIN = "https://localhost:8443"

WRITE_HEADERS = {
    **HEADERS,
    "Origin": ORIGIN,
}

CREATE_PAYLOAD = {
    "username": "test_user",
    "email": "test@example.com",
    "role": "viewer",
}

WRITE_ENDPOINTS = [
    "/api/v1/users",
    f"/api/v1/users/{USER_ID}/resend-invitation",
]


@pytest.fixture
def provisioning(monkeypatch):

    monkeypatch.setenv(
        "INTELSOC_DASHBOARD_ORIGIN",
        ORIGIN,
    )

    delivery = {
        "invitation_expires_at": datetime.now(timezone.utc),
        "email_delivery": "submitted",
        "audit_recorded": True,
    }

    create = Mock(return_value={
        "user": sample_user(),
        **delivery,
    })

    resend = Mock(return_value={
        "user_id": USER_ID,
        **delivery,
    })

    monkeypatch.setattr(
        user_management,
        "provision_user",
        create,
    )

    monkeypatch.setattr(
        user_management,
        "deliver_invitation",
        resend,
    )

    return create, resend


def test_admin_creates_user(client, provisioning):

    create, resend = provisioning

    response = client.post(
        WRITE_ENDPOINTS[0],
        headers=WRITE_HEADERS,
        json=CREATE_PAYLOAD,
    )

    assert response.status_code == 201
    assert response.json()["user"]["status"] == "invited"
    assert response.json()["email_delivery"] == "submitted"

    create.assert_called_once()
    resend.assert_not_called()

    args = create.call_args.kwargs

    assert args["username"] == "test_user"
    assert args["email"] == "test@example.com"
    assert args["role"] == "viewer"
    assert args["actor_user_id"] is not None


def test_admin_resends_invitation(client, provisioning):

    create, resend = provisioning

    response = client.post(
        WRITE_ENDPOINTS[1],
        headers=WRITE_HEADERS,
    )

    assert response.status_code == 200
    assert response.json()["email_delivery"] == "submitted"

    create.assert_not_called()
    resend.assert_called_once()

    assert resend.call_args.kwargs["user_id"] == USER_ID


@pytest.mark.parametrize("endpoint", WRITE_ENDPOINTS)
def test_write_requires_session(client, provisioning, endpoint):

    response = client.post(
        endpoint,
        headers={"Origin": ORIGIN},
        json=CREATE_PAYLOAD,
    )

    assert response.status_code == 401

    for mock in provisioning:
        mock.assert_not_called()


@pytest.mark.parametrize("endpoint", WRITE_ENDPOINTS)
@pytest.mark.parametrize("role", ["viewer", "analyst"])
def test_write_role_protection(
    client, provisioning, monkeypatch, endpoint, role
):

    monkeypatch.setattr(
        rbac,
        "validate_session",
        lambda token: {
            "user_id": USER_ID,
            "role": role,
            "status": "active",
        },
    )

    response = client.post(
        endpoint,
        headers=WRITE_HEADERS,
        json=CREATE_PAYLOAD,
    )

    assert response.status_code == 403

    for mock in provisioning:
        mock.assert_not_called()


@pytest.mark.parametrize("endpoint", WRITE_ENDPOINTS)
@pytest.mark.parametrize("origin", [
    None,
    "https://untrusted.example.com",
    "null",
    "http://localhost:8443",
])
def test_write_origin_protection(
    client, provisioning, endpoint, origin
):

    headers = dict(HEADERS)

    if origin is not None:
        headers["Origin"] = origin

    response = client.post(
        endpoint,
        headers=headers,
        json=CREATE_PAYLOAD,
    )

    assert response.status_code == 403

    for mock in provisioning:
        mock.assert_not_called()


@pytest.mark.parametrize("payload", [
    {**CREATE_PAYLOAD, "username": "ab"},
    {**CREATE_PAYLOAD, "email": ""},
    {**CREATE_PAYLOAD, "role": "superadmin"},
    {},
])
def test_invalid_creation_payload(
    client, provisioning, payload
):

    response = client.post(
        WRITE_ENDPOINTS[0],
        headers=WRITE_HEADERS,
        json=payload,
    )

    assert response.status_code == 422
    provisioning[0].assert_not_called()


def test_delivery_unconfirmed(client, provisioning):

    create, _ = provisioning

    create.return_value["email_delivery"] = "unconfirmed"

    response = client.post(
        WRITE_ENDPOINTS[0],
        headers=WRITE_HEADERS,
        json=CREATE_PAYLOAD,
    )

    assert response.status_code == 201
    assert response.json()["email_delivery"] == "unconfirmed"
    assert response.json()["user"]["status"] == "invited"


@pytest.mark.parametrize("index", [0, 1])
def test_write_token_protection(client, provisioning, index):

    provisioning[index].return_value.update({
        "invitation_token": "sensitive-raw-token",
        "token_hash": "sensitive-token-hash",
    })

    response = client.post(
        WRITE_ENDPOINTS[index],
        headers=WRITE_HEADERS,
        json=CREATE_PAYLOAD,
    )

    assert response.status_code == (201 if index == 0 else 200)
    assert "sensitive-raw-token" not in response.text
    assert "sensitive-token-hash" not in response.text
    assert "invitation_token" not in response.json()


@pytest.mark.parametrize("index,error,expected", [
    (0, DuplicateUserError(), 409),
    (0, UserManagementForbidden(), 403),
    (0, ValueError("Invalid account"), 422),
    (0, EmailConfigurationError("Sensitive config"), 503),
    (0, psycopg.OperationalError("Sensitive DB error"), 503),
    (1, InvitationUserNotFound(), 404),
    (1, InvitationNotAllowed(), 409),
    (1, UserManagementForbidden(), 403),
    (1, EmailConfigurationError("Sensitive config"), 503),
    (1, psycopg.OperationalError("Sensitive DB error"), 503),
])
def test_provisioning_error_handling(
    client, provisioning, index, error, expected
):

    provisioning[index].side_effect = error

    response = client.post(
        WRITE_ENDPOINTS[index],
        headers=WRITE_HEADERS,
        json=CREATE_PAYLOAD,
    )

    assert response.status_code == expected
    assert "Sensitive config" not in response.text
    assert "Sensitive DB error" not in response.text



from app.services.auth_rate_limit_service import (
    ProvisioningRateLimitExceeded,
    RateLimitUnavailable,
)


@pytest.mark.parametrize("index", [0, 1])
def test_provisioning_http_429(
    client, provisioning, index
):

    provisioning[index].side_effect = (
        ProvisioningRateLimitExceeded(60)
    )

    response = client.post(
        WRITE_ENDPOINTS[index],
        headers=WRITE_HEADERS,
        json=CREATE_PAYLOAD,
    )

    assert response.status_code == 429
    assert response.headers["Retry-After"] == "60"
    assert response.headers["Cache-Control"] == "no-store"


@pytest.mark.parametrize("index", [0, 1])
def test_provisioning_redis_unavailable(
    client, provisioning, index
):

    provisioning[index].side_effect = (
        RateLimitUnavailable("Sensitive Redis error")
    )

    response = client.post(
        WRITE_ENDPOINTS[index],
        headers=WRITE_HEADERS,
        json=CREATE_PAYLOAD,
    )

    assert response.status_code == 503
    assert response.headers["Cache-Control"] == "no-store"
    assert "Sensitive Redis error" not in response.text
