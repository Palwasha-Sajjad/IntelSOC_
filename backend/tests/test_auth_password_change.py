"""Password change endpoint, transactional service and rate limiter tests."""

from unittest.mock import Mock, MagicMock
from uuid import uuid4

import psycopg
import pytest
import redis
from fastapi.testclient import TestClient

from app.main import app
from app.api.routes import auth as route
from app.services import auth_password_change_service as service
from app.services import auth_rate_limit_service as limits

ORIGIN = "https://localhost:8443"
URL = "/api/v1/auth/change-password"
TOKEN = "A" * 43
USER_ID = uuid4()
OLD = "Example-old-password-123"
NEW = "Example-new-password-456"
PAYLOAD = {"current_password": OLD, "new_password": NEW}


@pytest.fixture
def api(monkeypatch):
    monkeypatch.setenv("INTELSOC_DASHBOARD_ORIGIN", ORIGIN)
    session = {"user_id": USER_ID, "role": "viewer", "status": "active"}
    validate = Mock(return_value=session)
    rate = Mock()
    change = Mock(return_value={"email": "viewer@example.com", "username": "viewer_test"})
    notify = Mock(return_value=True)
    monkeypatch.setattr(route, "validate_session", validate)
    monkeypatch.setattr(route, "enforce_password_change_rate_limit", rate)
    monkeypatch.setattr(route, "change_password", change)
    monkeypatch.setattr(route, "send_password_change_confirmation_email", notify)
    with TestClient(app, base_url=ORIGIN) as client:
        client.cookies.set(route.SESSION_COOKIE, TOKEN)
        yield client, session, validate, rate, change, notify


@pytest.mark.parametrize("role", ["viewer", "analyst", "administrator"])
def test_success(api, role):
    client, session, validate, rate, change, notify = api
    session["role"] = role
    response = client.post(URL, json=PAYLOAD, headers={"Origin": ORIGIN})
    assert response.status_code == 200
    assert response.json()["status"] == "password_changed"
    assert response.headers["cache-control"] == "no-store"
    cookie = response.headers["set-cookie"].lower()
    assert all(flag in cookie for flag in ("max-age=0", "httponly", "secure", "samesite=strict"))
    assert OLD not in response.text and NEW not in response.text
    validate.assert_called_once_with(TOKEN)
    assert change.call_args.kwargs["user_id"] == USER_ID
    assert change.call_args.kwargs["session_token"] == TOKEN
    notify.assert_called_once_with(recipient="viewer@example.com", username="viewer_test")


@pytest.mark.parametrize("origin", [None, "http://localhost:8443", "https://evil.example"])
def test_origin(api, origin):
    client, _, validate, _, change, _ = api
    headers = {"Origin": origin} if origin else {}
    assert client.post(URL, json=PAYLOAD, headers=headers).status_code == 403
    validate.assert_not_called()
    change.assert_not_called()


def test_missing_session(api):
    client, _, validate, rate, change, _ = api
    client.cookies.clear()
    validate.side_effect = route.InvalidSession()
    assert client.post(URL, json=PAYLOAD, headers={"Origin": ORIGIN}).status_code == 401
    validate.assert_called_once_with(None)
    rate.assert_not_called()
    change.assert_not_called()


def test_inactive_session(api):
    client, session, _, rate, change, _ = api
    session["status"] = "suspended"
    assert client.post(URL, json=PAYLOAD, headers={"Origin": ORIGIN}).status_code == 401
    rate.assert_not_called()
    change.assert_not_called()


@pytest.mark.parametrize("payload", [
    {}, {"current_password": "", "new_password": NEW},
    {"current_password": OLD, "new_password": "short"},
    {"current_password": "x" * 129, "new_password": NEW},
    {"current_password": OLD, "new_password": "y" * 129},
])
def test_invalid_payload(api, payload):
    client, _, _, _, change, notify = api
    response = client.post(URL, json=payload, headers={"Origin": ORIGIN})
    assert response.status_code == 422
    assert OLD not in response.text and NEW not in response.text
    assert "x" * 129 not in response.text and "y" * 129 not in response.text
    change.assert_not_called()
    notify.assert_not_called()


@pytest.mark.parametrize("error,status", [
    (route.InvalidSession(), 401),
    (route.InvalidCredentials(), 400),
    (ValueError(), 422),
    (psycopg.OperationalError(), 503),
])
def test_service_errors(api, error, status):
    client, _, _, _, change, notify = api
    change.side_effect = error
    response = client.post(URL, json=PAYLOAD, headers={"Origin": ORIGIN})
    assert response.status_code == status
    assert response.headers["cache-control"] == "no-store"
    assert "set-cookie" not in response.headers
    notify.assert_not_called()


@pytest.mark.parametrize("error,status", [
    (limits.PasswordChangeRateLimitExceeded(45), 429),
    (limits.RateLimitUnavailable(), 503),
])
def test_rate_limit(api, error, status):
    client, _, _, rate, change, notify = api
    rate.side_effect = error
    response = client.post(URL, json=PAYLOAD, headers={"Origin": ORIGIN})
    assert response.status_code == status
    if status == 429:
        assert response.headers["retry-after"] == "45"
    change.assert_not_called()
    notify.assert_not_called()


def test_busy(api, monkeypatch):
    client, _, _, _, change, notify = api
    slots = Mock()
    slots.acquire.return_value = False
    monkeypatch.setattr(route, "PASSWORD_VERIFICATION_SLOTS", slots)
    assert client.post(URL, json=PAYLOAD, headers={"Origin": ORIGIN}).status_code == 503
    change.assert_not_called()
    slots.release.assert_not_called()
    notify.assert_not_called()


def test_notification_failure(api):
    client, _, _, _, _, notify = api
    notify.side_effect = route.EmailDeliveryError("SMTP unavailable")
    assert client.post(URL, json=PAYLOAD, headers={"Origin": ORIGIN}).status_code == 200


@pytest.fixture
def db(monkeypatch):
    conn = MagicMock()
    cur = conn.cursor.return_value.__enter__.return_value
    cur.fetchone.side_effect = [
        {"user_id": USER_ID, "username": "viewer_test", "email": "viewer@example.com",
         "password_hash": "stored_hash", "status": "active"},
        {"session_id": uuid4()},
    ]
    cur.rowcount = 2
    connect = MagicMock()
    connect.return_value.__enter__.return_value = conn
    monkeypatch.setattr(service.psycopg, "connect", connect)
    monkeypatch.setattr(service, "get_postgres_config", lambda: {})
    verify = Mock(return_value=True)
    hashed = Mock(return_value="new_hash")
    audit = Mock()
    monkeypatch.setattr(service, "verify_password", verify)
    monkeypatch.setattr(service, "hash_password", hashed)
    monkeypatch.setattr(service, "record_auth_audit", audit)
    return cur, connect, verify, hashed, audit


def run_change(new=NEW):
    return service.change_password(
        user_id=USER_ID, session_token=TOKEN,
        current_password=OLD, new_password=new, source_ip="192.0.2.1",
    )


def test_service_success(db):
    cur, connect, verify, hashed, audit = db
    result = run_change()
    assert result["revoked_sessions"] == 2
    assert result["user_id"] == USER_ID
    verify.assert_called_once_with(OLD, "stored_hash")
    hashed.assert_called_once_with(NEW)
    statements = [" ".join(call.args[0].split()) for call in cur.execute.call_args_list]
    assert "FOR UPDATE" in statements[1] and "FOR UPDATE" in statements[2]
    assert "token_hash = %s" in statements[2]
    assert "UPDATE public.users" in statements[3]
    assert "UPDATE public.auth_sessions" in statements[4]
    assert "purpose = 'password_reset'" in statements[5]
    assert audit.call_args.kwargs["outcome"] == "success"
    assert "password_hash" not in result
    assert connect.return_value.__exit__.call_args.args[0] is None


def test_wrong_current_password(db):
    cur, connect, verify, hashed, audit = db
    verify.return_value = False
    with pytest.raises(service.InvalidCredentials):
        run_change()
    hashed.assert_not_called()
    assert cur.execute.call_count == 3
    assert audit.call_args.kwargs["outcome"] == "failure"
    # Failure audit is committed before the exception reaches the API.
    assert connect.return_value.__exit__.call_args.args[0] is None


def test_same_password(db):
    cur, _, _, hashed, _ = db
    with pytest.raises(ValueError):
        run_change(OLD)
    hashed.assert_not_called()
    assert cur.execute.call_count == 3


def test_revoked_session_recheck(db):
    cur, _, verify, hashed, _ = db
    cur.fetchone.side_effect = [
        {"user_id": USER_ID, "status": "active"}, None,
    ]
    with pytest.raises(service.InvalidSession):
        run_change()
    verify.assert_not_called()
    hashed.assert_not_called()


def test_audit_failure_rolls_back(db):
    cur, connect, _, _, audit = db
    audit.side_effect = psycopg.OperationalError("audit failed")
    with pytest.raises(psycopg.OperationalError):
        run_change()
    assert connect.return_value.__exit__.call_args.args[0] is psycopg.OperationalError


@pytest.mark.parametrize("allowed,retry", [(1, 0), (0, 40)])
def test_limiter(monkeypatch, allowed, retry):
    client = MagicMock()
    client.eval.return_value = (allowed, retry)
    factory = MagicMock()
    factory.return_value.__enter__.return_value = client
    monkeypatch.setattr(limits.redis, "Redis", factory)
    monkeypatch.setattr(limits, "get_redis_config", lambda: {})
    kwargs = {"user_id": USER_ID, "source_ip": "::ffff:192.0.2.1"}
    if allowed:
        limits.enforce_password_change_rate_limit(**kwargs)
    else:
        with pytest.raises(limits.PasswordChangeRateLimitExceeded) as exc:
            limits.enforce_password_change_rate_limit(**kwargs)
        assert exc.value.retry_after == retry
    args = client.eval.call_args.args
    assert args[-3:] == (60, 5, 20)
    assert str(USER_ID) not in args[2]
    assert args[3].endswith(limits._digest("192.0.2.1"))


def test_limiter_unavailable(monkeypatch):
    monkeypatch.setattr(limits, "get_redis_config", lambda: {})
    monkeypatch.setattr(limits.redis, "Redis", Mock(side_effect=redis.ConnectionError()))
    with pytest.raises(limits.RateLimitUnavailable):
        limits.enforce_password_change_rate_limit(user_id=USER_ID, source_ip=None)
