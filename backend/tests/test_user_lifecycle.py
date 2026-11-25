"""Account lifecycle transition, authorization and transactional tests."""
from datetime import datetime, timezone
from unittest.mock import MagicMock, Mock
from uuid import uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.api import rbac
from app.api.routes import user_management as route
from app.services import user_lifecycle_service as service

ACTOR = uuid4()
TARGET = uuid4()
TOKEN = "A" * 43
ORIGIN = "https://localhost:8443"
NOW = datetime.now(timezone.utc)
USER = dict(user_id=TARGET, username="test_viewer", email="test@example.com",
            role="viewer", status="suspended", created_by=ACTOR,
            created_at=NOW, updated_at=NOW, last_login_at=None,
            password_changed_at=NOW)


@pytest.mark.parametrize("before,after", [
    ("invited", "deactivated"), ("active", "suspended"),
    ("active", "deactivated"), ("suspended", "active"),
    ("suspended", "deactivated"),
])
def test_allowed_status(before, after):
    assert service.plan_change(
        {"role": "viewer", "status": before}, status=after
    ) == (after, "viewer")


@pytest.mark.parametrize("before,after", [
    ("invited", "active"), ("invited", "suspended"),
    ("active", "active"), ("suspended", "suspended"),
    ("deactivated", "active"), ("deactivated", "suspended"),
    ("deactivated", "deactivated"),
])
def test_blocked_status(before, after):
    with pytest.raises(service.LifecycleConflict):
        service.plan_change({"role": "viewer", "status": before}, status=after)


@pytest.mark.parametrize("status", ["active", "suspended"])
def test_allowed_role(status):
    assert service.plan_change(
        {"role": "viewer", "status": status}, role="analyst"
    ) == (status, "analyst")


@pytest.mark.parametrize("status", ["invited", "deactivated"])
def test_blocked_role(status):
    with pytest.raises(service.LifecycleConflict):
        service.plan_change({"role": "viewer", "status": status}, role="analyst")


def test_noop_role():
    with pytest.raises(service.LifecycleConflict):
        service.plan_change({"role": "viewer", "status": "active"}, role="viewer")


@pytest.mark.parametrize("kwargs", [{}, {"role": "analyst", "status": "suspended"},
                                       {"role": "invalid"}, {"status": "invited"}])
def test_invalid_change(kwargs):
    with pytest.raises(ValueError):
        service.plan_change({"role": "viewer", "status": "active"}, **kwargs)


@pytest.fixture
def api(monkeypatch):
    monkeypatch.setenv("INTELSOC_DASHBOARD_ORIGIN", ORIGIN)
    session = {"user_id": ACTOR, "role": "administrator", "status": "active"}
    validate = Mock(return_value=session)
    change = Mock(return_value={"user": USER, "revoked_sessions": 2, "revoked_tokens": 1})
    monkeypatch.setattr(rbac, "validate_session", validate)
    monkeypatch.setattr(route, "change_user_account", change)
    with TestClient(app, base_url=ORIGIN) as client:
        client.cookies.set(route.SESSION_COOKIE, TOKEN)
        yield client, session, validate, change


@pytest.mark.parametrize("field,value", [("status", "suspended"), ("role", "analyst")])
def test_api_success(api, field, value):
    client, _, _, change = api
    response = client.patch(f"/api/v1/users/{TARGET}/{field}",
                            json={field: value}, headers={"Origin": ORIGIN})
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["revoked_sessions"] == 2
    assert response.json()["revoked_tokens"] == 1
    assert "password_hash" not in response.text
    assert TOKEN not in response.text
    kwargs = change.call_args.kwargs
    assert kwargs["actor_user_id"] == ACTOR
    assert kwargs["user_id"] == TARGET
    assert kwargs["session_token"] == TOKEN
    assert kwargs[field] == value


@pytest.mark.parametrize("role", ["viewer", "analyst"])
def test_non_admin(api, role):
    client, session, _, change = api
    session["role"] = role
    assert client.patch(f"/api/v1/users/{TARGET}/status",
                        json={"status": "suspended"}, headers={"Origin": ORIGIN}).status_code == 403
    change.assert_not_called()


def test_missing_session(api):
    client, _, validate, change = api
    client.cookies.clear()
    validate.side_effect = service.InvalidSession()
    assert client.patch(f"/api/v1/users/{TARGET}/status",
                        json={"status": "suspended"}, headers={"Origin": ORIGIN}).status_code == 401
    change.assert_not_called()


def test_untrusted_origin(api):
    client, _, validate, change = api
    assert client.patch(f"/api/v1/users/{TARGET}/role",
                        json={"role": "analyst"}, headers={"Origin": "https://evil.example"}).status_code == 403
    validate.assert_not_called()
    change.assert_not_called()


@pytest.mark.parametrize("error,expected", [
    (service.InvalidSession(), 401), (service.UserManagementForbidden(), 403),
    (service.LifecycleUserNotFound(), 404), (service.LifecycleConflict("Blocked"), 409),
    (ValueError(), 422), (psycopg.OperationalError(), 503),
])
def test_api_errors(api, error, expected):
    client, _, _, change = api
    change.side_effect = error
    response = client.patch(f"/api/v1/users/{TARGET}/status",
                            json={"status": "suspended"}, headers={"Origin": ORIGIN})
    assert response.status_code == expected
    assert response.headers["cache-control"] == "no-store"


@pytest.fixture
def db(monkeypatch):
    connect = MagicMock()
    cur = connect.return_value.__enter__.return_value.cursor.return_value.__enter__.return_value
    actor = {"user_id": ACTOR, "role": "administrator", "status": "active", "has_password": True}
    target = {"user_id": TARGET, "role": "viewer", "status": "active", "has_password": True}
    cur.fetchall.return_value = [actor, target]
    cur.fetchone.side_effect = [{"session_id": uuid4()}, USER]
    cur.rowcount = 2
    monkeypatch.setattr(service.psycopg, "connect", connect)
    monkeypatch.setattr(service, "get_postgres_config", lambda: {})
    return cur, connect, actor, target


def run_change(**kwargs):
    return service.change_user_account(
        user_id=kwargs.pop("user_id", TARGET), actor_user_id=ACTOR,
        session_token=TOKEN, **kwargs,
    )


def test_transaction_success(db):
    cur, conn, _, _ = db
    result = run_change(status="suspended")
    assert result["revoked_sessions"] == 2
    assert result["revoked_tokens"] == 2
    sql = [" ".join(c.args[0].split()) for c in cur.execute.call_args_list]
    assert "pg_advisory_xact_lock" in sql[1]
    assert "ORDER BY user_id FOR UPDATE" in sql[2]
    assert "token_hash" in sql[3]
    assert "UPDATE public.users" in sql[4]
    assert "UPDATE public.auth_sessions" in sql[5]
    assert "UPDATE public.auth_tokens" in sql[6]
    assert "INSERT INTO public.auth_audit_logs" in sql[7]
    assert conn.return_value.__exit__.call_args.args[0] is None


def test_actor_recheck(db):
    cur, _, actor, _ = db
    actor["role"] = "viewer"
    with pytest.raises(service.UserManagementForbidden):
        run_change(status="suspended")
    assert cur.execute.call_count == 3


def test_session_recheck(db):
    cur, _, _, _ = db
    cur.fetchone.side_effect = [None]
    with pytest.raises(service.InvalidSession):
        run_change(status="suspended")
    assert cur.execute.call_count == 4


def test_self_modification(db):
    cur, _, _, _ = db
    with pytest.raises(service.LifecycleConflict):
        run_change(user_id=ACTOR, status="suspended")
    assert cur.execute.call_count == 4


def test_last_admin(db):
    cur, _, _, target = db
    target["role"] = "administrator"
    cur.fetchone.side_effect = [{"session_id": uuid4()}, {"count": 0}]
    with pytest.raises(service.LifecycleConflict):
        run_change(role="viewer")
    assert cur.execute.call_count == 5


def test_reactivation_requires_password(db):
    cur, _, _, target = db
    target.update(status="suspended", has_password=False)
    with pytest.raises(service.LifecycleConflict):
        run_change(status="active")
    assert cur.execute.call_count == 4


def test_audit_failure_rolls_back(db):
    cur, conn, _, _ = db
    cur.execute.side_effect = [None] * 7 + [psycopg.OperationalError()]
    with pytest.raises(psycopg.OperationalError):
        run_change(status="suspended")
    assert conn.return_value.__exit__.call_args.args[0] is psycopg.OperationalError
