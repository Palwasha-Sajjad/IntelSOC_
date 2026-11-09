from copy import deepcopy
from uuid import uuid4

import pytest

from app.services import windows_src_ip_service as service


def record(*, ip="198.51.100.27", provider="Microsoft-Windows-Security-Auditing"):
    inserts = ["-"] * 21
    inserts[5] = "testuser"
    inserts[10] = 3
    inserts[19] = ip
    return {
        "EventID": 4625,
        "Channel": "Security",
        "ProviderName": provider,
        "StringInserts": inserts,
        "Message": "An account failed to log on.",
    }


@pytest.mark.parametrize(
    ("ip", "expected"),
    [
        ("198.51.100.27", "198.51.100.27"),
        ("2001:0db8::7", "2001:db8::7"),
        ("-", None),
        ("not-an-ip", None),
        ("0.0.0.0", None),
        ("::", None),
    ],
)
def test_source_ip_validation(ip, expected):
    assert service.source_ip_from_4625(record(ip=ip)) == expected


def test_reject_wrong_provider_and_invalid_raw():
    assert service.source_ip_from_4625(record(provider="Other")) is None
    assert service.source_ip_from_4625(None) is None


def test_raw_event_is_not_modified():
    raw = record()
    original = deepcopy(raw)
    assert service.source_ip_from_4625(raw) == "198.51.100.27"
    assert raw == original


class FakeCursor:
    def __init__(self, rows):
        self.rows = rows
        self.executed = []
        self.rowcount = 0

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def execute(self, statement, params):
        self.executed.append((statement, params))
        self.rowcount = 1 if "UPDATE security_events" in statement else 0

    def fetchall(self):
        return self.rows


class FakeConnection:
    def __init__(self, rows):
        self.cursor_object = FakeCursor(rows)
        self.rollbacks = 0

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def cursor(self):
        return self.cursor_object

    def rollback(self):
        self.rollbacks += 1


def setup_connection(monkeypatch, rows):
    connection = FakeConnection(rows)
    monkeypatch.setattr(service, "get_postgres_config", lambda: {})
    monkeypatch.setattr(service.psycopg, "connect", lambda **kwargs: connection)
    return connection


def test_default_dry_run_never_updates(monkeypatch):
    event_id = uuid4()
    connection = setup_connection(monkeypatch, [(event_id, record())])

    report = service.enrich_stored_windows_4625_ips(limit=20)

    assert report.examined == 1
    assert report.valid_ips == 1
    assert report.updated == 0
    assert report.dry_run is True
    assert report.next_after_event_id == str(event_id)
    assert connection.rollbacks == 1
    assert len(connection.cursor_object.executed) == 1
    query, params = connection.cursor_object.executed[0]
    assert "device_id IS NOT NULL" in query
    assert params == (None, None, 20)


def test_apply_updates_only_valid_matching_rows(monkeypatch):
    first, second, third = uuid4(), uuid4(), uuid4()
    rows = [
        (first, record()),
        (second, record(ip="-")),
        (third, record(provider="Untrusted-Provider")),
    ]
    connection = setup_connection(monkeypatch, rows)

    report = service.enrich_stored_windows_4625_ips(apply=True)

    assert report.examined == 3
    assert report.valid_ips == 1
    assert report.updated == 1
    assert report.dry_run is False
    assert connection.rollbacks == 0
    statements = connection.cursor_object.executed
    updates = [(q, p) for q, p in statements if "UPDATE security_events" in q]
    assert len(updates) == 1
    query, params = updates[0]
    assert params == ("198.51.100.27", first)
    assert "src_ip IS NULL" in query
    assert "device_id IS NOT NULL" in query


def test_cursor_and_limit_validation(monkeypatch):
    with pytest.raises(ValueError):
        service.enrich_stored_windows_4625_ips(limit=0)
    with pytest.raises(ValueError):
        service.enrich_stored_windows_4625_ips(limit=5001)

    after_id = uuid4()
    connection = setup_connection(monkeypatch, [])
    report = service.enrich_stored_windows_4625_ips(
        after_event_id=str(after_id), limit=10,
    )
    assert report.examined == 0
    assert report.next_after_event_id is None
    _, params = connection.cursor_object.executed[0]
    assert params == (after_id, after_id, 10)
