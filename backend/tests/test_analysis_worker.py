from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.workers import analysis_worker


BASE_TIME = datetime(
    2026,
    11,
    9,
    5,
    50,
    0,
    tzinfo=timezone.utc,
)


def event(
    number: int,
    seconds: int,
):
    return {
        "event_id": str(uuid4()),
        "device_id": str(uuid4()),
        "event_time": BASE_TIME
        + timedelta(seconds=seconds),
        "raw_event": {
            "Channel": "Security",
            "EventID": 4625,
            "ProviderName": (
                "Microsoft-Windows-Security-Auditing"
            ),
            "StringInserts": [
                "sid",
                "requestor",
                "LAB",
                "0x1",
                "S-1-0-0",
                "testuser",
                "LAB",
                "0xc000006e",
                "%%2313",
                "0xc000006e",
                2,
                "Advapi",
                "Negotiate",
                "LAB",
                "-",
                "-",
                0,
                "0x1",
                "C:\\Windows\\System32\\winlogon.exe",
                "-",
                "-",
            ],
        },
    }


def same_device_events(count: int):
    device_id = str(uuid4())

    events = [
        event(i, i * 20)
        for i in range(count)
    ]

    for item in events:
        item["device_id"] = device_id

    return events


def test_analyze_once_persists_threshold_crossing(monkeypatch):
    events = same_device_events(5)

    monkeypatch.setattr(
        analysis_worker,
        "fetch_unprocessed_failed_login_events",
        lambda limit: events,
    )

    monkeypatch.setattr(
        analysis_worker,
        "fetch_failed_login_history",
        lambda start_time, end_time: events,
    )

    persisted = []

    class Result:
        created = True

    monkeypatch.setattr(
        analysis_worker,
        "persist_detection",
        lambda candidate: (
            persisted.append(candidate)
            or Result()
        ),
    )

    processed = []

    monkeypatch.setattr(
        analysis_worker,
        "mark_event_analysis_processed",
        lambda event_id: processed.append(str(event_id)),
    )

    result = analysis_worker.analyze_once()

    assert result == {
        "events_processed": 5,
        "detections_created": 1,
        "detections_reused": 0,
        "events_failed": 0,
    }

    assert len(persisted) == 1
    assert persisted[0].event_count == 5
    assert len(processed) == 5


def test_history_detection_is_not_persisted_again(monkeypatch):
    history = same_device_events(6)
    pending = [history[-1]]

    monkeypatch.setattr(
        analysis_worker,
        "fetch_unprocessed_failed_login_events",
        lambda limit: pending,
    )

    monkeypatch.setattr(
        analysis_worker,
        "fetch_failed_login_history",
        lambda start_time, end_time: history,
    )

    persisted = []

    monkeypatch.setattr(
        analysis_worker,
        "persist_detection",
        lambda candidate: persisted.append(candidate),
    )

    monkeypatch.setattr(
        analysis_worker,
        "mark_event_analysis_processed",
        lambda event_id: None,
    )

    result = analysis_worker.analyze_once()

    assert persisted == []
    assert result["detections_created"] == 0
    assert result["events_processed"] == 1


def test_no_pending_events_is_noop(monkeypatch):
    monkeypatch.setattr(
        analysis_worker,
        "fetch_unprocessed_failed_login_events",
        lambda limit: [],
    )

    assert analysis_worker.analyze_once() == {
        "events_processed": 0,
        "detections_created": 0,
        "detections_reused": 0,
        "events_failed": 0,
    }


def test_analysis_failure_marks_batch_failed(monkeypatch):
    events = same_device_events(2)

    monkeypatch.setattr(
        analysis_worker,
        "fetch_unprocessed_failed_login_events",
        lambda limit: events,
    )

    monkeypatch.setattr(
        analysis_worker,
        "fetch_failed_login_history",
        lambda start_time, end_time: (
            (_ for _ in ()).throw(
                RuntimeError("analysis exploded")
            )
        ),
    )

    failed = []

    monkeypatch.setattr(
        analysis_worker,
        "mark_event_analysis_failed",
        lambda event_id, error: failed.append(
            (str(event_id), error)
        ),
    )

    with pytest.raises(
        RuntimeError,
        match="analysis exploded",
    ):
        analysis_worker.analyze_once()

    assert len(failed) == 2
    assert all(
        error == "analysis exploded"
        for _, error in failed
    )


def test_reused_detection_is_counted(monkeypatch):
    events = same_device_events(5)

    monkeypatch.setattr(
        analysis_worker,
        "fetch_unprocessed_failed_login_events",
        lambda limit: events,
    )

    monkeypatch.setattr(
        analysis_worker,
        "fetch_failed_login_history",
        lambda start_time, end_time: events,
    )

    class Result:
        created = False

    monkeypatch.setattr(
        analysis_worker,
        "persist_detection",
        lambda candidate: Result(),
    )

    monkeypatch.setattr(
        analysis_worker,
        "mark_event_analysis_processed",
        lambda event_id: None,
    )

    result = analysis_worker.analyze_once()

    assert result["detections_created"] == 0
    assert result["detections_reused"] == 1
