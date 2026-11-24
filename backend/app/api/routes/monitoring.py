"""Authenticated read-only monitoring endpoints."""

from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.security import verify_admin_key
from app.services.monitoring_service import (
    list_events,
    list_alerts,
    list_incidents,
    get_alert_detail,
    get_alert_ti,
    get_alert_risk,
    get_incident_detail,
)

router = APIRouter(
    tags=["monitoring"],
    dependencies=[Depends(verify_admin_key)],
)


def _retrieve(service, **kwargs):
    try:
        return service(**kwargs)
    except (psycopg.Error, OSError, KeyError):
        raise HTTPException(
            status_code=503,
            detail="Monitoring data unavailable",
        ) from None


@router.get("/events")
def get_events(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=100000),
    hostname: str | None = Query(default=None, max_length=255),
    event_type: str | None = Query(default=None, max_length=255),
    device_id: UUID | None = None,
):
    return _retrieve(
        list_events,
        limit=limit,
        offset=offset,
        hostname=hostname,
        event_type=event_type,
        device_id=device_id,
    )


@router.get("/alerts")
def get_alerts(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=100000),
    severity: str | None = Query(default=None, max_length=32),
    status: str | None = Query(default=None, max_length=32),
    device_id: UUID | None = None,
):
    return _retrieve(
        list_alerts,
        limit=limit,
        offset=offset,
        severity=severity,
        status=status,
        device_id=device_id,
    )


@router.get("/incidents")
def get_incidents(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=100000),
    severity: str | None = Query(default=None, max_length=32),
    status: str | None = Query(default=None, max_length=32),
    device_id: UUID | None = None,
):
    return _retrieve(
        list_incidents,
        limit=limit,
        offset=offset,
        severity=severity,
        status=status,
        device_id=device_id,
    )


def _require_record(result, detail):
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=detail,
        )
    return result


@router.get("/alerts/{alert_id}")
def read_alert_detail(alert_id: UUID):
    result = _retrieve(
        get_alert_detail,
        alert_id=alert_id,
    )
    return _require_record(result, "Alert not found")


@router.get("/alerts/{alert_id}/ti")
def read_alert_ti(alert_id: UUID):
    result = _retrieve(
        get_alert_ti,
        alert_id=alert_id,
    )
    return _require_record(result, "Alert not found")


@router.get("/alerts/{alert_id}/risk")
def read_alert_risk(alert_id: UUID):
    result = _retrieve(
        get_alert_risk,
        alert_id=alert_id,
    )
    return _require_record(result, "Alert not found")


@router.get("/incidents/{incident_id}")
def read_incident_detail(incident_id: UUID):
    result = _retrieve(
        get_incident_detail,
        incident_id=incident_id,
    )
    return _require_record(result, "Incident not found")
