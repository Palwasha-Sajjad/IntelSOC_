"""Authenticated read-only monitoring endpoints."""

from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.rbac import (
    require_viewer,
    require_analyst,
    require_administrator,
)
from app.services.monitoring_service import (
    list_events,
    list_alerts,
    list_incidents,
    get_alert_detail,
    get_alert_ti,
    get_alert_risk,
    get_incident_detail,
    get_dashboard_summary,
    list_devices,
    get_device_detail,
)

router = APIRouter(
    tags=["monitoring"],
)


def _retrieve(service, **kwargs):
    try:
        return service(**kwargs)
    except (psycopg.Error, OSError, KeyError):
        raise HTTPException(
            status_code=503,
            detail="Monitoring data unavailable",
        ) from None


@router.get("/events", dependencies=[Depends(require_viewer)])
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
    user: dict = Depends(require_viewer),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=100000),
    severity: str | None = Query(default=None, max_length=32),
    status: str | None = Query(default=None, max_length=32),
    device_id: UUID | None = None,
):
    alerts = _retrieve(
        list_alerts,
        limit=limit,
        offset=offset,
        severity=severity,
        status=status,
        device_id=device_id,
    )

    if user["role"] == "viewer":
        allowed_fields = {
            "alert_id",
            "title",
            "severity",
            "status",
            "device_id",
            "hostname",
            "created_at",
            "updated_at",
            "overall_score",
            "classification",
            "assessment_status",
        }

        return [
            {
                key: value
                for key, value in alert.items()
                if key in allowed_fields
            }
            for alert in alerts
        ]

    return alerts


@router.get("/incidents", dependencies=[Depends(require_analyst)])
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


@router.get("/alerts/{alert_id}", dependencies=[Depends(require_analyst)])
def read_alert_detail(alert_id: UUID):
    result = _retrieve(
        get_alert_detail,
        alert_id=alert_id,
    )
    return _require_record(result, "Alert not found")


@router.get("/alerts/{alert_id}/ti", dependencies=[Depends(require_analyst)])
def read_alert_ti(alert_id: UUID):
    result = _retrieve(
        get_alert_ti,
        alert_id=alert_id,
    )
    return _require_record(result, "Alert not found")


@router.get("/alerts/{alert_id}/risk", dependencies=[Depends(require_analyst)])
def read_alert_risk(alert_id: UUID):
    result = _retrieve(
        get_alert_risk,
        alert_id=alert_id,
    )
    return _require_record(result, "Alert not found")


@router.get("/incidents/{incident_id}", dependencies=[Depends(require_analyst)])
def read_incident_detail(incident_id: UUID):
    result = _retrieve(
        get_incident_detail,
        incident_id=incident_id,
    )
    return _require_record(result, "Incident not found")


@router.get("/dashboard/summary", dependencies=[Depends(require_viewer)])
def read_dashboard_summary():
    return _retrieve(get_dashboard_summary)


@router.get("/devices", dependencies=[Depends(require_administrator)])
def read_devices(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=100000),
    hostname: str | None = Query(default=None, max_length=255),
    platform: str | None = Query(default=None, max_length=32),
    status: str | None = Query(default=None, max_length=32),
    criticality: str | None = Query(default=None, max_length=32),
):
    return _retrieve(
        list_devices,
        limit=limit,
        offset=offset,
        hostname=hostname,
        platform=platform,
        status=status,
        criticality=criticality,
    )


@router.get("/devices/{device_id}", dependencies=[Depends(require_administrator)])
def read_device_detail(device_id: UUID):
    result = _retrieve(
        get_device_detail,
        device_id=device_id,
    )
    return _require_record(result, "Device not found")
