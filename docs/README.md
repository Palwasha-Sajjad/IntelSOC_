# IntelSOC — Project Documentation Index

**Current status:** Windows/Linux telemetry, centralized event processing, rule-based detections, alerts/incidents, dual-provider Threat Intelligence, risk scoring, and device criticality are implemented in the validated backend.

## Current runtime

```text
Endpoint telemetry
  → Fluent Bit
  → Caddy HTTPS
  → FastAPI
  → Redis
  → event_worker
  → PostgreSQL
  → analysis_worker
  → detections / alerts / incidents
  → ti_worker
  → VirusTotal + AbuseIPDB
  → cached TI results
  → risk_worker
  → risk assessments
```

## Important documents

- `../INTELSOC_TI_HANDOFF.md` — authoritative current backend/TI handoff and continuation state
- `INTELSOC_ROADMAP.md` — development roadmap and module tracking
- `MODULE_1E_LINUX_INGESTION.md` — Linux ingestion implementation notes
- `LINUX_RULE_PLAN_ALIGNMENT.md` — frozen Linux detection-rule alignment

## Local runtime

From the repository root:

```powershell
.\Start-IntelSOC.ps1
```

This starts the database/queue services, FastAPI, event worker, analysis worker, Threat Intelligence worker, risk worker, and Caddy gateway.

To stop the local runtime:

```powershell
.\Stop-IntelSOC.ps1
```

## Tests

From `backend`:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

The committed test suite must remain green after each backend change.

## Device criticality

Registered endpoints have an administrator-controlled criticality classification:

- `low`
- `medium` (default for newly enrolled and existing devices)
- `high`

Criticality is stored on `registered_devices` and is intentionally separate from threat severity or risk score.

Administrators can change only this classification through:

```text
PATCH /api/v1/devices/{device_id}/criticality
X-IntelSOC-Admin-Key: <administrator key>
```

The endpoint requires the dedicated `INTELSOC_ADMIN_API_KEY` environment variable. The ingestion key and enrollment token are not accepted for administrator device-management operations.

High criticality is intended to become a Response Engine policy input: disruptive response actions against high-criticality devices must require administrator approval. This migration does not itself execute or alter response actions.

## Threat Intelligence status

- VirusTotal: implemented and validated
- AbuseIPDB: implemented and validated
- OTX: optional, not started
- persistent TI cache: PostgreSQL `ti_results`
- continuous TI processing: `app.workers.ti_worker`
- live endpoint-to-TI acceptance test: pending

## Secrets

The root `.env` contains local runtime secrets and is excluded from Git.

Required management credential for device criticality:

```text
INTELSOC_ADMIN_API_KEY=<strong administrator-only secret>
```

Never reuse `INTELSOC_INGEST_API_KEY` or `INTELSOC_ENROLLMENT_TOKEN` as the administrator key.

Never commit actual API keys or credentials.
