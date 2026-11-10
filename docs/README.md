# IntelSOC — Project Documentation Index

**Current status:** Windows/Linux telemetry, centralized event processing, rule-based detections, alerts/incidents, and dual-provider Threat Intelligence are implemented in the validated backend.

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

This starts the database/queue services, FastAPI, event worker, analysis worker, Threat Intelligence worker, and Caddy gateway.

To stop the local runtime:

```powershell
.\Stop-IntelSOC.ps1
```

## Tests

From `backend`:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Latest validated local baseline:

```text
533 passed
0 failed
1 known Starlette deprecation warning
```

## Threat Intelligence status

- VirusTotal: implemented and validated
- AbuseIPDB: implemented and validated
- OTX: optional, not started
- persistent TI cache: PostgreSQL `ti_results`
- continuous TI processing: `app.workers.ti_worker`
- live endpoint-to-TI acceptance test: pending

## Secrets

The root `.env` contains local runtime secrets and is excluded from Git.

Never commit actual API keys or credentials.
