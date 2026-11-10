# IntelSOC — Current Backend & Threat Intelligence Handoff

**Status date:** 11 November 2026  
**Purpose:** Preserve the latest validated IntelSOC state and provide the exact continuation point without reopening completed ingestion, detection, or Threat Intelligence work.

## 1. Current validated runtime

```text
Windows / Linux endpoints
        ↓
Fluent Bit
        ↓
Caddy HTTPS/TLS gateway
        ↓
FastAPI ingestion API
        ↓
Redis Stream: intelsoc:events
        ↓
event_worker
        ↓
PostgreSQL security_events
        ↓
analysis_worker
        ↓
Detection rules
        ↓
Detections → Alerts → Incidents
        ↓
ti_worker
        ↓
Evidence-backed IOC extraction
        ↓
VirusTotal + AbuseIPDB
        ↓
Normalized/cached TI results in PostgreSQL
```

Current runtime components:

- FastAPI + Uvicorn
- Redis 7
- PostgreSQL 17
- Fluent Bit endpoint collectors
- Caddy TLS gateway
- Python event, analysis, and Threat Intelligence workers
- Pytest regression suite
- PowerShell startup/shutdown orchestration

The validated repository still does not contain the earlier React/Vite dashboard prototype.

## 2. Ingestion status

### Windows
Working through managed Fluent Bit collection with preserved device identity and raw event evidence.

Important current Windows events include:

`4624, 4625, 4648, 4688, 4698, 4702, 4720, 4722, 4723, 4725, 4726, 4732, 4740, 1102`

PowerShell Operational Event 4104 is also collected for script-block analysis.

### Linux
Approved Linux scope is implemented for:

- SSH journald events
- sudo journald events
- auditd account/group lifecycle events
- narrowly keyed identity-file SYSCALL evidence

Broad Linux EXECVE collection remains intentionally disabled.

## 3. Detection status

Current Windows rules: **WIN-001 through WIN-012**.

Current Linux rules: **LIN-001 through LIN-005**.

**LIN-006 remains disabled by design** because the approved telemetry does not provide enough broad command-execution evidence for a reliable detector.

Detection processing remains:

```text
stored event
  → rule evaluation
  → deterministic detection fingerprint
  → detection persistence
  → alert persistence
  → incident correlation
  → per-rule processed/failed state
```

Replay/idempotency protections remain in place.

## 4. Threat Intelligence — implemented state

Threat Intelligence is now integrated and operational for the current FYP scope.

### Providers

| Provider | Status | Supported IOC types |
|---|---|---|
| VirusTotal | ✅ Implemented and validated | public IP, domain |
| AbuseIPDB | ✅ Implemented and validated | public IP |
| AlienVault OTX | ☐ Optional / not started | planned later only if needed |

### IOC policy

IntelSOC enriches only evidence-backed indicators from preserved event evidence.

Current safeguards:

- public/global IP validation before provider lookup
- private, loopback, link-local, reserved and documentation addresses rejected
- domains extracted only from approved structured evidence contexts
- arbitrary message text is not scanned for IOCs
- raw logs, internal hostnames, usernames and internal IPs are not sent to providers
- files are not uploaded to VirusTotal
- AbuseIPDB remains IP-only

## 5. TI processing flow

```text
Security alert
    ↓
Find linked detection/event evidence
    ↓
Extract eligible public IP/domain
    ↓
Check PostgreSQL ti_results cache
    ↓
Cache hit? ── yes → reuse result
    │
    no
    ↓
Query provider
    ↓
Normalize provider result
    ↓
Persist ti_results
    ↓
Persist alert/event/result provenance
    ↓
Update provider-specific alert TI state
```

### TI database tables

- `ti_results`
  - provider result + cache record
  - unique by provider / indicator type / indicator value
  - includes verdict, lookup status, confidence, provider data, checked time and expiry

- `alert_ti_indicators`
  - links TI results back to alert/event evidence
  - preserves provenance

- `alert_ti_analysis_state`
  - provider-aware processing state
  - primary identity is alert + provider

## 6. Cache and failure behavior

Threat Intelligence cache is persistent in PostgreSQL, not Redis.

Normal successful results use a **24-hour TTL**.

Transient failures use a **5-minute TTL**.

Lookup status and verdict are intentionally separate:

- verdict: malicious / suspicious / benign / unknown
- lookup status: success / not_found / rate_limited / error

Provider failures do not become benign results and do not block the core ingestion/detection pipeline.

## 7. Validated TI behavior

Validated scenarios include:

- VirusTotal domain lookup from preserved Windows evidence
- VirusTotal public-IP lookup
- AbuseIPDB public-IP lookup
- provider-specific cache hits
- no repeat provider call on valid cache hit
- idempotent TI result/event/alert links
- provider-specific processing state
- retry behavior after transient provider failure
- real VirusTotal authentication failure handled as unknown/error
- real AbuseIPDB lookup persisted successfully
- historical alerts with no eligible IOCs processed without unnecessary provider requests

The last validated provider queues were:

```text
VirusTotal pending: 0
AbuseIPDB pending: 0
```

## 8. Runtime startup/shutdown

`Start-IntelSOC.ps1` now starts:

1. Docker Desktop if needed
2. PostgreSQL + Redis
3. FastAPI
4. event_worker
5. analysis_worker
6. **ti_worker**
7. Caddy
8. health/runtime checks

The startup script verifies that the TI worker remains alive after launch instead of reporting a false successful start.

`Stop-IntelSOC.ps1` now stops:

1. Caddy ingress
2. FastAPI
3. **ti_worker**
4. analysis_worker
5. event_worker
6. PostgreSQL + Redis

This avoids leaving the TI worker running after IntelSOC shutdown and stops infrastructure only after backend workers.

The TI worker loads the root project `.env` with override enabled so stale PowerShell provider-key variables do not silently supersede the project configuration.

## 9. Secrets

Required TI variables:

```text
VT_API_KEY
ABUSEIPDB_KEY
```

They belong only in the root `.env`, which is ignored by Git.

Never commit, paste, screenshot, log, or document actual provider keys.

## 10. Latest regression baseline

Latest validated local full backend result:

```text
533 passed
0 failed
1 known warning
```

Known warning:

```text
Starlette TestClient:
anyio.abc.BlockingPortal alias is deprecated
```

The warning is dependency-related and not a functional failure.

## 11. Pending TI validation

One final TI acceptance scenario remains useful:

**live endpoint-to-TI validation**

The target flow is:

```text
real endpoint activity
 → Fluent Bit
 → HTTPS ingestion
 → Redis
 → event_worker
 → PostgreSQL
 → analysis_worker
 → real detection/alert
 → ti_worker
 → evidence-backed public IOC
 → VirusTotal / AbuseIPDB
 → persisted TI enrichment
```

No alert or TI result should be inserted manually during this test.

Do not weaken IOC validation just to make this demonstration work.

## 12. Current scope boundary

Threat Intelligence currently enriches alerts only.

It does **not** automatically:

- change alert severity
- block an IP
- isolate an endpoint
- trigger destructive response actions

Those decisions belong to later correlation/risk-scoring and controlled-response layers.

## 13. Next project layers

After the live TI validation and TI freeze:

1. Transformer anomaly analysis / LAnoBERT integration
2. correlation and explainable risk scoring
3. dashboard/API presentation of rule + TI + AI evidence
4. controlled response workflow
5. reporting and final evaluation

Do not add extra TI providers unless they add a clear missing capability. OTX remains optional.
