# IntelSOC — Threat Intelligence Handoff

**Purpose:** Continue IntelSOC from the exact validated pre-TI state without repeating or disturbing completed Windows/Linux ingestion and detection work.

## 1. Current validated architecture

Current runtime path:

```text
Windows endpoints / Ubuntu-Debian endpoints
        ↓
Fluent Bit collectors
        ↓
Caddy HTTPS gateway (TLS)
        ↓
FastAPI ingestion API
        ↓
Redis Stream: intelsoc:events
        ↓
event_worker
        ↓
PostgreSQL
        ↓
analysis_worker
        ↓
Detections → Alerts → Incidents
        ↓
Threat Intelligence enrichment (NEXT)
```

Current validated technologies:

- **Backend:** Python + FastAPI + Uvicorn
- **Queue:** Redis 7, Redis Streams, append-only persistence, no-eviction policy
- **Database:** PostgreSQL 17
- **Collectors:** Fluent Bit
- **Linux audit source:** journald + auditd
- **Gateway/TLS:** Caddy
- **Runtime orchestration:** Docker Compose for PostgreSQL/Redis; PowerShell startup/shutdown scripts for the local IntelSOC services
- **Testing:** Pytest
- **DB access:** psycopg 3
- **Redis client:** redis-py

PostgreSQL/Redis are bound to localhost in the current single-host lab setup. FastAPI runs on localhost and Caddy exposes the authenticated HTTPS collector endpoint.

The earlier React/Vite dashboard is **not present in this validated repository checkpoint**, so it must not be treated as part of the currently verified runtime.

## 2. Ingestion status

### Windows

Windows collection is complete and working through the managed Fluent Bit service.

Collected sources include:

- Application
- System
- Selected Security events
- PowerShell Operational Event 4104

Security telemetry used by current rules includes Event IDs:

`4624, 4625, 4648, 4688, 4698, 4702, 4720, 4722, 4723, 4725, 4726, 4732, 4740, 1102`

The Windows deployment installer performs authenticated enrollment, TLS verification, persistent buffering/checkpoints, preserves the existing endpoint identity during migration, and sends to:

`POST /api/v1/events/windows`

### Linux

Linux collection is complete for the approved scope:

- SSH journald events
- sudo journald events
- auditd account/group events:
  - `ADD_USER`
  - `DEL_USER`
  - `USER_MGMT`
  - `ADD_GROUP`
  - `DEL_GROUP`
  - `GRP_MGMT`
- narrowly keyed identity-file `SYSCALL` evidence using `intelsoc_identity_change`

Linux sends to:

`POST /api/v1/events/linux`

Broad Linux `EXECVE` collection is intentionally **not enabled**.

Both platforms preserve the trusted `device_id` and original `raw_event` evidence.

## 3. Linux detection rules — frozen alignment

| Rule | Current state |
|---|---|
| **LIN-001 — SSH brute-force attempts** | Complete. Five failed SSH authentications within five minutes, grouped by compatible device/source/user evidence. IPv4/IPv6 supported; missing/invalid source IP is not used for brute-force correlation. |
| **LIN-002 — Failed SSH followed by successful authentication** | Complete. Requires five prior failures followed by a later successful SSH login within five minutes using compatible device/source/user context. |
| **LIN-003 — Sensitive account lifecycle** | Complete. Detects successful `ADD_USER`, `DEL_USER`, and supported non-group `USER_MGMT`. Group-oriented evidence is left to LIN-004. |
| **LIN-004 — Privileged group changes** | Complete. Alerts only for explicitly privileged groups; ordinary groups are benign. Current privileged allowlist: `root`, `sudo`, `wheel`, `adm`, `shadow`, `docker`, `lxd`. |
| **LIN-005 — Suspicious sudo activity** | Complete. Ordinary local successful sudo is benign. Evidence-backed remote sudo or explicit authorization/authentication failure can alert. |
| **LIN-006 — Suspicious command execution** | **Disabled by design.** Current Linux telemetry does not collect broad EXECVE/PROCTITLE/PATH context needed to reconstruct command execution reliably. The frozen plan requires this rule to remain disabled rather than broaden telemetry or implement a weak detector. |

Important LIN-006 detail: keyed identity-file `SYSCALL` records are still collected, but they are not treated as generic command-execution alerts.

## 4. Existing Windows detection capabilities

Current active Windows rules:

- **WIN-001:** repeated failed logins (4625; five in five minutes)
- **WIN-002:** Windows Security audit log cleared (1102)
- **WIN-003:** member added to local Administrators (4732, verified by Administrators SID)
- **WIN-004:** user account created/enabled (4720/4722)
- **WIN-005:** user account disabled/deleted (4725/4726)
- **WIN-006:** user account locked out (4740)
- **WIN-007:** user password-change attempt (4723)
- **WIN-008:** failed logins followed by a successful login (4625 → 4624 correlation)
- **WIN-009:** high-confidence suspicious scheduled-task command (4698/4702)
- **WIN-010:** high-confidence suspicious process creation (4688)
- **WIN-011:** suspicious PowerShell script block (4104), including multi-part reconstruction
- **WIN-012:** unusual explicit-credential use (4648) with conservative context checks

The detection engine is Python-based and intentionally reuses a shared pipeline:

```text
normalized stored event
  → rule evaluation
  → deterministic detection fingerprint
  → detection persistence
  → one alert per detection
  → incident correlation
  → per-rule processed/failed state
```

Replay/idempotency is enforced through deterministic fingerprints and database uniqueness constraints.

## 5. Latest stabilization fixes

The pre-TI stabilization pass intentionally did **not** change detection logic.

Fixes added:

1. **Platform-bound device ingestion**
   - A registered Windows device cannot use the Linux collector endpoint and vice versa.
   - Prevents cross-platform device identity misuse.

2. **Atomic batch queueing**
   - Validated Windows/Linux batches are queued in one Redis transaction.
   - Prevents a failed request from partially accepting only part of a batch.

3. **Heartbeat safety**
   - A failed queue operation does not update the endpoint `last_seen` timestamp.

4. **Bounded Redis waits**
   - Redis connect/socket waits are capped at 5 seconds.
   - Prevents unhealthy Redis connections from hanging ingestion/workers indefinitely.

5. **Linux API-key regression coverage**
   - Linux ingestion is explicitly included in shared API-key enforcement tests.

6. **Frozen Linux rule-ID invariant**
   - Tests lock active Linux IDs to LIN-001 through LIN-005 and confirm LIN-006 remains inactive.

Existing reliability already retained:

- PostgreSQL failure does not ACK the Redis event.
- Invalid events move to the DLQ.
- Rule failures are isolated by the dispatcher.
- Per-rule retry state is independent.
- Raw evidence and device identity are preserved.
- Duplicate detections/alerts/incident links are prevented by stable fingerprints/DB constraints.

## 6. Verified test evidence

Latest laptop validation on **10 November 2026**:

### Focused pre-TI stability suite

```text
90 passed
0 failed
1 warning
```

### Full backend regression

```text
449 passed
0 failed
1 warning
```

Only known warning:

```text
Starlette TestClient:
anyio.abc.BlockingPortal alias is deprecated
```

This is a dependency deprecation warning and did not fail the test suite.

## 7. Git state / checkpoint

Validated code branch:

`pre-ti-stabilization`

Validated stabilization checkpoint:

`5f5b468 — Validate IntelSOC pre-TI stability and ingestion hardening`

At the time of validation:

- branch was up to date with `origin/pre-ti-stabilization`
- working tree was clean
- no failed backend tests

This handoff document is added after that validated code checkpoint and does not change runtime code.

## 8. Known limitations / do not reopen unnecessarily

- **LIN-006 is disabled** because Linux command-execution telemetry is insufficient by design.
- Historical development DB rows may contain older Linux rule numbering from before the final alignment; active code is correctly aligned now.
- The current collector authentication model uses a shared ingestion key plus registered device ID. It is suitable for the current FYP/lab design but is not a production zero-trust endpoint identity system.
- The validated repository checkpoint does not include the React/Vite dashboard.
- Threat Intelligence is not integrated yet.
- Transformer/AI, risk scoring, response automation, reporting and dashboard work are later phases and should not be mixed into the TI implementation unless explicitly planned.
- Do not broaden Linux telemetry, rewrite working detection rules, introduce YAML migration, or change the architecture during TI integration unless a real blocker requires it.

## 9. Next phase — Threat Intelligence

Implement Threat Intelligence in this order:

1. **VirusTotal**
2. **AbuseIPDB**
3. **AlienVault OTX**

Recommended approach for the next conversation:

- inspect the current event/detection/alert schema before adding TI tables/services
- reuse the existing FastAPI/PostgreSQL/service structure
- detect supported indicators from stored evidence (IP/domain/hash only when genuinely present)
- keep external provider failures/timeouts non-blocking to ingestion and rule processing
- add provider-specific normalization into one common TI result shape
- add caching/rate-limit awareness before repeated provider calls
- store enough provider evidence for explainability without storing secrets
- use mocked/offline tests first; do not require live API keys for the backend regression suite
- keep all provider keys in environment variables only
- preserve current 449-test green baseline before adding TI

**Immediate starting point:** inspect the current database schema and service patterns, then design the smallest additive TI data model/service contract for VirusTotal without changing existing ingestion/detection behavior.
