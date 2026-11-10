# IntelSOC — Master FYP Development Roadmap (v1.0)

**Project:** IntelSOC — Smart Threat Intelligence and Response System  
**Scope:** One student, two 14-week semesters, 8 GB Windows laptop, free tools  
**Status date:** 11 November 2026  
**Rule:** Do not start the next module until its acceptance test passes and the current code is committed.

## The finished product

Collect real Windows/Linux/network logs; normalize and queue them; run YAML rules, threat-intelligence checks, and **mandatory DistilBERT-based semantic and behavioral anomaly analysis**; correlate alerts into incidents; explain risk; provide a React dashboard, analyst approvals, safe time-limited MikroTik IP blocks, notifications, evidence collection, and PDF reports. Endpoint account/host-firewall responses are optional lab-only extensions if time permits.

## Final architecture

```
Windows / Linux / lab syslog
           ↓
Fluent Bit → Authenticated FastAPI collector / normalizer
           ↓
Redis Streams → Python storage/analysis workers
           ↓
PostgreSQL (events, alerts, incidents, action ledger)
           ↓
YAML detection + threat intelligence + DistilBERT analysis
           ↓
Risk / correlation → React dashboard & approvals
           ↓
Response policy → MikroTik REST (temporary blocks)
           ↓
Verification, expiry/reversal, audit trail & PDF reports
```

## Semester 1 — Data collection, detection, and BERT foundation

| ID | Suggested weeks | Module | Build | Definition of done | Status |
|---|---|---|---|---|---|
| **1A** | W1 | Backend foundation | FastAPI, `/health`, Swagger, Pytest | Health API returns 200; tests pass | ✅ Done |
| **1B** | W2 | Local infrastructure | Docker PostgreSQL 17, Redis 7, FastAPI service-status API | Both services respond; API returns `ready`; failure case tested | ✅ Done |
| **1C** | W3 | Event queue & persistence | `/events`, Pydantic schema, Redis consumer, SQL storage, duplicate protection, DLQ | Event stored; same ID saved once; pending message recovered; malformed event quarantined; **12 tests pass** | ✅ Core done |
| **1D** | W4–5 | Windows log collector | Fluent Bit Windows collection, checkpoint DB, authenticated HTTPS ingestion, log-to-schema adapter | Actual Windows event records arrive in PostgreSQL with host, time, type, device identity and raw evidence | ✅ Done |
| **1E** | W6–7 | Linux log ingestion & normalization | Linux journald/auditd collection, authenticated HTTPS ingestion, normalization, bounded retry/buffering | Windows + Linux representative logs stored; malformed/duplicate/replayed entries handled | ✅ Approved Linux scope done |
| **2A** | W8–9 | Detection rules | Windows and Linux evidence-based detections with correlation and replay protection | Rules have positive/benign coverage; duplicate alerts prevented on replay | ✅ Current Windows/Linux rule scope done |
| **2B** | W10 | Alerts and incidents | Alert DB tables, event-to-alert links, correlation, lifecycle statuses | Detections create traceable alerts/incidents without duplicate records | ✅ Done |
| **3A** | W11–12 | BERT dataset & feasibility | Collect normal log sequences, label held-out lab scenarios, normalize dynamic tokens, run DistilBERT embeddings | 100 sample log messages encoded on available hardware; train/validation/test split documented | ☐ |
| **3B** | W13–14 | BERT semantic analysis | Security event semantic representations; label/similarity evaluation; small MLM adaptation if compute allows | Semantic predictions evaluated against manually labeled examples; baseline and errors reported | ☐ |

## Semester 2 — Behavioral AI, intelligence, responses, final product

| ID | Suggested weeks | Module | Build | Definition of done | Status |
|---|---|---|---|---|---|
| **3C** | W1–2 | BERT behavioral anomaly analysis | Group ordered events by host/user; embed 10–20-event sequences; fit anomaly scorer; separate inference worker | Holdout results include precision, recall, F1, false-positive rate, and inference latency; compare with non-BERT baseline | ☐ |
| **4A** | W3–4 | Threat intelligence & risk | VirusTotal + AbuseIPDB enrichment, persistent cache, provider state, later rule/TI/AI risk combination | TI mock/live provider tests pass and cache avoids repeat lookups; risk scoring remains separate | 🟡 TI complete; risk pending |
| **4B** | W5–6 | Web dashboard & login | React incident list, event timeline, BERT results, JWT and server-side analyst/admin RBAC | Analyst can view events; unauthorized user cannot approve actions; incident detail shows evidence | ☐ |
| **5A** | W7–9 | Safe MikroTik response engine | Dry-run, action queue, audit ledger, safety allowlist, human approvals, native TTL blocks, verification, circuit breaker | Isolated-lab block expires; management IP denied; timeout results in uncertain status and reconciliation | ☐ |
| **5B** | W10–11 | Multi-action response playbooks | Notifications, evidence bundle, incident escalation; optionally lab endpoint response agent for approval-only host firewall block or test-account disable/restore | Three safe playbook action types visible and audited; any endpoint action is reversible and test-only | ☐ |
| **6A** | W12 | Reports & hardening | ReportLab incident PDF; secrets/config review; bounded retries, DLQ operational checks | Downloadable incident PDF; no secrets committed; failed events visible for review | ☐ |
| **6B** | W13–14 | Final evaluation and viva | Integration demo, 1,000-event replay, measured throughput/latency, false positives and wrongful-block cases, deployment guide and dissertation | Repeatable Windows-log-to-incident demo, BERT evaluation, safe block/expiry demo, saved metrics and viva script | ☐ |

> **Timelines are planning allocations, not fixed calendar dates.** Weeks already used are marked completed by evidence from the development conversation, not by a formal academic schedule. Rebalance week allocations to the university calendar without changing module order.

## Required vs optional (scope lock)

**Must ship:** Windows + Linux collection, normalized event pipeline, 3 YAML detections, PostgreSQL incidents, DistilBERT semantic representations **and** behavioral sequence anomaly analysis, one TI provider, explainable risk score, React analyst dashboard, manual approval flow, isolated-lab MikroTik temporary blocking and automatic expiry, notifications/evidence/escalation, audit trail, ReportLab PDF, recorded tests/metrics.

**Only if core is stable:** Endpoint response agent (test account disable/re-enable and host-firewall block); extra router vendors; additional BI maps; advanced ML comparison.

**Do not build for this FYP:** Kafka, ClickHouse, multi-vendor SOAR, arbitrary SSH command execution, production high availability, destructive endpoint actions, blanket autonomous AI-only blocking.

## Safety and engineering rules

- Collection endpoints stay bound to localhost during initial testing; real collectors must authenticate before we permit broader access.
- Never commit `.env`, credentials, raw sensitive user logs, or model checkpoints. Keep sample logs sanitized.
- BERT is a **mandatory analytic component**, but **advisory only** for automated blocking. Compare its value with rules and simpler anomaly baselines.
- Restrict actual firewall actions to isolated lab networks and verified external IPs; protect management ranges and require expiry/rollback.
- Use database uniqueness for replay safety. Acknowledge Redis only after database commit or successful DLQ handling; revisit multi-worker recovery and uncertain Redis transactions before high-throughput tests.
- Every module needs an executable test or demonstrable artifact, not just UI screenshots.

## Current confirmed evidence and next action

- `pytest`: **12 passed, 1 Starlette dependency warning** (no failed tests).
- PostgreSQL/Redis connected from FastAPI and from Python script.
- Duplicate event persisted exactly once.
- Pending event successfully replayed after single-consumer worker restart.
- Malformed event stored in `intelsoc:events:dlq`; later valid event stored in PostgreSQL.
- **Confirmed Git commit:** `05e37ce` (`Initial IntelSOC backend and event ingestion pipeline`).
- **Unconfirmed:** follow-up worker/DLQ reliability Git commit. Check `git status`, stage only safe files, and commit before Module 1D.

**Next action:** `git status` and `docker compose ps` in IntelSOC root; then start **1D: Fluent Bit Windows event capture**.

## Completion tracking rule

Update the status column to `✅ Done` only after the module's definition of done is demonstrated, tests recorded, and Git commit created. Write failed tests and blockers directly beneath the relevant module; never silently skip an unfinished dependency.


## Current implementation checkpoint — 11 November 2026

The original roadmap above is retained as planning history, but the implemented backend has progressed beyond several earlier status markers.

Current verified state:

- Windows and approved Linux telemetry ingestion are operational.
- Current Windows detections: WIN-001 through WIN-012.
- Current Linux detections: LIN-001 through LIN-005; LIN-006 remains disabled by design.
- Alerts/incidents and replay/idempotency protections are implemented.
- Threat Intelligence is implemented with VirusTotal and AbuseIPDB.
- TI uses evidence-backed public indicators only and stores its persistent cache in PostgreSQL.
- TI processing is provider-aware, retryable and non-blocking to the core SOC pipeline.
- `Start-IntelSOC.ps1` / `Stop-IntelSOC.ps1` now manage the TI worker.
- Latest validated local regression: **533 passed, 0 failed, 1 known warning**.
- Final live endpoint → alert → TI enrichment acceptance testing is pending.
- AlienVault OTX remains optional.
- Transformer analysis, combined risk scoring, dashboard integration, response automation and reporting remain later work.

### Transformer note

The current practical prototype direction is **LAnoBERT-style log anomaly scoring on CPU**, rather than treating the earlier DistilBERT wording in this v1.0 roadmap as a locked implementation requirement. Final model evaluation should remain documented and evidence-based before the AI module is frozen.
