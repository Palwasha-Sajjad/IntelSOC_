# IntelSOC - Module 1E: Linux Security Event Ingestion

## Status
Core implementation verified on November 4, 2026.

## Objective
Automatically collect real Ubuntu SSH security logs and securely
deliver them to IntelSOC for normalization, queueing, and storage.

## Architecture
Laptop B: Ubuntu Server 24.04
  -> systemd journal (ssh.service)
  -> Fluent Bit 5.1.5
  -> SSH reverse tunnel (127.0.0.1:18000)

Laptop A: Windows development system
  -> FastAPI POST /api/v1/events/linux
  -> Linux event normalizer
  -> Redis stream: intelsoc:events
  -> Event worker
  -> PostgreSQL: security_events

## Security Controls
- SSH public-key authentication.
- SSH password authentication disabled on Ubuntu.
- Encrypted reverse SSH tunnel.
- FastAPI bound to Laptop A loopback address.
- API key required for Linux ingestion.
- Fluent Bit credential file owned by root, permissions 600.
- Firewall SSH relay restricted to Laptop A.

## Verified Tests
1. Secure cross-device SSH connectivity: PASSED.
2. FastAPI tunnel connectivity, HTTP 200: PASSED.
3. Unauthorized event ingestion, HTTP 401: PASSED.
4. Linux authenticated ingestion, HTTP 202: PASSED.
5. Real SSH journal collection using Fluent Bit: PASSED.
6. Automatic Linux event storage in PostgreSQL: PASSED.
7. Fluent Bit starts as an enabled systemd service: PASSED.
8. Network interruption generated HTTP retry warnings: PASSED.
9. Delivery resumed after restoring SSH tunnel, HTTP 202: PASSED.
10. Linux PostgreSQL event count increased from 3 to 7: PASSED.
11. Backend regression tests: 24 passed, 1 dependency warning.

## Recovery and Operations
- Fluent Bit is enabled at Ubuntu startup.
- Laptop A must run FastAPI, Redis, PostgreSQL, and the event worker.
- The reverse SSH tunnel must currently be started manually on Laptop A.
- The router can change laptop IP addresses after reconnection.
- If IP addresses change, review the Windows SSH portproxy and firewall.
- Fluent Bit uses filesystem buffering and retry configuration.
- Successful delivery after one temporary tunnel interruption was tested.

## Scope and Limitations
- The Linux collector currently monitors ssh.service journal events.
- Automatic SSH tunnel startup has not been implemented.
- Full reboot recovery and extended outage durability are not yet verified.
- Other Linux security sources and advanced detections are future work.
- No API keys, passwords, or private keys are stored in this report.

## Additional Acceptance Evidence

Validation date: November 4, 2026.

### Linux Normalizer
- Identical replayed journal records produce the same event UUID.
- Four invalid records were rejected successfully.
- Result: LINUX_NORMALIZER_ACCEPTANCE_PASSED.

### End-to-End Duplicate Protection
- The same synthetic Linux SSH record was submitted twice.
- Both API requests returned HTTP 202.
- Deterministic event ID:
  e88112d0-ac86-5808-ae40-7936dad6a111
- PostgreSQL query returned exactly one matching row.
- Result: Database duplicate protection verified.

### Outstanding Roadmap Scope
- Linux journal collection is verified; a separate tail collector is not.
- Syslog/network ingestion has not been verified.
- The complete Windows event-count acceptance criterion remains pending.
- Extended outage limits and full reboot recovery remain unverified.

Module 1E status: Core verified; broader acceptance checks pending.