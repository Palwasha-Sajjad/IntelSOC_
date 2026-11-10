# IntelSOC Linux Detection Rules — Frozen Plan Alignment

Status: implementation alignment branch

## Active rules

| Rule | Contract | Implementation status |
|---|---|---|
| LIN-001 | SSH brute-force attempts | Complete and preserved |
| LIN-002 | Failed SSH followed by successful authentication | Complete and preserved |
| LIN-003 | Sensitive account lifecycle | Active: ADD_USER, DEL_USER, and supported non-group USER_MGMT |
| LIN-004 | Privileged group changes | Active: only explicitly privileged groups; ordinary groups are benign |
| LIN-005 | Suspicious sudo activity | Active; existing proven sudo detector renumbered from LIN-003 |
| LIN-006 | Suspicious command execution | Disabled by design: telemetry gap |

## LIN-003 — Sensitive account lifecycle

LIN-003 reuses the existing Linux audit ingestion and the existing detection,
alert, incident and per-rule state services.

It accepts successful account lifecycle evidence from:
- ADD_USER
- DEL_USER
- USER_MGMT only when the record is not clearly a group-membership operation

It does not invent actor, account or group fields that are absent from the audit
record. Group-oriented USER_MGMT evidence is left to LIN-004.

The targeted audit key `intelsoc_identity_change` remains collected. A generic
keyed SYSCALL is not treated as a standalone account alert because the current
collector filters out the associated PATH record. Without that PATH/account
context, promoting every keyed SYSCALL would create noisy, ambiguous alerts.

## LIN-004 — Privileged group changes

LIN-004 evaluates successful group-management records and alerts only when the
group identity is explicit and belongs to the privileged allowlist.

Current high-confidence privileged groups:
- root
- sudo
- wheel
- adm
- shadow
- docker
- lxd

Ordinary groups such as developers, students, project groups, and test groups
are intentionally processed as benign and do not generate detections.

The affected account is retained in the normal detection target field when it
is present. Device identity and the complete original audit record remain in
security_events/detection_events evidence.

## LIN-005 — Suspicious sudo activity

The previously validated sudo implementation is preserved. Only the rule
number changes to match the frozen plan.

Ordinary local successful sudo remains benign. Evidence-backed remote sudo or
explicit authorization/authentication failures remain detectable.

## LIN-006 — Suspicious command execution

LIN-006 is intentionally disabled.

Reason: the approved Linux collector does not enable broad EXECVE collection.
It currently sends narrowly approved account/group records and keyed
identity-file SYSCALL records. That is insufficient to reliably reconstruct a
general command execution with command arguments, cwd/path context, and
multi-record audit correlation.

The frozen plan explicitly requires LIN-006 to remain disabled when execution
telemetry is insufficient rather than broadening collection or implementing a
low-confidence rule.

## Historical development data

Earlier lab detections may retain the pre-alignment rule numbering in the
development database. This alignment changes active code and future rule state;
it does not destructively rewrite historical detection rows or fingerprints.
A clean acceptance dataset can be used for the final cross-rule reliability
pass.

## Next gate

After focused and full backend regression tests pass, create the alignment Git
checkpoint and proceed to the cross-rule reliability pass. No new telemetry,
AI/TI work, YAML conversion, or architecture change is part of this alignment.
