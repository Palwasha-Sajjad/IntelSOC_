# IntelSOC Risk Scoring Engine

## Purpose

The Risk Scoring Engine converts persisted IntelSOC security evidence into one
explainable 0-100 alert risk assessment.

It does not replace the existing Rule-Based Detection Engine, Threat
Intelligence module, incident correlation, or response logic.

## Evidence sources

Version 1.0 reserves the full 100-point range as:

- Rule-Based Detection: 0-60
- Threat Intelligence: 0-25
- LAnoBERT: 0-15

The Rule and TI components are active now. LAnoBERT is a confirmed architectural
source and already has a persistent evidence contract, but no model inference
code is included until the trained model is delivered.

## Classification bands

- 0-40: normal
- 41-70: suspicious
- 71-100: malicious

These are the existing IntelSOC risk bands.

## Rule contribution

Alert severity maps to:

- informational: 10
- low: 20
- medium: 35
- high: 50
- critical: 60

The scorer reads the severity already produced by the rule engine. It does not
change rule logic or alert severity.

## Threat Intelligence contribution

Only successfully persisted TI results are scored.

- suspicious evidence begins at 10
- corroborated suspicious evidence can reach 15
- malicious evidence begins at 20
- high-confidence or cross-provider malicious evidence can reach 25

Duplicate results from one provider cannot exceed the provider/corroboration
caps. Failed or rate-limited lookups never count as benign evidence.

The risk worker waits until both currently active TI providers, VirusTotal and
AbuseIPDB, have completed successfully for an alert. TI failures remain the TI
worker's retry responsibility.

## LAnoBERT contract

The table alert_ai_evidence is the integration boundary for the trained model.

The future LAnoBERT adapter will persist:

- model_name
- model_version
- raw anomaly_score
- selected threshold
- bounded risk_score from 0-15
- normal/anomalous verdict
- audit details
- analysis timestamp

The Risk Scoring Engine does not assume the raw LAnoBERT score scale. This keeps
the scoring engine stable when the final trained checkpoint and threshold are
delivered.

Before LAnoBERT evidence exists, assessments are marked provisional. LAnoBERT
absence is not interpreted as normal evidence and does not raise an error.

When LAnoBERT evidence is added or updated, the risk worker automatically
rescans the alert. The resulting assessment is marked complete.

## Persistence

alert_risk_assessments stores:

- rule_score
- ti_score
- lanobert_score
- overall_score
- classification
- assessment_status
- explainable JSON evidence
- score_version
- assessment timestamps

alert_risk_analysis_state provides retry-safe processing state.

## Runtime order

The existing pipeline remains:

security event
-> rule detection
-> alert
-> incident correlation
-> TI enrichment
-> risk scoring

The risk worker is independent. It reads persisted evidence and writes only its
own risk tables.

## Safety properties

- existing rule and TI services are not mutated by the scorer
- TI failures cannot silently become benign risk evidence
- risk writes are idempotent upserts per alert
- retries are persisted
- LAnoBERT absence is explicit and provisional
- future LAnoBERT evidence triggers automatic rescoring
- startup fails fast if migration 011 has not been applied
