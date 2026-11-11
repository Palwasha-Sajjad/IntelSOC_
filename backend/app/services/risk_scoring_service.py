import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID

import psycopg
from dotenv import load_dotenv

from app.core.config import get_postgres_config


ROOT = Path(__file__).resolve().parents[3]
load_dotenv(ROOT / ".env")


RULE_SCORES = {
    "informational": 10,
    "low": 20,
    "medium": 35,
    "high": 50,
    "critical": 60,
}

MAX_RULE_SCORE = 60
MAX_TI_SCORE = 25
MAX_LANOBERT_SCORE = 15
SCORE_VERSION = "1.1"


@dataclass(frozen=True)
class TiEvidence:
    provider: str
    verdict: str
    confidence: int | None
    lookup_status: str


@dataclass(frozen=True)
class AiEvidence:
    model_name: str
    model_version: str | None
    anomaly_score: float
    threshold: float
    risk_score: int
    verdict: str


@dataclass(frozen=True)
class RiskInputs:
    alert_id: UUID
    severity: str
    ti_evidence: tuple[TiEvidence, ...]
    lanobert_evidence: AiEvidence | None


@dataclass(frozen=True)
class RiskAssessment:
    alert_id: UUID
    rule_score: int
    ti_score: int
    lanobert_score: int
    overall_score: int
    classification: str
    assessment_status: str
    evidence: dict[str, Any]
    score_version: str = SCORE_VERSION


def classify_risk(score: int) -> str:
    """Apply the frozen IntelSOC 0-100 risk bands."""
    if not 0 <= score <= 100:
        raise ValueError("risk score must be between 0 and 100")
    if score <= 40:
        return "normal"
    if score <= 70:
        return "suspicious"
    return "malicious"


def apply_evidence_overrides(
    *,
    base_classification: str,
    rule_score: int,
    ti_score: int,
) -> str:
    """Prevent strong malicious TI evidence from being labeled normal.

    The numeric score remains unchanged for explainability. These are
    classification guardrails only.
    """
    if rule_score >= 50 and ti_score >= 20:
        return "malicious"

    if ti_score >= 20 and base_classification == "normal":
        return "suspicious"

    return base_classification


def score_rule_severity(severity: str) -> int:
    value = str(severity or "").strip().lower()
    try:
        return RULE_SCORES[value]
    except KeyError as error:
        raise ValueError("unsupported alert severity") from error


def score_threat_intelligence(
    evidence: tuple[TiEvidence, ...],
) -> tuple[int, dict[str, Any]]:
    """Convert persisted TI verdicts into one bounded 0-25 contribution.

    Failed/rate-limited lookups never count as benign evidence. Multiple
    providers can strengthen confidence, but duplicate indicator rows from the
    same provider cannot push the score past the provider/corroboration caps.
    """

    successful = [
        item
        for item in evidence
        if item.lookup_status == "success"
    ]

    provider_best: dict[str, tuple[str, int | None]] = {}
    rank = {"unknown": 0, "benign": 1, "suspicious": 2, "malicious": 3}

    for item in successful:
        current = provider_best.get(item.provider)
        if current is None or rank.get(item.verdict, 0) > rank.get(current[0], 0):
            provider_best[item.provider] = (item.verdict, item.confidence)

    malicious_providers = [
        provider
        for provider, (verdict, _) in provider_best.items()
        if verdict == "malicious"
    ]
    suspicious_providers = [
        provider
        for provider, (verdict, _) in provider_best.items()
        if verdict == "suspicious"
    ]

    score = 0

    if malicious_providers:
        score = 20
        if len(malicious_providers) >= 2:
            score = 25
        elif suspicious_providers:
            score = 23
        else:
            confidences = [
                confidence
                for _, (verdict, confidence) in provider_best.items()
                if verdict == "malicious" and confidence is not None
            ]
            if confidences and max(confidences) >= 80:
                score = 22

    elif suspicious_providers:
        score = 10
        if len(suspicious_providers) >= 2:
            score = 15
        else:
            confidences = [
                confidence
                for _, (verdict, confidence) in provider_best.items()
                if verdict == "suspicious" and confidence is not None
            ]
            if confidences and max(confidences) >= 80:
                score = 13

    return min(score, MAX_TI_SCORE), {
        "providers": {
            provider: {
                "verdict": verdict,
                "confidence": confidence,
            }
            for provider, (verdict, confidence) in sorted(provider_best.items())
        },
        "successful_results": len(successful),
        "total_linked_results": len(evidence),
    }


def calculate_risk(inputs: RiskInputs) -> RiskAssessment:
    rule_score = score_rule_severity(inputs.severity)
    ti_score, ti_details = score_threat_intelligence(inputs.ti_evidence)

    if inputs.lanobert_evidence is None:
        lanobert_score = 0
        lanobert_details: dict[str, Any] = {
            "status": "awaiting_model",
            "available": False,
        }
    else:
        lanobert_score = int(inputs.lanobert_evidence.risk_score)
        if not 0 <= lanobert_score <= MAX_LANOBERT_SCORE:
            raise ValueError("LAnoBERT risk contribution must be between 0 and 15")
        lanobert_details = {
            "status": "available",
            "available": True,
            "model_name": inputs.lanobert_evidence.model_name,
            "model_version": inputs.lanobert_evidence.model_version,
            "anomaly_score": inputs.lanobert_evidence.anomaly_score,
            "threshold": inputs.lanobert_evidence.threshold,
            "verdict": inputs.lanobert_evidence.verdict,
        }

    overall = min(
        100,
        rule_score + ti_score + lanobert_score,
    )

    evidence = {
        "rule": {
            "available": True,
            "severity": inputs.severity,
            "score": rule_score,
            "max_score": MAX_RULE_SCORE,
        },
        "threat_intelligence": {
            "available": bool(inputs.ti_evidence),
            "score": ti_score,
            "max_score": MAX_TI_SCORE,
            **ti_details,
        },
        "lanobert": {
            "score": lanobert_score,
            "max_score": MAX_LANOBERT_SCORE,
            **lanobert_details,
        },
        "completeness": {
            "rule": True,
            "threat_intelligence": True,
            "lanobert": inputs.lanobert_evidence is not None,
        },
    }

    base_classification = classify_risk(overall)
    classification = apply_evidence_overrides(
        base_classification=base_classification,
        rule_score=rule_score,
        ti_score=ti_score,
    )

    return RiskAssessment(
        alert_id=inputs.alert_id,
        rule_score=rule_score,
        ti_score=ti_score,
        lanobert_score=lanobert_score,
        overall_score=overall,
        classification=classification,
        assessment_status=(
            "complete"
            if inputs.lanobert_evidence is not None
            else "provisional"
        ),
        evidence=evidence,
    )


def load_risk_inputs(alert_id: UUID | str) -> RiskInputs:
    """Read only persisted rule, TI and future LAnoBERT evidence."""
    alert_id = UUID(str(alert_id))

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT severity
                FROM security_alerts
                WHERE alert_id = %s
                """,
                (alert_id,),
            )
            row = cursor.fetchone()
            if row is None:
                raise ValueError("Alert does not exist")

            severity = row[0]

            cursor.execute(
                """
                SELECT provider, status
                FROM alert_ti_analysis_state
                WHERE alert_id = %s
                  AND provider IN ('virustotal', 'abuseipdb')
                """,
                (alert_id,),
            )
            ti_states = {
                provider: status
                for provider, status in cursor.fetchall()
            }
            required_states = {
                "virustotal": "processed",
                "abuseipdb": "processed",
            }
            if ti_states != required_states:
                raise RuntimeError(
                    "Threat Intelligence is not complete for this alert"
                )

            cursor.execute(
                """
                SELECT DISTINCT
                    r.provider,
                    r.verdict,
                    r.confidence,
                    r.lookup_status
                FROM alert_ti_indicators AS ati
                JOIN ti_results AS r
                  ON r.result_id = ati.result_id
                WHERE ati.alert_id = %s
                ORDER BY r.provider, r.verdict
                """,
                (alert_id,),
            )
            ti_rows = cursor.fetchall()

            cursor.execute(
                """
                SELECT
                    model_name,
                    model_version,
                    anomaly_score,
                    threshold,
                    risk_score,
                    verdict
                FROM alert_ai_evidence
                WHERE alert_id = %s
                """,
                (alert_id,),
            )
            ai_row = cursor.fetchone()

    ai_evidence = None
    if ai_row is not None:
        ai_evidence = AiEvidence(
            model_name=ai_row[0],
            model_version=ai_row[1],
            anomaly_score=float(ai_row[2]),
            threshold=float(ai_row[3]),
            risk_score=int(ai_row[4]),
            verdict=ai_row[5],
        )

    return RiskInputs(
        alert_id=alert_id,
        severity=severity,
        ti_evidence=tuple(
            TiEvidence(
                provider=row[0],
                verdict=row[1],
                confidence=row[2],
                lookup_status=row[3],
            )
            for row in ti_rows
        ),
        lanobert_evidence=ai_evidence,
    )


def persist_risk_assessment(
    assessment: RiskAssessment,
) -> None:
    """Upsert one explainable assessment without mutating the source evidence."""
    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO alert_risk_assessments (
                    alert_id,
                    rule_score,
                    ti_score,
                    lanobert_score,
                    overall_score,
                    classification,
                    assessment_status,
                    evidence,
                    score_version,
                    assessed_at,
                    updated_at
                )
                VALUES (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s::jsonb, %s, NOW(), NOW()
                )
                ON CONFLICT (alert_id)
                DO UPDATE SET
                    rule_score = EXCLUDED.rule_score,
                    ti_score = EXCLUDED.ti_score,
                    lanobert_score = EXCLUDED.lanobert_score,
                    overall_score = EXCLUDED.overall_score,
                    classification = EXCLUDED.classification,
                    assessment_status = EXCLUDED.assessment_status,
                    evidence = EXCLUDED.evidence,
                    score_version = EXCLUDED.score_version,
                    assessed_at = NOW(),
                    updated_at = NOW()
                """,
                (
                    assessment.alert_id,
                    assessment.rule_score,
                    assessment.ti_score,
                    assessment.lanobert_score,
                    assessment.overall_score,
                    assessment.classification,
                    assessment.assessment_status,
                    json.dumps(assessment.evidence),
                    assessment.score_version,
                ),
            )


def assess_alert_risk(alert_id: UUID | str) -> RiskAssessment:
    inputs = load_risk_inputs(alert_id)
    assessment = calculate_risk(inputs)
    persist_risk_assessment(assessment)
    return assessment
