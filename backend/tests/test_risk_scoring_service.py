from uuid import uuid4

import pytest

from app.services.risk_scoring_service import (
    AiEvidence,
    RiskInputs,
    TiEvidence,
    calculate_risk,
    classify_risk,
    score_rule_severity,
    score_threat_intelligence,
)


def ti(provider, verdict, confidence=90, lookup_status="success"):
    return TiEvidence(
        provider=provider,
        verdict=verdict,
        confidence=confidence,
        lookup_status=lookup_status,
    )


def test_frozen_risk_bands():
    assert classify_risk(0) == "normal"
    assert classify_risk(40) == "normal"
    assert classify_risk(41) == "suspicious"
    assert classify_risk(70) == "suspicious"
    assert classify_risk(71) == "malicious"
    assert classify_risk(100) == "malicious"


@pytest.mark.parametrize(
    ("severity", "score"),
    [
        ("informational", 10),
        ("low", 20),
        ("medium", 35),
        ("high", 50),
        ("critical", 60),
    ],
)
def test_rule_score_mapping(severity, score):
    assert score_rule_severity(severity) == score


def test_two_malicious_ti_providers_reach_ti_cap():
    score, details = score_threat_intelligence(
        (
            ti("virustotal", "malicious"),
            ti("abuseipdb", "malicious"),
        )
    )

    assert score == 25
    assert set(details["providers"]) == {"virustotal", "abuseipdb"}


def test_failed_ti_lookup_does_not_count_as_benign_or_risk():
    score, details = score_threat_intelligence(
        (
            ti(
                "virustotal",
                "malicious",
                lookup_status="error",
            ),
        )
    )

    assert score == 0
    assert details["successful_results"] == 0


def test_duplicate_rows_from_one_provider_cannot_exceed_provider_cap():
    score, _ = score_threat_intelligence(
        (
            ti("virustotal", "malicious"),
            ti("virustotal", "malicious"),
            ti("virustotal", "suspicious"),
        )
    )

    assert score <= 22


def test_rule_and_ti_score_without_lanobert_is_provisional():
    result = calculate_risk(
        RiskInputs(
            alert_id=uuid4(),
            severity="high",
            ti_evidence=(
                ti("virustotal", "malicious"),
                ti("abuseipdb", "malicious"),
            ),
            lanobert_evidence=None,
        )
    )

    assert result.rule_score == 50
    assert result.ti_score == 25
    assert result.lanobert_score == 0
    assert result.overall_score == 75
    assert result.classification == "malicious"
    assert result.assessment_status == "provisional"
    assert result.evidence["lanobert"]["status"] == "awaiting_model"


def test_lanobert_plugs_into_same_contract_and_completes_assessment():
    result = calculate_risk(
        RiskInputs(
            alert_id=uuid4(),
            severity="medium",
            ti_evidence=(),
            lanobert_evidence=AiEvidence(
                model_name="LAnoBERT",
                model_version="intelsoc-v1",
                anomaly_score=0.82,
                threshold=0.70,
                risk_score=15,
                verdict="anomalous",
            ),
        )
    )

    assert result.rule_score == 35
    assert result.ti_score == 0
    assert result.lanobert_score == 15
    assert result.overall_score == 50
    assert result.classification == "suspicious"
    assert result.assessment_status == "complete"


def test_lanobert_contribution_is_bounded():
    with pytest.raises(ValueError, match="between 0 and 15"):
        calculate_risk(
            RiskInputs(
                alert_id=uuid4(),
                severity="medium",
                ti_evidence=(),
                lanobert_evidence=AiEvidence(
                    model_name="LAnoBERT",
                    model_version=None,
                    anomaly_score=1.0,
                    threshold=0.7,
                    risk_score=16,
                    verdict="anomalous",
                ),
            )
        )
