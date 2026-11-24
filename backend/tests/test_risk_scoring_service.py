from uuid import uuid4

import pytest

from app.services.risk_scoring_service import (
    AiEvidence,
    RiskInputs,
    TiEvidence,
    apply_evidence_overrides,
    calculate_risk,
    classify_risk,
    score_rule_severity,
    score_threat_intelligence,
)


def ti(
    provider, verdict, confidence=90, lookup_status="success",
    indicator_value="8.8.8.8", provider_data=None,
):
    return TiEvidence(
        provider=provider,
        verdict=verdict,
        confidence=confidence,
        lookup_status=lookup_status,
        indicator_type="ip",
        indicator_value=indicator_value,
        provider_data=provider_data,
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


def test_malicious_ti_cannot_be_classified_normal():
    result = calculate_risk(
        RiskInputs(
            alert_id=uuid4(),
            severity="low",
            ti_evidence=(
                ti("virustotal", "malicious", confidence=70),
            ),
            lanobert_evidence=None,
        )
    )

    assert result.rule_score == 20
    assert result.ti_score == 20
    assert result.overall_score == 40
    assert result.classification == "suspicious"
    assert result.assessment_status == "provisional"


def test_high_rule_plus_malicious_ti_escalates_to_malicious():
    result = calculate_risk(
        RiskInputs(
            alert_id=uuid4(),
            severity="high",
            ti_evidence=(
                ti("virustotal", "malicious", confidence=70),
            ),
            lanobert_evidence=None,
        )
    )

    assert result.rule_score == 50
    assert result.ti_score == 20
    assert result.overall_score == 70
    assert result.classification == "malicious"


def test_evidence_override_does_not_downgrade_existing_classification():
    classification, reason = apply_evidence_overrides(
        base_classification="malicious",
        rule_score=20,
        ti_score=20,
    )

    assert classification == "malicious"
    assert reason is None


def test_override_reason_is_preserved_in_explainable_evidence():
    result = calculate_risk(
        RiskInputs(
            alert_id=uuid4(),
            severity="low",
            ti_evidence=(
                ti("virustotal", "malicious", confidence=70),
            ),
            lanobert_evidence=None,
        )
    )

    assert result.evidence["decision"] == {
        "base_classification": "normal",
        "final_classification": "suspicious",
        "override_applied": True,
        "override_reason": "malicious_ti_minimum_suspicious",
    }


def test_legacy_weak_malicious_verdict_is_not_strong_evidence():
    score, _ = score_threat_intelligence(
        (ti("virustotal", "malicious", confidence=1),)
    )
    assert score == 5


def test_historical_virustotal_stats_are_reclassified():
    score, _ = score_threat_intelligence((
        ti(
            "virustotal", "malicious", confidence=1,
            provider_data={
                "analysis_stats": {
                    "malicious": 1,
                    "harmless": 53,
                    "undetected": 40,
                }
            },
        ),
        ti("abuseipdb", "benign", confidence=0),
    ))
    assert score == 5


def test_different_indicators_cannot_corroborate():
    score, _ = score_threat_intelligence((
        ti("virustotal", "malicious", indicator_value="8.8.8.8"),
        ti("abuseipdb", "malicious", indicator_value="1.1.1.1"),
    ))
    assert score == 22


def test_weak_evidence_cannot_trigger_malicious_override():
    result = calculate_risk(RiskInputs(
        alert_id=uuid4(),
        severity="high",
        ti_evidence=(ti("virustotal", "malicious", confidence=1),),
        lanobert_evidence=None,
    ))
    assert result.ti_score == 5
    assert result.overall_score == 55
    assert result.classification == "suspicious"
    assert result.score_version == "1.2"


@pytest.mark.parametrize("address", ["127.0.0.1", "::1", "192.168.1.10"])
def test_nonpublic_indicators_do_not_contribute_to_risk(address):
    score, _ = score_threat_intelligence((
        ti("virustotal", "malicious", indicator_value=address),
    ))
    assert score == 0


def test_abuseipdb_zero_confidence_adds_no_risk():
    score, _ = score_threat_intelligence((
        ti("abuseipdb", "benign", confidence=0),
    ))
    assert score == 0


def test_weak_provider_cannot_inflate_strong_malicious_score():
    score, _ = score_threat_intelligence((
        ti("virustotal", "malicious", confidence=80),
        ti("abuseipdb", "suspicious", confidence=1),
    ))
    assert score == 22


def test_stronger_suspicious_providers_corroborate():
    score, _ = score_threat_intelligence((
        ti("virustotal", "suspicious", confidence=15),
        ti("abuseipdb", "suspicious", confidence=40),
    ))
    assert score == 15
