from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "migrations" / "011_create_risk_scoring.sql"


def migration_sql() -> str:
    return MIGRATION.read_text(encoding="utf-8")


def test_risk_migration_creates_expected_tables():
    sql = migration_sql()

    assert "CREATE TABLE IF NOT EXISTS alert_ai_evidence" in sql
    assert "CREATE TABLE IF NOT EXISTS alert_risk_assessments" in sql
    assert "CREATE TABLE IF NOT EXISTS alert_risk_analysis_state" in sql


def test_risk_assessment_preserves_frozen_contract():
    sql = migration_sql()

    assert "rule_score SMALLINT NOT NULL" in sql
    assert "ti_score SMALLINT NOT NULL" in sql
    assert "lanobert_score SMALLINT NOT NULL" in sql
    assert "overall_score SMALLINT NOT NULL" in sql
    assert "overall_score >= 0 AND overall_score <= 100" in sql
    assert "'normal'" in sql
    assert "'suspicious'" in sql
    assert "'malicious'" in sql
    assert "'provisional'" in sql
    assert "'complete'" in sql
    assert "evidence JSONB NOT NULL" in sql


def test_ai_evidence_contract_is_ready_for_lanobert():
    sql = migration_sql()

    assert "anomaly_score DOUBLE PRECISION NOT NULL" in sql
    assert "threshold DOUBLE PRECISION NOT NULL" in sql
    assert "risk_score >= 0 AND risk_score <= 15" in sql
    assert "verdict IN ('normal', 'anomalous')" in sql
    assert "details JSONB NOT NULL" in sql
