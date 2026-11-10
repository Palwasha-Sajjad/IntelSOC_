from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "migrations" / "009_create_threat_intelligence.sql"


def migration_sql() -> str:
    return MIGRATION.read_text(encoding="utf-8")


def test_ti_migration_creates_expected_tables():
    sql = migration_sql()

    assert "CREATE TABLE IF NOT EXISTS ti_results" in sql
    assert "CREATE TABLE IF NOT EXISTS alert_ti_indicators" in sql
    assert "CREATE TABLE IF NOT EXISTS alert_ti_analysis_state" in sql


def test_ti_results_lock_provider_indicator_and_cache_contract():
    sql = migration_sql()

    assert "provider IN ('virustotal', 'abuseipdb', 'otx')" in sql
    assert "indicator_type IN ('ip', 'domain')" in sql
    assert "UNIQUE (provider, indicator_type, indicator_value)" in sql
    assert "checked_at TIMESTAMPTZ NOT NULL" in sql
    assert "expires_at TIMESTAMPTZ NOT NULL" in sql
    assert "provider_data JSONB NOT NULL" in sql


def test_ti_results_separate_verdict_from_lookup_status():
    sql = migration_sql()

    assert "'benign'" in sql
    assert "'suspicious'" in sql
    assert "'malicious'" in sql
    assert "'unknown'" in sql

    assert "'success'" in sql
    assert "'not_found'" in sql
    assert "'rate_limited'" in sql
    assert "'error'" in sql


def test_alert_ti_indicators_preserve_alert_and_event_provenance():
    sql = migration_sql()

    assert "REFERENCES security_alerts(alert_id)" in sql
    assert "REFERENCES security_events(event_id)" in sql
    assert "REFERENCES ti_results(result_id)" in sql
    assert "PRIMARY KEY (alert_id, event_id, result_id)" in sql


def test_alert_ti_analysis_state_is_retryable_and_idempotent():
    sql = migration_sql()

    assert "alert_id UUID PRIMARY KEY" in sql
    assert "status IN ('pending', 'processed', 'failed')" in sql
    assert "attempts INTEGER NOT NULL DEFAULT 0" in sql
    assert "last_error TEXT" in sql
    assert "processed_at TIMESTAMPTZ" in sql


PROVIDER_STATE_MIGRATION = (
    ROOT / "migrations" / "010_make_ti_state_provider_aware.sql"
)


def test_provider_state_migration_preserves_existing_vt_state():
    sql = PROVIDER_STATE_MIGRATION.read_text(encoding="utf-8")

    assert "ADD COLUMN IF NOT EXISTS provider VARCHAR(50)" in sql
    assert "SET provider = 'virustotal'" in sql
    assert "ALTER COLUMN provider SET NOT NULL" in sql
    assert "provider IN ('virustotal', 'abuseipdb', 'otx')" in sql
    assert "ADD PRIMARY KEY (alert_id, provider)" in sql
