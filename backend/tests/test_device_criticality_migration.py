from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "migrations" / "012_add_device_criticality.sql"


def migration_sql() -> str:
    return MIGRATION.read_text(encoding="utf-8")


def test_device_criticality_migration_is_additive():
    sql = migration_sql()

    assert "ALTER TABLE registered_devices" in sql
    assert "ADD COLUMN IF NOT EXISTS criticality" in sql
    assert "DROP COLUMN" not in sql
    assert "DROP TABLE" not in sql


def test_device_criticality_has_safe_default_and_allowed_values():
    sql = migration_sql()

    assert "DEFAULT 'medium'" in sql
    assert "'low'" in sql
    assert "'medium'" in sql
    assert "'high'" in sql
    assert "NOT NULL" in sql
