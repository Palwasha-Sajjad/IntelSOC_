import pytest


@pytest.fixture(autouse=True)
def configure_test_ingestion_key(monkeypatch):
    monkeypatch.setenv(
        "INTELSOC_INGEST_API_KEY",
        "intelsoc-test-only-key",
    )