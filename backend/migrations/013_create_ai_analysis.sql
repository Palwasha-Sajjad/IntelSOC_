-- LAnoBERT v0.2: advisory-only, event-level inference results.
-- This table is deliberately separate from alert_ai_evidence and risk scoring.
-- No existing tables, workers, or alert scores are modified.

CREATE TABLE IF NOT EXISTS event_ai_analysis (
    event_id UUID NOT NULL
        REFERENCES security_events(event_id) ON DELETE CASCADE,
    model_version VARCHAR(100) NOT NULL,
    status VARCHAR(20) NOT NULL
        CHECK (status IN ('processed', 'failed', 'skipped')),
    anomaly_score DOUBLE PRECISION,
    latency_ms DOUBLE PRECISION,
    attempts INTEGER NOT NULL DEFAULT 0
        CHECK (attempts >= 0),
    last_error TEXT,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    processed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (event_id, model_version),
    CONSTRAINT event_ai_score_finite_nonnegative CHECK (
        anomaly_score IS NULL OR (
            anomaly_score >= 0 AND anomaly_score < 'Infinity'::float8
        )
    ),
    CONSTRAINT event_ai_latency_finite_nonnegative CHECK (
        latency_ms IS NULL OR (
            latency_ms >= 0 AND latency_ms < 'Infinity'::float8
        )
    ),
    CONSTRAINT event_ai_processed_score_required CHECK (
        status <> 'processed' OR anomaly_score IS NOT NULL
    )
);

CREATE INDEX IF NOT EXISTS idx_event_ai_analysis_status
    ON event_ai_analysis (status, updated_at);
