CREATE TABLE IF NOT EXISTS alert_ai_evidence (
    alert_id UUID PRIMARY KEY
        REFERENCES security_alerts(alert_id)
        ON DELETE CASCADE,
    model_name VARCHAR(100) NOT NULL,
    model_version VARCHAR(100),
    anomaly_score DOUBLE PRECISION NOT NULL,
    threshold DOUBLE PRECISION NOT NULL,
    risk_score SMALLINT NOT NULL
        CHECK (risk_score >= 0 AND risk_score <= 15),
    verdict VARCHAR(20) NOT NULL
        CHECK (verdict IN ('normal', 'anomalous')),
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    analyzed_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alert_ai_evidence_updated_at
ON alert_ai_evidence (updated_at);


CREATE TABLE IF NOT EXISTS alert_risk_assessments (
    alert_id UUID PRIMARY KEY
        REFERENCES security_alerts(alert_id)
        ON DELETE CASCADE,
    rule_score SMALLINT NOT NULL
        CHECK (rule_score >= 0 AND rule_score <= 60),
    ti_score SMALLINT NOT NULL
        CHECK (ti_score >= 0 AND ti_score <= 25),
    lanobert_score SMALLINT NOT NULL
        CHECK (lanobert_score >= 0 AND lanobert_score <= 15),
    overall_score SMALLINT NOT NULL
        CHECK (overall_score >= 0 AND overall_score <= 100),
    classification VARCHAR(20) NOT NULL
        CHECK (
            classification IN (
                'normal',
                'suspicious',
                'malicious'
            )
        ),
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    score_version VARCHAR(20) NOT NULL DEFAULT '1.0',
    assessed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alert_risk_assessments_score
ON alert_risk_assessments (overall_score DESC);

CREATE INDEX IF NOT EXISTS idx_alert_risk_assessments_classification
ON alert_risk_assessments (classification);


CREATE TABLE IF NOT EXISTS alert_risk_analysis_state (
    alert_id UUID PRIMARY KEY
        REFERENCES security_alerts(alert_id)
        ON DELETE CASCADE,
    status VARCHAR(20) NOT NULL
        CHECK (status IN ('pending', 'processed', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 0
        CHECK (attempts >= 0),
    last_error TEXT,
    processed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alert_risk_analysis_state_status
ON alert_risk_analysis_state (status, updated_at);
