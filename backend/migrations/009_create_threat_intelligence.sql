CREATE TABLE IF NOT EXISTS ti_results (
    result_id UUID PRIMARY KEY,
    provider VARCHAR(50) NOT NULL
        CHECK (provider IN ('virustotal', 'abuseipdb', 'otx')),
    indicator_type VARCHAR(20) NOT NULL
        CHECK (indicator_type IN ('ip', 'domain')),
    indicator_value VARCHAR(253) NOT NULL,
    verdict VARCHAR(20) NOT NULL
        CHECK (
            verdict IN (
                'benign',
                'suspicious',
                'malicious',
                'unknown'
            )
        ),
    lookup_status VARCHAR(20) NOT NULL
        CHECK (
            lookup_status IN (
                'success',
                'not_found',
                'rate_limited',
                'error'
            )
        ),
    confidence SMALLINT
        CHECK (
            confidence IS NULL
            OR (confidence >= 0 AND confidence <= 100)
        ),
    provider_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    checked_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (provider, indicator_type, indicator_value)
);

CREATE INDEX IF NOT EXISTS idx_ti_results_expires_at
ON ti_results (expires_at);


CREATE TABLE IF NOT EXISTS alert_ti_indicators (
    alert_id UUID NOT NULL
        REFERENCES security_alerts(alert_id)
        ON DELETE CASCADE,
    event_id UUID NOT NULL
        REFERENCES security_events(event_id)
        ON DELETE CASCADE,
    result_id UUID NOT NULL
        REFERENCES ti_results(result_id)
        ON DELETE CASCADE,
    linked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (alert_id, event_id, result_id)
);

CREATE INDEX IF NOT EXISTS idx_alert_ti_indicators_alert_id
ON alert_ti_indicators (alert_id);

CREATE INDEX IF NOT EXISTS idx_alert_ti_indicators_result_id
ON alert_ti_indicators (result_id);


CREATE TABLE IF NOT EXISTS alert_ti_analysis_state (
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

CREATE INDEX IF NOT EXISTS idx_alert_ti_analysis_state_status
ON alert_ti_analysis_state (status);
