CREATE TABLE IF NOT EXISTS incidents (
    incident_id UUID PRIMARY KEY,
    correlation_key VARCHAR(64) NOT NULL,
    title VARCHAR(255) NOT NULL,
    severity VARCHAR(20) NOT NULL
        CHECK (
            severity IN (
                'informational',
                'low',
                'medium',
                'high',
                'critical'
            )
        ),
    status VARCHAR(20) NOT NULL DEFAULT 'open'
        CHECK (
            status IN (
                'open',
                'investigating',
                'resolved',
                'false_positive'
            )
        ),
    device_id UUID,
    target_user VARCHAR(255),
    source_ip VARCHAR(45),
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    resolution_note TEXT
);

CREATE INDEX IF NOT EXISTS idx_incidents_correlation_key
ON incidents (correlation_key);

CREATE INDEX IF NOT EXISTS idx_incidents_status
ON incidents (status);

CREATE INDEX IF NOT EXISTS idx_incidents_last_seen_at
ON incidents (last_seen_at);


CREATE TABLE IF NOT EXISTS incident_alerts (
    incident_id UUID NOT NULL
        REFERENCES incidents(incident_id)
        ON DELETE CASCADE,
    alert_id UUID NOT NULL UNIQUE
        REFERENCES security_alerts(alert_id)
        ON DELETE CASCADE,
    linked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (incident_id, alert_id)
);

CREATE INDEX IF NOT EXISTS idx_incident_alerts_incident_id
ON incident_alerts (incident_id);


CREATE TABLE IF NOT EXISTS incident_history (
    history_id UUID PRIMARY KEY,
    incident_id UUID NOT NULL
        REFERENCES incidents(incident_id)
        ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,
    details TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incident_history_incident_id
ON incident_history (incident_id, created_at);
