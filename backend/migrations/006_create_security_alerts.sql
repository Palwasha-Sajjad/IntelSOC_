CREATE TABLE IF NOT EXISTS security_alerts (
    alert_id UUID PRIMARY KEY,
    detection_id UUID NOT NULL UNIQUE
        REFERENCES detections(detection_id)
        ON DELETE CASCADE,
    rule_id VARCHAR(100) NOT NULL,
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
                'acknowledged',
                'resolved',
                'false_positive'
            )
        ),
    device_id UUID,
    target_user VARCHAR(255),
    source_ip VARCHAR(45),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    resolution_note TEXT
);

CREATE INDEX IF NOT EXISTS idx_security_alerts_status
ON security_alerts (status);

CREATE INDEX IF NOT EXISTS idx_security_alerts_severity
ON security_alerts (severity);

CREATE INDEX IF NOT EXISTS idx_security_alerts_created_at
ON security_alerts (created_at);

CREATE INDEX IF NOT EXISTS idx_security_alerts_device_id
ON security_alerts (device_id);
