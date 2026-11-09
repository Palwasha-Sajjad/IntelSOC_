CREATE TABLE IF NOT EXISTS event_analysis_state (
    event_id UUID PRIMARY KEY
        REFERENCES security_events(event_id)
        ON DELETE CASCADE,
    status VARCHAR(20) NOT NULL
        CHECK (status IN ('pending', 'processed', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 0
        CHECK (attempts >= 0),
    last_error TEXT,
    processed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_event_analysis_state_status
ON event_analysis_state (status);


CREATE TABLE IF NOT EXISTS detections (
    detection_id UUID PRIMARY KEY,
    rule_id VARCHAR(100) NOT NULL,
    rule_name VARCHAR(255) NOT NULL,
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
    device_id UUID,
    target_user VARCHAR(255),
    source_ip VARCHAR(45),
    logon_type INTEGER,
    grouping_basis VARCHAR(100) NOT NULL,
    fingerprint VARCHAR(64) NOT NULL UNIQUE,
    event_count INTEGER NOT NULL
        CHECK (event_count > 0),
    window_start TIMESTAMPTZ NOT NULL,
    window_end TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_detections_rule_id
ON detections (rule_id);

CREATE INDEX IF NOT EXISTS idx_detections_device_id
ON detections (device_id);

CREATE INDEX IF NOT EXISTS idx_detections_created_at
ON detections (created_at);


CREATE TABLE IF NOT EXISTS detection_events (
    detection_id UUID NOT NULL
        REFERENCES detections(detection_id)
        ON DELETE CASCADE,
    event_id UUID NOT NULL
        REFERENCES security_events(event_id)
        ON DELETE CASCADE,
    PRIMARY KEY (detection_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_detection_events_event_id
ON detection_events (event_id);
