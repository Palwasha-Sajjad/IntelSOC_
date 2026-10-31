
CREATE TABLE IF NOT EXISTS security_events (
    event_id UUID PRIMARY KEY,
    schema_version VARCHAR(20) NOT NULL,
    event_time TIMESTAMPTZ NOT NULL,
    source VARCHAR(100) NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    src_ip VARCHAR(45),
    message TEXT NOT NULL,
    raw_event JSONB NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_security_events_time
ON security_events (event_time);

CREATE INDEX IF NOT EXISTS idx_security_events_type
ON security_events (event_type);
