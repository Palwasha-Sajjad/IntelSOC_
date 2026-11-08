ALTER TABLE security_events
    ADD COLUMN IF NOT EXISTS device_id UUID;

CREATE INDEX IF NOT EXISTS idx_security_events_device_id
ON security_events (device_id);
