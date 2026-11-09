-- Independent completion state for every detection rule.
-- Existing WIN-001 results are carried forward without replaying old alerts.
CREATE TABLE IF NOT EXISTS event_rule_analysis_state (
    event_id UUID NOT NULL REFERENCES security_events(event_id) ON DELETE CASCADE,
    rule_id VARCHAR(100) NOT NULL,
    status VARCHAR(20) NOT NULL CHECK (status IN ('pending','processed','failed')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error TEXT,
    processed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (event_id, rule_id)
);

CREATE INDEX IF NOT EXISTS idx_event_rule_analysis_state_rule_status
ON event_rule_analysis_state (rule_id, status);

-- Migration is repeatable. Respect any existing per-rule state.
INSERT INTO event_rule_analysis_state (
    event_id, rule_id, status, attempts, last_error, processed_at, updated_at
)
SELECT s.event_id, 'RULE-WIN-001', s.status, s.attempts,
       s.last_error, s.processed_at, s.updated_at
FROM event_analysis_state AS s
JOIN security_events AS e ON e.event_id = s.event_id
WHERE e.source = 'windows_eventlog'
  AND e.raw_event->>'EventID' = '4625'
ON CONFLICT (event_id, rule_id) DO NOTHING;
