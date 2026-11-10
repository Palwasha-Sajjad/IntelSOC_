ALTER TABLE alert_ti_analysis_state
ADD COLUMN IF NOT EXISTS provider VARCHAR(50);

UPDATE alert_ti_analysis_state
SET provider = 'virustotal'
WHERE provider IS NULL;

ALTER TABLE alert_ti_analysis_state
ALTER COLUMN provider SET NOT NULL;

ALTER TABLE alert_ti_analysis_state
DROP CONSTRAINT IF EXISTS alert_ti_analysis_state_provider_check;

ALTER TABLE alert_ti_analysis_state
ADD CONSTRAINT alert_ti_analysis_state_provider_check
CHECK (provider IN ('virustotal', 'abuseipdb', 'otx'));

ALTER TABLE alert_ti_analysis_state
DROP CONSTRAINT IF EXISTS alert_ti_analysis_state_pkey;

ALTER TABLE alert_ti_analysis_state
ADD PRIMARY KEY (alert_id, provider);

CREATE INDEX IF NOT EXISTS idx_alert_ti_analysis_state_provider_status
ON alert_ti_analysis_state (provider, status);
