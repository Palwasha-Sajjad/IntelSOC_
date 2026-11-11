ALTER TABLE registered_devices
    ADD COLUMN IF NOT EXISTS criticality VARCHAR(10) NOT NULL DEFAULT 'medium'
        CHECK (criticality IN ('low', 'medium', 'high'));
