CREATE TABLE IF NOT EXISTS registered_devices (
    device_id UUID PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL,
    platform VARCHAR(20) NOT NULL
        CHECK (platform IN ('windows', 'linux')),
    certificate_common_name VARCHAR(255) NOT NULL UNIQUE,
    certificate_fingerprint VARCHAR(128) UNIQUE,
    status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (
            status IN (
                'pending',
                'active',
                'disabled',
                'revoked'
            )
        ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_registered_devices_status
ON registered_devices (status);

CREATE INDEX IF NOT EXISTS idx_registered_devices_hostname
ON registered_devices (hostname);
