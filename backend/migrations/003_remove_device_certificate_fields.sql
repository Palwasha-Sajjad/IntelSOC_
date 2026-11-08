ALTER TABLE registered_devices
    DROP COLUMN IF EXISTS certificate_common_name,
    DROP COLUMN IF EXISTS certificate_fingerprint;
