-- Add counter column to app_attest_keys table
-- This migration adds the missing counter column that is required for App Attestation

ALTER TABLE app_attest_keys ADD COLUMN counter INTEGER NOT NULL DEFAULT 0;
