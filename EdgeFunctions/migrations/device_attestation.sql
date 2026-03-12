-- SecureAttest: Device Attestation Tables
--
-- Deploy this migration to your Supabase project.
-- These tables support App Attest challenge-response and device attestation.

-- Challenges for App Attest (ephemeral, single-use, short-lived)
CREATE TABLE IF NOT EXISTS device_attestation_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    challenge TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- Index for fast lookups by user + challenge
CREATE INDEX IF NOT EXISTS idx_dac_user_challenge
    ON device_attestation_challenges(user_id, challenge)
    WHERE consumed = FALSE;

-- Index for cleanup of expired challenges
CREATE INDEX IF NOT EXISTS idx_dac_expires
    ON device_attestation_challenges(expires_at)
    WHERE consumed = FALSE;

-- Attested device keys (long-lived, one per user per device)
CREATE TABLE IF NOT EXISTS device_attestations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    key_id TEXT NOT NULL,
    public_key TEXT NOT NULL,
    counter BIGINT DEFAULT 0,
    attested_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE(user_id, key_id)
);

-- Index for fast lookups by user
CREATE INDEX IF NOT EXISTS idx_da_user
    ON device_attestations(user_id);

-- RLS: Users can only read their own attestations (Edge Functions use service_role to write)
ALTER TABLE device_attestation_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_attestations ENABLE ROW LEVEL SECURITY;

-- Challenges: users can read their own (needed for debugging), service_role writes
CREATE POLICY "Users can read own challenges"
    ON device_attestation_challenges FOR SELECT
    USING (auth.uid() = user_id);

-- Attestations: users can read their own, service_role writes
CREATE POLICY "Users can read own attestations"
    ON device_attestations FOR SELECT
    USING (auth.uid() = user_id);

-- Optional: Cron job to clean up expired challenges (requires pg_cron on Supabase Pro)
-- SELECT cron.schedule(
--     'cleanup-expired-challenges',
--     '0 * * * *',  -- Every hour
--     $$DELETE FROM device_attestation_challenges WHERE expires_at < now() - interval '1 hour'$$
-- );
