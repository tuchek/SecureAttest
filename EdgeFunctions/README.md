# SecureAttest Edge Functions

Deploy these to your Supabase project for server-side App Attest verification.

## Prerequisites

- Supabase project (Pro plan recommended for pg_cron cleanup)
- Apple Developer account with Team ID
- App bundle identifier

## Setup

### 1. Run the migration

```bash
# Via Supabase CLI
supabase db push < migrations/device_attestation.sql

# Or via SQL Editor in Supabase Dashboard
# Copy-paste the contents of migrations/device_attestation.sql
```

### 2. Set environment variables

In your Supabase Dashboard → Edge Functions → Secrets:

| Variable | Value | Example |
|----------|-------|---------|
| `APPLE_TEAM_ID` | Your Apple Developer Team ID | `5AW6XGHK6E` |
| `APPLE_BUNDLE_ID` | Your app's bundle identifier | `com.example.myapp` |
| `ENVIRONMENT` | `development` or `production` | `production` |

### 3. Deploy Edge Functions

```bash
# Copy functions to your Supabase project
cp -r challenge/ /path/to/your-project/supabase/functions/
cp -r attest-device/ /path/to/your-project/supabase/functions/
cp -r _shared/ /path/to/your-project/supabase/functions/

# Deploy
cd /path/to/your-project
supabase functions deploy challenge
supabase functions deploy attest-device
```

### 4. Add assertion verification to your existing Edge Functions

Import the shared utility in any Edge Function that needs assertion verification:

```typescript
import { verifyRequestAssertion } from "../_shared/assert.ts";

// In your Edge Function handler:
const assertionStatus = await verifyRequestAssertion(supabase, user.id, {
  assertion: body.assertion,
  challenge: body.challenge,
  payload: body.payload,
});

if (!assertionStatus.verified && assertionStatus.required) {
  // User has attested device but assertion failed — suspicious
  return new Response("Forbidden", { status: 403 });
}

if (!assertionStatus.required) {
  // User hasn't attested — device may not support App Attest
  // Continue but log for monitoring
}
```

## Architecture

```
Client (iOS)                          Server (Supabase)
─────────────                         ─────────────────
1. Sign in                     →
2. Request challenge           →      challenge/
3. Generate key (Secure Enclave)
4. Attest key with Apple
5. Send attestation + challenge →      attest-device/
                                       ├── Verify cert chain (Apple root)
                                       ├── Extract public key
                                       └── Store in device_attestations

--- Per sensitive request ---

6. Request challenge           →      challenge/
7. Sign payload (Secure Enclave)
8. Send assertion + challenge  →      your-function/
                                       └── _shared/assert.ts
                                           ├── Verify signature (stored key)
                                           ├── Check counter increment
                                           └── Consume challenge
```

## Tables

| Table | Purpose | Retention |
|-------|---------|-----------|
| `device_attestation_challenges` | One-time challenges (5 min TTL) | Auto-cleaned |
| `device_attestations` | Attested device public keys + counters | Permanent |
