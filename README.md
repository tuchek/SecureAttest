# SecureAttest

A plug-and-play iOS security SDK that combines local device integrity checks with Apple App Attest for comprehensive device verification. Ships with Supabase Edge Functions for server-side attestation.

## Features

**Layer 1 — Local Device Integrity** (via [IOSSecuritySuite](https://github.com/securing/IOSSecuritySuite))
- Jailbreak detection (Cydia, Sileo, Zebra, checkra1n, unc0ver, rootless)
- Debugger attachment detection + active denial
- Reverse engineering tool detection (Frida, Cycript, MobileSubstrate)
- Emulator detection
- Runtime hook detection
- Network proxy/VPN detection

**Layer 2 — Apple App Attest** (via [DCAppAttestService](https://developer.apple.com/documentation/devicecheck/dcappattestservice))
- Secure Enclave key pair generation
- Cryptographic attestation registered with your server
- Per-request signed assertions (prevents replay attacks)
- Monotonic counter verification

**Server-Side** (via [node-app-attest](https://github.com/uebelack/node-app-attest))
- Supabase Edge Functions included (copy and deploy)
- CBOR decoding + Apple certificate chain validation
- Challenge-response with single-use nonces (5 min TTL)
- Shared assertion verification utility for any Edge Function

## Installation

### Swift Package Manager

```swift
dependencies: [
    .package(url: "https://github.com/tuchek/SecureAttest.git", from: "1.0.0"),
]
```

Two targets available:

| Target | Use when | Dependencies |
|--------|----------|-------------|
| `SecureAttest` | Any backend or local-only checks | IOSSecuritySuite |
| `SecureAttestSupabase` | Supabase backend | SecureAttest + Supabase SDK |

```swift
.target(
    name: "YourApp",
    dependencies: [
        .product(name: "SecureAttest", package: "SecureAttest"),
        .product(name: "SecureAttestSupabase", package: "SecureAttest"),
    ]
)
```

## Quick Start

### 1. Configure (app launch)

```swift
import SecureAttest
import SecureAttestSupabase

// With Supabase (full protection)
let server = SupabaseAttestationServer(supabase: supabaseClient)
let secureAttest = SecureAttest(configuration: .init(
    integrityPolicy: .hardBlock,
    serverProvider: server
))

// Without Supabase (local checks only)
let secureAttest = SecureAttest(configuration: .init(
    integrityPolicy: .hardBlock
))
```

### 2. Check device integrity (synchronous)

```swift
do {
    let report = try secureAttest.checkIntegrity()
    // Device is clean — proceed
} catch SecureAttestError.deviceCompromised(let report) {
    // Device is jailbroken/hooked/debugged
    // Block sensitive operations (IAP, etc.)
    print("Failed checks: \(report.findings.map(\.message))")
}
```

### 3. Attest device (one-time, after sign-in)

```swift
do {
    try await secureAttest.attestDevice()
} catch {
    // App Attest not supported (simulator, old device) — degrade gracefully
}
```

### 4. Protect sensitive requests

```swift
// Combined integrity check + assertion generation
let (report, assertion) = try await secureAttest.protectRequest(
    payload: requestBody
)

// Include assertion in your server request
if let assertion {
    request.addValue(assertion.assertion.base64EncodedString(), forHTTPHeaderField: "X-App-Assertion")
    request.addValue(assertion.challenge, forHTTPHeaderField: "X-App-Challenge")
}
```

### 5. Clear on sign-out

```swift
secureAttest.clearAttestation()
```

## Integrity Policies

| Policy | Behavior |
|--------|----------|
| `.hardBlock` | Throws `SecureAttestError.deviceCompromised` if any critical check fails |
| `.warn` | Returns report, caller decides what to do |
| `.logOnly` | Returns report silently (for analytics) |
| `.disabled` | Skips all checks (development/testing) |

## Server Setup (Supabase)

### 1. Run the migration

```bash
# Creates device_attestation_challenges + device_attestations tables
psql < EdgeFunctions/migrations/device_attestation.sql
```

### 2. Set environment variables

In Supabase Dashboard → Edge Functions → Secrets:

| Variable | Example |
|----------|---------|
| `APPLE_TEAM_ID` | `5AW6XGHK6E` |
| `APPLE_BUNDLE_ID` | `com.example.myapp` |
| `ENVIRONMENT` | `production` |

### 3. Deploy Edge Functions

```bash
cp -r EdgeFunctions/challenge/ your-project/supabase/functions/
cp -r EdgeFunctions/attest-device/ your-project/supabase/functions/
cp -r EdgeFunctions/_shared/ your-project/supabase/functions/

supabase functions deploy challenge
supabase functions deploy attest-device
```

### 4. Add assertion verification to existing endpoints

```typescript
import { verifyRequestAssertion } from "../_shared/assert.ts";

const status = await verifyRequestAssertion(supabase, user.id, {
  assertion: body.assertion,
  challenge: body.challenge,
  payload: body.payload,
});

if (!status.verified && status.required) {
  return new Response("Forbidden", { status: 403 });
}
```

See [EdgeFunctions/README.md](EdgeFunctions/README.md) for the full setup guide.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│ iOS App                                              │
│                                                      │
│  SecureAttest (facade)                               │
│  ├── DeviceIntegrityService    ← IOSSecuritySuite    │
│  │   └── Local checks (sync)                         │
│  └── AppAttestClient           ← DCAppAttestService  │
│      ├── Key generation (Secure Enclave)             │
│      ├── Attestation (one-time)                      │
│      └── Assertions (per-request)                    │
│                                                      │
│  AttestationServerProvider (protocol)                │
│  └── SupabaseAttestationServer (adapter)             │
└──────────────────────┬───────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────┐
│ Supabase Edge Functions          ← node-app-attest   │
│                                                      │
│  challenge/         Issues single-use nonces         │
│  attest-device/     Verifies attestation + stores    │
│  _shared/assert.ts  Reusable assertion verification  │
└──────────────────────────────────────────────────────┘
```

## Custom Backend

If you don't use Supabase, implement the `AttestationServerProvider` protocol:

```swift
public protocol AttestationServerProvider: Sendable {
    func requestChallenge() async throws -> String
    func submitAttestation(keyId: String, attestation: Data, challenge: String) async throws
    func submitAssertion(assertion: Data, challenge: String, payload: Data) async throws
}
```

Then pass your implementation to the configuration:

```swift
let secureAttest = SecureAttest(configuration: .init(
    integrityPolicy: .hardBlock,
    serverProvider: MyCustomServer()
))
```

## Simulator & Development

- All local integrity checks return clean on simulator (`skipInSimulator: true` by default)
- App Attest is not supported on simulator — `isAppAttestAvailable` returns `false`
- Use `.disabled` policy during development to skip all checks
- Keychain storage uses `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` for background task compatibility

## Requirements

- iOS 15.0+
- Swift 5.9+
- Xcode 15.0+

## Dependencies

| Library | Purpose | License |
|---------|---------|---------|
| [IOSSecuritySuite](https://github.com/securing/IOSSecuritySuite) | Local device integrity checks | EULA (free < 100 employees) |
| [supabase-swift](https://github.com/supabase/supabase-swift) | Supabase adapter (optional target) | MIT |
| [node-app-attest](https://github.com/uebelack/node-app-attest) | Server-side attestation verification | MIT |

## License

MIT — see [LICENSE](LICENSE).
