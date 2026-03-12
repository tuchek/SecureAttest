import Foundation
import SecureAttest
import Supabase

/// Supabase implementation of `AttestationServerProvider`.
///
/// Communicates with three Edge Functions:
/// - `challenge`: Issues one-time challenges
/// - `attest-device`: Verifies attestation objects
/// - `verify-assertion`: Verifies signed assertions
///
/// Deploy the Edge Functions from `SecureAttest/EdgeFunctions/` to your Supabase project.
///
/// Usage:
/// ```swift
/// let server = SupabaseAttestationServer(supabase: myClient)
/// let secureAttest = SecureAttest(configuration: .init(
///     integrityPolicy: .hardBlock,
///     serverProvider: server
/// ))
/// ```
public final class SupabaseAttestationServer: AttestationServerProvider {
    private let supabase: SupabaseClient
    private let challengeFunction: String
    private let attestFunction: String
    private let assertionFunction: String

    /// - Parameters:
    ///   - supabase: Your Supabase client instance.
    ///   - challengeFunction: Edge Function name for challenges. Default: `"challenge"`.
    ///   - attestFunction: Edge Function name for attestation. Default: `"attest-device"`.
    ///   - assertionFunction: Edge Function name for assertion. Default: `"verify-assertion"`.
    public init(
        supabase: SupabaseClient,
        challengeFunction: String = "challenge",
        attestFunction: String = "attest-device",
        assertionFunction: String = "verify-assertion"
    ) {
        self.supabase = supabase
        self.challengeFunction = challengeFunction
        self.attestFunction = attestFunction
        self.assertionFunction = assertionFunction
    }

    // MARK: - AttestationServerProvider

    public func requestChallenge() async throws -> String {
        let decoded: ChallengeResponse = try await supabase.functions.invoke(
            challengeFunction,
            options: .init(method: .post)
        )
        return decoded.challenge
    }

    public func submitAttestation(keyId: String, attestation: Data, challenge: String) async throws {
        try await supabase.functions.invoke(
            attestFunction,
            options: .init(body: AttestationRequest(
                keyId: keyId,
                attestation: attestation.base64EncodedString(),
                challenge: challenge
            ))
        )
    }

    public func submitAssertion(assertion: Data, challenge: String, payload: Data) async throws {
        try await supabase.functions.invoke(
            assertionFunction,
            options: .init(body: AssertionRequest(
                assertion: assertion.base64EncodedString(),
                challenge: challenge,
                payload: payload.base64EncodedString()
            ))
        )
    }
}

// MARK: - Request/Response Models

private struct ChallengeResponse: Decodable {
    let challenge: String
}

private struct AttestationRequest: Encodable {
    let keyId: String
    let attestation: String
    let challenge: String
}

private struct AssertionRequest: Encodable {
    let assertion: String
    let challenge: String
    let payload: String
}
