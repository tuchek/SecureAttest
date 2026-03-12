import Foundation

/// Protocol for server-side attestation operations.
///
/// Implement this protocol to connect SecureAttest to your backend.
/// A Supabase implementation is provided in the `SecureAttestSupabase` module.
public protocol AttestationServerProvider: Sendable {
    /// Request a one-time challenge from the server.
    /// Challenges must be single-use and expire within a short time window (e.g., 5 minutes).
    func requestChallenge() async throws -> String

    /// Submit the attestation object for server-side verification.
    ///
    /// The server should:
    /// 1. CBOR-decode the attestation
    /// 2. Validate the certificate chain against Apple's root cert
    /// 3. Verify the challenge matches
    /// 4. Store the public key and initial counter (0)
    ///
    /// - Parameters:
    ///   - keyId: The key identifier from `DCAppAttestService.generateKey()`.
    ///   - attestation: The raw attestation data from `DCAppAttestService.attestKey()`.
    ///   - challenge: The challenge that was used to generate the attestation.
    func submitAttestation(keyId: String, attestation: Data, challenge: String) async throws

    /// Submit an assertion for server-side verification.
    ///
    /// The server should:
    /// 1. CBOR-decode the assertion
    /// 2. Verify the signature using the stored public key
    /// 3. Verify the counter has incremented
    /// 4. Verify the challenge matches
    ///
    /// - Parameters:
    ///   - assertion: The raw assertion data from `DCAppAttestService.generateAssertion()`.
    ///   - challenge: The challenge that was used to generate the assertion.
    ///   - payload: The request payload that was signed.
    func submitAssertion(assertion: Data, challenge: String, payload: Data) async throws
}
