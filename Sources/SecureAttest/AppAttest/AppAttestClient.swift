import CryptoKit
import DeviceCheck
import Foundation

/// Client-side App Attest operations.
///
/// Wraps Apple's `DCAppAttestService` with Keychain key storage and
/// server communication via `AttestationServerProvider`.
///
/// Usage:
/// ```swift
/// let client = AppAttestClient(serverProvider: myServer)
///
/// // One-time: attest device after sign-in
/// try await client.attestDevice()
///
/// // Per-request: generate assertion for sensitive operations
/// let result = try await client.generateAssertion(for: payloadData)
/// ```
public final class AppAttestClient {
    private let serverProvider: AttestationServerProvider
    private let keyStorage: AppAttestKeyStorage

    public init(
        serverProvider: AttestationServerProvider,
        keyStorage: AppAttestKeyStorage = AppAttestKeyStorage()
    ) {
        self.serverProvider = serverProvider
        self.keyStorage = keyStorage
    }

    // MARK: - Public API

    /// Whether App Attest is supported on this device.
    /// Returns `false` on simulator and devices without Secure Enclave.
    public var isSupported: Bool {
        DCAppAttestService.shared.isSupported
    }

    /// Whether this device has been successfully attested (key generated + server verified).
    public var isAttested: Bool {
        keyStorage.storedKeyId != nil
    }

    /// Generate a key pair in Secure Enclave, attest it with Apple, and register with your server.
    ///
    /// Call this once after the user signs in. If already attested, this is a no-op.
    ///
    /// - Throws: `SecureAttestError.appAttestNotSupported` if the device doesn't support App Attest.
    /// - Throws: `SecureAttestError.attestationRejected` if the server rejects the attestation.
    public func attestDevice() async throws {
        // Already attested — verify key still exists
        if let existingKeyId = keyStorage.storedKeyId {
            // Verify the key is still in the Secure Enclave by attempting to use it
            // If the app was reinstalled, the key is gone but our Keychain entry remains
            let service = DCAppAttestService.shared
            do {
                // Request a throwaway challenge to test the key
                let challenge = try await serverProvider.requestChallenge()
                let clientDataHash = Data(SHA256.hash(data: Data(challenge.utf8)))
                _ = try await service.generateAssertion(existingKeyId, clientDataHash: clientDataHash)
                return // Key works, already attested
            } catch {
                // Key is invalid — clear and re-attest
                keyStorage.clear()
            }
        }

        guard DCAppAttestService.shared.isSupported else {
            throw SecureAttestError.appAttestNotSupported
        }

        let service = DCAppAttestService.shared

        // 1. Generate key pair in Secure Enclave
        let keyId = try await service.generateKey()

        // 2. Request challenge from server
        let challenge: String
        do {
            challenge = try await serverProvider.requestChallenge()
        } catch {
            throw SecureAttestError.challengeFailed(error.localizedDescription)
        }

        // 3. Create client data hash from challenge
        let clientDataHash = Data(SHA256.hash(data: Data(challenge.utf8)))

        // 4. Attest key with Apple
        let attestation = try await service.attestKey(keyId, clientDataHash: clientDataHash)

        // 5. Send attestation to server for verification
        do {
            try await serverProvider.submitAttestation(
                keyId: keyId,
                attestation: attestation,
                challenge: challenge
            )
        } catch {
            throw SecureAttestError.attestationRejected(error.localizedDescription)
        }

        // 6. Store key ID in Keychain
        keyStorage.store(keyId: keyId)
    }

    /// Generate a signed assertion for a sensitive request.
    ///
    /// The returned `AssertionResult` contains the assertion data and the challenge.
    /// Include both in your server request so the server can verify.
    ///
    /// - Parameter payload: The request payload to sign (e.g., JSON body as Data).
    /// - Returns: An `AssertionResult` containing the assertion and challenge.
    /// - Throws: `SecureAttestError.notAttested` if the device hasn't been attested.
    public func generateAssertion(for payload: Data) async throws -> AssertionResult {
        guard let keyId = keyStorage.storedKeyId else {
            throw SecureAttestError.notAttested
        }

        let service = DCAppAttestService.shared

        // 1. Request challenge from server
        let challenge: String
        do {
            challenge = try await serverProvider.requestChallenge()
        } catch {
            throw SecureAttestError.challengeFailed(error.localizedDescription)
        }

        // 2. Create client data hash from challenge + payload
        var hashInput = Data(challenge.utf8)
        hashInput.append(payload)
        let clientDataHash = Data(SHA256.hash(data: hashInput))

        // 3. Generate assertion signed by Secure Enclave
        let assertion: Data
        do {
            assertion = try await service.generateAssertion(keyId, clientDataHash: clientDataHash)
        } catch {
            // Key may have been invalidated (reinstall, etc.)
            keyStorage.clear()
            throw SecureAttestError.attestationKeyLost
        }

        return AssertionResult(assertion: assertion, challenge: challenge)
    }

    /// Clear the stored attestation key. Call on sign-out.
    /// A new attestation will be required on next sign-in.
    public func clearAttestation() {
        keyStorage.clear()
    }
}
