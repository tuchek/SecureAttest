import Foundation
import SecureAttest

/// Mock server for testing App Attest flows without a real backend.
final class MockAttestationServer: AttestationServerProvider, @unchecked Sendable {
    var challengeToReturn = "mock-challenge-\(UUID().uuidString)"
    var shouldFailChallenge = false
    var shouldFailAttestation = false
    var shouldFailAssertion = false

    private(set) var lastSubmittedKeyId: String?
    private(set) var lastSubmittedAttestation: Data?
    private(set) var lastSubmittedAssertion: Data?
    private(set) var challengeRequestCount = 0
    private(set) var attestationSubmitCount = 0
    private(set) var assertionSubmitCount = 0

    func requestChallenge() async throws -> String {
        challengeRequestCount += 1
        if shouldFailChallenge {
            throw MockError.challengeFailed
        }
        return challengeToReturn
    }

    func submitAttestation(keyId: String, attestation: Data, challenge: String) async throws {
        attestationSubmitCount += 1
        lastSubmittedKeyId = keyId
        lastSubmittedAttestation = attestation
        if shouldFailAttestation {
            throw MockError.attestationRejected
        }
    }

    func submitAssertion(assertion: Data, challenge: String, payload: Data) async throws {
        assertionSubmitCount += 1
        lastSubmittedAssertion = assertion
        if shouldFailAssertion {
            throw MockError.assertionRejected
        }
    }

    enum MockError: Error {
        case challengeFailed
        case attestationRejected
        case assertionRejected
    }
}
