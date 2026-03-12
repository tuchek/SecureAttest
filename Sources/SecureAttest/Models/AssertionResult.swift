import Foundation

/// Result of generating an App Attest assertion.
/// Include both the assertion data and the challenge in your server request.
public struct AssertionResult: Sendable {
    /// The signed assertion data (CBOR-encoded, base64 this for transport).
    public let assertion: Data

    /// The challenge that was used to generate this assertion.
    /// The server needs this to verify the assertion.
    public let challenge: String

    public init(assertion: Data, challenge: String) {
        self.assertion = assertion
        self.challenge = challenge
    }
}
