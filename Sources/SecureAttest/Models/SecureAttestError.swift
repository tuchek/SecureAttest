import Foundation

/// Errors thrown by SecureAttest operations.
public enum SecureAttestError: Error, LocalizedError {
    /// App Attest is not supported on this device.
    case appAttestNotSupported

    /// Device has not been attested yet. Call `attestDevice()` first.
    case notAttested

    /// The attestation key was lost (app reinstall, Keychain reset).
    case attestationKeyLost

    /// Server rejected the attestation.
    case attestationRejected(String)

    /// Server rejected the assertion.
    case assertionRejected(String)

    /// Challenge request failed.
    case challengeFailed(String)

    /// Device integrity check failed — device is compromised.
    case deviceCompromised(IntegrityReport)

    /// Network or server communication error.
    case serverError(Error)

    public var errorDescription: String? {
        switch self {
        case .appAttestNotSupported:
            return "App Attest is not supported on this device."
        case .notAttested:
            return "Device has not been attested. Please sign in again."
        case .attestationKeyLost:
            return "Attestation key is no longer available. Please sign in again."
        case .attestationRejected(let reason):
            return "Attestation rejected: \(reason)"
        case .assertionRejected(let reason):
            return "Assertion rejected: \(reason)"
        case .challengeFailed(let reason):
            return "Challenge request failed: \(reason)"
        case .deviceCompromised:
            return "This device has been modified. This operation is not available on modified devices."
        case .serverError(let error):
            return "Server error: \(error.localizedDescription)"
        }
    }
}
