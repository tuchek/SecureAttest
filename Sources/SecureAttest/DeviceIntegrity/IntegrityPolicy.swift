import Foundation

/// Determines what happens when a device integrity issue is detected.
public enum IntegrityPolicy: Sendable {
    /// Block the operation entirely. Throw `SecureAttestError.deviceCompromised`.
    case hardBlock

    /// Return the report but don't block. Caller decides what to do.
    case warn

    /// Silently return the report. For logging/analytics only.
    case logOnly

    /// Skip all checks. For development/testing.
    case disabled
}
