import Foundation

/// Result of a device integrity check.
public struct IntegrityReport: Sendable {
    /// Whether the device is considered compromised based on critical findings.
    public let isCompromised: Bool

    /// Whether a network proxy or VPN is detected (separate from compromise — VPNs are legitimate).
    public let isProxied: Bool

    /// Individual findings from each check that was performed.
    public let findings: [IntegrityFinding]

    public init(isCompromised: Bool, isProxied: Bool, findings: [IntegrityFinding]) {
        self.isCompromised = isCompromised
        self.isProxied = isProxied
        self.findings = findings
    }
}

/// A single finding from an integrity check.
public struct IntegrityFinding: Sendable {
    public let check: IntegrityCheck
    public let severity: Severity
    public let message: String

    public init(check: IntegrityCheck, severity: Severity, message: String) {
        self.check = check
        self.severity = severity
        self.message = message
    }
}

/// Categories of integrity checks.
public enum IntegrityCheck: String, CaseIterable, Sendable {
    case jailbreak
    case debugger
    case reverseEngineering
    case emulator
    case proxy
    case tampered
}

/// Severity of a finding.
public enum Severity: String, Sendable, Comparable {
    case critical
    case high
    case medium
    case low

    public static func < (lhs: Severity, rhs: Severity) -> Bool {
        let order: [Severity] = [.low, .medium, .high, .critical]
        return order.firstIndex(of: lhs)! < order.firstIndex(of: rhs)!
    }
}
