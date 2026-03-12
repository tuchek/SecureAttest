import Foundation

/// Main entry point for SecureAttest.
///
/// Combines local device integrity checks (IOSSecuritySuite) with
/// Apple App Attest (server-verified cryptographic attestation) for
/// comprehensive device security.
///
/// Usage:
/// ```swift
/// import SecureAttest
/// import SecureAttestSupabase
///
/// // Configure once at app launch
/// let server = SupabaseAttestationServer(supabase: client)
/// let secureAttest = SecureAttest(configuration: .init(
///     integrityPolicy: .hardBlock,
///     serverProvider: server
/// ))
///
/// // Check device integrity (local, synchronous)
/// let report = secureAttest.checkIntegrity()
///
/// // Attest device (async, one-time after sign-in)
/// try await secureAttest.attestDevice()
///
/// // Generate assertion for a sensitive request
/// let result = try await secureAttest.generateAssertion(for: payloadData)
/// ```
public final class SecureAttest {
    /// Configuration for this SecureAttest instance.
    public let configuration: Configuration

    /// The App Attest client. `nil` if no server provider was configured.
    public let appAttest: AppAttestClient?

    public init(configuration: Configuration) {
        self.configuration = configuration
        if let serverProvider = configuration.serverProvider {
            self.appAttest = AppAttestClient(
                serverProvider: serverProvider,
                keyStorage: configuration.keyStorage
            )
        } else {
            self.appAttest = nil
        }
    }

    // MARK: - Device Integrity

    /// Perform local device integrity checks.
    ///
    /// Behavior depends on the configured `integrityPolicy`:
    /// - `.hardBlock`: Throws `SecureAttestError.deviceCompromised` if compromised.
    /// - `.warn`: Returns the report (caller decides what to do).
    /// - `.logOnly`: Returns the report silently.
    /// - `.disabled`: Skips all checks, returns a clean report.
    ///
    /// - Returns: An `IntegrityReport` with findings.
    /// - Throws: `SecureAttestError.deviceCompromised` if policy is `.hardBlock` and device is compromised.
    @discardableResult
    public func checkIntegrity() throws -> IntegrityReport {
        switch configuration.integrityPolicy {
        case .disabled:
            return IntegrityReport(isCompromised: false, isProxied: false, findings: [])

        case .hardBlock:
            let report = DeviceIntegrityService.performFullCheck()
            if report.isCompromised {
                throw SecureAttestError.deviceCompromised(report)
            }
            return report

        case .warn, .logOnly:
            return DeviceIntegrityService.performFullCheck()
        }
    }

    // MARK: - App Attest

    /// Whether App Attest is available and configured.
    public var isAppAttestAvailable: Bool {
        appAttest?.isSupported ?? false
    }

    /// Whether this device has been successfully attested.
    public var isAttested: Bool {
        appAttest?.isAttested ?? false
    }

    /// Attest this device with Apple and register with your server.
    /// No-op if already attested or App Attest is not configured.
    public func attestDevice() async throws {
        try await appAttest?.attestDevice()
    }

    /// Generate a signed assertion for a sensitive request.
    ///
    /// If App Attest is not configured or not supported, returns `nil`.
    /// Callers should treat `nil` as "unattested" and handle accordingly.
    public func generateAssertion(for payload: Data) async throws -> AssertionResult? {
        try await appAttest?.generateAssertion(for: payload)
    }

    /// Clear stored attestation data. Call on sign-out.
    public func clearAttestation() {
        appAttest?.clearAttestation()
    }

    // MARK: - Combined Check

    /// Perform both integrity check and generate an assertion in one call.
    ///
    /// Convenience method for protecting sensitive operations (e.g., IAP).
    ///
    /// - Parameter payload: The request payload to sign.
    /// - Returns: A tuple of the integrity report and optional assertion result.
    /// - Throws: `SecureAttestError.deviceCompromised` if integrity check fails with `.hardBlock` policy.
    public func protectRequest(payload: Data) async throws -> (IntegrityReport, AssertionResult?) {
        let report = try checkIntegrity()
        let assertion = try await generateAssertion(for: payload)
        return (report, assertion)
    }
}

// MARK: - Configuration

extension SecureAttest {
    /// Configuration for SecureAttest.
    public struct Configuration {
        /// Policy for local device integrity checks.
        public let integrityPolicy: IntegrityPolicy

        /// Server provider for App Attest operations.
        /// If `nil`, App Attest is disabled (local checks only).
        public let serverProvider: AttestationServerProvider?

        /// Keychain storage for App Attest key IDs.
        public let keyStorage: AppAttestKeyStorage

        /// - Parameters:
        ///   - integrityPolicy: How to handle compromised devices. Default: `.hardBlock`.
        ///   - serverProvider: Backend for App Attest. `nil` disables App Attest.
        ///   - keyStorage: Custom Keychain storage. Defaults to standard storage.
        public init(
            integrityPolicy: IntegrityPolicy = .hardBlock,
            serverProvider: AttestationServerProvider? = nil,
            keyStorage: AppAttestKeyStorage = AppAttestKeyStorage()
        ) {
            self.integrityPolicy = integrityPolicy
            self.serverProvider = serverProvider
            self.keyStorage = keyStorage
        }
    }
}
