import Foundation
import IOSSecuritySuite

/// Performs local device integrity checks using IOSSecuritySuite.
///
/// All checks are synchronous and run on the calling thread.
/// On simulator, returns `isCompromised: false` by default (configurable).
public enum DeviceIntegrityService {

    /// Run all integrity checks and return a report.
    ///
    /// - Parameter skipInSimulator: If `true` (default), returns a clean report on simulator.
    /// - Returns: An `IntegrityReport` with all findings.
    public static func performFullCheck(skipInSimulator: Bool = true) -> IntegrityReport {
        #if targetEnvironment(simulator)
        if skipInSimulator {
            return IntegrityReport(isCompromised: false, isProxied: false, findings: [])
        }
        #endif

        var findings: [IntegrityFinding] = []

        // Jailbreak detection
        let jailbreakResult = IOSSecuritySuite.amIJailbrokenWithFailedChecks()
        if jailbreakResult.jailbroken {
            findings.append(IntegrityFinding(
                check: .jailbreak,
                severity: .critical,
                message: "Jailbreak detected: \(jailbreakResult.failedChecks.map(\.failMessage).joined(separator: ", "))"
            ))
        }

        // Debugger detection
        if IOSSecuritySuite.amIDebugged() {
            findings.append(IntegrityFinding(
                check: .debugger,
                severity: .critical,
                message: "Debugger attached to process"
            ))
        }

        // Reverse engineering tools (Frida, Cycript, etc.)
        let reverseResult = IOSSecuritySuite.amIReverseEngineeredWithFailedChecks()
        if reverseResult.reverseEngineered {
            findings.append(IntegrityFinding(
                check: .reverseEngineering,
                severity: .critical,
                message: "Reverse engineering tools detected: \(reverseResult.failedChecks.map(\.failMessage).joined(separator: ", "))"
            ))
        }

        // Emulator detection
        if IOSSecuritySuite.amIRunInEmulator() {
            findings.append(IntegrityFinding(
                check: .emulator,
                severity: .critical,
                message: "App is running in an emulator"
            ))
        }

        // Proxy/VPN detection (informational — VPNs are legitimate)
        let isProxied = IOSSecuritySuite.amIProxied()

        if isProxied {
            findings.append(IntegrityFinding(
                check: .proxy,
                severity: .low,
                message: "Network proxy or VPN detected"
            ))
        }

        let isCompromised = findings.contains { $0.severity >= .critical }

        return IntegrityReport(
            isCompromised: isCompromised,
            isProxied: isProxied,
            findings: findings
        )
    }

    /// Run a specific subset of checks.
    ///
    /// - Parameters:
    ///   - checks: The set of checks to perform.
    ///   - skipInSimulator: If `true` (default), returns a clean report on simulator.
    /// - Returns: An `IntegrityReport` with findings for the requested checks only.
    public static func performChecks(
        _ checks: Set<IntegrityCheck>,
        skipInSimulator: Bool = true
    ) -> IntegrityReport {
        #if targetEnvironment(simulator)
        if skipInSimulator {
            return IntegrityReport(isCompromised: false, isProxied: false, findings: [])
        }
        #endif

        var findings: [IntegrityFinding] = []
        var isProxied = false

        if checks.contains(.jailbreak) {
            let result = IOSSecuritySuite.amIJailbrokenWithFailedChecks()
            if result.jailbroken {
                findings.append(IntegrityFinding(
                    check: .jailbreak,
                    severity: .critical,
                    message: "Jailbreak detected"
                ))
            }
        }

        if checks.contains(.debugger), IOSSecuritySuite.amIDebugged() {
            findings.append(IntegrityFinding(
                check: .debugger,
                severity: .critical,
                message: "Debugger attached to process"
            ))
        }

        if checks.contains(.reverseEngineering), IOSSecuritySuite.amIReverseEngineered() {
            findings.append(IntegrityFinding(
                check: .reverseEngineering,
                severity: .critical,
                message: "Reverse engineering tools detected"
            ))
        }

        if checks.contains(.emulator), IOSSecuritySuite.amIRunInEmulator() {
            findings.append(IntegrityFinding(
                check: .emulator,
                severity: .critical,
                message: "App is running in an emulator"
            ))
        }

        if checks.contains(.proxy) {
            isProxied = IOSSecuritySuite.amIProxied()
            if isProxied {
                findings.append(IntegrityFinding(
                    check: .proxy,
                    severity: .low,
                    message: "Network proxy or VPN detected"
                ))
            }
        }

        let isCompromised = findings.contains { $0.severity >= .critical }

        return IntegrityReport(
            isCompromised: isCompromised,
            isProxied: isProxied,
            findings: findings
        )
    }

    /// Actively deny debugger attachment using ptrace.
    /// Kills the process if a debugger is attached.
    ///
    /// **Warning:** Only call this in release builds. Calling in debug builds
    /// will immediately terminate the process.
    public static func denyDebugger() {
        #if !DEBUG
        IOSSecuritySuite.denyDebugger()
        #endif
    }
}
