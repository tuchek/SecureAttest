import Testing
@testable import SecureAttest

@Suite("DeviceIntegrityService")
struct DeviceIntegrityServiceTests {

    @Test("Full check returns a report")
    func fullCheckReturnsReport() {
        let report = DeviceIntegrityService.performFullCheck()
        // On simulator, should return clean (not compromised)
        #if targetEnvironment(simulator)
        #expect(report.isCompromised == false)
        #expect(report.findings.isEmpty)
        #endif
    }

    @Test("Selective check with empty set returns clean report")
    func selectiveCheckEmptySet() {
        let report = DeviceIntegrityService.performChecks([])
        #expect(report.isCompromised == false)
        #expect(report.findings.isEmpty)
    }

    @Test("Selective check with specific checks returns report")
    func selectiveCheckSpecific() {
        let report = DeviceIntegrityService.performChecks([.jailbreak, .debugger])
        // On simulator with skipInSimulator=true (default), should be clean
        #if targetEnvironment(simulator)
        #expect(report.isCompromised == false)
        #endif
    }

    @Test("IntegrityReport model")
    func integrityReportModel() {
        let finding = IntegrityFinding(
            check: .jailbreak,
            severity: .critical,
            message: "Test finding"
        )
        let report = IntegrityReport(
            isCompromised: true,
            isProxied: false,
            findings: [finding]
        )

        #expect(report.isCompromised == true)
        #expect(report.isProxied == false)
        #expect(report.findings.count == 1)
        #expect(report.findings[0].check == .jailbreak)
        #expect(report.findings[0].severity == .critical)
    }

    @Test("Severity ordering")
    func severityOrdering() {
        #expect(Severity.low < Severity.medium)
        #expect(Severity.medium < Severity.high)
        #expect(Severity.high < Severity.critical)
        #expect(Severity.low < Severity.critical)
    }
}
