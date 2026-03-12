import Testing
@testable import SecureAttest

@Suite("SecureAttest Facade")
struct SecureAttestFacadeTests {

    @Test("Disabled policy skips all checks")
    func disabledPolicy() throws {
        let sa = SecureAttest(configuration: .init(integrityPolicy: .disabled))
        let report = try sa.checkIntegrity()
        #expect(report.isCompromised == false)
        #expect(report.findings.isEmpty)
    }

    @Test("Warn policy returns report without throwing")
    func warnPolicy() throws {
        let sa = SecureAttest(configuration: .init(integrityPolicy: .warn))
        let report = try sa.checkIntegrity()
        // On simulator, should be clean
        #if targetEnvironment(simulator)
        #expect(report.isCompromised == false)
        #endif
    }

    @Test("LogOnly policy returns report without throwing")
    func logOnlyPolicy() throws {
        let sa = SecureAttest(configuration: .init(integrityPolicy: .logOnly))
        let report = try sa.checkIntegrity()
        #if targetEnvironment(simulator)
        #expect(report.isCompromised == false)
        #endif
    }

    @Test("HardBlock policy on clean device does not throw")
    func hardBlockCleanDevice() throws {
        let sa = SecureAttest(configuration: .init(integrityPolicy: .hardBlock))
        // On simulator, device is clean
        #if targetEnvironment(simulator)
        let report = try sa.checkIntegrity()
        #expect(report.isCompromised == false)
        #endif
    }

    @Test("No server provider means App Attest is nil")
    func noServerProvider() {
        let sa = SecureAttest(configuration: .init())
        #expect(sa.appAttest == nil)
        #expect(sa.isAppAttestAvailable == false)
        #expect(sa.isAttested == false)
    }

    @Test("With server provider creates App Attest client")
    func withServerProvider() {
        let server = MockAttestationServer()
        let sa = SecureAttest(configuration: .init(serverProvider: server))
        #expect(sa.appAttest != nil)
    }

    @Test("Error descriptions are user-friendly")
    func errorDescriptions() {
        let errors: [SecureAttestError] = [
            .appAttestNotSupported,
            .notAttested,
            .attestationKeyLost,
            .attestationRejected("bad cert"),
            .assertionRejected("counter mismatch"),
            .challengeFailed("timeout"),
        ]

        for error in errors {
            #expect(error.errorDescription != nil)
            #expect(!error.errorDescription!.isEmpty)
        }
    }
}
