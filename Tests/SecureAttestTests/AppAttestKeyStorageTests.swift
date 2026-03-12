import Foundation
import Testing
@testable import SecureAttest

// Keychain tests require a proper test host with entitlements (e.g., an Xcode project).
// SPM test targets on simulator don't have Keychain access.
// These tests are validated when SecureAttest is integrated into an app project.

@Suite("AppAttestKeyStorage", .serialized, .disabled("Keychain requires app test host with entitlements"))
struct AppAttestKeyStorageTests {

    private func makeStorage() -> AppAttestKeyStorage {
        AppAttestKeyStorage(
            service: "com.secureattest.test.\(UUID().uuidString)",
            account: "test"
        )
    }

    @Test("Store and retrieve key ID")
    func storeAndRetrieve() {
        let storage = makeStorage()
        defer { storage.clear() }

        #expect(storage.storedKeyId == nil)

        let stored = storage.store(keyId: "test-key-123")
        #expect(stored == true)
        #expect(storage.storedKeyId == "test-key-123")
    }

    @Test("Clear removes key ID")
    func clearRemovesKey() {
        let storage = makeStorage()

        storage.store(keyId: "test-key-456")
        #expect(storage.storedKeyId == "test-key-456")

        let cleared = storage.clear()
        #expect(cleared == true)
        #expect(storage.storedKeyId == nil)
    }

    @Test("Store overwrites previous key")
    func storeOverwrites() {
        let storage = makeStorage()
        defer { storage.clear() }

        storage.store(keyId: "key-1")
        #expect(storage.storedKeyId == "key-1")

        storage.store(keyId: "key-2")
        #expect(storage.storedKeyId == "key-2")
    }

    @Test("Clear on empty Keychain succeeds")
    func clearOnEmpty() {
        let storage = makeStorage()
        let cleared = storage.clear()
        #expect(cleared == true)
    }
}
