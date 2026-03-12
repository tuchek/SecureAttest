import Foundation
import Security

/// Stores and retrieves the App Attest key ID in the iOS Keychain.
///
/// Thread-safe — Keychain operations are atomic.
public final class AppAttestKeyStorage: Sendable {
    private let service: String
    private let account: String

    /// - Parameters:
    ///   - service: Keychain service identifier. Defaults to `"com.secureattest.keyid"`.
    ///   - account: Keychain account identifier. Defaults to `"appattest"`.
    public init(service: String = "com.secureattest.keyid", account: String = "appattest") {
        self.service = service
        self.account = account
    }

    /// The currently stored App Attest key ID, or `nil` if not attested.
    public var storedKeyId: String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess, let data = result as? Data else {
            return nil
        }

        return String(data: data, encoding: .utf8)
    }

    /// Store an App Attest key ID in the Keychain.
    ///
    /// Uses `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` so the key
    /// is available during background operations but doesn't migrate to other devices.
    @discardableResult
    public func store(keyId: String) -> Bool {
        // Delete any existing entry first
        clear()

        guard let data = keyId.data(using: .utf8) else { return false }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        return status == errSecSuccess
    }

    /// Remove the stored key ID from the Keychain.
    @discardableResult
    public func clear() -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]

        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }
}
