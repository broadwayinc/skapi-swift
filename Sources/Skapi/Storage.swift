import Foundation
#if canImport(Security)
import Security
#endif

/// Where the signed-in session is kept between launches.
///
/// skapi-swift stores the same keys skapi-js keeps in localStorage
/// (`CognitoIdentityServiceProvider.<clientId>.LastAuthUser` and
/// `.<username>.idToken / accessToken / refreshToken / clockDrift`). Implement this protocol to keep
/// them somewhere else, for example your own encrypted database.
public protocol SkapiStorage: AnyObject, Sendable {
    func getItem(_ key: String) -> String?
    func setItem(_ key: String, _ value: String)
    func removeItem(_ key: String)
}

/// Kept for the life of the Skapi object only.
public final class MemoryStorage: SkapiStorage, @unchecked Sendable {
    private var data: [String: String] = [:]
    private let lock = NSLock()

    public init() {}

    public func getItem(_ key: String) -> String? { lock.lock(); defer { lock.unlock() }; return data[key] }
    public func setItem(_ key: String, _ value: String) { lock.lock(); data[key] = value; lock.unlock() }
    public func removeItem(_ key: String) { lock.lock(); data[key] = nil; lock.unlock() }
}

/// One JSON file, readable by the current user only (mode 600). Useful for command line tools on
/// macOS and Linux. On iOS prefer the default `KeychainStorage`.
public final class FileStorage: SkapiStorage, @unchecked Sendable {
    public let url: URL
    private let lock = NSLock()

    public init(path: String) {
        url = URL(fileURLWithPath: (path as NSString).expandingTildeInPath).standardizedFileURL
    }

    public init(url: URL) { self.url = url }

    private func read() -> [String: String] {
        guard let d = try? Data(contentsOf: url), let v = try? JSON.parse(d), let o = v.object else { return [:] }
        var out: [String: String] = [:]
        for (k, x) in o { if let s = x.string { out[k] = s } }
        return out
    }

    private func write(_ data: [String: String]) {
        let dir = url.deletingLastPathComponent()
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let tmp = dir.appendingPathComponent(".skapi-\(UUID().uuidString).tmp")
        var o = JSONObject()
        for k in data.keys.sorted() { o[k] = .string(data[k]!) }
        guard FileManager.default.createFile(atPath: tmp.path, contents: Data(JSON.object(o).jsonString.utf8),
                                             attributes: [.posixPermissions: 0o600]) else { return }
        if (try? FileManager.default.replaceItemAt(url, withItemAt: tmp)) == nil {
            try? FileManager.default.removeItem(at: url)
            if (try? FileManager.default.moveItem(at: tmp, to: url)) == nil {
                try? FileManager.default.removeItem(at: tmp)
            }
        }
    }

    public func getItem(_ key: String) -> String? { lock.lock(); defer { lock.unlock() }; return read()[key] }
    public func setItem(_ key: String, _ value: String) {
        lock.lock(); defer { lock.unlock() }
        var d = read()
        d[key] = value
        write(d)
    }
    public func removeItem(_ key: String) {
        lock.lock(); defer { lock.unlock() }
        var d = read()
        if d.removeValue(forKey: key) != nil { write(d) }
    }
}

#if canImport(Security) && (os(iOS) || os(macOS) || os(tvOS) || os(watchOS) || os(visionOS))
/// The iOS / macOS Keychain: each key is one generic password item under `service`.
/// This is the default storage on Apple platforms.
public final class KeychainStorage: SkapiStorage, @unchecked Sendable {
    public let service: String
    public let accessGroup: String?
    private let accessible: CFString

    /// service: the Keychain service name the items are kept under.
    /// accessGroup: a shared Keychain access group, to share the session with your app extensions.
    /// thisDeviceOnly: true keeps the items out of backups and off other devices.
    public init(service: String, accessGroup: String? = nil, thisDeviceOnly: Bool = false) {
        self.service = service
        self.accessGroup = accessGroup
        // AfterFirstUnlock: a token refresh can still run while the device is locked in the background.
        accessible = thisDeviceOnly ? kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly : kSecAttrAccessibleAfterFirstUnlock
    }

    private func query(_ key: String) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]
        if let g = accessGroup { q[kSecAttrAccessGroup as String] = g }
        return q
    }

    public func getItem(_ key: String) -> String? {
        var q = query(key)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data else { return nil }
        return String(data: d, encoding: .utf8)
    }

    public func setItem(_ key: String, _ value: String) {
        let data = Data(value.utf8)
        let attrs: [String: Any] = [kSecValueData as String: data, kSecAttrAccessible as String: accessible]
        let status = SecItemUpdate(query(key) as CFDictionary, attrs as CFDictionary)
        if status == errSecItemNotFound {
            var q = query(key)
            for (k, v) in attrs { q[k] = v }
            SecItemAdd(q as CFDictionary, nil)
        }
    }

    public func removeItem(_ key: String) {
        SecItemDelete(query(key) as CFDictionary)
    }
}
#endif

/// The storage a Skapi object uses when none is given: the Keychain on Apple platforms (one
/// service per project), memory elsewhere.
func defaultStorage(service: String) -> SkapiStorage {
    #if canImport(Security) && (os(iOS) || os(macOS) || os(tvOS) || os(watchOS) || os(visionOS))
    return KeychainStorage(service: "skapi.session.\(service)")
    #else
    return MemoryStorage()
    #endif
}

/// Where "remember this device" keeps the encryption master key: the Keychain, on this device only.
func defaultDeviceKeyStorage(service: String) -> SkapiStorage? {
    #if canImport(Security) && (os(iOS) || os(macOS) || os(tvOS) || os(watchOS) || os(visionOS))
    return KeychainStorage(service: "skapi.encryption.\(service)", thisDeviceOnly: true)
    #else
    return nil
    #endif
}
