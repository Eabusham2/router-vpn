import CryptoKit
import Foundation
import Security

@MainActor
final class IOSNodeBundleStore {
    static let shared = IOSNodeBundleStore()
    private let legacyDefaultsKey = "router-vpn.ios.node-bundles.v1"
    private let legacyBundleKeychainService = "com.eabusham.routervpn.private-node-bundles"
    private let legacyBundleKeychainAccount = "linked-bundles-v1"
    private let keychainService = "com.eabusham.routervpn.private-node-key"
    private let keychainAccount = "bundle-encryption-key-v1"
    private let encryptedStoreName = "private-node-bundles-v2.sealed"
    private let maxEncryptedStoreBytes = 192 * 1024 * 1024
    private let storeAAD = Data("router-vpn-ios-private-node-store-v2".utf8)
    private var records: [String: Data] = [:]
    private var storageError: Error?

    private init() {
        do {
            if try encryptedStoreExists() {
                records = try readEncryptedRecords()
                cleanupLegacyStoresBestEffort()
                return
            }
            if let legacy = try keychainData(service: legacyBundleKeychainService, account: legacyBundleKeychainAccount) {
                guard let decoded = try? JSONDecoder().decode([String: Data].self, from: legacy) else {
                    throw NSError(domain: "RouterVPN.NodeStore", code: 90, userInfo: [NSLocalizedDescriptionKey: "Legacy private linked-node Keychain data is corrupt; refusing to replace it with weaker fallback storage"])
                }
                records = decoded
                try persist()
                cleanupLegacyStoresBestEffort()
                return
            }
            if let legacy = UserDefaults.standard.data(forKey: legacyDefaultsKey) {
                guard let decoded = try? JSONDecoder().decode([String: Data].self, from: legacy) else {
                    throw NSError(domain: "RouterVPN.NodeStore", code: 91, userInfo: [NSLocalizedDescriptionKey: "Legacy linked-node data is corrupt; refusing automatic migration"])
                }
                records = decoded
                try persist()
                cleanupLegacyStoresBestEffort()
            }
        } catch {
            records = [:]
            storageError = error
        }
    }

    func link(_ incomingData: Data, preserving current: ClientBundle?) throws -> Data {
        try ensureStorageReady()
        if let current { _ = try store(current, replaceExistingRecord: true) }
        let incoming = try JSONDecoder().decode(ClientBundle.self, from: incomingData)
        return try store(incoming, replaceExistingRecord: true)
    }

    func profiles(current: ClientBundle?) -> [RouterProfile] {
        guard storageError == nil else { return [] }
        if let current { _ = try? store(current, replaceExistingRecord: true) }
        var result: [RouterProfile] = []
        var seen = Set<String>()
        for key in records.keys.sorted() {
            guard let data = records[key],
                  let bundle = try? JSONDecoder().decode(ClientBundle.self, from: data) else { continue }
            for profile in bundle.routerProfiles where seen.insert(profile.id).inserted {
                result.append(profile)
            }
        }
        return result.sorted {
            if $0.normalizedNodeKind != $1.normalizedNodeKind { return $0.normalizedNodeKind < $1.normalizedNodeKind }
            return $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
        }
    }

    func bundleData(containing profileID: String, current: ClientBundle?) -> Data? {
        guard storageError == nil else { return nil }
        if let current { _ = try? store(current, replaceExistingRecord: true) }
        let wanted = canonicalProfileID(profileID, current: current)
        for key in records.keys.sorted() {
            guard let data = records[key],
                  let bundle = try? JSONDecoder().decode(ClientBundle.self, from: data),
                  bundle.routerProfiles.contains(where: { $0.id == wanted }) else { continue }
            return data
        }
        return nil
    }

    func remove(profileID: String, current: ClientBundle?) throws -> Data? {
        try ensureStorageReady()
        if let current { _ = try store(current, replaceExistingRecord: true) }
        let wanted = canonicalProfileID(profileID, current: current)
        for key in records.keys.sorted() {
            guard let data = records[key],
                  var bundle = try? JSONDecoder().decode(ClientBundle.self, from: data),
                  bundle.routerProfiles.contains(where: { $0.id == wanted }) else { continue }
            bundle.routerProfiles.removeAll(where: { $0.id == wanted })
            var next = records
            if bundle.routerProfiles.isEmpty {
                next.removeValue(forKey: key)
                try commitRecords(next)
                return firstBundleData()
            }
            if bundle.selectedRouterID == wanted { bundle.selectedRouterID = bundle.routerProfiles[0].id }
            let replacement = try JSONEncoder().encode(bundle)
            next[key] = replacement
            try commitRecords(next)
            return replacement
        }
        throw NSError(domain: "RouterVPN.NodeStore", code: 404, userInfo: [NSLocalizedDescriptionKey: "Linked node was not found in the iOS node store"])
    }

    func updateMetadata(
        profileID: String,
        current: ClientBundle?,
        name: String,
        location: String?,
        latitude: Double?,
        longitude: Double?
    ) throws -> Data {
        try ensureStorageReady()
        if let current { _ = try store(current, replaceExistingRecord: true) }
        let wanted = canonicalProfileID(profileID, current: current)
        for key in records.keys.sorted() {
            guard let data = records[key],
                  var bundle = try? JSONDecoder().decode(ClientBundle.self, from: data),
                  let index = bundle.routerProfiles.firstIndex(where: { $0.id == wanted }) else { continue }
            bundle.routerProfiles[index].name = name
            bundle.routerProfiles[index].location = location
            bundle.routerProfiles[index].latitude = latitude
            bundle.routerProfiles[index].longitude = longitude
            let replacement = try JSONEncoder().encode(bundle)
            var next = records
            next[key] = replacement
            try commitRecords(next)
            return replacement
        }
        throw NSError(domain: "RouterVPN.NodeStore", code: 404, userInfo: [NSLocalizedDescriptionKey: "Linked node was not found in the iOS node store"])
    }

    private func store(_ source: ClientBundle, replaceExistingRecord: Bool) throws -> Data {
        try ensureStorageReady()
        var bundle = source
        guard !bundle.routerProfiles.isEmpty else {
            throw NSError(domain: "RouterVPN.NodeStore", code: 1, userInfo: [NSLocalizedDescriptionKey: "Node bundle contains no Router VPN or external profiles"])
        }
        var selectedID = bundle.selectedRouterID
        var localIDs = Set<String>()
        for index in bundle.routerProfiles.indices {
            var profile = bundle.routerProfiles[index]
            let oldID = profile.id
            if profile.normalizedNodeKind == "router-vpn" {
                let proof = (profile.nodeProofID?.isEmpty == false ? profile.nodeProofID! : bundle.nodeProofID).lowercased()
                guard isProofID(proof) else {
                    throw NSError(domain: "RouterVPN.NodeStore", code: 2, userInfo: [NSLocalizedDescriptionKey: "Router VPN node bundle is missing its 64-hex selected-node proof identity"])
                }
                profile.id = deterministicRouterID(proof)
                profile.nodeProofID = proof
                if bundle.nodeProofID.isEmpty { bundle.nodeProofID = proof }
            } else {
                let trimmed = profile.id.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !trimmed.isEmpty, trimmed.count <= 96,
                      trimmed.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "." || $0 == "_" || $0 == "-" }),
                      !trimmed.contains("..") else {
                    throw NSError(domain: "RouterVPN.NodeStore", code: 3, userInfo: [NSLocalizedDescriptionKey: "External node id is unsafe"])
                }
                profile.id = trimmed
            }
            guard localIDs.insert(profile.id).inserted else {
                throw NSError(domain: "RouterVPN.NodeStore", code: 4, userInfo: [NSLocalizedDescriptionKey: "Node bundle contains duplicate node ids"])
            }
            if selectedID == oldID { selectedID = profile.id }
            bundle.routerProfiles[index] = profile
        }
        if !bundle.routerProfiles.contains(where: { $0.id == selectedID }) { selectedID = bundle.routerProfiles[0].id }
        bundle.selectedRouterID = selectedID
        if let selected = bundle.routerProfiles.first(where: { $0.id == selectedID }) {
            bundle.endpoint = selected.endpoint
            if selected.normalizedNodeKind == "router-vpn" {
                bundle.apiToken = selected.apiToken
                bundle.routerAPI = selected.routerAPI
                bundle.adGuardIPv4 = selected.adGuardIPv4
                bundle.adGuardIPv6 = selected.adGuardIPv6
                bundle.socks5Host = selected.socksHost
                bundle.socks5Port = selected.socksPort
            } else {
                bundle.apiToken = ""; bundle.routerAPI = ""; bundle.adGuardIPv4 = ""; bundle.adGuardIPv6 = ""
                bundle.socks5Host = ""; bundle.socks5Port = 0
            }
        }
        let key = recordKey(bundle)
        let existingIDs = globalProfileIDs(excludingRecord: replaceExistingRecord ? key : nil)
        for profile in bundle.routerProfiles where existingIDs.contains(profile.id) {
            throw NSError(domain: "RouterVPN.NodeStore", code: 5, userInfo: [NSLocalizedDescriptionKey: "A different linked bundle already uses node id \(profile.id)"])
        }
        let normalized = try JSONEncoder().encode(bundle)
        var next = records
        next[key] = normalized
        try commitRecords(next)
        return normalized
    }

    private func canonicalProfileID(_ id: String, current: ClientBundle?) -> String {
        guard let current,
              let profile = current.routerProfiles.first(where: { $0.id == id }),
              profile.normalizedNodeKind == "router-vpn" else { return id }
        let proof = (profile.nodeProofID?.isEmpty == false ? profile.nodeProofID! : current.nodeProofID).lowercased()
        return isProofID(proof) ? deterministicRouterID(proof) : id
    }

    private func deterministicRouterID(_ proof: String) -> String {
        "rvpn-" + String(proof.prefix(16))
    }

    private func isProofID(_ value: String) -> Bool {
        value.count == 64 && value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
    }

    private func recordKey(_ bundle: ClientBundle) -> String {
        if isProofID(bundle.nodeProofID.lowercased()) {
            return "router-" + bundle.nodeProofID.lowercased()
        }
        return "bundle-" + bundle.selectedRouterID
    }

    private func globalProfileIDs(excludingRecord: String?) -> Set<String> {
        var ids = Set<String>()
        for (key, data) in records where key != excludingRecord {
            guard let bundle = try? JSONDecoder().decode(ClientBundle.self, from: data) else { continue }
            for profile in bundle.routerProfiles { ids.insert(profile.id) }
        }
        return ids
    }

    private func firstBundleData() -> Data? {
        records.keys.sorted().compactMap { records[$0] }.first
    }

    private func ensureStorageReady() throws {
        if let storageError { throw storageError }
    }

    private func storeDirectory() throws -> URL {
        guard let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            throw NSError(domain: "RouterVPN.NodeStore", code: 92, userInfo: [NSLocalizedDescriptionKey: "Application Support storage is unavailable"])
        }
        let directory = base.appendingPathComponent("RouterVPN", isDirectory: true)
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication]
        )
        let values = try directory.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
        guard values.isDirectory == true, values.isSymbolicLink != true else {
            throw NSError(domain: "RouterVPN.NodeStore", code: 93, userInfo: [NSLocalizedDescriptionKey: "Private node storage directory is unsafe"])
        }
        return directory
    }

    private func encryptedStoreURL() throws -> URL {
        try storeDirectory().appendingPathComponent(encryptedStoreName, isDirectory: false)
    }

    private func encryptedStoreExists() throws -> Bool {
        let url = try encryptedStoreURL()
        guard FileManager.default.fileExists(atPath: url.path) else { return false }
        let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey])
        guard values.isRegularFile == true, values.isSymbolicLink != true else {
            throw NSError(domain: "RouterVPN.NodeStore", code: 94, userInfo: [NSLocalizedDescriptionKey: "Private linked-node store is not a regular file"])
        }
        let size = values.fileSize ?? 0
        guard size > 0, size <= maxEncryptedStoreBytes else {
            throw NSError(domain: "RouterVPN.NodeStore", code: 95, userInfo: [NSLocalizedDescriptionKey: "Private linked-node store is empty or exceeds its safety limit"])
        }
        return true
    }

    private func readEncryptedRecords() throws -> [String: Data] {
        guard let key = try encryptionKey(createIfMissing: false) else {
            throw NSError(domain: "RouterVPN.NodeStore", code: 96, userInfo: [NSLocalizedDescriptionKey: "Encrypted linked-node store exists but its ThisDeviceOnly Keychain key is missing"])
        }
        let url = try encryptedStoreURL()
        guard try encryptedStoreExists() else { return [:] }
        let encrypted = try Data(contentsOf: url, options: [.mappedIfSafe])
        let box = try AES.GCM.SealedBox(combined: encrypted)
        let clear = try AES.GCM.open(box, using: key, authenticating: storeAAD)
        guard let decoded = try? JSONDecoder().decode([String: Data].self, from: clear) else {
            throw NSError(domain: "RouterVPN.NodeStore", code: 97, userInfo: [NSLocalizedDescriptionKey: "Encrypted linked-node store plaintext is corrupt"])
        }
        return decoded
    }

    private func writeEncryptedRecords(_ next: [String: Data]) throws {
        let clear = try JSONEncoder().encode(next)
        guard clear.count <= maxEncryptedStoreBytes else {
            throw NSError(domain: "RouterVPN.NodeStore", code: 98, userInfo: [NSLocalizedDescriptionKey: "Linked-node store exceeds its bounded private-storage limit"])
        }
        guard let key = try encryptionKey(createIfMissing: true) else {
            throw NSError(domain: "RouterVPN.NodeStore", code: 99, userInfo: [NSLocalizedDescriptionKey: "Could not create the private linked-node encryption key"])
        }
        let sealed = try AES.GCM.seal(clear, using: key, authenticating: storeAAD)
        guard let combined = sealed.combined, combined.count <= maxEncryptedStoreBytes else {
            throw NSError(domain: "RouterVPN.NodeStore", code: 100, userInfo: [NSLocalizedDescriptionKey: "Encrypted linked-node store exceeds its safety limit"])
        }
        let url = try encryptedStoreURL()
        if FileManager.default.fileExists(atPath: url.path) {
            let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
            guard values.isRegularFile == true, values.isSymbolicLink != true else {
                throw NSError(domain: "RouterVPN.NodeStore", code: 101, userInfo: [NSLocalizedDescriptionKey: "Refusing to replace an unsafe private linked-node store path"])
            }
        }
        try combined.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        let committed = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey])
        guard committed.isRegularFile == true, committed.isSymbolicLink != true, (committed.fileSize ?? 0) == combined.count else {
            throw NSError(domain: "RouterVPN.NodeStore", code: 102, userInfo: [NSLocalizedDescriptionKey: "Private linked-node store commit could not be verified"])
        }
    }

    private func encryptionKey(createIfMissing: Bool) throws -> SymmetricKey? {
        if let raw = try keychainData(service: keychainService, account: keychainAccount) {
            guard raw.count == 32 else {
                throw NSError(domain: "RouterVPN.NodeStore", code: 103, userInfo: [NSLocalizedDescriptionKey: "Private linked-node encryption key has invalid length"])
            }
            return SymmetricKey(data: raw)
        }
        guard createIfMissing else { return nil }
        let key = SymmetricKey(size: .bits256)
        let raw = key.withUnsafeBytes { Data($0) }
        try writeKeychain(raw, service: keychainService, account: keychainAccount)
        return key
    }

    private func keychainQuery(service: String, account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }

    private func keychainData(service: String, account: String) throws -> Data? {
        var query = keychainQuery(service: service, account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = item as? Data else {
            throw keychainError(status, action: "read private Keychain item")
        }
        return data
    }

    private func writeKeychain(_ data: Data, service: String, account: String) throws {
        let query = keychainQuery(service: service, account: account)
        let update: [String: Any] = [kSecValueData as String: data]
        let updateStatus = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if updateStatus == errSecSuccess { return }
        if updateStatus != errSecItemNotFound {
            throw keychainError(updateStatus, action: "update private Keychain item")
        }
        var add = query
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let addStatus = SecItemAdd(add as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw keychainError(addStatus, action: "create private Keychain item")
        }
    }

    private func deleteKeychain(service: String, account: String) throws {
        let status = SecItemDelete(keychainQuery(service: service, account: account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw keychainError(status, action: "delete legacy private Keychain item")
        }
    }

    private func keychainError(_ status: OSStatus, action: String) -> NSError {
        let detail = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
        return NSError(domain: "RouterVPN.NodeStore", code: Int(status), userInfo: [NSLocalizedDescriptionKey: "Could not \(action): \(detail)"])
    }

    private func cleanupLegacyStoresBestEffort() {
        try? deleteKeychain(service: legacyBundleKeychainService, account: legacyBundleKeychainAccount)
        UserDefaults.standard.removeObject(forKey: legacyDefaultsKey)
    }

    private func commitRecords(_ next: [String: Data]) throws {
        try writeEncryptedRecords(next)
        // Adopt RAM only after authenticated encryption + atomic protected-file commit.
        records = next
        cleanupLegacyStoresBestEffort()
    }

    private func persist() throws {
        try commitRecords(records)
    }
}
