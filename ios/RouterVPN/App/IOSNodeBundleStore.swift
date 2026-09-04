import Foundation
import Security

@MainActor
final class IOSNodeBundleStore {
    static let shared = IOSNodeBundleStore()
    private let legacyDefaultsKey = "router-vpn.ios.node-bundles.v1"
    private let keychainService = "com.eabusham.routervpn.private-node-bundles"
    private let keychainAccount = "linked-bundles-v1"
    private var records: [String: Data] = [:]
    private var storageError: Error?

    private init() {
        do {
            if let raw = try keychainData() {
                guard let decoded = try? JSONDecoder().decode([String: Data].self, from: raw) else {
                    throw NSError(domain: "RouterVPN.NodeStore", code: 90, userInfo: [NSLocalizedDescriptionKey: "Private linked-node Keychain data is corrupt; refusing to replace it with weaker fallback storage"])
                }
                records = decoded
                UserDefaults.standard.removeObject(forKey: legacyDefaultsKey)
                return
            }
            if let legacy = UserDefaults.standard.data(forKey: legacyDefaultsKey),
               let decoded = try? JSONDecoder().decode([String: Data].self, from: legacy) {
                records = decoded
                try persist()
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
            if bundle.routerProfiles.isEmpty {
                records.removeValue(forKey: key)
                try persist()
                return firstBundleData()
            }
            if bundle.selectedRouterID == wanted { bundle.selectedRouterID = bundle.routerProfiles[0].id }
            let replacement = try JSONEncoder().encode(bundle)
            records[key] = replacement
            try persist()
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
            records[key] = replacement
            try persist()
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
        records[key] = normalized
        try persist()
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

    private func keychainQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
        ]
    }

    private func keychainData() throws -> Data? {
        var query = keychainQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = item as? Data else {
            throw keychainError(status, action: "read private linked-node bundles")
        }
        return data
    }

    private func writeKeychain(_ data: Data) throws {
        let query = keychainQuery()
        let update: [String: Any] = [kSecValueData as String: data]
        let updateStatus = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if updateStatus == errSecSuccess { return }
        if updateStatus != errSecItemNotFound {
            throw keychainError(updateStatus, action: "update private linked-node bundles")
        }
        var add = query
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let addStatus = SecItemAdd(add as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw keychainError(addStatus, action: "create private linked-node bundles")
        }
    }

    private func keychainError(_ status: OSStatus, action: String) -> NSError {
        let detail = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
        return NSError(domain: "RouterVPN.NodeStore", code: Int(status), userInfo: [NSLocalizedDescriptionKey: "Could not \(action): \(detail)"])
    }

    private func persist() throws {
        let data = try JSONEncoder().encode(records)
        try writeKeychain(data)
        // Remove the legacy copy only after the stronger Keychain commit succeeds.
        UserDefaults.standard.removeObject(forKey: legacyDefaultsKey)
    }
}
