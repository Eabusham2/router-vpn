import Foundation

/// A private in-memory identity of the running NetworkExtension configuration.
/// It is never logged, exposed as result metadata, or persisted as a profile.
/// Matching node/mode labels alone cannot distinguish a reconnect or new entry.
struct IOSSessionIdentity: Equatable {
    let connectedAt: Date
    let engine: String
    let rawProfile: String
    let bundleData: Data
    let entryBundleData: Data?
    let entryMode: String?
    let providerSession: String?
    let runtimeEpoch: String?

    init(connectedAt: Date, engine: String, rawProfile: String,
         bundleData: Data, entryBundleData: Data?, providerSession: String? = nil,
         runtimeEpoch: String? = nil, entryMode: String? = nil) throws {
        guard ["wireguard", "libbox", "external-libbox", "multihop-libbox"].contains(engine),
              !rawProfile.isEmpty, rawProfile.utf8.count <= 128,
              !bundleData.isEmpty, bundleData.count <= 32 * 1024 * 1024 else {
            throw Self.invalid()
        }
        if engine == "multihop-libbox" || engine == "external-libbox" && entryBundleData != nil {
            guard let entryBundleData, !entryBundleData.isEmpty,
                  entryBundleData.count <= 32 * 1024 * 1024 else { throw Self.invalid() }
        } else if entryBundleData != nil { throw Self.invalid() }
        if let entryMode {
            guard entryBundleData != nil, !entryMode.isEmpty, entryMode.utf8.count <= 128,
                  entryMode == entryMode.lowercased(),
                  entryMode.utf8.allSatisfy({ ($0 >= 97 && $0 <= 122) || ($0 >= 48 && $0 <= 57) || $0 == 45 }) else { throw Self.invalid() }
        }
        if engine == "external-libbox", entryBundleData != nil, entryMode == nil { throw Self.invalid() }
        if providerSession != nil || runtimeEpoch != nil {
            guard engine == "libbox", let providerSession, let runtimeEpoch,
                  UUID(uuidString: providerSession) != nil,
                  UUID(uuidString: runtimeEpoch) != nil else { throw Self.invalid() }
        }
        self.connectedAt = connectedAt
        self.engine = engine
        self.rawProfile = rawProfile
        self.bundleData = bundleData
        self.entryBundleData = entryBundleData
        self.entryMode = entryMode
        self.providerSession = providerSession
        self.runtimeEpoch = runtimeEpoch
    }

    /// Capture every predecessor byte from the same saved native configuration.
    /// Separate Tor/ordinary slots must never be silently treated as direct, and
    /// a malformed or mixed owner invalidates measurements until readback works.
    init(connectedAt: Date, engine: String, rawProfile: String,
         bundleData: Data, configuration: [String: Any]) throws {
        let externalKeys = ["external_entry_bundle", "external_entry_mode", "tor_entry_bundle", "tor_entry_mode"]
        var entry: Data?
        var mode: String?
        if engine == "external-libbox" {
            guard configuration["entryBundle"] == nil else { throw Self.invalid() }
            let tor = ["external-tor", "external-tor-bridge"].contains(rawProfile)
            let prefix = tor ? "tor_entry" : "external_entry"
            let foreign = tor ? "external_entry" : "tor_entry"
            guard configuration[foreign + "_bundle"] == nil, configuration[foreign + "_mode"] == nil else { throw Self.invalid() }
            if configuration[prefix + "_bundle"] != nil || configuration[prefix + "_mode"] != nil {
                guard let captured = configuration[prefix + "_bundle"] as? Data,
                      let selected = configuration[prefix + "_mode"] as? String else { throw Self.invalid() }
                entry = captured; mode = selected
            }
        } else {
            guard externalKeys.allSatisfy({ configuration[$0] == nil }) else { throw Self.invalid() }
            if configuration["entryBundle"] != nil {
                guard let captured = configuration["entryBundle"] as? Data else { throw Self.invalid() }
                entry = captured
            }
        }
        try self.init(connectedAt: connectedAt, engine: engine, rawProfile: rawProfile,
                      bundleData: bundleData, entryBundleData: entry, entryMode: mode)
    }

    private static func invalid() -> NSError {
        NSError(domain: "RouterVPN.SessionIdentity", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "The active tunnel's exact session/configuration identity is unavailable."])
    }
}
