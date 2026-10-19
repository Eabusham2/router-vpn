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
    let providerSession: String?
    let runtimeEpoch: String?

    init(connectedAt: Date, engine: String, rawProfile: String,
         bundleData: Data, entryBundleData: Data?, providerSession: String? = nil,
         runtimeEpoch: String? = nil) throws {
        guard ["wireguard", "libbox", "external-libbox", "multihop-libbox"].contains(engine),
              !rawProfile.isEmpty, rawProfile.utf8.count <= 128,
              !bundleData.isEmpty, bundleData.count <= 32 * 1024 * 1024 else {
            throw Self.invalid()
        }
        if engine == "multihop-libbox" {
            guard let entryBundleData, !entryBundleData.isEmpty,
                  entryBundleData.count <= 32 * 1024 * 1024 else { throw Self.invalid() }
        } else if entryBundleData != nil { throw Self.invalid() }
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
        self.providerSession = providerSession
        self.runtimeEpoch = runtimeEpoch
    }

    private static func invalid() -> NSError {
        NSError(domain: "RouterVPN.SessionIdentity", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "The active tunnel's exact session/configuration identity is unavailable."])
    }
}
