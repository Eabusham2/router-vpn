import Foundation

/// A private in-memory identity of the running NetworkExtension configuration.
/// It is never logged, exposed as result metadata, or persisted as a profile.
/// Matching node/mode labels alone cannot distinguish a reconnect or new entry.
struct IOSSessionIdentity: Equatable, Sendable {
    let connectedAt: Date
    let engine: String
    let rawProfile: String
    let bundleData: Data
    let entryBundleData: Data?
    let nodeChainSource: Data?
    let nodeChainExecutionSource: Data?
    let entryMode: String?
    let providerSession: String?
    let runtimeEpoch: String?

    init(connectedAt: Date, engine: String, rawProfile: String,
         bundleData: Data, entryBundleData: Data?, nodeChainSource: Data? = nil, nodeChainExecutionSource: Data? = nil, providerSession: String? = nil,
         runtimeEpoch: String? = nil, entryMode: String? = nil) throws {
        guard ["wireguard", "libbox", "external-libbox", "multihop-libbox"].contains(engine),
              !rawProfile.isEmpty, rawProfile.utf8.count <= 128,
              !bundleData.isEmpty, bundleData.count <= 32 * 1024 * 1024 else {
            throw Self.invalid()
        }
        guard nodeChainSource == nil || nodeChainExecutionSource == nil else { throw Self.invalid() }
        if let nodeChainExecutionSource {
            guard engine == "multihop-libbox", rawProfile == "shadowsocks", entryBundleData == nil, entryMode == nil,
                  Self.executionSource(nodeChainExecutionSource) else { throw Self.invalid() }
        } else if let nodeChainSource {
            guard engine == "multihop-libbox", entryBundleData == nil, entryMode == nil,
                  !nodeChainSource.isEmpty, nodeChainSource.count <= 40 * 1024 * 1024,
                  let source = try JSONSerialization.jsonObject(with: nodeChainSource) as? [String: Any],
                  (source["kind"] as? String == "routervpn-node-chain-launch-input" ||
                   [3, 4].contains(source["schema"] as? Int ?? 0) && Set(source.keys) == Set(["schema", "execution", "nodes", "identity_sources"]) && (source["nodes"] as? [String])?.count == 3), source["execution"] as? String == "local",
                  source["projection_kind"] == nil, source["session_id"] == nil, source["target_os"] == nil, source["restored_mtu"] == nil,
                  let nodes = source["nodes"] as? [String], (2...8).contains(nodes.count) else { throw Self.invalid() }
        } else if engine == "multihop-libbox" || engine == "external-libbox" && entryBundleData != nil {
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
        self.nodeChainSource = nodeChainSource
        self.nodeChainExecutionSource = nodeChainExecutionSource
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
        var chain: Data?, execution: Data?
        if let source = configuration["nodeChainExecutionSource"] {
            guard let input = source as? String else { throw Self.invalid() }
            execution = Data(input.utf8)
        }
        if let source = configuration["nodeChainSource"] {
            guard let input = source as? String, !input.isEmpty, input.utf8.count <= 40 * 1024 * 1024,
                  let value = try JSONSerialization.jsonObject(with: Data(input.utf8)) as? [String: Any],
                  ![3, 4].contains(value["schema"] as? Int ?? 0) else { throw Self.invalid() }
            chain = Data(input.utf8)
        }
        if let source = configuration["nodeChainSOCKSSource"] {
            guard chain == nil, execution == nil, let input = source as? String, !input.isEmpty, input.utf8.count <= 40 * 1024 * 1024,
                  let value = try JSONSerialization.jsonObject(with: Data(input.utf8)) as? [String: Any],
                  value["schema"] as? Int == 3 else { throw Self.invalid() }
            chain = Data(input.utf8)
        }
        if let source = configuration["nodeChainCONNECTSource"] {
            guard chain == nil, execution == nil, let input = source as? String, !input.isEmpty, input.utf8.count <= 40 * 1024 * 1024,
                  let value = try JSONSerialization.jsonObject(with: Data(input.utf8)) as? [String: Any],
                  value["schema"] as? Int == 4 else { throw Self.invalid() }
            chain = Data(input.utf8)
        }
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
                      bundleData: bundleData, entryBundleData: entry, nodeChainSource: chain, nodeChainExecutionSource: execution, entryMode: mode)
    }

    /// This is a private equality identity, not a native proof. The complete
    /// ordinary source is recompiled before startup; typed restore authority
    /// stays in PacketTunnel and is never reconstructed from these bytes.
    private static func executionSource(_ data: Data) -> Bool {
        guard !data.isEmpty, data.count <= 40 * 1024 * 1024,
              let launch = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(launch.keys) == Set(["kind", "schema", "source", "source_sha256", "config_sha256"]),
              launch["kind"] as? String == "routervpn-node-chain-execution-preparation-input", launch["schema"] as? Int == 1,
              let digest = launch["source_sha256"] as? String, let config = launch["config_sha256"] as? String,
              [digest, config].allSatisfy({ $0.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil }),
              let input = launch["source"] as? String,
              let source = try? JSONSerialization.jsonObject(with: Data(input.utf8)) as? [String: Any],
              Set(source.keys) == Set(["schema", "execution", "local_source"]), source["schema"] as? Int == 1,
              ["server", "auto"].contains(source["execution"] as? String ?? ""),
              let raw = source["local_source"] as? String,
              let local = try? JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any],
              Set(local.keys) == Set(["schema", "execution", "nodes", "identity_sources"]),
              local["execution"] as? String == "local",
              let nodes = local["nodes"] as? [String], let identities = local["identity_sources"] as? [String],
              (2...8).contains(nodes.count), identities.count == nodes.count,
              let schema = local["schema"] as? Int, schema == 1 || schema == 2 && nodes.count == 3 else { return false }
        // Schema two retains one imported SS member at its original middle
        // position. Its empty paired-identity slot is intentional; accepting
        // the same exception for an entry/final or a paired source is not.
        for (position, input) in nodes.enumerated() {
            guard !input.isEmpty,
                  let member = try? JSONSerialization.jsonObject(with: Data(input.utf8)) as? [String: Any],
                  member["schema"] as? Int == 1 else { return false }
            if schema == 2 && position == 1 {
                guard member["kind"] as? String == "routervpn-node-chain-imported-member",
                      identities[position].isEmpty else { return false }
            } else {
                guard member["kind"] as? String == "routervpn-node-launch-input",
                      !identities[position].isEmpty else { return false }
            }
        }
        return true
    }

    private static func invalid() -> NSError {
        NSError(domain: "RouterVPN.SessionIdentity", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "The active tunnel's exact session/configuration identity is unavailable."])
    }
}
