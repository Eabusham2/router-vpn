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
    let deviceMTU: IOSDeviceMTUPreference
    let runtimeEpoch: String?
    struct SelectedMeasurementSource: Equatable, Sendable {
        let source: String, config: String, requested: String
        let ids: [String]
        let privateStreamPositions: Set<Int>
    }
    let selectedMeasurementSource: SelectedMeasurementSource?
    let hopMeasurementRows: Int
    private static let physicalTraversalDepth = 96

    init(connectedAt: Date, engine: String, rawProfile: String,
         bundleData: Data, entryBundleData: Data?, nodeChainSource: Data? = nil, nodeChainExecutionSource: Data? = nil, providerSession: String? = nil,
         runtimeEpoch: String? = nil, entryMode: String? = nil, deviceMTU: IOSDeviceMTUPreference = .initial) throws {
        guard ["wireguard", "libbox", "external-libbox", "multihop-libbox"].contains(engine),
              !rawProfile.isEmpty, rawProfile.utf8.count <= 128,
              !bundleData.isEmpty, bundleData.count <= 32 * 1024 * 1024 else {
            throw Self.invalid()
        }
        guard nodeChainSource == nil || nodeChainExecutionSource == nil else { throw Self.invalid() }
        var capturedRows = 8, selectedSource: SelectedMeasurementSource?
        if let nodeChainExecutionSource {
            guard engine == "multihop-libbox", ["shadowsocks", "hysteria2"].contains(rawProfile), entryBundleData == nil, entryMode == nil,
                  Self.executionSource(nodeChainExecutionSource, rawProfile: rawProfile, capturedRows: &capturedRows, selectedSource: &selectedSource) else { throw Self.invalid() }
        } else if let nodeChainSource {
            guard engine == "multihop-libbox", entryBundleData == nil, entryMode == nil,
                  !nodeChainSource.isEmpty, nodeChainSource.count <= 40 * 1024 * 1024,
                  let source = try JSONSerialization.jsonObject(with: nodeChainSource) as? [String: Any],
                  (source["kind"] as? String == "routervpn-node-chain-launch-input" ||
                   Set(source.keys) == Set(["schema", "execution", "nodes", "identity_sources"]) &&
                   (source["schema"] as? Int == 3 && (3...8).contains((source["nodes"] as? [String])?.count ?? 0) ||
                    source["schema"] as? Int == 4 && (3...8).contains((source["nodes"] as? [String])?.count ?? 0))), source["execution"] as? String == "local",
                  source["projection_kind"] == nil, source["session_id"] == nil, source["target_os"] == nil, source["restored_mtu"] == nil,
                  let nodes = source["nodes"] as? [String], (2...Self.physicalTraversalDepth).contains(nodes.count) else { throw Self.invalid() }
            if nodes.count > 8 || source["schema"] as? Int == 8 {
                guard rawProfile == "shadowsocks", Self.extendedLocalMembers(source, nodes: nodes) else { throw Self.invalid() }
                if nodes.count > 8 { capturedRows = nodes.count }
            }
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
        self.selectedMeasurementSource = selectedSource
        self.hopMeasurementRows = capturedRows
        self.connectedAt = connectedAt
        self.engine = engine
        self.rawProfile = rawProfile
        self.bundleData = bundleData
        self.entryBundleData = entryBundleData
        self.nodeChainSource = nodeChainSource
        self.nodeChainExecutionSource = nodeChainExecutionSource
        self.entryMode = entryMode
        self.providerSession = providerSession
        self.deviceMTU = deviceMTU
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
                      bundleData: bundleData, entryBundleData: entry, nodeChainSource: chain, nodeChainExecutionSource: execution, entryMode: mode, deviceMTU: IOSDeviceMTUPreference.decode(configuration[IOSDeviceMTUPreference.key]))
    }

    /// This is a private equality identity, not a native proof. The complete
    /// ordinary source is recompiled before startup; typed restore authority
    /// stays in PacketTunnel and is never reconstructed from these bytes.
    private static func executionSource(_ data: Data, rawProfile: String, capturedRows: inout Int, selectedSource: inout SelectedMeasurementSource?) -> Bool {
        guard !data.isEmpty, data.count <= 40 * 1024 * 1024,
              let launch = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(launch.keys) == Set(["kind", "schema", "source", "source_sha256", "config_sha256"]),
              let kind = launch["kind"] as? String, launch["schema"] as? Int == 1,
              let digest = launch["source_sha256"] as? String, let config = launch["config_sha256"] as? String,
              [digest, config].allSatisfy({ $0.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil }),
              let input = launch["source"] as? String,
              let source = try? JSONSerialization.jsonObject(with: Data(input.utf8)) as? [String: Any] else { return false }
        let preparationSchema: Int, sealedField: String?
        switch kind {
        case "routervpn-node-chain-execution-preparation-input": (preparationSchema, sealedField) = (1, nil)
        case "routervpn-node-chain-socks-execution-preparation-input": (preparationSchema, sealedField) = (3, nil)
        case "routervpn-node-chain-connect-execution-preparation-input": (preparationSchema, sealedField) = (4, nil)
        case "routervpn-node-chain-openvpn-execution-preparation-input": (preparationSchema, sealedField) = (5, "openvpn_local_launch")
        case "routervpn-node-chain-multiple-imported-execution-preparation-input": (preparationSchema, sealedField) = (6, "multiple_imported_local_launch")
        default: return false
        }
        let keys = ["schema", "execution", "local_source"] + (sealedField.map { [$0] } ?? [])
        guard Set(source.keys) == Set(keys), source["schema"] as? Int == preparationSchema,
              ["server", "auto"].contains(source["execution"] as? String ?? ""),
              let raw = source["local_source"] as? String,
              let local = try? JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any],
              Set(local.keys) == Set(["schema", "execution", "nodes", "identity_sources"]),
              local["execution"] as? String == "local",
              let nodes = local["nodes"] as? [String], let identities = local["identity_sources"] as? [String],
              (2...8).contains(nodes.count) || preparationSchema == 6 && (9...Self.physicalTraversalDepth).contains(nodes.count), identities.count == nodes.count,
              let schema = local["schema"] as? Int,
              preparationSchema == 1 ? (schema == 1 || schema == 2 && nodes.count >= 3) : (schema == preparationSchema && nodes.count >= 3),
              schema != 6 || rawProfile == "shadowsocks" else { return false }
        var selectedPrivateStreams = Set<Int>()
        if let sealedField {
            // Bind both representations of every private member and independent
            // identity before retaining the complete original launch for replay.
            guard let input = source[sealedField] as? String,
                  !input.isEmpty, input.utf8.count <= 40 * 1024 * 1024,
                  let sealed = try? JSONSerialization.jsonObject(with: Data(input.utf8)) as? [String: Any],
                  Set(sealed.keys) == Set(["kind", "schema", "execution", "nodes", "identity_sources", "source_sha256", "config_sha256", "metadata_sha256", "original_config_sha256"]),
                  sealed["kind"] as? String == "routervpn-node-chain-launch-input",
                  sealed["schema"] as? Int == schema, sealed["execution"] as? String == "local",
                  let sealedNodes = sealed["nodes"] as? [String], let sealedIdentities = sealed["identity_sources"] as? [String],
                  sealedNodes.elementsEqual(nodes, by: { $0.utf8.elementsEqual($1.utf8) }),
                  sealedIdentities.elementsEqual(identities, by: { $0.utf8.elementsEqual($1.utf8) }),
                  ["source_sha256", "config_sha256", "metadata_sha256", "original_config_sha256"].allSatisfy({ key in
                      guard let value = sealed[key] as? String else { return false }
                      return value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
                  }) else { return false }
            if schema == 6 {
                let privateStreams = nodes.indices.dropFirst().dropLast().filter { position in
                    guard !identities[position].isEmpty,
                          let member = try? JSONSerialization.jsonObject(with: Data(nodes[position].utf8)) as? [String: Any] else { return false }
                    return member["mode"] as? String == "shadowsocks"
                }
                if !privateStreams.isEmpty {
                    guard !privateStreams.contains(1), Self.extendedLocalMembers(sealed, nodes: nodes, selected: true) else { return false }
                    for (i, text) in nodes.enumerated() {
                        guard let member = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] else { return false }
                        if identities[i].isEmpty {
                            guard let raw = member["capture"] as? String,
                                  let capture = try? JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any],
                                  capture["protocol"] as? String == "shadowsocks", let profile = capture["profile"] as? [String: Any],
                                  ["", "off"].contains(profile["start_layer"] as? String ?? ""), let external = profile["external"] as? [String: Any],
                                  let transport = external["shadowsocks"] as? [String: Any], let host = transport["server"] as? String else { return false }
                            var v4 = in_addr(), v6 = in6_addr()
                            guard !host.utf8.contains(0), inet_pton(AF_INET, host, &v4) == 1 || inet_pton(AF_INET6, host, &v6) == 1 else { return false }
                        } else {
                            guard let layer = member["start"] as? String, ["", "off"].contains(layer) else { return false }
                        }
                    }
                    selectedPrivateStreams = Set(privateStreams)
                }
            }
            if nodes.count > 8 {
                guard Self.extendedLocalMembers(sealed, nodes: nodes, selected: true), let requested = source["execution"] as? String else { return false }
                var ids: [String] = []
                for (position, raw) in nodes.enumerated() {
                    guard let member = try? JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any] else { return false }
                    let profile: [String: Any]?
                    if !identities[position].isEmpty {
                        guard let layer = member["start"] as? String, ["", "off"].contains(layer),
                              let rawProfile = member["profile_json"] as? String else { return false }
                        profile = try? JSONSerialization.jsonObject(with: Data(rawProfile.utf8)) as? [String: Any]
                    } else {
                        guard let rawCapture = member["capture"] as? String,
                              let capture = try? JSONSerialization.jsonObject(with: Data(rawCapture.utf8)) as? [String: Any],
                              capture["protocol"] as? String == "shadowsocks" else { return false }
                        profile = capture["profile"] as? [String: Any]
                    }
                    guard let profile, let id = profile["id"] as? String,
                          id.range(of: #"\A[A-Za-z0-9_-]{1,64}\z"#, options: .regularExpression) != nil,
                          ["", "off"].contains(profile["start_layer"] as? String ?? "") else { return false }
                    ids.append(id)
                }
                guard Set(ids).count == ids.count else { return false }
                selectedSource = SelectedMeasurementSource(source: digest, config: config, requested: requested, ids: ids, privateStreamPositions: selectedPrivateStreams)
                capturedRows = nodes.count
            }
        }
        // Schema two retains one imported SS member at its original penultimate
        // position. Its empty paired-identity slot is intentional; accepting
        // the same exception for an entry/final or a paired source is not.
        var hasImportedInterior = false
        for (position, input) in nodes.enumerated() {
            guard !input.isEmpty,
                  let member = try? JSONSerialization.jsonObject(with: Data(input.utf8)) as? [String: Any],
                  member["schema"] as? Int == 1 else { return false }
            if schema == 6 && member["kind"] as? String == "routervpn-node-chain-imported-member" {
                guard position > 0, position < nodes.count - 1, identities[position].isEmpty,
                      Set(member.keys) == Set(["kind", "schema", "config", "capture"]),
                      let config = member["config"] as? String, !config.isEmpty,
                      let capture = member["capture"] as? String, !capture.isEmpty else { return false }
                hasImportedInterior = true
            } else if (schema == 2 || schema == 3 || schema == 4 || schema == 5) && position == nodes.count - 2 {
                guard member["kind"] as? String == (schema == 5 ? "routervpn-node-chain-openvpn-member" : schema == 3 ? "routervpn-node-chain-socks-member" : schema == 4 ? "routervpn-node-chain-connect-member" : "routervpn-node-chain-imported-member"),
                      identities[position].isEmpty else { return false }
            } else {
                guard member["kind"] as? String == "routervpn-node-launch-input",
                      !identities[position].isEmpty else { return false }
                if position == nodes.count - 1 {
                    guard member["mode"] as? String == rawProfile else { return false }
                } else if schema == 6 {
                    guard selectedPrivateStreams.contains(position) ? member["mode"] as? String == "shadowsocks" :
                          ["wg", "awg2-fast", "awg2-strong"].contains(member["mode"] as? String ?? "") else { return false }
                }
                if rawProfile == "hysteria2" {
                    guard schema == 1 else { return false }
                    if position == nodes.count - 1 {
                        guard let raw = member["profile_json"] as? String,
                              let profile = try? JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any],
                              profile["start_layer"] == nil || (profile["start_layer"] as? String).map({ ["", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"].contains($0) }) == true else { return false }
                    } else {
                        guard selectedPrivateStreams.contains(position) ? member["mode"] as? String == "shadowsocks" :
                          ["wg", "awg2-fast", "awg2-strong"].contains(member["mode"] as? String ?? "") else { return false }
                    }
                }
            }
        }
        return schema != 6 || hasImportedInterior
    }

    // A session has the private launch record, not a profile editor or live
    // native handle. Check each original member's concrete family before
    // retaining the wider reply budget for this immutable session.
    private static func extendedLocalMembers(_ source: [String: Any], nodes: [String], selected: Bool = false) -> Bool {
        guard let schema = source["schema"] as? Int, schema == 6 || schema == 1 || schema == 8, source["kind"] as? String == "routervpn-node-chain-launch-input",
              let identities = source["identity_sources"] as? [String], identities.count == nodes.count else { return false }
        guard !selected || schema == 6 else { return false }
        if schema == 8 {
            guard (3...physicalTraversalDepth).contains(nodes.count), !identities[0].isEmpty,
                  identities.dropFirst().allSatisfy({ $0.isEmpty }) else { return false }
            return nodes.enumerated().allSatisfy { index, raw in
                guard let row = try? JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any] else { return false }
                if index == 0 { return row["kind"] as? String == "routervpn-node-launch-input" && row["mode"] as? String == "wg" }
                let kind = index == nodes.count-1 ? "routervpn-node-chain-external-final" : "routervpn-node-chain-imported-member"
                guard row["kind"] as? String == kind, let bytes = row["capture"] as? String,
                      let capture = try? JSONSerialization.jsonObject(with: Data(bytes.utf8)) as? [String:Any],
                      capture["protocol"] as? String == "shadowsocks", let profile = capture["profile"] as? [String:Any],
                      profile["node_kind"] as? String == "external", profile["id"] as? String == capture["exit_id"] as? String else { return false }
                return true
            }
        }
        var packets = 0, hasStream = false, hasImport = false
        var entryMode: String?
        for (index, text) in nodes.enumerated() {
            guard let member = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] else { return false }
            if identities[index].isEmpty {
                guard schema == 6, packets > 0, index < nodes.count - 1,
                      member["kind"] as? String == "routervpn-node-chain-imported-member" else { return false }
                hasStream = true; hasImport = true
                continue
            }
            guard member["kind"] as? String == "routervpn-node-launch-input", let mode = member["mode"] as? String,
                  let raw = member["profile_json"] as? String,
                  let profile = try? JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any],
                  profile["node_kind"] as? String == "router-vpn", profile["external"] == nil,
                  profile["start_layer"] == nil || (profile["start_layer"] as? String).map({ ["", "off"].contains($0) }) == true else { return false }
            if index == nodes.count - 1 {
                guard mode == "shadowsocks" else { return false }
            } else if mode == "shadowsocks" {
                if selected {
                    guard index >= 2, packets == 1, ["wg", "awg2-fast", "awg2-strong"].contains(entryMode ?? ""), hasImport else { return false }
                }
                guard schema == 6, packets > 0, let id = profile["node_proof_id"] as? String, !id.isEmpty else { return false }
                hasStream = true
            } else {
                let permitted = !selected && schema == 1 ? ["wg"] : ["wg", "awg2-fast", "awg2-strong"]
                guard !hasStream, permitted.contains(mode) else { return false }
                if index == 0 { entryMode = mode }
                packets += 1
            }
        }
        return packets > 0 && (schema == 1 || hasImport) && (!selected || packets == 1)
    }

    private static func invalid() -> NSError {
        NSError(domain: "RouterVPN.SessionIdentity", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "The active tunnel's exact session/configuration identity is unavailable."])
    }
}

/// Device-local policy shared by the app and its PacketTunnel. A change back to
/// per-profile mode gets a fresh revision so an earlier fixed launch cannot
/// regain ownership through a disconnect or permission dialog.
struct IOSDeviceMTUPreference: Equatable, Sendable {
    static let key = "routervpn_device_mtu_v1"
    static let initial = Self(revision: "", value: 0)
    let revision: String
    let value: Int
    var token: String? { revision.isEmpty ? nil : "\(revision):\(value)" }

    private static func issue() -> NSError {
        NSError(domain: "RouterVPN.DeviceMTU", code: 1, userInfo: [NSLocalizedDescriptionKey:
            "The device MTU setting changed or could not be verified. Reopen Settings or reconnect from Router VPN."])
    }
    static func decode(_ raw: Any?) throws -> Self {
        guard let raw else { return .initial }
        guard let text = raw as? String, text.utf8.count <= 38 else { throw issue() }
        let parts = text.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 2, parts[0].utf8.count == 32,
              parts[0].utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              let value = Int(parts[1]), String(value) == parts[1],
              value == 0 || (1280...9000).contains(value) else { throw issue() }
        return Self(revision: String(parts[0]), value: value)
    }
    private static func defaults() throws -> UserDefaults {
        guard let store = UserDefaults(suiteName: "group.com.eabusham.routervpn") else { throw issue() }
        return store
    }
    static func current() throws -> Self {
        let store = try defaults()
        guard store.synchronize() else { throw issue() }
        return try decode(store.object(forKey: key))
    }
    func historyFingerprint(_ source: String, digest: (Data) -> String) -> String {
        guard let token else { return source }
        return digest(Data(("routervpn-device-mtu-v1\0" + source + "\0" + token).utf8))
    }
    func requireCurrent() throws {
        guard self == (try Self.current()) else { throw Self.issue() }
    }
    func require(_ configuration: [String: Any]?) throws {
        guard let configuration, self == (try Self.decode(configuration[Self.key])) else { throw Self.issue() }
        try requireCurrent()
    }
    @MainActor func save(value: Int) throws -> Self {
        try requireCurrent()
        guard value == 0 || (1280...9000).contains(value) else { throw Self.issue() }
        let new = Self(revision: UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased(), value: value)
        let store = try Self.defaults()
        store.set(new.token, forKey: Self.key)
        try new.requireCurrent()
        return new
    }
}
