import Foundation
import Libbox

/// A distinct schema-three source and native owner. This never becomes an
/// ordinary NodeChain, execution preparation, projection or candidate owner.
final class IOSNodeChainSOCKSCapture {
    let plan: LibboxRouterNodeChainSOCKS
    let source: String
    let config: String
    let members: [IOSNodeChainCapture.Member]
    let strict: Bool
    let homeLANAccess: Bool
    var finalProfile: [String: Any] { members[2].profile }
    var startupTimeout: TimeInterval { 75 }
    static let providerKey = "nodeChainSOCKSSource"

    static func compile(bundles: [Data]) throws -> IOSNodeChainSOCKSCapture {
        guard bundles.count == 3 else { throw issue() }
        var inputs: [String] = [], identities: [String] = []
        for (position, data) in bundles.enumerated() {
            let root = try object(data, maximum: 32 * 1024 * 1024)
            guard let id = root["selectedRouterID"] as? String,
                  let profiles = root["routerProfiles"] as? [[String: Any]],
                  profiles.filter({ $0["id"] as? String == id }).count == 1,
                  let profile = profiles.first(where: { $0["id"] as? String == id }),
                  let assets = root["profiles"] as? [String: [String: String]] else { throw issue() }
            let final = try object(bundles[2], maximum: 32 * 1024 * 1024)
            guard let finalID = final["selectedRouterID"] as? String,
                  let finals = final["routerProfiles"] as? [[String: Any]],
                  finals.filter({ $0["id"] as? String == finalID }).count == 1,
                  let control = finals.first(where: { $0["id"] as? String == finalID }),
                  let selected = control["multihop_nodes"] as? [[String: Any]], selected.count == 3,
                  selected[position]["id"] as? String == id, let mode = selected[position]["mode"] as? String else { throw issue() }
            var failure: NSError?
            if position == 1 {
                let typed = try JSONDecoder().decode(RouterProfile.self, from: Data(json(profile).utf8))
                guard mode == "socks5", IOSImportedSOCKSSource.eligible(typed) else { throw issue() }
                let original = try IOSImportedSOCKSSource.capture(typed)
                guard let input: String = LibboxRouterNodeChainImportedSOCKSMemberInput(original.config, original.capture, &failure), failure == nil else { throw failure ?? issue() }
                inputs.append(input); identities.append("")
            } else {
                guard profile["node_kind"] as? String == "router-vpn", profile["external"] == nil,
                      position == 0 ? IOSMultihopNodeSelection.supportsNativePrefix(mode) : mode == "shadowsocks",
                      let files = assets[mode], !files.isEmpty, let identity = assets["wg"], !identity.isEmpty else { throw issue() }
                let layer = try IOSMultihopStartLayer.capture(profile: profile, profiles: assets)
                var start = ""
                if layer.mode != "off", mode != "shadowsocks" {
                    guard let source = layer.source,
                          let captured = try object(Data(source.utf8), maximum: IOSMultihopStartLayer.maximumBytes)["profile"] as? [String: String] else { throw issue() }
                    start = try json(captured)
                }
                let bootstrap = try profile["dns_bootstrap"].map { try json($0) } ?? ""
                guard let input: String = LibboxRouterNodeChainMemberInput(mode, try json(files), try json(profile), start, bootstrap, &failure), failure == nil else { throw failure ?? issue() }
                inputs.append(input); identities.append(try json(identity))
            }
        }
        return try open(json(["schema": 3, "execution": "local", "nodes": inputs, "identity_sources": identities]))
    }

    static func reopen(_ source: String, selectedProfile: [String: Any]) throws -> IOSNodeChainSOCKSCapture {
        let result = try open(source)
        do {
            guard result.source == source, try json(selectedProfile) == json(result.finalProfile) else { throw issue() }
            return result
        } catch { try? result.plan.close(); throw error }
    }

    private static func open(_ source: String) throws -> IOSNodeChainSOCKSCapture {
        guard !source.isEmpty, source.utf8.count <= IOSNodeChainCapture.maximumInputBytes else { throw issue() }
        var failure: NSError?
        let returned = LibboxNewRouterNodeChainSOCKS(source, &failure)
        guard let plan = returned, failure == nil else { try? returned?.close(); throw failure ?? issue() }
        do { return try IOSNodeChainSOCKSCapture(plan: plan) }
        catch { try? plan.close(); throw error }
    }

    private init(plan: LibboxRouterNodeChainSOCKS) throws {
        var failure: NSError?
        let original: String? = plan.source(&failure)
        guard failure == nil, let original else { throw failure ?? Self.issue() }
        let graph: String? = plan.config(&failure)
        guard failure == nil, let graph, !graph.isEmpty, graph.utf8.count <= 4 * 1024 * 1024 else { throw failure ?? Self.issue() }
        let root = try Self.object(Data(original.utf8), maximum: IOSNodeChainCapture.maximumInputBytes)
        guard Set(root.keys) == Set(["schema", "execution", "nodes", "identity_sources"]),
              root["schema"] as? Int == 3, root["execution"] as? String == "local",
              let nodes = root["nodes"] as? [String], nodes.count == 3,
              let identities = root["identity_sources"] as? [String], identities.count == 3,
              !identities[0].isEmpty, identities[1].isEmpty, !identities[2].isEmpty else { throw Self.issue() }
        var members: [IOSNodeChainCapture.Member] = []
        for (position, input) in nodes.enumerated() {
            let node = try Self.object(Data(input.utf8), maximum: IOSNodeChainCapture.maximumInputBytes)
            let profile: [String: Any], mode: String, files: String
            if position == 1 {
                guard node["kind"] as? String == "routervpn-node-chain-socks-member", node["schema"] as? Int == 1,
                      let raw = node["capture"] as? String, let config = node["config"] as? String,
                      let saved = try Self.object(Data(raw.utf8), maximum: 8 * 1024 * 1024)["profile"] as? [String: Any] else { throw Self.issue() }
                let typed = try JSONDecoder().decode(RouterProfile.self, from: Data(Self.json(saved).utf8))
                guard IOSImportedSOCKSSource.eligible(typed) else { throw Self.issue() }
                profile = saved; mode = "socks5"; files = config
            } else {
                guard node["kind"] as? String == "routervpn-node-launch-input", node["schema"] as? Int == 1,
                      let raw = node["profile_json"] as? String, let selected = node["mode"] as? String,
                      let assets = node["files"] as? String,
                      position == 0 ? IOSMultihopNodeSelection.supportsNativePrefix(selected) : selected == "shadowsocks" else { throw Self.issue() }
                profile = try Self.object(Data(raw.utf8), maximum: 256 * 1024)
                guard profile["node_kind"] as? String == "router-vpn", profile["external"] == nil else { throw Self.issue() }
                mode = selected; files = assets
            }
            guard let id = profile["id"] as? String else { throw Self.issue() }
            members.append(.init(id: id, mode: mode, profileJSON: try Self.json(profile), filesJSON: files, profile: profile))
        }
        let final = try JSONDecoder().decode(RouterProfile.self, from: Data(members[2].profileJSON.utf8))
        guard final.multihopEnabled == true, let selected = final.multihopNodes,
              selected == members.map({ .init(id: $0.id, mode: $0.mode) }) else { throw Self.issue() }
        try IOSMultihopNodeSelection.validate(selected, execution: final.multihopExecution,
            entryID: final.multihopEntryID, entryMode: final.multihopEntryMode,
            exitID: final.multihopExitID, exitMode: final.multihopExitMode, controlID: final.id)
        let metadata = try Self.object(Data(plan.metadata().utf8), maximum: 65536)
        guard metadata["kind"] as? String == "routervpn-node-chain-socks-source", metadata["schema"] as? Int == 1,
              metadata["source_sha256"] as? String == plan.sourceSHA256(), metadata["config_sha256"] as? String == plan.configSHA256(),
              plan.sourceSHA256().range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
              plan.configSHA256().range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
              let devices = metadata["devices"] as? [[String: Any]], devices.count == 3 else { throw Self.issue() }
        var strict = false, lan = true
        for (position, device) in devices.enumerated() {
            guard device["position"] as? Int == position, device["profile_id"] as? String == members[position].id,
                  let policy = device["kill_switch_policy"] as? String, ["off", "on-connect", "always"].contains(policy),
                  let allowsLAN = device["home_lan_access"] as? Bool else { throw Self.issue() }
            strict = strict || policy != "off"; lan = lan && allowsLAN
        }
        self.plan = plan; self.source = original; self.config = graph; self.members = members
        self.strict = strict; self.homeLANAccess = lan
    }

    static func reopenProvider(_ configuration: [String: Any]) throws -> IOSNodeChainSOCKSCapture {
        guard configuration["engine"] as? String == "multihop-libbox",
              ["nodeChainCONNECTSource", IOSNodeChainProviderCapture.key, IOSNodeChainProviderCapture.executionKey, "entryBundle", "external_entry_bundle", "external_entry_mode", "tor_entry_bundle", "tor_entry_mode", "strategy", "strategy_catalog", "max_source_sha256"].allSatisfy({ configuration[$0] == nil }),
              let source = configuration[providerKey] as? String,
              let data = configuration["bundle"] as? Data else { throw issue() }
        let root = try object(data, maximum: 32 * 1024 * 1024)
        guard let id = root["selectedRouterID"] as? String, let profiles = root["routerProfiles"] as? [[String: Any]],
              profiles.filter({ $0["id"] as? String == id }).count == 1,
              let profile = profiles.first(where: { $0["id"] as? String == id }) else { throw issue() }
        let capture = try reopen(source, selectedProfile: profile)
        do {
            let final = capture.members[2]
            guard final.id == id, configuration["mode"] as? String == final.mode,
                  configuration["rawProfileID"] as? String == final.mode,
                  configuration["modeCandidates"] as? [String] == [final.mode],
                  let assets = root["profiles"] as? [String: [String: String]], let selected = assets[final.mode],
                  let original = try JSONSerialization.jsonObject(with: Data(final.filesJSON.utf8)) as? [String: String], selected == original else { throw issue() }
            return capture
        } catch { try? capture.plan.close(); throw error }
    }

    private static func object(_ data: Data, maximum: Int) throws -> [String: Any] {
        guard !data.isEmpty, data.count <= maximum, let value = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw issue() }
        return value
    }
    private static func json(_ value: Any) throws -> String {
        let data = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        guard !data.isEmpty, data.count <= IOSNodeChainCapture.maximumInputBytes else { throw issue() }
        return String(decoding: data, as: UTF8.self)
    }
    static func issue() -> NSError { IOSMultihopNodeSelection.issue("The original ordered SOCKS source, policy or native owner changed.") }
}
