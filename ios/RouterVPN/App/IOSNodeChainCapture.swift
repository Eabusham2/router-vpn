import Foundation
import CoreFoundation
import Libbox

/// One private, reproducible native chain source. Compilation creates no
/// system VPN and no live proof. PacketTunnel reopens this exact launch input
/// and retains the resulting plan beside its one original CommandServer.
struct IOSNodeChainCapture {
    struct Member {
        let id: String
        let mode: String
        let profileJSON: String
        let filesJSON: String
        let profile: [String: Any]
    }

    static let maximumInputBytes = 40 * 1024 * 1024
    let plan: LibboxRouterNodeChain
    let launchInput: String
    let members: [Member]
    let strict: Bool
    let homeLANAccess: Bool
    let selectionExecution: String

    var config: String { plan.config() }
    var sourceSHA256: String { plan.sourceSHA256() }
    var configSHA256: String { plan.configSHA256() }
    var finalProfile: [String: Any] { members[members.count - 1].profile }
    var startupTimeout: TimeInterval { TimeInterval(25 + 10 * members.count) }

    static func compile(bundles: [Data]) throws -> Self {
        try compile(bundles: bundles, selectionExecution: "local")
    }

    /// An execution preparation keeps every saved member byte. Its Local
    /// packet graph is source material only; the execution owner gates traffic.
    static func compileOriginalForExecution(bundles: [Data], requested: String) throws -> Self {
        guard requested == "server" || requested == "auto" else { throw issue("Choose the captured Server or Compare execution.") }
        return try compile(bundles: bundles, selectionExecution: requested)
    }

    private static func compile(bundles: [Data], selectionExecution: String) throws -> Self {
        guard (2...8).contains(bundles.count) else { throw issue("Capture every ordered node before compiling the chain.") }
        // The final captured profile owns the exact selected order. It is
        // never inferred from map labels or from the current UI selection.
        let finalRoot = try object(bundles[bundles.count - 1], maximum: 32 * 1024 * 1024)
        guard let finalID = finalRoot["selectedRouterID"] as? String,
              let finalProfiles = finalRoot["routerProfiles"] as? [[String: Any]],
              finalProfiles.filter({ $0["id"] as? String == finalID }).count == 1,
              let final = finalProfiles.first(where: { $0["id"] as? String == finalID }),
              let selection = final["multihop_nodes"] as? [[String: Any]], selection.count == bundles.count else {
            throw issue("The final node lost its exact captured chain selection.")
        }
        var inputs: [String] = [], identitySources: [String] = []
        var imported = false
        for (position, data) in bundles.enumerated() {
            guard !data.isEmpty, data.count <= 32 * 1024 * 1024,
                  let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let selected = root["selectedRouterID"] as? String,
                  let profiles = root["routerProfiles"] as? [[String: Any]],
                  profiles.filter({ $0["id"] as? String == selected }).count == 1,
                  let profile = profiles.first(where: { $0["id"] as? String == selected }),
                  let assets = root["profiles"] as? [String: [String: String]] else {
                throw issue("A selected node lost its complete private bundle.")
            }
            if profile["node_kind"] as? String == "external" {
                let typed = try JSONDecoder().decode(RouterProfile.self, from: JSONSerialization.data(withJSONObject: profile))
                guard bundles.count == 3, position == 1, !imported, IOSImportedShadowsocksSource.eligible(typed),
                      selection[position]["id"] as? String == selected, selection[position]["mode"] as? String == "shadowsocks" else {
                    throw issue("One original imported Shadowsocks 2022 node may sit between the paired first and final nodes.")
                }
                let original = try IOSImportedShadowsocksSource.capture(typed)
                var failure: NSError?
                guard let input: String = LibboxRouterNodeChainImportedMemberInput(original.config, original.capture, &failure), failure == nil else {
                    throw failure ?? issue("The imported intermediate source could not be captured.")
                }
                inputs.append(input); identitySources.append(""); imported = true; continue
            }
            guard selection[position]["id"] as? String == selected,
                  let mode = selection[position]["mode"] as? String,
                  let files = assets[mode], !files.isEmpty,
                  let identity = assets["wg"], !identity.isEmpty else {
                throw issue("A native source no longer matches its captured chain position.")
            }
            // The shared parser validates this independent standard-WG peer
            // against the Router identity. Retain every original byte beside
            // the selected transport, including AWG's separate packet keys.
            identitySources.append(try json(identity, maximum: 16 * 1024 * 1024))
            let layer = try IOSMultihopStartLayer.capture(profile: profile, profiles: assets)
            var start = ""
            if layer.mode != "off", mode != "shadowsocks" {
                guard let source = layer.source,
                      let captured = try object(Data(source.utf8), maximum: IOSMultihopStartLayer.maximumBytes)["profile"] as? [String: String] else {
                    throw issue("A selected chain Start Layer lost its independent original assets.")
                }
                start = try json(captured, maximum: 16 * 1024 * 1024)
            }
            let bootstrap = try profile["dns_bootstrap"].map { try json($0, maximum: 16384) } ?? ""
            // Startup scheduling is owned by the saved app profile, not the
            // forwarding path. Keep full bundle ownership outside this exact
            // private Server/Compare compiler projection.
            let nativeProfile = selectionExecution == "local" ? profile : executionProfile(profile)
            var failure: NSError?
            let input: String? = LibboxRouterNodeChainMemberInput(mode,
                try json(files, maximum: 16 * 1024 * 1024), try json(nativeProfile, maximum: 256 * 1024), start, bootstrap, &failure)
            guard let input, failure == nil, !input.isEmpty else {
                throw failure ?? issue("A selected node could not compile from its original source.")
            }
            inputs.append(input)
        }
        let source = try json(["schema": imported ? 2 : 1, "execution": "local", "nodes": inputs,
                               "identity_sources": identitySources], maximum: maximumInputBytes)
        var failure: NSError?
        guard let plan = LibboxNewRouterNodeChain(source, &failure), failure == nil else {
            throw failure ?? issue("The selected ordered native graph is unavailable.")
        }
        do { return try Self(plan: plan, selectionExecution: selectionExecution) }
        catch { try? plan.close(); throw error }
    }

    static func reopen(_ input: String, selectedProfile: [String: Any]) throws -> Self {
        guard !input.isEmpty, input.utf8.count <= maximumInputBytes else { throw issue("The captured chain exceeds its private launch bound.") }
        var failure: NSError?
        guard let plan = LibboxRouterNodeChainLaunch(input, &failure), failure == nil else {
            throw failure ?? issue("The ordered native source could not be reproduced.")
        }
        do {
            let capture = try Self(plan: plan)
            guard capture.launchInput == input,
                  try json(selectedProfile, maximum: 256 * 1024) == json(capture.finalProfile, maximum: 256 * 1024) else {
                throw issue("The selected final node differs from the chain's original control source.")
            }
            return capture
        } catch { try? plan.close(); throw error }
    }

    // Inspect the retained original source without constructing another native plan.
    init(plan: LibboxRouterNodeChain, selectionExecution: String = "local") throws {
        guard ["local", "server", "auto"].contains(selectionExecution) else { throw Self.issue("The ordered source lost its explicit execution selection.") }
        var failure: NSError?
        let returned: String? = plan.launchInput(&failure)
        guard failure == nil, let launch = returned, !launch.isEmpty else {
            throw failure ?? Self.issue("The native chain returned no private launch source.")
        }
        let root = try Self.object(Data(launch.utf8), maximum: Self.maximumInputBytes)
        guard root["kind"] as? String == "routervpn-node-chain-launch-input", root["execution"] as? String == "local",
              root["projection_kind"] == nil, root["session_id"] == nil, root["target_os"] == nil, root["restored_mtu"] == nil,
              root["source_sha256"] as? String == plan.sourceSHA256(), root["config_sha256"] as? String == plan.configSHA256(),
              root["original_config_sha256"] as? String == plan.configSHA256(),
              let nodes = root["nodes"] as? [String], (2...8).contains(nodes.count),
              let identitySources = root["identity_sources"] as? [String], identitySources.count == nodes.count,
              identitySources.allSatisfy({ $0.utf8.count <= 16 * 1024 * 1024 }),
              let schema = root["schema"] as? Int, schema == 1 || schema == 2 && nodes.count == 3 else {
            throw Self.issue("The native chain returned another source or platform owner.")
        }
        var members: [Member] = [], strict = false, lan = true
        for (position, input) in nodes.enumerated() {
            let node = try Self.object(Data(input.utf8), maximum: Self.maximumInputBytes)
            let mode: String, profileJSON: String, filesJSON: String, profile: [String: Any]
            if node["kind"] as? String == "routervpn-node-chain-imported-member" {
                guard schema == 2, position == 1, nodes.count == 3, identitySources[position].isEmpty,
                      let config = node["config"] as? String, let capture = node["capture"] as? String,
                      let saved = try Self.object(Data(capture.utf8), maximum: 8 * 1024 * 1024)["profile"] as? [String: Any] else {
                    throw Self.issue("The imported intermediate source lost its original external capture.")
                }
                profileJSON = try Self.json(saved, maximum: 256 * 1024)
                let typed = try JSONDecoder().decode(RouterProfile.self, from: Data(profileJSON.utf8))
                guard IOSImportedShadowsocksSource.eligible(typed) else { throw Self.issue("The imported member cannot claim a paired Router identity.") }
                mode = "shadowsocks"; filesJSON = config; profile = saved
            } else {
                guard !identitySources[position].isEmpty, !(schema == 2 && position == 1),
                      let nativeMode = node["mode"] as? String, let saved = node["profile_json"] as? String,
                      let files = node["files"] as? String else { throw Self.issue("A complete native member source is missing.") }
                mode = nativeMode; profileJSON = saved; filesJSON = files
                profile = try Self.object(Data(profileJSON.utf8), maximum: 256 * 1024)
                guard profile["node_kind"] as? String == "router-vpn", profile["external"] == nil else { throw Self.issue("An ordered member is not the captured paired Router node.") }
            }
            guard let id = profile["id"] as? String else { throw Self.issue("The ordered source lost its original profile identity.") }
            let policy = profile["kill_switch_policy"] as? String ?? (profile["kill_switch"] as? Bool == true ? "on-connect" : "off")
            guard ["off", "on-connect", "always"].contains(policy) else { throw Self.issue("A chain member has an unsupported protection policy.") }
            strict = strict || policy != "off" || (profile["kill_switch"] as? Bool == true)
            lan = lan && (profile["home_lan_access"] as? Bool ?? true)
            members.append(Member(id: id, mode: mode, profileJSON: profileJSON, filesJSON: filesJSON, profile: profile))
        }
        guard let final = members.last,
              let enabled = final.profile["multihop_enabled"] as? NSNumber, CFGetTypeID(enabled) == CFBooleanGetTypeID(), enabled.boolValue,
              final.profile["multihop_execution"] as? String == selectionExecution,
              ["multihop_entry_id", "multihop_entry_mode", "multihop_exit_id", "multihop_exit_mode"].allSatisfy({ final.profile[$0] == nil || final.profile[$0] as? String == "" }),
              let selection = final.profile["multihop_nodes"] as? [[String: Any]], selection.count == members.count else {
            throw Self.issue("The chain's final profile lost its explicit ordered execution selection.")
        }
        for (position, member) in members.enumerated() {
            guard Set(selection[position].keys) == Set(["id", "mode"]),
                  selection[position]["id"] as? String == member.id,
                  selection[position]["mode"] as? String == member.mode else {
                throw Self.issue("The original member order or selected transport changed.")
            }
        }
        self.plan = plan; self.launchInput = launch; self.members = members; self.strict = strict; self.homeLANAccess = lan; self.selectionExecution = selectionExecution
    }

    static func executionProfile(_ profile: [String: Any]) -> [String: Any] {
        var result = profile
        result.removeValue(forKey: "startup_mode")
        result.removeValue(forKey: "auto_connect")
        return result
    }

    private static func object(_ data: Data, maximum: Int) throws -> [String: Any] {
        guard !data.isEmpty, data.count <= maximum,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw issue("The private chain source is missing, oversized or malformed.")
        }
        return object
    }
    private static func json(_ object: Any, maximum: Int) throws -> String {
        guard JSONSerialization.isValidJSONObject(object) else { throw issue("The private chain source must be a complete JSON object.") }
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        guard !data.isEmpty, data.count <= maximum else { throw issue("The private chain source exceeds its bound.") }
        return String(decoding: data, as: UTF8.self)
    }
    static func issue(_ text: String) -> NSError {
        NSError(domain: "RouterVPN.NodeChain", code: 2, userInfo: [NSLocalizedDescriptionKey: text])
    }
}
