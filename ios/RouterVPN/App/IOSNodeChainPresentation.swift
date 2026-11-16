import Foundation
import CoreFoundation

/// Public map fields projected from the selected record or the running
/// session's captured source. This projection never authorizes a connection.
struct IOSNodePathPoint: Equatable {
    let id: String
    let name: String
    let location: String
    let latitude: Double?
    let longitude: Double?
    let kind: String
    let mode: String?
    let savedLatency: Double?

    init(_ profile: RouterProfile, mode: String? = nil) {
        id = profile.id; name = profile.name.isEmpty ? profile.id : profile.name
        location = profile.location ?? profile.endpoint
        latitude = profile.latitude; longitude = profile.longitude
        kind = profile.normalizedNodeKind; self.mode = mode
        savedLatency = profile.latencyMedianMs
    }

    var hasCoordinates: Bool {
        guard let latitude, let longitude else { return false }
        return latitude.isFinite && longitude.isFinite && (-90...90).contains(latitude) &&
            (-180...180).contains(longitude) && !(latitude == 0 && longitude == 0)
    }
}

enum IOSNodeChainPresentation {
    /// Testing identifies only the original prepared members. The remainder
    /// of the displayed saved path has no test or ordinary proof authority.
    static func candidateLabel(id: String, path: [IOSNodePathPoint]?, testing: Set<String>?) -> String? {
        guard let testing, path?.contains(where: { $0.id == id }) == true else { return nil }
        return testing.contains(id) ? "Testing" : "Saved"
    }

    private static func boolean(_ value: Any?) -> Bool? {
        guard let value = value as? NSNumber, CFGetTypeID(value) == CFBooleanGetTypeID() else { return nil }
        return value.boolValue
    }
    private struct Launch: Decodable {
        let schema: Int
        let kind: String
        let execution: String
        let nodes: [String]
        let source_sha256: String
        let config_sha256: String
        let original_config_sha256: String
        let target_os: String?
        let projection_kind: String?
        let session_id: String?
        let restored_mtu: Int?
    }
    private struct Member: Decodable {
        let schema: Int
        let kind: String
        let mode: String?
        let profile_json: String?
        let capture: String?
    }

    static func planned(selected: RouterProfile?, catalog: [RouterProfile]) -> [IOSNodePathPoint]? {
        guard let selected, selected.multihopEnabled == true, let nodes = selected.multihopNodes,
              (try? IOSMultihopNodeSelection.validate(nodes, execution: selected.multihopExecution,
                entryID: selected.multihopEntryID, entryMode: selected.multihopEntryMode,
                exitID: selected.multihopExitID, exitMode: selected.multihopExitMode, controlID: selected.id)) != nil else { return nil }
        var points: [IOSNodePathPoint] = []
        for (position, node) in nodes.enumerated() {
            let matches = catalog.filter { $0.id == node.id }
            guard matches.count == 1, let profile = matches.first,
                  (profile.normalizedNodeKind == "router-vpn" && profile.external == nil &&
                   (position == nodes.count - 1 ? node.mode == "shadowsocks" || node.mode == "hysteria2" &&
                    ["", "off"].contains(profile.startLayer ?? "") &&
                    points.allSatisfy({ $0.kind == "router-vpn" && IOSMultihopNodeSelection.supportsNativePrefix($0.mode ?? "") }) : IOSMultihopNodeSelection.supportsNativePrefix(node.mode)) ||
                   IOSMultihopNodeSelection.supportsImportedMiddle(node.mode, position: position, count: nodes.count) && (node.mode == "shadowsocks" && IOSImportedShadowsocksSource.eligible(profile) || node.mode == "socks5" && IOSImportedSOCKSSource.eligible(profile) || node.mode == profile.external?.protocolName && (IOSImportedCONNECTSource.eligible(profile) || IOSImportedOpenVPNSource.eligible(profile)))) else { return nil }
            points.append(IOSNodePathPoint(profile, mode: node.mode))
        }
        return points
    }

    static func active(_ identity: IOSSessionIdentity?) -> [IOSNodePathPoint]? {
        guard let identity, identity.engine == "multihop-libbox" else { return nil }
        if let input = identity.nodeChainExecutionSource {
            guard let launch = try? JSONSerialization.jsonObject(with: input) as? [String: Any],
                  let kind = launch["kind"] as? String,
                  let raw = launch["source"] as? String,
                  let preparation = try? JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any],
                  let requested = preparation["execution"] as? String, ["server", "auto"].contains(requested),
                  let source = preparation["local_source"] as? String else { return nil }
            let path: [IOSNodePathPoint]?
            if kind == "routervpn-node-chain-connect-execution-preparation-input", preparation["schema"] as? Int == 4 {
                path = capturedCONNECT(source: Data(source.utf8), bundleData: identity.bundleData, selectionExecution: requested)
            } else if kind == "routervpn-node-chain-socks-execution-preparation-input", preparation["schema"] as? Int == 3 {
                path = capturedSOCKS(source: Data(source.utf8), bundleData: identity.bundleData, selectionExecution: requested)
            } else if kind == "routervpn-node-chain-execution-preparation-input", preparation["schema"] as? Int == 1 {
                path = capturedGenericExecution(source: Data(source.utf8), bundleData: identity.bundleData, selectionExecution: requested)
            } else { return nil }
            guard let path, identity.rawProfile == path.last?.mode else { return nil }
            return path
        }
        guard let source = identity.nodeChainSource,
              let path = captured(source: source, bundleData: identity.bundleData),
              identity.rawProfile == path.last?.mode else { return nil }
        return path
    }

    static func captured(source: Data, bundleData: Data) -> [IOSNodePathPoint]? {
        guard !source.isEmpty, source.count <= 40 * 1024 * 1024 else { return nil }
        if let root = try? JSONSerialization.jsonObject(with: source) as? [String: Any], root["schema"] as? Int == 4 {
            return capturedCONNECT(source: source, bundleData: bundleData)
        }
        if let root = try? JSONSerialization.jsonObject(with: source) as? [String: Any], root["schema"] as? Int == 3 {
            return capturedSOCKS(source: source, bundleData: bundleData)
        }
        guard !source.isEmpty, source.count <= 40 * 1024 * 1024,
              !bundleData.isEmpty, bundleData.count <= 32 * 1024 * 1024,
              let bundle = try? JSONDecoder().decode(ClientBundle.self, from: bundleData),
              bundle.routerProfiles.filter({ $0.id == bundle.selectedRouterID }).count == 1,
              let control = bundle.routerProfiles.first(where: { $0.id == bundle.selectedRouterID }),
              let launch = try? JSONDecoder().decode(Launch.self, from: source),
              (launch.schema == 1 || (launch.schema == 2 || launch.schema == 5) && launch.nodes.count >= 3), launch.kind == "routervpn-node-chain-launch-input", launch.execution == "local",
              launch.target_os == nil, launch.projection_kind == nil, launch.session_id == nil, launch.restored_mtu == nil,
              launch.source_sha256.range(of: "\\A[0-9a-f]{64}\\z", options: .regularExpression) != nil,
              launch.config_sha256.range(of: "\\A[0-9a-f]{64}\\z", options: .regularExpression) != nil,
              launch.original_config_sha256 == launch.config_sha256, (2...8).contains(launch.nodes.count) else { return nil }
        var profiles: [RouterProfile] = [], nodes: [IOSMultihopNodeSelection] = []
        for (position,raw) in launch.nodes.enumerated() {
            guard let member = try? JSONDecoder().decode(Member.self, from: Data(raw.utf8)), member.schema == 1 else { return nil }
            let profile: RouterProfile, mode: String
            if member.kind == "routervpn-node-chain-imported-member" || member.kind == "routervpn-node-chain-openvpn-member" {
                let openVPN = member.kind == "routervpn-node-chain-openvpn-member"
                guard launch.schema == (openVPN ? 5 : 2), IOSMultihopNodeSelection.supportsImportedMiddle(openVPN ? "openvpn" : "shadowsocks", position: position, count: launch.nodes.count),
                      let raw=member.capture, raw.utf8.count<=8*1024*1024,
                      let capture=(try? JSONSerialization.jsonObject(with:Data(raw.utf8))) as? [String:Any],
                      let saved=capture["profile"], let data=try? JSONSerialization.data(withJSONObject:saved),
                      let source=try? JSONDecoder().decode(RouterProfile.self,from:data), (openVPN ? IOSImportedOpenVPNSource.eligible(source) : IOSImportedShadowsocksSource.eligible(source)) else { return nil }
                profile=source; mode=openVPN ? "openvpn" : "shadowsocks"
            } else {
                guard member.kind == "routervpn-node-launch-input", !((launch.schema == 2 || launch.schema == 5) && position == launch.nodes.count - 2),
                      let raw=member.profile_json, !raw.isEmpty, raw.utf8.count<=256*1024, let transport=member.mode,
                      let source=try? JSONDecoder().decode(RouterProfile.self,from:Data(raw.utf8)) else { return nil }
                profile=source;mode=transport
            }
            profiles.append(profile); nodes.append(.init(id: profile.id, mode: mode))
        }
        guard profiles.last == control, control.multihopNodes == nodes else { return nil }
        return planned(selected: control, catalog: profiles)
    }

    private static func capturedGenericExecution(source: Data, bundleData: Data, selectionExecution: String) -> [IOSNodePathPoint]? {
        guard !source.isEmpty, source.count <= 40 * 1024 * 1024, !bundleData.isEmpty, bundleData.count <= 32 * 1024 * 1024,
              let root = try? JSONSerialization.jsonObject(with: source) as? [String: Any],
              Set(root.keys) == Set(["schema", "execution", "nodes", "identity_sources"]),
              let schema = root["schema"] as? Int, schema == 1 || schema == 2,
              root["execution"] as? String == "local", let inputs = root["nodes"] as? [String],
              (2...8).contains(inputs.count), schema == 1 || inputs.count >= 3,
              let identities = root["identity_sources"] as? [String], identities.count == inputs.count,
              identities.enumerated().allSatisfy({ schema == 2 && $0.offset == inputs.count - 2 ? $0.element.isEmpty : !$0.element.isEmpty }),
              let bundle = try? JSONDecoder().decode(ClientBundle.self, from: bundleData),
              bundle.routerProfiles.filter({ $0.id == bundle.selectedRouterID }).count == 1,
              let control = bundle.routerProfiles.first(where: { $0.id == bundle.selectedRouterID }) else { return nil }
        var profiles: [RouterProfile] = [], nodes: [IOSMultihopNodeSelection] = []
        for (position, input) in inputs.enumerated() {
            guard let member = try? JSONDecoder().decode(Member.self, from: Data(input.utf8)), member.schema == 1 else { return nil }
            let profile: RouterProfile, mode: String
            if schema == 2 && position == inputs.count - 2 {
                guard member.kind == "routervpn-node-chain-imported-member", let raw = member.capture,
                      let capture = try? JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any],
                      let saved = capture["profile"], let data = try? JSONSerialization.data(withJSONObject: saved),
                      let value = try? JSONDecoder().decode(RouterProfile.self, from: data), IOSImportedShadowsocksSource.eligible(value) else { return nil }
                profile = value; mode = "shadowsocks"
            } else {
                guard member.kind == "routervpn-node-launch-input", let raw = member.profile_json, let selected = member.mode,
                      let value = try? JSONDecoder().decode(RouterProfile.self, from: Data(raw.utf8)),
                      value.normalizedNodeKind == "router-vpn", value.external == nil else { return nil }
                profile = value; mode = selected
            }
            profiles.append(profile); nodes.append(.init(id: profile.id, mode: mode))
        }
        guard let last = profiles.last, IOSMultihopNodeSelection.supportsGenericExecution(nodes),
              control.multihopNodes == nodes, control.multihopExecution == selectionExecution else { return nil }
        var expected = control; expected.startupMode = nil; expected.autoConnect = nil
        guard last == expected else { return nil }
        return planned(selected: control, catalog: profiles)
    }

    private static func capturedSOCKS(source: Data, bundleData: Data, selectionExecution: String = "local") -> [IOSNodePathPoint]? {
        guard !source.isEmpty, source.count <= 40 * 1024 * 1024, !bundleData.isEmpty, bundleData.count <= 32 * 1024 * 1024,
              let root = try? JSONSerialization.jsonObject(with: source) as? [String: Any],
              Set(root.keys) == Set(["schema", "execution", "nodes", "identity_sources"]), root["schema"] as? Int == 3,
              root["execution"] as? String == "local", let inputs = root["nodes"] as? [String], (3...8).contains(inputs.count),
              ["local", "server", "auto"].contains(selectionExecution),
              let identities = root["identity_sources"] as? [String], identities.count == inputs.count,
              identities.enumerated().allSatisfy({ $0.offset == inputs.count - 2 ? $0.element.isEmpty : !$0.element.isEmpty }),
              let bundle = try? JSONDecoder().decode(ClientBundle.self, from: bundleData),
              bundle.routerProfiles.filter({ $0.id == bundle.selectedRouterID }).count == 1,
              let control = bundle.routerProfiles.first(where: { $0.id == bundle.selectedRouterID }) else { return nil }
        var profiles: [RouterProfile] = [], nodes: [IOSMultihopNodeSelection] = []
        for (position, input) in inputs.enumerated() {
            guard let member = try? JSONDecoder().decode(Member.self, from: Data(input.utf8)), member.schema == 1 else { return nil }
            let profile: RouterProfile, mode: String
            if position == inputs.count - 2 {
                guard member.kind == "routervpn-node-chain-socks-member", let raw = member.capture,
                      let capture = try? JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any],
                      let saved = capture["profile"], let data = try? JSONSerialization.data(withJSONObject: saved),
                      let value = try? JSONDecoder().decode(RouterProfile.self, from: data), IOSImportedSOCKSSource.eligible(value) else { return nil }
                profile = value; mode = "socks5"
            } else {
                guard member.kind == "routervpn-node-launch-input", let raw = member.profile_json, let selected = member.mode,
                      let value = try? JSONDecoder().decode(RouterProfile.self, from: Data(raw.utf8)) else { return nil }
                profile = value; mode = selected
            }
            profiles.append(profile); nodes.append(.init(id: profile.id, mode: mode))
        }
        guard let last = profiles.last, control.multihopNodes == nodes, control.multihopExecution == selectionExecution else { return nil }
        var expected = control
        if selectionExecution != "local" { expected.startupMode = nil; expected.autoConnect = nil }
        guard last == expected else { return nil }
        return planned(selected: control, catalog: profiles)
    }

    private static func capturedCONNECT(source: Data, bundleData: Data, selectionExecution: String = "local") -> [IOSNodePathPoint]? {
        guard !source.isEmpty, source.count <= 40 * 1024 * 1024, !bundleData.isEmpty, bundleData.count <= 32 * 1024 * 1024,
              let root = try? JSONSerialization.jsonObject(with: source) as? [String: Any],
              Set(root.keys) == Set(["schema", "execution", "nodes", "identity_sources"]), root["schema"] as? Int == 4,
              root["execution"] as? String == "local", let inputs = root["nodes"] as? [String], (3...8).contains(inputs.count),
              ["local", "server", "auto"].contains(selectionExecution),
              let identities = root["identity_sources"] as? [String], identities.count == inputs.count,
              identities.enumerated().allSatisfy({ $0.offset == inputs.count - 2 ? $0.element.isEmpty : !$0.element.isEmpty }),
              let bundle = try? JSONDecoder().decode(ClientBundle.self, from: bundleData),
              bundle.routerProfiles.filter({ $0.id == bundle.selectedRouterID }).count == 1,
              let control = bundle.routerProfiles.first(where: { $0.id == bundle.selectedRouterID }) else { return nil }
        var profiles: [RouterProfile] = [], nodes: [IOSMultihopNodeSelection] = []
        for (position, input) in inputs.enumerated() {
            guard let member = try? JSONDecoder().decode(Member.self, from: Data(input.utf8)), member.schema == 1 else { return nil }
            let profile: RouterProfile, mode: String
            if position == inputs.count - 2 {
                guard member.kind == "routervpn-node-chain-connect-member", let raw = member.capture,
                      let capture = try? JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any],
                      let saved = capture["profile"], let data = try? JSONSerialization.data(withJSONObject: saved),
                      let value = try? JSONDecoder().decode(RouterProfile.self, from: data), IOSImportedCONNECTSource.eligible(value) else { return nil }
                profile = value; mode = value.external!.protocolName
            } else {
                guard member.kind == "routervpn-node-launch-input", let raw = member.profile_json, let selected = member.mode,
                      let value = try? JSONDecoder().decode(RouterProfile.self, from: Data(raw.utf8)) else { return nil }
                profile = value; mode = selected
            }
            profiles.append(profile); nodes.append(.init(id: profile.id, mode: mode))
        }
        guard let last = profiles.last, control.multihopNodes == nodes, control.multihopExecution == selectionExecution else { return nil }
        var expected = control
        if selectionExecution != "local" { expected.startupMode = nil; expected.autoConnect = nil }
        guard last == expected else { return nil }
        return planned(selected: control, catalog: profiles)
    }

    /// Progress durations are initial, routed private HTTP verifications.
    /// Periodic health renewals do not publish fresh RTT samples here.
    static func progress(_ value: [String: Any], expected: [String], requestedExecution: String = "local") -> String? {
        guard (2...8).contains(expected.count), Set(expected).count == expected.count,
              ["local", "server", "auto"].contains(requestedExecution),
              let execution = value["execution"] as? String,
              (requestedExecution == "auto" ? ["local", "server"].contains(execution) : execution == requestedExecution),
              let stage = value["stage"] as? String, ["verifying", "selected", "closed"].contains(stage),
              let rows = value["prefixes"] as? [[String: Any]], rows.count <= expected.count else { return nil }
        var lines = ["Ordered route • \(execution == "server" ? "Server" : "Local") • \(stage)"]
        for (position, row) in rows.enumerated() {
            guard let reported = row["position"] as? NSNumber, CFGetTypeID(reported) != CFBooleanGetTypeID(),
                  reported.doubleValue == Double(position), row["profile_id"] as? String == expected[position],
                  boolean(row["proven"]) == true,
                  let response = row["response_ms"] as? NSNumber, CFGetTypeID(response) != CFBooleanGetTypeID(),
                  response.doubleValue.isFinite, response.doubleValue > 0 else { return nil }
            let role = position == 0 ? "Entry" : position == expected.count - 1 ? "Exit" : "Hop \(position)"
            let publicPath = row["kind"] as? String == "public-path"
            guard row["kind"] == nil || publicPath && expected.count >= 3 && position == expected.count - 2 || row["kind"] as? String == "private-node" else { return nil }
            lines.append(String(format: publicPath ? "%@ · %@: public path via custom node %.1f ms" : "%@ · %@: verification HTTP response %.1f ms", role, expected[position], response.doubleValue))
        }
        if rows.count < expected.count { lines.append("Verified \(rows.count) of \(expected.count) nodes") }
        if boolean(value["dns_proven"]) == true { lines.append("Final-path DNS verified") }
        if boolean(value["public_proven"]) == true { lines.append("Final public exit verified") }
        if boolean(value["ready"]) == true && boolean(value["complete"]) == true && rows.count == expected.count && boolean(value["dns_proven"]) == true && boolean(value["public_proven"]) == true {
            lines.append("Every captured node and final path verified")
        } else if stage == "selected" { lines.append("The captured path is not currently ready") }
        if stage == "closed" { lines.append("Captured path is closed") }
        return lines.joined(separator: "\n")
    }
}

@MainActor
extension RouterVPNModel {
    var iosVisibleOrderedNodePath: [IOSNodePathPoint]? {
        if connected && !iosCandidateTesting { return IOSNodeChainPresentation.active(activeSessionIdentity) }
        return IOSNodeChainPresentation.planned(selected: selectedNodeProfile, catalog: allNodeProfiles)
    }

    var iosMapNodePoints: [IOSNodePathPoint] {
        var points = allNodeProfiles.map { IOSNodePathPoint($0) }
        for captured in iosVisibleOrderedNodePath ?? [] {
            if let index = points.firstIndex(where: { $0.id == captured.id }) { points[index] = captured }
            else { points.append(captured) }
        }
        return points
    }
}
