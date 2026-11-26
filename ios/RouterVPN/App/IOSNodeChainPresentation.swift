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

    // Call only for a validated visible ordered path. A temporary candidate
    // tunnel shows the saved request. A live Compare winner comes exclusively
    // from the provider's observation for this exact NetworkExtension session.
    static func executionTitle(saved: String?, running: Bool, identity: IOSSessionIdentity?,
                               observed: (identity: IOSSessionIdentity, requested: String, selected: String)?) -> String {
        if running {
            if identity?.nodeChainSource != nil { return "Local" }
            guard let identity, identity.nodeChainExecutionSource != nil, let observed,
                  observed.identity == identity, ["local", "server"].contains(observed.selected),
                  observed.requested == "auto" || observed.requested == observed.selected else { return "Checking execution" }
            let winner = observed.selected == "server" ? "Server" : "Local"
            return observed.requested == "auto" ? "Compare • \(winner) selected" : winner
        }
        switch saved {
        case "local": return "Local"
        case "server": return "Server"
        case "auto": return "Compare"
        default: return "Execution unavailable"
        }
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
        let identity_sources: [String]?
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
        let publicExit = IOSMultihopNodeSelection.externalExitReferences(nodes, controlID: selected.id, execution: selected.multihopExecution)
        let independentImports = !publicExit && IOSMultihopNodeSelection.usesIndependentImports(nodes, execution: selected.multihopExecution)
        let importedEntry = IOSMultihopNodeSelection.usesLocalImportedEntry(nodes)
        let streams = IOSMultihopNodeSelection.localStreamLayout(nodes, execution: selected.multihopExecution, profiles: catalog)
        let pairedStreams = streams?.paired ?? []
        var points: [IOSNodePathPoint] = []
        for (position, node) in nodes.enumerated() {
            let matches = catalog.filter { $0.id == node.id }
            guard matches.count == 1, let profile = matches.first,
                  (profile.normalizedNodeKind == "router-vpn" && profile.external == nil && (!publicExit || position == 0) &&
                   (position == nodes.count - 1 ? node.mode == "shadowsocks" || node.mode == "hysteria2" &&
                    ["", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"].contains(profile.startLayer ?? "") &&
                    points.allSatisfy({ $0.kind == "router-vpn" && IOSMultihopNodeSelection.supportsNativePrefix($0.mode ?? "") }) : IOSMultihopNodeSelection.supportsNativePrefix(node.mode) || pairedStreams.contains(position)) ||
                   (publicExit ? position > 0 && IOSImportedShadowsocksSource.eligibleLiteral(profile) : independentImports ? IOSMultihopNodeSelection.supportsLocalImportedNode(node.mode, position: position, count: nodes.count, importedEntry: importedEntry) && IOSImportedShadowsocksSource.eligibleIndependent(profile, position: position, hostnamePosition: streams?.hostname) : IOSMultihopNodeSelection.supportsImportedMiddle(node.mode, position: position, count: nodes.count)) && (node.mode == "shadowsocks" && IOSImportedShadowsocksSource.eligible(profile) || node.mode == "socks5" && IOSImportedSOCKSSource.eligible(profile) || node.mode == profile.external?.protocolName && (IOSImportedCONNECTSource.eligible(profile) || IOSImportedOpenVPNSource.eligible(profile)))) else { return nil }
            if publicExit && position == 0 {
                guard IOSMultihopNodeSelection.supportsExternalExitEntry(profile) else { return nil }
            } else if nodes.count > IOSMultihopNodeSelection.maximumNodes {
                if IOSMultihopNodeSelection.supportsNativePrefix(node.mode) || position == nodes.count - 1 && !publicExit || pairedStreams.contains(position) {
                    guard profile.normalizedNodeKind == "router-vpn", [nil, "", "off"].contains(profile.startLayer) else { return nil }
                } else {
                    guard IOSImportedShadowsocksSource.eligibleIndependent(profile, position: position, hostnamePosition: streams?.hostname) else { return nil }
                }
            }
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
            if kind == "routervpn-node-chain-external-final-execution-preparation-input", preparation["schema"] as? Int == 8 {
                guard Set(preparation.keys) == Set(["schema", "execution", "local_source", "external_final_local_launch"]),
                      let original = preparation["external_final_local_launch"] as? String else { return nil }
                path = captured(source: Data(original.utf8), bundleData: identity.bundleData, externalFinalExecution: requested)
            } else if kind == "routervpn-node-chain-multiple-imported-execution-preparation-input", preparation["schema"] as? Int == 6 {
                guard Set(preparation.keys) == Set(["schema", "execution", "local_source", "multiple_imported_local_launch"]),
                      let rawLocal = preparation["multiple_imported_local_launch"] as? String,
                      let sealed = try? JSONSerialization.jsonObject(with: Data(rawLocal.utf8)) as? [String: Any],
                      let original = try? JSONSerialization.jsonObject(with: Data(source.utf8)) as? [String: Any],
                      sealed["kind"] as? String == "routervpn-node-chain-launch-input", sealed["schema"] as? Int == 6,
                      sealed["execution"] as? String == "local", sealed["nodes"] as? [String] == original["nodes"] as? [String],
                      sealed["identity_sources"] as? [String] == original["identity_sources"] as? [String] else { return nil }
                path = capturedGenericExecution(source: Data(source.utf8), bundleData: identity.bundleData, selectionExecution: requested, multipleImported: true)
            } else if kind == "routervpn-node-chain-connect-execution-preparation-input", preparation["schema"] as? Int == 4 {
                path = capturedCONNECT(source: Data(source.utf8), bundleData: identity.bundleData, selectionExecution: requested)
            } else if kind == "routervpn-node-chain-socks-execution-preparation-input", preparation["schema"] as? Int == 3 {
                path = capturedSOCKS(source: Data(source.utf8), bundleData: identity.bundleData, selectionExecution: requested)
            } else if kind == "routervpn-node-chain-openvpn-execution-preparation-input", preparation["schema"] as? Int == 5 {
                path = capturedOpenVPNExecution(source: Data(source.utf8), bundleData: identity.bundleData, selectionExecution: requested)
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

    static func captured(source: Data, bundleData: Data, externalFinalExecution: String? = nil) -> [IOSNodePathPoint]? {
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
              externalFinalExecution == nil || (launch.schema == 8 && externalFinalExecution == control.multihopExecution && ["server","auto"].contains(externalFinalExecution ?? "")),
              (launch.schema == 1 || (launch.schema == 2 || launch.schema == 5 || launch.schema == 6 || launch.schema == 8) && launch.nodes.count >= 3 || launch.schema == 7 && launch.nodes.count == 3), launch.kind == "routervpn-node-chain-launch-input", launch.execution == "local",
              launch.target_os == nil, launch.projection_kind == nil, launch.session_id == nil, launch.restored_mtu == nil,
              launch.source_sha256.range(of: "\\A[0-9a-f]{64}\\z", options: .regularExpression) != nil,
              launch.config_sha256.range(of: "\\A[0-9a-f]{64}\\z", options: .regularExpression) != nil,
              launch.original_config_sha256 == launch.config_sha256, (2...8).contains(launch.nodes.count) || IOSMultihopNodeSelection.extendedLocalSource(launch.schema, execution: externalFinalExecution == nil ? control.multihopExecution : launch.execution, count: launch.nodes.count, identities: launch.identity_sources, allowPairedStreams: control.multihopExecution == "local") else { return nil }
        if launch.schema == 7 {
            guard let identities = launch.identity_sources, identities.count == 3, identities[0].isEmpty,
                  identities[1].isEmpty, !identities[2].isEmpty, control.multihopExecution == "local" else { return nil }
        }
        var profiles: [RouterProfile] = [], nodes: [IOSMultihopNodeSelection] = []
        for (position,raw) in launch.nodes.enumerated() {
            guard let member = try? JSONDecoder().decode(Member.self, from: Data(raw.utf8)), member.schema == 1 else { return nil }
            let profile: RouterProfile, mode: String
            let publicExit = member.kind == "routervpn-node-chain-external-final"
            if publicExit || member.kind == "routervpn-node-chain-imported-member" || member.kind == "routervpn-node-chain-openvpn-member" {
                let openVPN = member.kind == "routervpn-node-chain-openvpn-member"
                guard publicExit == (launch.schema == 8 && position == launch.nodes.count-1), (launch.schema == 8 ? position > 0 && !openVPN : (launch.schema == 6 || launch.schema == 7) ? !openVPN && IOSMultihopNodeSelection.supportsLocalImportedNode("shadowsocks", position: position, count: launch.nodes.count, importedEntry: launch.schema == 7) : launch.schema == (openVPN ? 5 : 2) && IOSMultihopNodeSelection.supportsImportedMiddle(openVPN ? "openvpn" : "shadowsocks", position: position, count: launch.nodes.count)),
                      let raw=member.capture, raw.utf8.count<=8*1024*1024,
                      let capture=(try? JSONSerialization.jsonObject(with:Data(raw.utf8))) as? [String:Any],
                      let saved=capture["profile"], let data=try? JSONSerialization.data(withJSONObject:saved),
                      let source=try? JSONDecoder().decode(RouterProfile.self,from:data), (launch.schema == 8 ? IOSImportedShadowsocksSource.eligibleLiteral(source) : openVPN ? IOSImportedOpenVPNSource.eligible(source) : ((launch.schema == 6 || launch.schema == 7) ? IOSImportedShadowsocksSource.eligibleIndependent(source, position: position, hostnamePosition: launch.schema == 6 && IOSMultihopNodeSelection.permitsHostnamePosition(control.multihopNodes ?? [], execution: control.multihopExecution, position: position) ? position : nil) : IOSImportedShadowsocksSource.eligible(source))) else { return nil }
                profile=source; mode=openVPN ? "openvpn" : "shadowsocks"
            } else {
                guard launch.schema != 8 || position == 0, !(launch.schema == 7 && position < 2), member.kind == "routervpn-node-launch-input", !((launch.schema == 2 || launch.schema == 5) && position == launch.nodes.count - 2),
                      let raw=member.profile_json, !raw.isEmpty, raw.utf8.count<=256*1024, let transport=member.mode,
                      let source=try? JSONDecoder().decode(RouterProfile.self,from:Data(raw.utf8)) else { return nil }
                profile=source;mode=transport
            }
            if launch.nodes.count > IOSMultihopNodeSelection.maximumNodes {
                guard launch.identity_sources?[position].isEmpty == (profile.normalizedNodeKind == "external") else { return nil }
            }
            profiles.append(profile); nodes.append(.init(id: profile.id, mode: mode))
        }
        var expectedControl = control
        if externalFinalExecution != nil { expectedControl.startupMode = nil; expectedControl.autoConnect = nil }
        guard launch.schema != 7 || IOSMultihopNodeSelection.usesLocalImportedEntry(nodes), (launch.schema == 8 ? profiles.first : profiles.last) == expectedControl, control.multihopNodes == nodes else { return nil }
        return planned(selected: control, catalog: profiles)
    }

    private static func capturedOpenVPNExecution(source: Data, bundleData: Data, selectionExecution: String) -> [IOSNodePathPoint]? {
        guard !source.isEmpty, source.count <= 40 * 1024 * 1024, !bundleData.isEmpty, bundleData.count <= 32 * 1024 * 1024,
              let root = try? JSONSerialization.jsonObject(with: source) as? [String: Any],
              Set(root.keys) == Set(["schema", "execution", "nodes", "identity_sources"]),
              let schema = root["schema"] as? Int, schema == 5,
              root["execution"] as? String == "local", let inputs = root["nodes"] as? [String],
              (3...8).contains(inputs.count),
              let identities = root["identity_sources"] as? [String], identities.count == inputs.count,
              identities.enumerated().allSatisfy({ schema == 5 && $0.offset == inputs.count - 2 ? $0.element.isEmpty : !$0.element.isEmpty }),
              let bundle = try? JSONDecoder().decode(ClientBundle.self, from: bundleData),
              bundle.routerProfiles.filter({ $0.id == bundle.selectedRouterID }).count == 1,
              let control = bundle.routerProfiles.first(where: { $0.id == bundle.selectedRouterID }) else { return nil }
        var profiles: [RouterProfile] = [], nodes: [IOSMultihopNodeSelection] = []
        for (position, input) in inputs.enumerated() {
            guard let member = try? JSONDecoder().decode(Member.self, from: Data(input.utf8)), member.schema == 1 else { return nil }
            let profile: RouterProfile, mode: String
            if schema == 5 && position == inputs.count - 2 {
                guard member.kind == "routervpn-node-chain-openvpn-member", let raw = member.capture,
                      let capture = try? JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any],
                      let saved = capture["profile"], let data = try? JSONSerialization.data(withJSONObject: saved),
                      let value = try? JSONDecoder().decode(RouterProfile.self, from: data), IOSImportedOpenVPNSource.eligible(value), value.external?.openVPNPairing != nil else { return nil }
                profile = value; mode = "openvpn"
            } else {
                guard member.kind == "routervpn-node-launch-input", let raw = member.profile_json, let selected = member.mode,
                      let value = try? JSONDecoder().decode(RouterProfile.self, from: Data(raw.utf8)),
                      value.normalizedNodeKind == "router-vpn", value.external == nil else { return nil }
                profile = value; mode = selected
            }
            profiles.append(profile); nodes.append(.init(id: profile.id, mode: mode))
        }
        guard let last = profiles.last, IOSMultihopNodeSelection.supportsOpenVPNExecution(nodes),
              control.multihopNodes == nodes, control.multihopExecution == selectionExecution else { return nil }
        var expected = control; expected.startupMode = nil; expected.autoConnect = nil
        guard last == expected else { return nil }
        return planned(selected: control, catalog: profiles)
    }

    private static func capturedGenericExecution(source: Data, bundleData: Data, selectionExecution: String, multipleImported: Bool = false) -> [IOSNodePathPoint]? {
        guard !source.isEmpty, source.count <= 40 * 1024 * 1024, !bundleData.isEmpty, bundleData.count <= 32 * 1024 * 1024,
              let root = try? JSONSerialization.jsonObject(with: source) as? [String: Any],
              Set(root.keys) == Set(["schema", "execution", "nodes", "identity_sources"]),
              let schema = root["schema"] as? Int, multipleImported ? schema == 6 : (schema == 1 || schema == 2),
              root["execution"] as? String == "local", let inputs = root["nodes"] as? [String],
              let identities = root["identity_sources"] as? [String], identities.count == inputs.count,
              (2...8).contains(inputs.count) || multipleImported && IOSMultihopNodeSelection.extendedLocalSource(schema, execution: "local", count: inputs.count, identities: identities, selectedPrivateStream: true), schema == 1 || inputs.count >= 3,
              multipleImported || identities.enumerated().allSatisfy({ schema == 2 && $0.offset == inputs.count - 2 ? $0.element.isEmpty : !$0.element.isEmpty }),
              let bundle = try? JSONDecoder().decode(ClientBundle.self, from: bundleData),
              bundle.routerProfiles.filter({ $0.id == bundle.selectedRouterID }).count == 1,
              let control = bundle.routerProfiles.first(where: { $0.id == bundle.selectedRouterID }) else { return nil }
        var profiles: [RouterProfile] = [], nodes: [IOSMultihopNodeSelection] = []
        for (position, input) in inputs.enumerated() {
            guard let member = try? JSONDecoder().decode(Member.self, from: Data(input.utf8)), member.schema == 1 else { return nil }
            let profile: RouterProfile, mode: String
            if (schema == 2 && position == inputs.count - 2) || (multipleImported && member.kind == "routervpn-node-chain-imported-member") {
                guard position > 0, position < inputs.count - 1, identities[position].isEmpty, member.kind == "routervpn-node-chain-imported-member", let raw = member.capture,
                      let capture = try? JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any],
                      let saved = capture["profile"], let data = try? JSONSerialization.data(withJSONObject: saved),
                      let value = try? JSONDecoder().decode(RouterProfile.self, from: data), (multipleImported ? IOSImportedShadowsocksSource.eligibleLiteral(value) : IOSImportedShadowsocksSource.eligible(value)) else { return nil }
                profile = value; mode = "shadowsocks"
            } else {
                guard !identities[position].isEmpty, member.kind == "routervpn-node-launch-input", let raw = member.profile_json, let selected = member.mode,
                      let value = try? JSONDecoder().decode(RouterProfile.self, from: Data(raw.utf8)),
                      value.normalizedNodeKind == "router-vpn", value.external == nil else { return nil }
                profile = value; mode = selected
            }
            profiles.append(profile); nodes.append(.init(id: profile.id, mode: mode))
        }
        guard let last = profiles.last, (multipleImported ? IOSMultihopNodeSelection.supportsMultipleImportedExecution(nodes) : IOSMultihopNodeSelection.supportsGenericExecution(nodes)),
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
    static func progress(_ value: [String: Any], expected: [String], requestedExecution: String = "local", expectedPublicPositions: Set<Int>? = nil, capturedExtendedCount: Int = 0) -> String? {
        guard (2...8).contains(expected.count) || (9...IOSMultihopNodeSelection.physicalTraversalDepth).contains(expected.count) && expected.count == capturedExtendedCount && expectedPublicPositions != nil, Set(expected).count == expected.count,
              ["local", "server", "auto"].contains(requestedExecution),
              let execution = value["execution"] as? String,
              let stage = value["stage"] as? String,
              ["pending", "verifying", "starting", "probing", "stopping", "measured", "activating", "activation-failed", "selected", "failed", "closed"].contains(stage),
              requestedExecution == "auto" ? (["local", "server"].contains(execution) || execution == "auto" && boolean(value["ready"]) != true) : execution == requestedExecution else { return nil }
        let rows: [[String: Any]]
        if let prefixes = value["prefixes"] as? [[String: Any]] { rows = prefixes }
        else if value["prefixes"] is NSNull && boolean(value["ready"]) != true { rows = [] }
        else { return nil }
        guard rows.count <= expected.count else { return nil }
        let ready = stage == "selected" && boolean(value["ready"]) == true && boolean(value["complete"]) == true
            && rows.count == expected.count && boolean(value["dns_proven"]) == true && boolean(value["public_proven"]) == true
        let lane = execution == "server" ? "Server" : execution == "local" ? "Local" : "Waiting"
        let title = requestedExecution == "auto" ? "Compare • \(lane)\(ready ? " selected" : "")" : lane
        var lines = [requestedExecution == "auto" && ready ? "Ordered route • \(title)" : "Ordered route • \(title) • \(stage)"]
        for (position, row) in rows.enumerated() {
            guard let reported = row["position"] as? NSNumber, CFGetTypeID(reported) != CFBooleanGetTypeID(),
                  reported.doubleValue == Double(position), row["profile_id"] as? String == expected[position],
                  boolean(row["proven"]) == true,
                  let response = row["response_ms"] as? NSNumber, CFGetTypeID(response) != CFBooleanGetTypeID(),
                  response.doubleValue.isFinite, response.doubleValue > 0 else { return nil }
            let role = position == 0 ? "Entry" : position == expected.count - 1 ? "Exit" : "Hop \(position)"
            let publicPath = row["kind"] as? String == "public-path"
            if let expectedPublicPositions {
                guard (expected.count == 3 && expectedPublicPositions == Set([0, 1]) && requestedExecution == "local" || expected.count >= 3 && expectedPublicPositions == Set(1..<expected.count) || expectedPublicPositions.allSatisfy({ $0 > 0 && $0 < expected.count - 1 })),
                      publicPath == expectedPublicPositions.contains(position),
                      publicPath || row["kind"] == nil || row["kind"] as? String == "private-node" else { return nil }
            } else {
                guard row["kind"] == nil || publicPath && expected.count >= 3 && position == expected.count - 2 || row["kind"] as? String == "private-node" else { return nil }
            }
            lines.append(String(format: publicPath ? "%@ · %@: public path via custom node %.1f ms" : "%@ · %@: verification HTTP response %.1f ms", role, expected[position], response.doubleValue))
        }
        if rows.count < expected.count { lines.append("Verified \(rows.count) of \(expected.count) nodes") }
        if boolean(value["dns_proven"]) == true { lines.append("Final-path DNS verified") }
        if boolean(value["public_proven"]) == true { lines.append("Final public exit verified") }
        if ready {
            lines.append("Every captured node and final path verified")
            if requestedExecution == "auto" {
                lines.append(contentsOf: comparisonLines(value["comparison"], expected: expected, execution: execution))
            }
        } else if stage == "selected" { lines.append("The captured path is not currently ready") }
        if stage == "closed" { lines.append("Captured path is closed") }
        return lines.joined(separator: "\n")
    }

    /// Display the original comparison receipts, never an inferred total or a stale score.
    private static func comparisonLines(_ value: Any?, expected: [String], execution: String) -> [String] {
        let unavailable = ["Comparison trial scores unavailable for this captured route"]
        func lane(_ value: Any?) -> String? {
            guard let candidate = value as? [String: Any],
                  candidate["transport"] as? String == "ordered-node-chain",
                  candidate["entry_id"] as? String == expected.first,
                  candidate["exit_id"] as? String == expected.last,
                  let execution = candidate["execution"] as? String,
                  ["local", "server"].contains(execution) else { return nil }
            return execution
        }
        func positive(_ value: Any?) -> Double? {
            guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
                  number.doubleValue.isFinite, number.doubleValue > 0 else { return nil }
            return number.doubleValue
        }
        guard let comparison = value as? [String: Any], lane(comparison["winner"]) == execution,
              let target = comparison["target"] as? String, !target.isEmpty,
              let rows = comparison["measurements"] as? [[String: Any]], rows.count == 2 else { return unavailable }
        var lines: [String] = ["Comparison trial scores"]
        var seen = Set<String>()
        for row in rows {
            guard let candidate = lane(row["candidate"]), seen.insert(candidate).inserted,
                  let eligible = boolean(row["eligible"]) else { return unavailable }
            let name = candidate == "server" ? "Server" : "Local"
            if eligible {
                guard let last = positive(row["last_node_ms"]), let external = positive(row["external_ms"]),
                      let score = positive(row["score_ms"]), abs(score - (last / 2 + external / 2)) <= max(0.000001, score * 0.000001) else { return unavailable }
                lines.append(String(format: "%@: (last node %.1f + external %.1f) / 2 = %.1f ms", name, last, external, score))
            } else {
                guard candidate != execution else { return unavailable }
                lines.append("\(name): rejected — no valid comparison score")
            }
        }
        return lines
    }
}

@MainActor
extension RouterVPNModel {
    var iosVisibleOrderedNodePath: [IOSNodePathPoint]? {
        if connected && !iosCandidateTesting { return IOSNodeChainPresentation.active(activeSessionIdentity) }
        return IOSNodeChainPresentation.planned(selected: selectedNodeProfile, catalog: allNodeProfiles)
    }

    /// Legacy pairs have independently captured entry and exit bundles. Only
    /// the map uses this projection; ordered-route controls retain their own source.
    var iosVisibleMapPath: [IOSNodePathPoint]? {
        if let path = iosVisibleOrderedNodePath { return path }
        guard connected, !iosCandidateTesting, let identity = activeSessionIdentity,
              ["multihop-libbox", "external-libbox"].contains(identity.engine),
              identity.nodeChainSource == nil, identity.nodeChainExecutionSource == nil,
              let entryData = identity.entryBundleData,
              let entry = try? JSONDecoder().decode(ClientBundle.self, from: entryData),
              let exit = try? JSONDecoder().decode(ClientBundle.self, from: identity.bundleData),
              entry.selectedRouterID != exit.selectedRouterID,
              entry.routerProfiles.filter({ $0.id == entry.selectedRouterID }).count == 1,
              exit.routerProfiles.filter({ $0.id == exit.selectedRouterID }).count == 1,
              let first = entry.routerProfiles.first(where: { $0.id == entry.selectedRouterID }),
              let last = exit.routerProfiles.first(where: { $0.id == exit.selectedRouterID }),
              last.multihopEnabled == true, last.multihopNodes == nil,
              last.multihopEntryID == first.id, last.multihopExitID == last.id else { return nil }
        return [IOSNodePathPoint(first, mode: last.multihopEntryMode), IOSNodePathPoint(last, mode: last.multihopExitMode)]
    }

    var iosMapNodePoints: [IOSNodePathPoint] { iosMapNodePoints(path: iosVisibleMapPath) }

    func iosMapNodePoints(path: [IOSNodePathPoint]?) -> [IOSNodePathPoint] {
        var points = allNodeProfiles.map { IOSNodePathPoint($0) }
        for captured in path ?? [] {
            if let index = points.firstIndex(where: { $0.id == captured.id }) { points[index] = captured }
            else { points.append(captured) }
        }
        return points
    }
}
