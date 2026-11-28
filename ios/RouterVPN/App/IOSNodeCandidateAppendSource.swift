import Foundation
import Libbox

/// A genuine unfinished prefix and its independent device policy. This owner
/// never creates a complete NodeChain or grants a selected-final connection.
struct IOSNodeCandidateAppendSource {
    static let nextModes = IOSMultihopNodeSelection.nativePrefixModes + ["shadowsocks", "hysteria2"]
    static let executionNextModes = ["shadowsocks", "wg", "awg2-fast", "awg2-strong", "hysteria2"]
    static func supportsNextMode(_ mode: String) -> Bool { nextModes.contains(mode) }
    struct NextChoice: Hashable {
        let kind: String, mode: String, execution: String
        init(kind: String, mode: String, execution: String = "local") { self.kind = kind; self.mode = mode; self.execution = execution }
        var title: String {
            if execution != "local" { return IOSMultihopNodeSelection.transportName(mode) + " — " + (execution == "server" ? "Server" : "Compare Local / Server") + " private response" }
            return kind == "external" ? "Shadowsocks — imported public HTTPS" : IOSMultihopNodeSelection.transportName(mode) + " — Local private response"
        }
    }
    static let nextChoices = nextModes.map { NextChoice(kind: "router-vpn", mode: $0) } + [NextChoice(kind: "external", mode: "shadowsocks")]
    static func supportsNext(kind: String, mode: String) -> Bool {
        kind == "router-vpn" && supportsNextMode(mode) || kind == "external" && mode == "shadowsocks"
    }
    static func proxyEntryMode(_ mode: String) -> Bool { ["shadowsocks", "hysteria2"].contains(mode) }
    static func proxyEntry(_ nodes: [IOSMultihopNodeSelection]) -> Bool { proxyEntryMode(nodes.first?.mode ?? "") }
    static func availableNextChoices(proxyEntry: Bool) -> [NextChoice] { nextChoices.filter { !proxyEntry || $0.kind == "router-vpn" } }
    static func supportsNext(kind: String, mode: String, proxyEntry: Bool) -> Bool {
        (!proxyEntry || kind == "router-vpn") && supportsNext(kind: kind, mode: mode)
    }
    // Shape is only a hint; each caller still checks actual paired profiles,
    // and the original native Local source remains the capture authority.
    static func executionSourceSchema(_ modes: [String], nextMode: String) -> Int? {
        guard executionNextModes.contains(nextMode), (1..<IOSMultihopNodeSelection.physicalTraversalDepth).contains(modes.count),
              let first = modes.first, IOSMultihopNodeSelection.supportsNativePrefix(first) else { return nil }
        var hasProxy = false
        for mode in modes {
            if proxyEntryMode(mode) {
                hasProxy = true
            } else if !IOSMultihopNodeSelection.supportsNativePrefix(mode) { return nil }
        }
        return hasProxy ? 2 : 1
    }
    static func permitsExecution(nodes: [IOSMultihopNodeSelection], profiles: [RouterProfile], choice: NextChoice) -> Bool {
        guard supportsNext(kind: choice.kind, mode: choice.mode, proxyEntry: proxyEntry(nodes)) else { return false }
        if choice.execution == "local" { return true }
        guard ["server", "auto"].contains(choice.execution), choice.kind == "router-vpn",
              executionSourceSchema(nodes.map(\.mode), nextMode: choice.mode) != nil, Set(nodes.map(\.id)).count == nodes.count else { return false }
        return nodes.allSatisfy { node in
            let originals = profiles.filter { $0.id == node.id }
            guard originals.count == 1 else { return false }
            let profile = originals[0]
            return profile.normalizedNodeKind == "router-vpn" && profile.external == nil && [nil, "", "off"].contains(profile.startLayer) &&
                IOSImportedShadowsocksSource.literal(profile.endpoint)
        }
    }
    static func availableNextChoices(nodes: [IOSMultihopNodeSelection], profiles: [RouterProfile]) -> [NextChoice] {
        let remote = executionNextModes.flatMap { mode in
            ["server", "auto"].map { NextChoice(kind: "router-vpn", mode: mode, execution: $0) }
        }
        return availableNextChoices(proxyEntry: proxyEntry(nodes)) + remote.filter { permitsExecution(nodes: nodes, profiles: profiles, choice: $0) }
    }
    func requireExecution(_ requested: String) throws {
        try requireDeviceCurrent()
        if requested == "local" { return }
        guard ["server", "auto"].contains(requested), nextKind == "router-vpn",
              let schema = Self.executionSourceSchema(members.map(\.mode), nextMode: nextMode),
              let input = try JSONSerialization.jsonObject(with: Data(source.utf8)) as? [String: Any], input["schema"] as? Int == schema,
              members.allSatisfy({ member in
                  member.profile["node_kind"] as? String == "router-vpn" &&
                  member.profile["external"] == nil && [nil, "", "off"].contains(member.profile["start_layer"] as? String) &&
                  IOSImportedShadowsocksSource.literal(member.profile["endpoint"] as? String ?? "")
              }) else { throw Self.executionIssue() }
    }
    static func executionIssue() -> NSError { NSError(domain: "RouterVPN.CandidateAppendExecution", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Server and Compare require paired literal nodes with Start Layer Off and a WireGuard or AmneziaWG first node. Choose Local explicitly for other prefixes."]) }

    static func measurement(kind: String) -> String {
        kind == "external" ? "routed-public-candidate-response" : kind == "router-vpn" ? "routed-candidate-response" : ""
    }
    let plan: LibboxRouterNodeChainCandidateAppendSource
    let source: String, metadata: String, nextKind: String, measurement: String
    let members: [IOSNodeChainCapture.Member]
    let device: IOSNodeChainCapture.Member
    let deviceMTU: IOSDeviceMTUPreference
    let strict: Bool, homeLANAccess: Bool
    var sourceSHA256: String { plan.sourceSHA256() }
    var configSHA256: String { plan.configSHA256() }
    var config: String { plan.config() }
    var nextMode: String { plan.candidateMode() }
    var metadataSHA256: String { IOSCandidateCatalogPublication.digest(Data(metadata.utf8)) }
    var prefixes: [IOSNodeCandidatePrefix] {
        members.enumerated().map { position, member in
            let last = position == members.count - 1
            return IOSNodeCandidatePrefix(position: position, profile_id: member.id,
                node_id: member.profile["node_proof_id"] as? String ?? "", mode: member.mode,
                measurement: last ? measurement : nil, candidate_mode: last ? nextMode : nil,
                candidate_kind: last && nextKind == "external" ? "external" : nil, purpose: last ? "draft-prefix-append" : nil)
        }
    }

    static func compile(deviceBundle: Data, records: [String: Data], nodes: [IOSMultihopNodeSelection],
                        nextKind: String, nextMode: String, draftRevision: String, deviceRevision: String,
                        deviceMTU: IOSDeviceMTUPreference) throws -> Self {
        guard !nodes.isEmpty, nodes.count < IOSMultihopNodeSelection.physicalTraversalDepth,
              Set(nodes.map(\.id)).count == nodes.count,
              nodes.allSatisfy({ !$0.id.isEmpty }),
              supportsNext(kind: nextKind, mode: nextMode) else { throw issue() }
        let firstProxy = Self.proxyEntry(nodes)
        guard supportsNext(kind: nextKind, mode: nextMode, proxyEntry: firstProxy) else { throw issue() }
        let root = try object(deviceBundle, maximum: 32 * 1024 * 1024)
        guard let selected = root["selectedRouterID"] as? String,
              let profiles = root["routerProfiles"] as? [[String: Any]],
              profiles.filter({ $0["id"] as? String == selected }).count == 1,
              let profile = profiles.first(where: { $0["id"] as? String == selected }),
              let assets = root["profiles"] as? [String: [String: String]] else { throw issue() }
        // These original standard assets carry the control's TUN/settings only.
        // The device's transport is not a prefix member or a candidate endpoint.
        let deviceInput = try memberInput(profile: profile, assets: assets, mode: "wg")
        var inputs: [String] = [], identities: [String] = []
        for (position, node) in nodes.enumerated() {
            let source = try saved(node.id, records: records)
            let typed = try JSONDecoder().decode(RouterProfile.self, from: Data(json(source.profile, maximum: 256 * 1024).utf8))
            guard prefixModes(typed, position: position, proxyEntry: firstProxy).contains(node.mode) else { throw issue() }
            inputs.append(try memberInput(profile: source.profile, assets: source.assets, mode: node.mode))
            if typed.normalizedNodeKind == "external" {
                identities.append("")
            } else {
                guard let identity = source.assets["wg"], !identity.isEmpty else { throw issue() }
                identities.append(try json(identity, maximum: 16 * 1024 * 1024))
            }
        }
        var value: [String: Any] = [
            "kind": "routervpn-node-chain-candidate-append-source", "schema": firstProxy ? 3 : nodes.contains(where: { ["shadowsocks", "hysteria2"].contains($0.mode) }) ? 2 : 1, "execution": "local",
            "draft_revision": draftRevision, "device_revision": deviceRevision, "device_source": deviceInput,
            "next_mode": nextMode, "append_position": nodes.count, "nodes": inputs, "identity_sources": identities
        ]
        if nextKind == "external" { value["next_kind"] = "external" }
        if !deviceMTU.revision.isEmpty { value["device_mtu_revision"] = deviceMTU.revision }
        if deviceMTU.value != 0 { value["device_fixed_mtu"] = deviceMTU.value }
        let request = try json(value, maximum: IOSNodeChainCapture.maximumInputBytes)
        let capture = try Self(input: request)
        guard NSDictionary(dictionary: try object(Data(capture.source.utf8), maximum: IOSNodeChainCapture.maximumInputBytes)).isEqual(to: value),
              capture.deviceMTU == deviceMTU else { throw issue() }
        try capture.requireDeviceCurrent()
        return capture
    }

    static func reopen(_ input: String, selectedProfile: [String: Any]) throws -> Self {
        let value = try Self(input: input)
        guard value.source == input,
              try json(value.device.profile, maximum: 256 * 1024) == json(selectedProfile, maximum: 256 * 1024) else { throw issue() }
        try value.requireDeviceCurrent()
        return value
    }

    init(input: String) throws {
        guard !input.isEmpty, input.utf8.count <= IOSNodeChainCapture.maximumInputBytes else { throw Self.issue() }
        var failure: NSError?
        guard let plan = LibboxNewRouterNodeChainCandidateAppendSource(input, &failure), failure == nil else { throw failure ?? Self.issue() }
        let source = plan.source(), metadata = plan.metadata(), config = plan.config()
        let value = try Self.object(Data(source.utf8), maximum: IOSNodeChainCapture.maximumInputBytes)
        let safe = try Self.object(Data(metadata.utf8), maximum: 256 * 1024)
        let nextKind = plan.candidateKind(), measurement = plan.candidateMeasurement()
        guard value["kind"] as? String == "routervpn-node-chain-candidate-append-source",
              let schema = value["schema"] as? Int, [1, 2, 3].contains(schema), value["execution"] as? String == "local",
              let nodes = value["nodes"] as? [String], !nodes.isEmpty, nodes.count < IOSMultihopNodeSelection.physicalTraversalDepth,
              let identities = value["identity_sources"] as? [String], identities.count == nodes.count,
              let deviceInput = value["device_source"] as? String, let mode = value["next_mode"] as? String,
              Self.supportsNext(kind: nextKind, mode: mode, proxyEntry: schema == 3), mode == plan.candidateMode(),
              measurement == Self.measurement(kind: nextKind),
              nextKind == "external" ? value["next_kind"] as? String == "external" : value["next_kind"] == nil,
              nextKind == "external" ? safe["candidate_kind"] as? String == "external" : safe["candidate_kind"] == nil,
              value["append_position"] as? Int == nodes.count, Int(plan.appendPosition()) == nodes.count,
              safe["schema"] as? Int == 1, safe["purpose"] as? String == "draft-prefix-append",
              safe["source_sha256"] as? String == plan.sourceSHA256(), safe["config_sha256"] as? String == plan.configSHA256(),
              safe["candidate_mode"] as? String == mode, safe["append_position"] as? Int == nodes.count,
              safe["prefix_position"] as? Int == nodes.count - 1,
              [plan.sourceSHA256(), plan.configSHA256()].allSatisfy(IOSCandidateCatalogPublication.isDigest),
              !config.isEmpty, config.utf8.count <= 4 * 1024 * 1024,
              IOSCandidateCatalogPublication.digest(Data(config.utf8)) == plan.configSHA256(),
              safe["application_open"] as? Bool == false, safe["dns_open"] as? Bool == false, safe["ready"] as? Bool == false else { throw Self.issue() }
        for key in ["draft_revision", "device_revision"] {
            guard let expected = value[key] as? String, !expected.isEmpty, safe[key] as? String == expected else { throw Self.issue() }
        }
        let revision = value["device_mtu_revision"] as? String ?? ""
        let mtu = value["device_fixed_mtu"] as? Int ?? 0
        let deviceMTU = try IOSDeviceMTUPreference.decode(revision.isEmpty ? nil : "\(revision):\(mtu)")
        guard safe["device_mtu_revision"] as? String == deviceMTU.revision,
              mtu == deviceMTU.value else { throw Self.issue() }
        let deviceRecord = try Self.object(Data(deviceInput.utf8), maximum: IOSNodeChainCapture.maximumInputBytes)
        guard safe["device_source_sha256"] as? String == deviceRecord["source_sha256"] as? String else { throw Self.issue() }
        let members = try nodes.map(Self.member), device = try Self.member(deviceInput)
        guard device.mode == "wg", device.profile["node_kind"] as? String == "router-vpn", device.profile["external"] == nil,
              schema == (Self.proxyEntryMode(members.first?.mode ?? "") ? 3 : members.contains(where: { ["shadowsocks", "hysteria2"].contains($0.mode) }) ? 2 : 1),
              Set(members.map(\.id)).count == members.count else { throw Self.issue() }
        for (position, member) in members.enumerated() {
            let typed = try JSONDecoder().decode(RouterProfile.self, from: Data(member.profileJSON.utf8))
            guard Self.prefixModes(typed, position: position, proxyEntry: schema == 3).contains(member.mode),
                  identities[position].isEmpty == (typed.normalizedNodeKind == "external") else { throw Self.issue() }
        }
        var protect = false, lan = true
        for member in [device] + members {
            let profile = member.profile
            let policy = profile["kill_switch_policy"] as? String ?? (profile["kill_switch"] as? Bool == true ? "on-connect" : "off")
            guard ["off", "on-connect", "always"].contains(policy) else { throw Self.issue() }
            protect = protect || policy != "off" || (profile["kill_switch"] as? Bool == true)
            lan = lan && (profile["home_lan_access"] as? Bool ?? true)
        }
        self.plan = plan; self.source = source; self.metadata = metadata; self.nextKind = nextKind; self.measurement = measurement
        self.members = members; self.device = device; self.deviceMTU = deviceMTU
        strict = protect; homeLANAccess = lan
    }

    func requireDeviceCurrent() throws {
        try deviceMTU.requireCurrent()
        guard plan.source() == source, plan.metadata() == metadata, plan.candidateKind() == nextKind, plan.candidateMeasurement() == measurement,
              IOSCandidateCatalogPublication.digest(Data(plan.config().utf8)) == plan.configSHA256() else { throw Self.issue() }
    }
    func fits(_ input: String) throws -> Bool {
        try requireDeviceCurrent()
        return LibboxRouterNodeChainCandidateAppendInputFitsSource(plan, input)
    }
    static func saved(_ id: String, records: [String: Data]) throws -> (profile: [String: Any], assets: [String: [String: String]]) {
        var found: ([String: Any], [String: [String: String]])?
        for data in records.values {
            let root = try object(data, maximum: 32 * 1024 * 1024)
            guard let profiles = root["routerProfiles"] as? [[String: Any]], let assets = root["profiles"] as? [String: [String: String]] else { throw issue() }
            for profile in profiles where profile["id"] as? String == id {
                guard found == nil else { throw issue() }
                found = (profile, assets)
            }
        }
        guard let found else { throw issue() }
        return found
    }
    // The original imported capture binds a hostname to explicit Custom TCP
    // DNS. Eligibility is source-only; the append preparation admits answers.
    static func prefixStartModes(_ profile: RouterProfile?) -> [String] {
        prefixModes(profile, position: 0) + prefixModes(profile, position: 0, proxyEntry: true)
    }
    static func prefixModes(_ profile: RouterProfile?, position: Int, proxyEntry: Bool = false) -> [String] {
        guard position >= 0, let profile else { return [] }
        if proxyEntry {
            let modes = position == 0 ? ["shadowsocks", "hysteria2"] : nextModes
            return modes.filter { IOSMultihopNodeSelection.pairedProxyEntryMember(profile, mode: $0) }
        }
        if profile.normalizedNodeKind == "external" {
            return position > 0 && IOSImportedShadowsocksSource.eligible(profile) ? ["shadowsocks"] : []
        }
        guard profile.normalizedNodeKind == "router-vpn", profile.external == nil else { return [] }
        return IOSMultihopNodeSelection.nativePrefixModes +
            (position > 0 && [nil, "", "off"].contains(profile.startLayer) ? ["shadowsocks", "hysteria2"] : [])
    }
    static func memberInput(profile: [String: Any], assets: [String: [String: String]], mode: String) throws -> String {
        if profile["node_kind"] as? String == "external" {
            let typed = try JSONDecoder().decode(RouterProfile.self, from: Data(json(profile, maximum: 256 * 1024).utf8))
            guard mode == "shadowsocks", IOSImportedShadowsocksSource.eligible(typed) else { throw issue() }
            let captured = try IOSImportedShadowsocksSource.capture(typed)
            var failure: NSError?
            let input: String? = LibboxRouterNodeChainImportedMemberInput(captured.config, captured.capture, &failure)
            guard failure == nil, let input, !input.isEmpty else { throw failure ?? issue() }
            return input
        }
        guard profile["node_kind"] as? String == "router-vpn", profile["external"] == nil,
              IOSMultihopNodeSelection.supportsNativePrefix(mode) || ["shadowsocks", "hysteria2"].contains(mode),
              let files = assets[mode], !files.isEmpty else { throw issue() }
        let layer = try IOSMultihopStartLayer.capture(profile: profile, profiles: assets)
        guard !["shadowsocks", "hysteria2"].contains(mode) || layer.mode == "off" else { throw issue() }
        var start = ""
        if layer.mode != "off" {
            guard let source = layer.source,
                  let captured = try object(Data(source.utf8), maximum: IOSMultihopStartLayer.maximumBytes)["profile"] as? [String: String] else { throw issue() }
            start = try json(captured, maximum: 16 * 1024 * 1024)
        }
        let bootstrap = try profile["dns_bootstrap"].map { try json($0, maximum: 16384) } ?? ""
        var failure: NSError?
        let value: String? = LibboxRouterNodeChainMemberInput(mode, try json(files, maximum: 16 * 1024 * 1024),
            try json(profile, maximum: 256 * 1024), start, bootstrap, &failure)
        guard failure == nil, let value, !value.isEmpty else { throw failure ?? issue() }
        return value
    }
    private static func member(_ input: String) throws -> IOSNodeChainCapture.Member {
        let value = try object(Data(input.utf8), maximum: IOSNodeChainCapture.maximumInputBytes)
        if value["kind"] as? String == "routervpn-node-chain-imported-member" {
            guard let config = value["config"] as? String, let capture = value["capture"] as? String,
                  let profile = try object(Data(capture.utf8), maximum: 8 * 1024 * 1024)["profile"] as? [String: Any] else { throw issue() }
            let profileJSON = try json(profile, maximum: 256 * 1024)
            let typed = try JSONDecoder().decode(RouterProfile.self, from: Data(profileJSON.utf8))
            guard IOSImportedShadowsocksSource.eligible(typed) else { throw issue() }
            return IOSNodeChainCapture.Member(id: typed.id, mode: "shadowsocks", profileJSON: profileJSON,
                filesJSON: config, profile: profile, startFilesJSON: nil)
        }
        guard let mode = value["mode"] as? String, let profileJSON = value["profile_json"] as? String,
              let files = value["files"] as? String else { throw issue() }
        let profile = try object(Data(profileJSON.utf8), maximum: 256 * 1024)
        guard let id = profile["id"] as? String, profile["node_kind"] as? String == "router-vpn", profile["external"] == nil else { throw issue() }
        return IOSNodeChainCapture.Member(id: id, mode: mode, profileJSON: profileJSON, filesJSON: files, profile: profile, startFilesJSON: value["start"] as? String)
    }
    private static func object(_ data: Data, maximum: Int) throws -> [String: Any] {
        guard !data.isEmpty, data.count <= maximum else { throw issue() }
        var failure: NSError?
        guard LibboxRouterValidatePrivateNodeJSON(String(decoding: data, as: UTF8.self), &failure), failure == nil,
              let value = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw failure ?? issue() }
        return value
    }
    private static func json(_ value: Any, maximum: Int) throws -> String {
        let data = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        guard !data.isEmpty, data.count <= maximum else { throw issue() }
        return String(decoding: data, as: UTF8.self)
    }
    static func issue() -> NSError { NSError(domain: "RouterVPN.CandidateAppend", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "The unfinished prefix, next transport or independently captured device policy changed."]) }
}
