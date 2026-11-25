import AppKit
import Foundation
import CoreFoundation

private let macConnectionModeKey = "routervpn.unified.selected-mode.v1"
private let macConnectionCustomPresetsKey = "routervpn.unified.custom-presets.v1"
private let macConnectionMultihopEnabledKey = "routervpn.unified.multihop-enabled.v1"

func macCustomPresetName(in mode: String) -> String? {
    let prefix = "custom:".utf8
    guard mode.utf8.starts(with: prefix) else { return nil }
    return String(mode.unicodeScalars.dropFirst(prefix.count))
}

enum RouterVPNOrderedNodes {
    static let prefixModes = ["wg", "awg2-fast", "awg2-strong"]
    static let finalModes = ["shadowsocks", "hysteria2"]
    static let editorModes = prefixModes + finalModes + ["socks5", "http-connect", "https-connect", "openvpn"]
    static func finalProfile(_ profile: [String: Any], mode: String) -> Bool {
        guard finalModes.contains(mode), profile["external"] == nil else { return false }
        if let kind = profile["node_kind"] {
            guard let kind = kind as? String, ["", "router-vpn"].contains(kind) else { return false }
        }
        if mode == "shadowsocks" { return true }
        guard let raw = profile["start_layer"] else { return true }
        guard let hysteriaFinalLayer = raw as? String else { return false }
        return ["", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"].contains(hysteriaFinalLayer)
    }
    static func pairedHysteriaExecutionPath(_ rows: [[String: String]], profiles: [[String: Any]]) -> Bool {
        guard (2...8).contains(rows.count), rows.last?["mode"] == "hysteria2",
              rows.dropLast().allSatisfy({ prefixModes.contains($0["mode"] ?? "") }),
              Set(rows.compactMap { $0["id"] }).count == rows.count else { return false }
        for (position, row) in rows.enumerated() {
            let matches = profiles.filter { $0["id"] as? String == row["id"] }
            guard matches.count == 1,
                  finalProfile(matches[0], mode: position == rows.count - 1 ? "hysteria2" : "shadowsocks") else { return false }
            if position < rows.count - 1, let raw = matches[0]["start_layer"] {
                guard let hysteriaPrefixLayer = raw as? String, ["", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"].contains(hysteriaPrefixLayer) else { return false }
            }
        }
        return true
    }
    static func pairedSSExecutionPath(_ rows: [[String: String]], profiles: [[String: Any]]) -> Bool {
        guard (2...8).contains(rows.count), rows.last?["mode"] == "shadowsocks",
              rows.dropLast().allSatisfy({ prefixModes.contains($0["mode"] ?? "") }),
              Set(rows.compactMap { $0["id"] }).count == rows.count else { return false }
        for row in rows {
            let matches = profiles.filter { $0["id"] as? String == row["id"] }
            guard matches.count == 1,
                  finalProfile(matches[0], mode: "shadowsocks") else { return false }
            if let raw = matches[0]["start_layer"] {
                guard let pairedSSLayer = raw as? String, ["", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"].contains(pairedSSLayer) else { return false }
            }
        }
        return true
    }
    static func importedPosition(_ mode: String, position: Int, count: Int) -> Bool {
        if ["shadowsocks", "socks5", "http-connect", "https-connect", "openvpn"].contains(mode) {
            return (3...8).contains(count) && position == count - 2
        }
        return count == 3 && position == 1
    }
    static let physicalTraversalDepth = 96
    static func extendedLocalShape(_ rows: [[String: String]]) -> Bool {
        rows.count > 8 && rows.count <= physicalTraversalDepth && rows.first?["mode"] == "wg" &&
            rows.dropFirst().allSatisfy { $0["mode"] == "shadowsocks" }
    }
    static func extendedSelectedShape(_ rows: [[String: String]]) -> Bool {
        (9...physicalTraversalDepth).contains(rows.count) && ["wg", "awg2-fast"].contains(rows.first?["mode"] ?? "") &&
            rows.dropFirst().allSatisfy { $0["mode"] == "shadowsocks" }
    }
    static func extendedMixedPacketCount(_ rows: [[String: String]]) -> Int {
        (9...physicalTraversalDepth).contains(rows.count) ? mixedOriginalPacketCount(rows) : 0
    }
    static func mixedOriginalPacketCount(_ rows: [[String: String]]) -> Int {
        guard rows.count >= 3, rows.last?["mode"] == "shadowsocks" else { return 0 }
        let packets = rows.prefix(while: { prefixModes.contains($0["mode"] ?? "") }).count
        guard packets > 0, packets < rows.count - 1, packets > 1 || rows[0]["mode"] != "wg",
              rows.dropFirst(packets).allSatisfy({ $0["mode"] == "shadowsocks" }) else { return 0 }
        return packets
    }
    static func extendedPairedShape(_ rows: [[String: String]]) -> Bool {
        rows.count > 8 && rows.count <= physicalTraversalDepth && rows.last?["mode"] == "shadowsocks" &&
            rows.dropLast().allSatisfy { $0["mode"] == "wg" }
    }
    static func extendedPairedPath(_ rows: [[String: String]], execution: String, profiles: [[String: Any]]) -> Bool {
        guard execution == "local", extendedPairedShape(rows) else { return false }
        return pairedMembersOff(rows, profiles: profiles)
    }
    static func pairedMembersOff(_ rows: [[String: String]], profiles: [[String: Any]]) -> Bool {
        return rows.allSatisfy { row in
            let matches = profiles.filter { $0["id"] as? String == row["id"] }
            guard matches.count == 1, let profile = matches.first else { return false }
            return finalProfile(profile, mode: "shadowsocks") && startLayerOff(profile)
        }
    }
    static func startLayerOff(_ profile: [String: Any]) -> Bool {
        guard let raw = profile["start_layer"] else { return true }
        guard let layer = raw as? String else { return false }
        return layer.isEmpty || layer == "off"
    }
    static func localSSPosition(_ mode: String, position: Int, count: Int) -> Bool {
        mode == "shadowsocks" && (3...physicalTraversalDepth).contains(count) && position > 0 && position < count - 1
    }
    static func customEntryShape(_ rows: [[String: String]]) -> Bool {
        rows.count == 3 && rows.allSatisfy { $0["mode"] == "shadowsocks" }
    }
    static func importedMiddleMode(_ profile: [String: Any]) -> String? {
        guard profile["node_kind"] as? String == "external",
              let external = profile["external"] as? [String: Any],
              let value = external["ordered_middle_supported"] as? NSNumber,
              CFGetTypeID(value) == CFBooleanGetTypeID(), value.boolValue,
              let mode = external["protocol"] as? String,
              ["shadowsocks", "socks5", "http-connect", "https-connect", "openvpn"].contains(mode) else { return nil }
        return mode
    }
    static func importedMiddle(_ profile: [String: Any]) -> Bool {
        importedMiddleMode(profile) != nil
    }
    static func multipleImportedShape(_ rows: [[String: String]]) -> Bool {
        guard (3...8).contains(rows.count) || extendedSelectedShape(rows), prefixModes.contains(rows[0]["mode"] ?? ""), rows.last?["mode"] == "shadowsocks",
              rows.dropLast(2).contains(where: { $0["mode"] == "shadowsocks" }) else { return false }
        return rows.dropLast().allSatisfy { $0["mode"] == "shadowsocks" || prefixModes.contains($0["mode"] ?? "") }
    }

    static func originalHostnameHint(_ external: [String: Any]) -> Bool {
        func flag(_ key: String) -> Bool? {
            guard let value = external[key] as? NSNumber, CFGetTypeID(value) == CFBooleanGetTypeID() else { return nil }
            return value.boolValue
        }
        return flag("ordered_hostname_execution_middle_supported") == true &&
            flag("ordered_execution_middle_supported") == false && flag("ordered_local_imported_nodes_supported") == false
    }

    static func localImportedPath(_ rows: [[String: String]], profiles: [[String: Any]], selectedExecution: Bool = false) -> Bool {
        guard !selectedExecution || multipleImportedShape(rows) else { return false }
        let hint = selectedExecution ? "ordered_multiple_imported_execution_supported" : "ordered_local_imported_nodes_supported"
        let mixedPackets = selectedExecution ? 0 : extendedMixedPacketCount(rows)
        guard ((3...8).contains(rows.count) || (selectedExecution ? extendedSelectedShape(rows) : extendedLocalShape(rows) || mixedPackets > 0)), rows.last?["mode"] == "shadowsocks",
              Set(rows.compactMap { $0["id"] }).count == rows.count else { return false }
        let packets = rows.prefix { prefixModes.contains($0["mode"] ?? "") }.count
        var imports = 0, pairedStream = false, hostname = false, allOff = true
        for (position, row) in rows.enumerated() {
            guard let id = row["id"], let mode = row["mode"] else { return false }
            let matches = profiles.filter { $0["id"] as? String == id }
            guard matches.count == 1 else { return false }
            let profile = matches[0]
            allOff = allOff && startLayerOff(profile)
            if rows.count > 8 {
                let imported = position >= max(1, mixedPackets) && position < rows.count - 1
                let isExternal = profile["node_kind"] as? String == "external"
                guard (!isExternal || imported), (!selectedExecution || imported == isExternal), startLayerOff(profile) else { return false }
            }
            if profile["node_kind"] as? String == "external" {
                guard (localSSPosition(mode, position: position, count: rows.count) || position == 0 && customEntryShape(rows)), importedMiddleMode(profile) == "shadowsocks",
                      let external = profile["external"] as? [String: Any],
                      let allowed = external[hint] as? NSNumber,
                      CFGetTypeID(allowed) == CFBooleanGetTypeID() else { return false }
                if let raw = external["ordered_hostname_execution_middle_supported"] {
                    guard let typed = raw as? NSNumber, CFGetTypeID(typed) == CFBooleanGetTypeID() else { return false }
                    if typed.boolValue {
                        guard !selectedExecution, rows.count >= 4, packets > 0, packets == position,
                              (position < rows.count - 2 || rows.count > 8), originalHostnameHint(external),
                              rows.dropFirst(packets).allSatisfy({ $0["mode"] == "shadowsocks" }) else { return false }
                        hostname = true
                        imports += 1
                        continue
                    }
                }
                guard allowed.boolValue else { return false }
                imports += 1
            } else {
                guard finalProfile(profile, mode: "shadowsocks") else { return false }
                if position < rows.count - 1 && !prefixModes.contains(mode) {
                    guard !selectedExecution, packets > 0, position >= packets, mode == "shadowsocks",
                          rows.dropFirst(packets).allSatisfy({ $0["mode"] == "shadowsocks" }) else { return false }
                    pairedStream = true
                }
            }
        }
        return imports > 0 && (!(pairedStream || hostname) || allOff)
    }
    // This is a presentation capability, never native source authority. The
    // controller rechecks the original private members and preparation receipt.
    static func importedExecutionPrefixes(_ rows: [[String: String]], profiles: [[String: Any]]) -> Bool {
        guard (3...8).contains(rows.count), rows.dropLast(2).allSatisfy({ prefixModes.contains($0["mode"] ?? "") }),
              rows[rows.count - 2]["mode"] == "shadowsocks", rows.last?["mode"] == "shadowsocks" else { return false }
        let middle = rows.count - 2
        var members = [[String: Any]]()
        for row in rows {
            let matches = profiles.filter { $0["id"] as? String == row["id"] }
            guard matches.count == 1 else { return false }
            members.append(matches[0])
        }
        // Each paired source retains its independent canonical Start Layer.
        // The native compiler and original tokens authorize keys and transport.
        for (position, paired) in members.enumerated() where position != middle {
            guard finalProfile(paired, mode: "shadowsocks") else { return false }
            if let raw = paired["start_layer"] {
                guard let layer = raw as? String, ["", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"].contains(layer) else { return false }
            }
        }
        guard importedMiddleMode(members[middle]) == "shadowsocks",
              let external = members[middle]["external"] as? [String: Any] else { return false }
        guard let literal = external["ordered_execution_middle_supported"] as? NSNumber,
              CFGetTypeID(literal) == CFBooleanGetTypeID() else { return false }
        let hostnameRaw = external["ordered_hostname_execution_middle_supported"]
        if let hostnameRaw {
            guard let hostname = hostnameRaw as? NSNumber, CFGetTypeID(hostname) == CFBooleanGetTypeID(),
                  !(literal.boolValue && hostname.boolValue) else { return false }
        }
        if literal.boolValue { return true }
        guard rows.count >= 4, let hostname = hostnameRaw as? NSNumber, hostname.boolValue else { return false }
        return true
    }
    // The retained capability key includes its historical "trio" name. The
    // captured typed path now permits one to six complete paired prefixes.
    static func connectExecutionTrio(_ rows: [[String: String]], profiles: [[String: Any]]) -> Bool {
        let count = rows.count
        guard (3...8).contains(count), rows.dropLast(2).allSatisfy({ prefixModes.contains($0["mode"] ?? "") }),
              ["http-connect", "https-connect"].contains(rows[count - 2]["mode"] ?? ""), rows.last?["mode"] == "shadowsocks" else { return false }
        let middle = count - 2
        var members = [[String: Any]]()
        for row in rows {
            let matches = profiles.filter { $0["id"] as? String == row["id"] }
            guard matches.count == 1 else { return false }
            members.append(matches[0])
        }
        for (position, sourceMember) in members.enumerated() {
            if position != middle {
                guard finalProfile(sourceMember, mode: "shadowsocks") else { return false }
            }
            if let raw = sourceMember["start_layer"] {
                guard let allowedLayer = raw as? String,
                      ["", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"].contains(allowedLayer),
                      position != middle || allowedLayer == "" || allowedLayer == "off" else { return false }
            }
        }
        guard importedMiddleMode(members[middle]) == rows[middle]["mode"],
              let external = members[middle]["external"] as? [String: Any],
              let hint = external["ordered_connect_execution_middle_supported"] as? NSNumber,
              CFGetTypeID(hint) == CFBooleanGetTypeID(), hint.boolValue else { return false }
        return true
    }
    static func socksExecutionTrio(_ rows: [[String: String]], profiles: [[String: Any]]) -> Bool {
        let socksCount = rows.count
        guard (3...8).contains(socksCount), rows.dropLast(2).allSatisfy({ prefixModes.contains($0["mode"] ?? "") }),
              rows[socksCount - 2]["mode"] == "socks5", rows.last?["mode"] == "shadowsocks" else { return false }
        let socksMiddle = socksCount - 2
        var members = [[String: Any]]()
        for row in rows {
            let matches = profiles.filter { $0["id"] as? String == row["id"] }
            guard matches.count == 1 else { return false }
            members.append(matches[0])
        }
        for (position, sourceMember) in members.enumerated() {
            if position != socksMiddle {
                guard finalProfile(sourceMember, mode: "shadowsocks") else { return false }
            }
            if let raw = sourceMember["start_layer"] {
                guard let socksPrefixLayer = raw as? String,
                      ["", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"].contains(socksPrefixLayer),
                      position != socksMiddle || socksPrefixLayer == "" || socksPrefixLayer == "off" else { return false }
            }
        }
        guard importedMiddleMode(members[socksMiddle]) == rows[socksMiddle]["mode"],
              let external = members[socksMiddle]["external"] as? [String: Any],
              let socksHint = external["ordered_socks_execution_middle_supported"] as? NSNumber,
              CFGetTypeID(socksHint) == CFBooleanGetTypeID(), socksHint.boolValue else { return false }
        return true
    }
    static func openVPNExecutionPath(_ rows: [[String: String]], profiles: [[String: Any]]) -> Bool {
        let openVPNCount = rows.count
        guard (3...8).contains(openVPNCount), rows.dropLast(2).allSatisfy({ prefixModes.contains($0["mode"] ?? "") }),
              rows[openVPNCount - 2]["mode"] == "openvpn", rows.last?["mode"] == "shadowsocks" else { return false }
        let openVPNMiddle = openVPNCount - 2
        var members = [[String: Any]]()
        for row in rows {
            let matches = profiles.filter { $0["id"] as? String == row["id"] }
            guard matches.count == 1 else { return false }
            members.append(matches[0])
        }
        for (position, sourceMember) in members.enumerated() {
            if position != openVPNMiddle {
                guard finalProfile(sourceMember, mode: "shadowsocks") else { return false }
            }
            if let raw = sourceMember["start_layer"] {
                guard let openVPNLayer = raw as? String,
                      ["", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"].contains(openVPNLayer),
                      position != openVPNMiddle || openVPNLayer == "" || openVPNLayer == "off" else { return false }
            }
        }
        guard importedMiddleMode(members[openVPNMiddle]) == rows[openVPNMiddle]["mode"],
              let external = members[openVPNMiddle]["external"] as? [String: Any],
              let openVPNHint = external["ordered_openvpn_execution_middle_supported"] as? NSNumber,
              CFGetTypeID(openVPNHint) == CFBooleanGetTypeID(), openVPNHint.boolValue else { return false }
        return true
    }
    static func modeName(_ mode: String) -> String {
        switch mode {
        case "wg": return "WireGuard"
        case "awg2-fast": return "AWG2 Fast"
        case "awg2-strong": return "AWG2 Strong"
        case "shadowsocks": return "Shadowsocks 2022"
        case "socks5": return "SOCKS5"
        case "http-connect": return "HTTP CONNECT"
        case "https-connect": return "HTTPS CONNECT"
        case "hysteria2": return "Hysteria2"
        case "openvpn": return "OpenVPN"
        default: return "Unknown saved transport"
        }
    }
    static func issue(_ message: String) -> NSError {
        NSError(domain: "RouterVPN.OrderedNodes", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
    static func decode(_ raw: Any, control: String) throws -> [[String: String]] {
        guard let rows = raw as? [[String: String]], (2...8).contains(rows.count) || extendedLocalShape(rows) || extendedPairedShape(rows) || extendedMixedPacketCount(rows) > 0 else {
            throw issue("Choose at least two ordered nodes. Longer routes require a supported sequence of paired and imported nodes.")
        }
        var seen = Set<String>()
        for (position, row) in rows.enumerated() {
            guard Set(row.keys) == Set(["id", "mode"]), let id = row["id"],
                  id.range(of: "\\A[A-Za-z0-9_-]{1,64}\\z", options: .regularExpression) != nil,
                  seen.insert(id).inserted,
                  let mode = row["mode"],
                  position == rows.count - 1 ? finalModes.contains(mode) : prefixModes.contains(mode) || ((importedPosition(mode, position: position, count: rows.count) || localSSPosition(mode, position: position, count: rows.count) || position == 0 && customEntryShape(rows)) && ["shadowsocks", "socks5", "http-connect", "https-connect", "openvpn"].contains(mode) && rows.last?["mode"] == "shadowsocks") else {
                throw issue("Use paired packet prefixes, supported imported middle hops, or two distinct custom Shadowsocks hops before a paired Shadowsocks exit in Local. Keep SOCKS5, CONNECT and OpenVPN immediately before a Shadowsocks exit.")
            }
        }
        guard !control.isEmpty, rows.last?["id"] == control else {
            throw issue("The final ordered node must be the independently selected exit.")
        }
        return rows
    }
    static func connectBody(_ selection: RouterVPNConnectionProfileSelection, current: [String: Any]) throws -> [String: Any] {
        let rows = try decode(selection.orderedNodes, control: selection.selectedNodeID)
        guard selection.multihopEnabled, ["local", "server", "auto"].contains(selection.execution),
              selection.entryID.isEmpty, selection.exitID.isEmpty, selection.entryMode == "", selection.exitMode.isEmpty,
              current["selected_id"] as? String == selection.selectedNodeID,
              let profiles = current["profiles"] as? [[String: Any]] else {
            throw issue("The ordered path or selected exit changed. Reopen its editor.")
        }
        let localImported = selection.execution == "local" && localImportedPath(rows, profiles: profiles)
        let multipleImported = selection.execution != "local" && localImportedPath(rows, profiles: profiles, selectedExecution: true)
        guard rows.count <= 8 || localImported || multipleImported || extendedPairedPath(rows, execution: selection.execution, profiles: profiles) else { throw issue("For a longer Local route, choose paired WireGuard nodes or paired WireGuard/AWG2 nodes followed by literal Shadowsocks 2022 imports. End at a paired Shadowsocks node and use Start Layer Off throughout. Longer Server or Compare routes require a single WireGuard or AWG2 Fast entry before the imports.") }
        if selection.execution != "local" && multipleImportedShape(rows) && !multipleImported { throw issue("Each imported Shadowsocks interior must support the selected execution.") }
        for (position, row) in rows.enumerated() {
            let id = row["id"]!
            let matches = profiles.filter { $0["id"] as? String == id }
            guard matches.count == 1 else { throw issue("An ordered source is missing.") }
            let importedMode = importedMiddleMode(matches[0])
            guard importedMode == nil || selection.execution == "local" || multipleImported || importedExecutionPrefixes(rows, profiles: profiles) || connectExecutionTrio(rows, profiles: profiles) || socksExecutionTrio(rows, profiles: profiles) || openVPNExecutionPath(rows, profiles: profiles) else { throw issue("This imported ordered path has not enabled native Server or Compare execution.") }
            guard importedMode != nil ? (importedPosition(importedMode!, position: position, count: rows.count) || (localImported || multipleImported) && (localSSPosition(importedMode!, position: position, count: rows.count) || position == 0 && customEntryShape(rows))) && row["mode"] == importedMode && rows.last?["mode"] == "shadowsocks" : ["", "router-vpn"].contains(matches[0]["node_kind"] as? String ?? "router-vpn") && (position == rows.count - 1 || prefixModes.contains(row["mode"]!) || localImported && row["mode"] == "shadowsocks") else { throw issue("The ordered source kind or position changed.") }
            if position == rows.count - 1 {
                guard finalProfile(matches[0], mode: row["mode"]!) else { throw issue("Choose a paired final transport supported by its captured settings. Hysteria2 keeps its own Start Layer.") }
            }
            guard
                  let token = selection.profileTokens[id], token.range(of: "\\A[0-9a-f]{64}\\z", options: .regularExpression) != nil,
                  matches[0]["profile_token"] as? String == token else {
                throw issue("An ordered node is missing or has been relinked. Reopen its editor before connecting.")
            }
        }
        let tokens = Dictionary(uniqueKeysWithValues: rows.map { ($0["id"]!, selection.profileTokens[$0["id"]!]!) })
        return ["nodes": rows, "execution": selection.execution, "expected_selected_node_id": selection.selectedNodeID,
                "expected_profile_tokens": tokens]
    }
}

// Public references only. Source tokens are opaque hashes produced by the
// controller; credentials remain in its private node store.
struct RouterVPNConnectionProfileSelection: Codable, Equatable, Sendable {
    var selectedNodeID = ""
    var multihopEnabled = false
    var entryID = ""
    var entryMode: String? = ""
    var exitID = ""
    var exitMode = ""
    var execution = ""
    var profileTokens: [String: String] = [:]
    var orderedNodes: [[String: String]] = []
    var nodeDefaultsPending = false
}

struct RouterVPNOrderedNodeDraft {
    let control: String
    let generation: UUID
    let names: [String: String]
    let tokens: [String: String]
    let candidates: [String]
    let importedIDs: Set<String>
    let importedModes: [String: String]
    let capturedCatalog: [[String: Any]]
    let finalModes: [String]
    let execution: String
    private(set) var finalMode: String
    private(set) var prefixes: [String]
    private(set) var modes: [String]

    init(selection: RouterVPNConnectionProfileSelection, generation: UUID, catalog: [[String: Any]]) throws {
        control = selection.selectedNodeID; self.generation = generation
        capturedCatalog = catalog
        execution = selection.orderedNodes.isEmpty && selection.execution.isEmpty ? "local" : selection.execution
        guard ["local", "server", "auto"].contains(execution) else { throw RouterVPNOrderedNodes.issue("Choose Local, Server or Compare for the complete ordered path.") }
        var names: [String: String] = [:], tokens: [String: String] = [:]
        var importedIDs = Set<String>()
        var importedModes: [String: String] = [:]
        for row in catalog {
            guard let id = row["id"] as? String, names[id] == nil,
                  id.range(of: "\\A[A-Za-z0-9_-]{1,64}\\z", options: .regularExpression) != nil,
                  let token = row["profile_token"] as? String,
                  token.range(of: "\\A[0-9a-f]{64}\\z", options: .regularExpression) != nil else {
                throw RouterVPNOrderedNodes.issue("Refresh the node catalog before opening the ordered editor.")
            }
            let importedMode = RouterVPNOrderedNodes.importedMiddleMode(row)
            guard importedMode != nil || ["", "router-vpn"].contains(row["node_kind"] as? String ?? "router-vpn") else { continue }
            if let importedMode { importedIDs.insert(id); importedModes[id] = importedMode }
            names[id] = row["name"] as? String ?? id; tokens[id] = token
        }
        guard let selectedToken = selection.profileTokens[control], tokens[control] == selectedToken, !importedIDs.contains(control) else {
            throw RouterVPNOrderedNodes.issue("Select the linked final exit before opening the ordered editor.")
        }
        guard let finalProfile = catalog.first(where: { $0["id"] as? String == selection.selectedNodeID }) else { throw RouterVPNOrderedNodes.issue("The selected final source is missing.") }
        finalModes = RouterVPNOrderedNodes.finalModes.filter { RouterVPNOrderedNodes.finalProfile(finalProfile, mode: $0) }
        self.names = names; self.tokens = tokens; self.importedIDs = importedIDs; self.importedModes = importedModes
        candidates = names.keys.filter { $0 != selection.selectedNodeID }.sorted()
        if selection.orderedNodes.isEmpty { prefixes = []; modes = []; finalMode = "shadowsocks" }
        else {
            let nodes = try RouterVPNOrderedNodes.decode(selection.orderedNodes, control: control)
            guard nodes.allSatisfy({ tokens[$0["id"]!] == selection.profileTokens[$0["id"]!] }) else {
                throw RouterVPNOrderedNodes.issue("A saved ordered node was relinked. Reload its profile before editing.")
            }
            prefixes = nodes.dropLast().map { $0["id"]! }
            modes = nodes.dropLast().map { $0["mode"]! }
            finalMode = nodes.last!["mode"]!
        }
        guard finalModes.contains(finalMode) else { throw RouterVPNOrderedNodes.issue("The saved final transport no longer matches its paired source settings.") }
        if !selection.orderedNodes.isEmpty { _ = try self.selection() }
    }
    var nodes: [[String: String]] { prefixes.enumerated().map { ["id": $0.element, "mode": modes[$0.offset]] } + [["id": control, "mode": finalMode]] }
    func allowedModes(at index: Int) -> [String] {
        if nodes.count > 8 {
            if index == prefixes.count { return ["shadowsocks"] }
            guard prefixes.indices.contains(index) else { return [] }
            if let mode = importedModes[prefixes[index]] { return [mode] }
            if modes[index] == "shadowsocks", execution == "local",
               RouterVPNOrderedNodes.localImportedPath(nodes, profiles: capturedCatalog) { return ["shadowsocks"] }
            if execution == "local", modes.contains("shadowsocks") { return RouterVPNOrderedNodes.prefixModes }
            if execution != "local", index == 0, RouterVPNOrderedNodes.extendedSelectedShape(nodes) { return ["wg", "awg2-fast"] }
            return ["wg"]
        }
        if prefixes.indices.contains(index) {
            if let imported = importedModes[prefixes[index]] { return [imported] }
            if modes[index] == "shadowsocks", execution == "local",
               RouterVPNOrderedNodes.localImportedPath(nodes, profiles: capturedCatalog) { return ["shadowsocks"] }
            return RouterVPNOrderedNodes.prefixModes
        }
        if index == prefixes.count { return finalModes.filter { $0 == "shadowsocks" || importedIDs.isDisjoint(with: prefixes) } }
        return []
    }
    var hasRoomForMeasuredHop: Bool {
        if prefixes.count >= 7 && prefixes.count < RouterVPNOrderedNodes.physicalTraversalDepth - 1 &&
            execution == "local" && finalMode == "shadowsocks" && modes.allSatisfy({ $0 == "wg" }) {
            return RouterVPNOrderedNodes.pairedMembersOff(nodes, profiles: capturedCatalog)
        }
        return prefixes.count < 7 || (prefixes.count < RouterVPNOrderedNodes.physicalTraversalDepth - 1 &&
            (modes.first == "wg" || execution != "local" && modes.first == "awg2-fast") && modes.dropFirst().allSatisfy { $0 == "shadowsocks" } && finalMode == "shadowsocks" &&
            RouterVPNOrderedNodes.localImportedPath(nodes, profiles: capturedCatalog, selectedExecution: execution != "local"))
    }
    func canMeasure(after index: Int) -> Bool {
        guard modes.indices.contains(index) else { return false }
        if execution != "local", RouterVPNOrderedNodes.extendedSelectedShape(nodes) {
            return index == 0 && RouterVPNOrderedNodes.localImportedPath(nodes, profiles: capturedCatalog, selectedExecution: true)
        }
        let mixedPackets = RouterVPNOrderedNodes.extendedMixedPacketCount(nodes)
        if mixedPackets > 0 {
            return execution == "local" && RouterVPNOrderedNodes.localImportedPath(nodes, profiles: capturedCatalog)
        }
        if RouterVPNOrderedNodes.prefixModes.contains(modes[index]) {
            if nodes.count == 8, execution == "local", index < RouterVPNOrderedNodes.mixedOriginalPacketCount(nodes) {
                let ids = Set(prefixes + [control])
                return RouterVPNOrderedNodes.localImportedPath(nodes, profiles: capturedCatalog) &&
                    capturedCatalog.filter { ($0["id"] as? String).map(ids.contains) == true }.allSatisfy(RouterVPNOrderedNodes.startLayerOff)
            }
            return hasRoomForMeasuredHop
        }
        let packets = modes.prefix(index + 1).prefix(while: RouterVPNOrderedNodes.prefixModes.contains).count
        guard execution == "local", packets > 0, packets <= index, finalMode == "shadowsocks",
              nodes.count <= 8 || RouterVPNOrderedNodes.extendedLocalShape(nodes),
              modes[packets...index].allSatisfy({ $0 == "shadowsocks" }),
              RouterVPNOrderedNodes.pairedMembersOff(Array(nodes.prefix(packets)) + [nodes[prefixes.count]], profiles: capturedCatalog) else { return false }
        let literalPath = RouterVPNOrderedNodes.localImportedPath(nodes, profiles: capturedCatalog)
        let singleHostname = nodes.count <= 8 && index == packets && index == nodes.count - 2
        return prefixes[packets...index].allSatisfy { id in
            if literalPath && !importedIDs.contains(id) {
                return true // The complete Local path retains each original private and public stream.
            }
            guard importedModes[id] == "shadowsocks", let profile = capturedCatalog.first(where: { $0["id"] as? String == id }),
                  RouterVPNOrderedNodes.startLayerOff(profile), let external = profile["external"] as? [String: Any] else { return false }
            guard let rawHost = external["ordered_hostname_execution_middle_supported"] else { return literalPath }
            guard let hostname = rawHost as? NSNumber, CFGetTypeID(hostname) == CFBooleanGetTypeID() else { return false }
            if hostname.boolValue {
                guard (singleHostname || literalPath && id == prefixes[packets]), let literal = external["ordered_execution_middle_supported"] as? NSNumber,
                      CFGetTypeID(literal) == CFBooleanGetTypeID(), !literal.boolValue else { return false }
                if let raw = external["ordered_local_imported_nodes_supported"] {
                    guard let local = raw as? NSNumber, CFGetTypeID(local) == CFBooleanGetTypeID(), !local.boolValue else { return false }
                }
                return true
            }
            return literalPath
        }
    }
    mutating func add(_ id: String) throws {
        try insert(id, mode: importedModes[id] ?? "wg", at: prefixes.count)
    }
    private mutating func insert(_ id: String, mode: String, at position: Int) throws {
        guard (0...prefixes.count).contains(position), candidates.contains(id), !prefixes.contains(id),
              !importedIDs.contains(id) || mode == importedModes[id] && finalMode == "shadowsocks" else {
            throw RouterVPNOrderedNodes.issue("Choose a different linked hop with its supported transport.")
        }
        var proposed = nodes
        proposed.insert(["id": id, "mode": mode], at: position)
        guard proposed.count <= 8 ||
                RouterVPNOrderedNodes.extendedPairedPath(proposed, execution: execution, profiles: capturedCatalog) ||
                RouterVPNOrderedNodes.localImportedPath(proposed, profiles: capturedCatalog, selectedExecution: execution != "local") else {
            throw RouterVPNOrderedNodes.issue("This node cannot occupy the selected position in the longer route.")
        }
        prefixes.insert(id, at: position)
        modes.insert(mode, at: position)
    }
    mutating func insertMeasured(_ response: [String: Any], after index: Int) throws {
        guard prefixes.indices.contains(index), let id = response["candidate_id"] as? String,
              response["expected_selected_node_id"] as? String == control,
              execution == "local" || response["requested_execution"] as? String == execution,
              let proposed = response["proposed_path"] as? [[String: String]],
              let sourceTokens = response["expected_profile_tokens"] as? [String: String] else {
            throw RouterVPNOrderedNodes.issue("The measured hop belongs to another draft.")
        }
        var updated = self
        guard proposed.indices.contains(index + 1), let proposedMode = proposed[index + 1]["mode"] else { throw RouterVPNOrderedNodes.issue("The measured hop has no transport.") }
        try updated.insert(id, mode: proposedMode, at: index + 1)
        try updated.chooseMode(proposedMode, at: index + 1)
        let checked = try updated.selection()
        guard checked.orderedNodes == proposed, checked.profileTokens == sourceTokens else {
            throw RouterVPNOrderedNodes.issue("The measured path or a linked source changed. Recapture the prefix.")
        }
        self = updated
    }
    mutating func chooseMode(_ mode: String, at index: Int) throws {
        guard allowedModes(at: index).contains(mode) else {
            throw RouterVPNOrderedNodes.issue("Choose a supported transport for this captured node. Hysteria2 requires a paired final and paired WireGuard or AWG2 prefixes.")
        }
        if index == prefixes.count { finalMode = mode }
        else { modes[index] = mode }
    }
    mutating func move(_ index: Int, by offset: Int) throws {
        guard [-1, 1].contains(offset), prefixes.indices.contains(index), prefixes.indices.contains(index + offset) else {
            throw RouterVPNOrderedNodes.issue("Move an entry or hop within the prefix. The selected final exit stays last.")
        }
        prefixes.swapAt(index, index + offset)
        modes.swapAt(index, index + offset)
    }
    mutating func remove(_ index: Int) throws {
        guard prefixes.indices.contains(index) else { throw RouterVPNOrderedNodes.issue("The selected final exit cannot be removed here.") }
        prefixes.remove(at: index)
        modes.remove(at: index)
    }
    func selection() throws -> RouterVPNConnectionProfileSelection {
        let ordered = try RouterVPNOrderedNodes.decode(nodes, control: control)
        let localImported = execution == "local" && RouterVPNOrderedNodes.localImportedPath(ordered, profiles: capturedCatalog)
        let multipleImported = execution != "local" && RouterVPNOrderedNodes.localImportedPath(ordered, profiles: capturedCatalog, selectedExecution: true)
        guard ordered.count <= 8 || localImported || multipleImported ||
                RouterVPNOrderedNodes.extendedPairedPath(ordered, execution: execution, profiles: capturedCatalog) else {
            throw RouterVPNOrderedNodes.issue("Longer Local packet routes require paired WireGuard prefixes and a paired Shadowsocks final, all with Start Layer Off.")
        }
        if execution != "local" && RouterVPNOrderedNodes.multipleImportedShape(ordered) && !multipleImported { throw RouterVPNOrderedNodes.issue("Each imported Shadowsocks interior must support the selected execution.") }
        guard execution == "local" || multipleImported || !prefixes.contains(where: importedIDs.contains) || RouterVPNOrderedNodes.importedExecutionPrefixes(ordered, profiles: capturedCatalog) || RouterVPNOrderedNodes.connectExecutionTrio(ordered, profiles: capturedCatalog) || RouterVPNOrderedNodes.socksExecutionTrio(ordered, profiles: capturedCatalog) || RouterVPNOrderedNodes.openVPNExecutionPath(ordered, profiles: capturedCatalog) else { throw RouterVPNOrderedNodes.issue("Imported ordered paths retain Local execution until native Server admission is available.") }
        for (index, id) in prefixes.enumerated() {
            guard importedIDs.contains(id) ? (RouterVPNOrderedNodes.importedPosition(modes[index], position: index, count: ordered.count) || (localImported || multipleImported) && (RouterVPNOrderedNodes.localSSPosition(modes[index], position: index, count: ordered.count) || index == 0 && RouterVPNOrderedNodes.customEntryShape(ordered))) && modes[index] == importedModes[id] && finalMode == "shadowsocks" : (RouterVPNOrderedNodes.prefixModes.contains(modes[index]) || localImported && modes[index] == "shadowsocks") else { throw RouterVPNOrderedNodes.issue("Keep each imported node in a position supported by its captured Local or Server path.") }
        }
        return RouterVPNConnectionProfileSelection(selectedNodeID: control, multihopEnabled: true, entryMode: "",
            execution: execution, profileTokens: tokens.filter { key, _ in ordered.contains { $0["id"] == key } }, orderedNodes: ordered)
    }
}

struct RouterVPNConnectionProfileRefresh: Sendable {
    let generation: UUID
    let request: UUID
    let selection: RouterVPNConnectionProfileSelection
}

private struct MacConnectionProfileList: Decodable {
    var profiles: [MacConnectionProfileSummary]
}

private struct MacConnectionProfileSummary: Decodable {
    var id: String
    var name: String
    var nodeID: String
    var mode: String

    enum CodingKeys: String, CodingKey {
        case id, name, mode
        case nodeID = "node_id"
    }
}

struct MacConnectionCustomPreset: Codable {
    var name: String
    var layers: [String]

    static func catalog(_ data: Data?) throws -> [Self] {
        guard let data else { return [] }
        return try JSONDecoder().decode([Self].self, from: data)
    }

    static func target(_ name: String, in presets: [Self]) throws -> Int? {
        let exact = presets.indices.filter { presets[$0].name.utf8.elementsEqual(name.utf8) }
        if exact.count == 1 { return exact[0] }
        guard exact.isEmpty, !presets.contains(where: { $0.name.caseInsensitiveCompare(name) == .orderedSame }) else {
            throw RouterVPNOrderedNodes.issue("A different or duplicate CUSTOM preset uses this name. Resolve the conflicting names before loading this profile.")
        }
        return nil
    }
}

extension ProductWindowController {
    func requireCoordinatedProfilePath(_ pending: MacProfileLoadTransaction.Journal) throws {
        guard connectionProfileSelection != nil else { return } // A fresh window has no prior live selectors.
        let displayed = captureConnectionProfileSelection()
        var old = pending.previous.selection
        var staged = pending.desired?.selection
        // The preference compare-and-swap separately checks the toggle, which
        // can be one of the fields already written before a crash.
        old.multihopEnabled = displayed.multihopEnabled
        staged?.multihopEnabled = displayed.multihopEnabled
        guard displayed == old || displayed == staged else {
            throw RouterVPNOrderedNodes.issue("A newer native path is displayed. AppKit kept the original Load for recovery.")
        }
    }

    func adoptCoordinatedProfileSelection(_ selection: RouterVPNConnectionProfileSelection) throws {
        adoptLoadedConnectionProfileSelection(selection, persistPreferences: false)
        guard connectionProfileSelection == selection, connectionProfileCatalogSelectedID == selection.selectedNodeID else {
            throw RouterVPNOrderedNodes.issue("The AppKit window could not adopt the captured profile path.")
        }
    }

    func recoverCoordinatedProfileLoad() throws {
        let store = MacProfileLoadTransaction.Store.standard
        guard store.pending else { return }
        try store.locked {
            guard let record = try store.read() else { return }
            _ = try MacProfileLoadTransaction.recover(record, store: store, defaults: .standard,
                send: { phase, fields in try self.api.request(MacProfileLoadTransaction.base + phase, method: "POST", body: fields, timeout: 15) },
                checkPath: requireCoordinatedProfilePath, adopt: adoptCoordinatedProfileSelection)
        }
    }

    func makeOrderedNodeDraft() throws -> RouterVPNOrderedNodeDraft {
        try requireMutationIdle("editing the ordered path")
        let selection = captureConnectionProfileSelection()
        guard selection.selectedNodeID == connectionProfileCatalogSelectedID,
              routerIDs.indices.contains(routerPopup.indexOfSelectedItem),
              routerIDs[routerPopup.indexOfSelectedItem] == selection.selectedNodeID else {
            throw RouterVPNOrderedNodes.issue("Wait for the selected exit's captured catalog before editing its path.")
        }
        return try RouterVPNOrderedNodeDraft(selection: selection, generation: connectionProfileSelectionGeneration, catalog: profiles)
    }

    func applyOrderedNodeDraft(_ draft: RouterVPNOrderedNodeDraft) throws {
        try requireMutationIdle("applying the ordered path")
        guard connectionProfileSelectionGeneration == draft.generation,
              captureConnectionProfileSelection().selectedNodeID == draft.control else {
            throw RouterVPNOrderedNodes.issue("The selected exit or path changed while the editor was open. Open it again.")
        }
        let selection = try draft.selection()
        let current = try api.json("/api/profiles", timeout: 5) as? [String: Any] ?? [:]
        _ = try RouterVPNOrderedNodes.connectBody(selection, current: current)
        try requireMutationIdle("retaining the captured ordered path")
        guard connectionProfileSelectionGeneration == draft.generation,
              captureConnectionProfileSelection().selectedNodeID == draft.control else {
            throw RouterVPNOrderedNodes.issue("The selected exit changed while the path was checked.")
        }
        adoptLoadedConnectionProfileSelection(selection)
        let mode = selection.orderedNodes.last!["mode"]!
        UserDefaults.standard.set(mode, forKey: macConnectionModeKey)
        refreshUnifiedModeMenu(preferred: mode)
    }

    func clearOrderedNodeDraft() throws {
        try requireMutationIdle("switching to an entry and exit pair")
        var selection = captureConnectionProfileSelection()
        selection.orderedNodes = []
        connectionProfileSelection = selection
        recordVisibleConnectionProfileSelection()
        restoreOwnedConnectionProfileSelection()
    }

    func connectOrderedMultihopIfSelected() -> Bool {
        let selection = captureConnectionProfileSelection()
        guard !selection.orderedNodes.isEmpty else { return false }
        do {
            try requireMutationIdle("starting the ordered path")
            _ = try RouterVPNOrderedNodes.connectBody(selection, current: ["selected_id": connectionProfileCatalogSelectedID, "profiles": profiles])
        } catch { appendHelp(error.localizedDescription); return true }
        let generation = connectionProfileSelectionGeneration
        multihopComparisonLabel.stringValue = "Starting the ordered path on this device…"
        startMultihopProgress(timeout: 180); let orderedProgressOwner = multihopProgressGeneration
        asyncAction {
            defer { DispatchQueue.main.async { self.stopCapturedComparisonProgress(orderedProgressOwner) } }
            try self.requireMutationIdle("starting the captured ordered path")
            let capabilities = try self.api.json("/api/multihop/status", timeout: 5) as? [String: Any] ?? [:]
            let current = try self.api.json("/api/profiles", timeout: 5) as? [String: Any] ?? [:]
            let body = try RouterVPNOrderedNodes.connectBody(selection, current: current)
            let importedPrefixes = RouterVPNOrderedNodes.importedExecutionPrefixes(selection.orderedNodes, profiles: current["profiles"] as? [[String: Any]] ?? [])
            let connectTrio = RouterVPNOrderedNodes.connectExecutionTrio(selection.orderedNodes, profiles: current["profiles"] as? [[String: Any]] ?? [])
            let socksTrio = RouterVPNOrderedNodes.socksExecutionTrio(selection.orderedNodes, profiles: current["profiles"] as? [[String: Any]] ?? [])
            let openVPNPath = RouterVPNOrderedNodes.openVPNExecutionPath(selection.orderedNodes, profiles: current["profiles"] as? [[String: Any]] ?? [])
            let pairedHysteria = RouterVPNOrderedNodes.pairedHysteriaExecutionPath(selection.orderedNodes, profiles: current["profiles"] as? [[String: Any]] ?? [])
            let pairedSS = RouterVPNOrderedNodes.pairedSSExecutionPath(selection.orderedNodes, profiles: current["profiles"] as? [[String: Any]] ?? [])
            let multipleImported = selection.execution != "local" && RouterVPNOrderedNodes.multipleImportedShape(selection.orderedNodes)
            let executionCapability = multipleImported ? "ordered_multiple_imported_executions" : pairedSS && selection.execution != "local" ? "ordered_paired_ss_executions" : pairedHysteria && selection.execution != "local" ? "ordered_hysteria_executions" : openVPNPath && selection.execution != "local" ? "ordered_openvpn_executions" : (socksTrio && selection.execution != "local" ? "ordered_socks_trio_executions" : (connectTrio && selection.execution != "local" ? "ordered_connect_trio_executions" : (importedPrefixes && selection.execution != "local" ? "ordered_imported_trio_executions" : "ordered_executions")))
            guard let enabled = capabilities["ordered_nodes_supported"] as? NSNumber,
                  CFGetTypeID(enabled) == CFBooleanGetTypeID(), enabled.boolValue,
                  let executions = capabilities[executionCapability] as? [String], executions.contains(selection.execution) else {
                throw RouterVPNOrderedNodes.issue("This controller has not enabled the selected ordered execution on this device.")
            }
            guard DispatchQueue.main.sync(execute: {
                self.connectionProfileSelectionGeneration == generation && self.captureConnectionProfileSelection() == selection
            }) else {
                throw RouterVPNOrderedNodes.issue("The selected path changed before Connect. Connect the current selection again.")
            }
            return String(data: try self.api.request("/api/multihop/connect", method: "POST", body: body, timeout: 180), encoding: .utf8) ?? "Ordered path connected"
        }
        return true
    }

    func captureConnectionProfileSelection() -> RouterVPNConnectionProfileSelection {
        var value = connectionProfileSelection ?? RouterVPNConnectionProfileSelection()
        let selected = routerPopup.indexOfSelectedItem
        if routerIDs.indices.contains(selected) {
            value.selectedNodeID = routerIDs[selected]
            if profiles.indices.contains(selected), let token = profiles[selected]["profile_token"] as? String {
                value.profileTokens[value.selectedNodeID] = token
            }
        }
        value.multihopEnabled = UserDefaults.standard.bool(forKey: macConnectionMultihopEnabledKey)
        let selectedSources = profiles.filter { $0["id"] as? String == value.selectedNodeID }
        if selectedSources.count == 1,
           value.profileTokens[value.selectedNodeID] == nil || value.profileTokens[value.selectedNodeID] == selectedSources[0]["profile_token"] as? String,
           (selectedSources[0]["node_kind"] as? String ?? "router-vpn").lowercased() == "external" {
            value.multihopEnabled = false
        }
        if !value.orderedNodes.isEmpty {
            value.entryID = ""; value.exitID = ""; value.entryMode = ""; value.exitMode = ""
            let executionIndex = multihopExecutionPopup.indexOfSelectedItem
            value.execution = (0..<3).contains(executionIndex) ? ["local", "server", "auto"][executionIndex] : ""
            let referenced = Set(value.orderedNodes.compactMap { $0["id"] } + [value.selectedNodeID])
            value.profileTokens = value.profileTokens.filter { referenced.contains($0.key) }
            return value
        }
        let entry = multihopEntryPopup.indexOfSelectedItem, exit = multihopExitPopup.indexOfSelectedItem
        if multihopNodeIDs.indices.contains(entry) {
            value.entryID = multihopNodeIDs[entry]
            if let token = multihopNodeTokens[value.entryID] { value.profileTokens[value.entryID] = token }
        }
        if multihopNodeIDs.indices.contains(exit) {
            value.exitID = multihopNodeIDs[exit]
            if let token = multihopNodeTokens[value.exitID] { value.profileTokens[value.exitID] = token }
        }
        value.entryMode = RouterVPNNodeEntryModes.id(at: multihopEntryModePopup.indexOfSelectedItem)
        value.exitMode = RouterVPNNodeExitModes.id(at: multihopExitModePopup.indexOfSelectedItem) ?? ""
        let executionIndex = multihopExecutionPopup.indexOfSelectedItem
        value.execution = (0..<3).contains(executionIndex) ? ["local", "server", "auto"][executionIndex] : ""
        let referenced = Set([value.selectedNodeID, value.entryID, value.exitID].filter { !$0.isEmpty })
        value.profileTokens = value.profileTokens.filter { referenced.contains($0.key) }
        return value
    }

    func recordVisibleConnectionProfileSelection() {
        connectionProfileSelection = captureConnectionProfileSelection()
        connectionProfileSelectionGeneration = UUID()
    }

    func recordConnectionProfileNodeChoice(_ id: String) {
        let originalID = connectionProfileSelection?.selectedNodeID
        var selection = captureConnectionProfileSelection()
        if originalID != id { selection.orderedNodes = []; selection.nodeDefaultsPending = true }
        selection.selectedNodeID = id
        let sources = profiles.filter { $0["id"] as? String == id }
        if sources.count == 1, let token = sources[0]["profile_token"] as? String { selection.profileTokens[id] = token }
        connectionProfileSelection = selection
        connectionProfileSelectionGeneration = UUID()
        // Selection is provisional until a matching controller catalog confirms
        // it. A failed or pending /profile/select cannot leave a different node
        // looking ready for a subsequent connection/profile mutation.
        routerPopup.selectItem(at: -1)
    }

    func restoreOwnedConnectionProfileSelection() {
        if let selection = connectionProfileSelection {
            let confirmed = connectionProfileCatalogSelectedID
            adoptLoadedConnectionProfileSelection(selection)
            connectionProfileCatalogSelectedID = confirmed
            if confirmed != selection.selectedNodeID { routerPopup.selectItem(at: -1); nodePopup.selectItem(at: -1) }
        }
    }

    @objc func connectionProfileHopChanged() {
        guard ensureMutationIdle("changing multihop selection") else { restoreOwnedConnectionProfileSelection(); return }
        recordVisibleConnectionProfileSelection()
        refreshUnifiedHopOverlay()
    }

    @objc func connectionProfileEntryChanged() {
        guard ensureMutationIdle("changing multihop entry") else { restoreOwnedConnectionProfileSelection(); return }
        recordVisibleConnectionProfileSelection()
        unifiedEntryCandidatesChanged()
    }

    func validConnectionProfileToken(_ token: String?) -> Bool {
        guard let token else { return false }
        return token.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
    }

    func connectionProfileCatalogTokens(_ nodes: [[String: Any]]) throws -> [String: String] {
        var tokens: [String: String] = [:]
        for node in nodes {
            guard let id = node["id"] as? String, !id.isEmpty, tokens[id] == nil,
                  let token = node["profile_token"] as? String, validConnectionProfileToken(token) else {
                throw NSError(domain: "RouterVPN.ConnectionProfile", code: 2, userInfo: [NSLocalizedDescriptionKey: "The node catalog has missing or duplicate source identities. Refresh before using this setup."])
            }
            tokens[id] = token
        }
        return tokens
    }

    func connectionProfileIdentityIndex(_ id: String, ids: [String], tokens: [String: String], selection: RouterVPNConnectionProfileSelection) -> Int {
        guard !id.isEmpty, ids.filter({ $0 == id }).count == 1, let index = ids.firstIndex(of: id),
              let actual = tokens[id], validConnectionProfileToken(actual) else { return -1 }
        if let expected = selection.profileTokens[id], expected != actual { return -1 }
        return index
    }

    func beginConnectionProfileRefresh(hops: Bool) -> RouterVPNConnectionProfileRefresh {
        let selection = captureConnectionProfileSelection()
        connectionProfileSelection = selection
        let request = UUID()
        if hops { connectionProfileHopsRequest = request } else { connectionProfileNodesRequest = request }
        return RouterVPNConnectionProfileRefresh(generation: connectionProfileSelectionGeneration, request: request, selection: selection)
    }

    func ownsConnectionProfileRefresh(_ capture: RouterVPNConnectionProfileRefresh, hops: Bool) -> Bool {
        capture.generation == connectionProfileSelectionGeneration &&
            capture.request == (hops ? connectionProfileHopsRequest : connectionProfileNodesRequest) &&
            capture.selection == captureConnectionProfileSelection()
    }

    func validatedLoadedConnectionProfileSelection(_ payload: [String: Any], fromCatalog: Bool = false) throws -> RouterVPNConnectionProfileSelection {
        let stored = payload["profile"] as? [String: Any]
        let external = stored?["external_policy"] is [String: Any]
        var selection = RouterVPNConnectionProfileSelection(
            selectedNodeID: payload["selected_node_id"] as? String ?? "",
            multihopEnabled: !external && (payload["multihop_enabled"] as? Bool ?? false),
            entryID: payload["multihop_entry_id"] as? String ?? "",
            entryMode: payload["multihop_entry_mode"] == nil ? "" : payload["multihop_entry_mode"] as? String,
            exitID: payload["multihop_exit_id"] as? String ?? "",
            exitMode: payload["multihop_exit_mode"] as? String ?? "",
            execution: payload["multihop_execution"] as? String ?? "local")
        let tokens = payload["profile_tokens"] as? [String: String] ?? [:]
        var referenced = Set([selection.selectedNodeID])
        if let raw = payload["multihop_nodes"], !(raw is NSNull) {
            selection.orderedNodes = try RouterVPNOrderedNodes.decode(raw, control: selection.selectedNodeID)
            guard !external, selection.multihopEnabled, ["local", "server", "auto"].contains(selection.execution),
                  selection.entryID.isEmpty, selection.exitID.isEmpty, selection.entryMode == "", selection.exitMode.isEmpty,
                  fromCatalog || (stored?["mode"] as? String == selection.orderedNodes.last?["mode"] && payload["mode"] as? String == selection.orderedNodes.last?["mode"]) else {
                throw RouterVPNOrderedNodes.issue("The loaded ordered path mixes an independent entry, exit or execution.")
            }
            referenced.formUnion(selection.orderedNodes.compactMap { $0["id"] })
        } else if selection.multihopEnabled {
            guard !selection.entryID.isEmpty, !selection.exitID.isEmpty, selection.entryID != selection.exitID,
                  selection.entryMode.flatMap({ RouterVPNNodeEntryModes.index(for: $0) }) != nil,
                  RouterVPNNodeExitModes.index(for: selection.exitMode) != nil,
                  ["local", "server", "auto"].contains(selection.execution) else {
                throw NSError(domain: "RouterVPN.ConnectionProfile", code: 3, userInfo: [NSLocalizedDescriptionKey: "The loaded multihop setup is incomplete or unsupported. No replacement path was selected."])
            }
            referenced.formUnion([selection.entryID, selection.exitID])
        }
        if external && (payload["multihop_enabled"] as? Bool ?? false) {
            referenced.formUnion([selection.entryID, selection.exitID])
        }
        guard !selection.selectedNodeID.isEmpty, !referenced.contains(""), Set(tokens.keys) == referenced,
              referenced.allSatisfy({ validConnectionProfileToken(tokens[$0]) }) else {
            throw NSError(domain: "RouterVPN.ConnectionProfile", code: 4, userInfo: [NSLocalizedDescriptionKey: "The loaded setup has no captured node source identities. Reload it with the matching controller."])
        }
        selection.profileTokens = tokens.filter { referenced.contains($0.key) }
        return selection
    }

    func adoptLoadedConnectionProfileSelection(_ selection: RouterVPNConnectionProfileSelection, persistPreferences: Bool = true) {
        connectionProfileSelectionGeneration = UUID()
        connectionProfileSelection = selection
        connectionProfileCatalogSelectedID = selection.selectedNodeID
        if persistPreferences {
            UserDefaults.standard.set(selection.multihopEnabled, forKey: macConnectionMultihopEnabledKey)
            UserDefaults.standard.set(selection.execution, forKey: "routervpn.multihop.execution.v1")
        }
        let tokens = (try? connectionProfileCatalogTokens(profiles)) ?? [:]
        routerPopup.selectItem(at: connectionProfileIdentityIndex(selection.selectedNodeID, ids: routerIDs, tokens: tokens, selection: selection))
        nodePopup.selectItem(at: connectionProfileIdentityIndex(selection.selectedNodeID, ids: routerIDs, tokens: tokens, selection: selection))
        multihopEntryPopup.selectItem(at: connectionProfileIdentityIndex(selection.entryID, ids: multihopNodeIDs, tokens: multihopNodeTokens, selection: selection))
        multihopExitPopup.selectItem(at: connectionProfileIdentityIndex(selection.exitID, ids: multihopNodeIDs, tokens: multihopNodeTokens, selection: selection))
        multihopEntryModePopup.selectItem(at: selection.entryMode.flatMap { RouterVPNNodeEntryModes.index(for: $0) } ?? -1)
        multihopExitModePopup.selectItem(at: RouterVPNNodeExitModes.index(for: selection.exitMode) ?? -1)
        multihopExecutionPopup.selectItem(at: ["local", "server", "auto"].firstIndex(of: selection.execution) ?? -1)
        if let content = window?.contentView {
            func find(_ view: NSView) -> NSButton? {
                if view.identifier?.rawValue == "unified-multihop-toggle" { return view as? NSButton }
                for child in view.subviews { if let found = find(child) { return found } }
                return nil
            }
            find(content)?.state = selection.multihopEnabled ? .on : .off
        }
        refreshUnifiedHopOverlay()
    }

    func requireResolvedConnectionProfileSelection() throws {
        guard !MacProfileLoadTransaction.Store.standard.pending else { throw RouterVPNOrderedNodes.issue("Recover the pending connection profile Load first.") }
        let selection = captureConnectionProfileSelection()
        let tokens = try connectionProfileCatalogTokens(profiles)
        guard selection.selectedNodeID == connectionProfileCatalogSelectedID,
              connectionProfileIdentityIndex(selection.selectedNodeID, ids: routerIDs, tokens: tokens, selection: selection) == routerPopup.indexOfSelectedItem,
              routerIDs.indices.contains(routerPopup.indexOfSelectedItem) else {
            throw NSError(domain: "RouterVPN.ConnectionProfile", code: 5, userInfo: [NSLocalizedDescriptionKey: "Wait for the captured node catalog, or explicitly select a linked node. A removed or relinked node cannot substitute for the saved identity."])
        }
        if selection.multihopEnabled && !selection.orderedNodes.isEmpty {
            _ = try RouterVPNOrderedNodes.connectBody(selection, current: ["selected_id": connectionProfileCatalogSelectedID, "profiles": profiles])
        } else if selection.multihopEnabled {
            guard multihopNodeIDs.indices.contains(multihopEntryPopup.indexOfSelectedItem),
                  multihopNodeIDs.indices.contains(multihopExitPopup.indexOfSelectedItem),
                  connectionProfileIdentityIndex(selection.entryID, ids: multihopNodeIDs, tokens: multihopNodeTokens, selection: selection) == multihopEntryPopup.indexOfSelectedItem,
                  connectionProfileIdentityIndex(selection.exitID, ids: multihopNodeIDs, tokens: multihopNodeTokens, selection: selection) == multihopExitPopup.indexOfSelectedItem else {
                throw NSError(domain: "RouterVPN.ConnectionProfile", code: 6, userInfo: [NSLocalizedDescriptionKey: "Wait for both captured multihop nodes, or explicitly select their replacements. No first-node fallback is allowed."])
            }
        }
    }

    @discardableResult func applyConnectionProfileNodeCatalog(_ payload: [String: Any], capture: RouterVPNConnectionProfileRefresh) throws -> Bool {
        guard ownsConnectionProfileRefresh(capture, hops: false) else { return false }
        guard let nodes = payload["profiles"] as? [[String: Any]], let selected = payload["selected_id"] as? String else {
            throw NSError(domain: "RouterVPN.ConnectionProfile", code: 7, userInfo: [NSLocalizedDescriptionKey: "The node catalog response is incomplete."])
        }
        let tokens = try connectionProfileCatalogTokens(nodes)
        let ids = nodes.compactMap { $0["id"] as? String }
        let names = nodes.map { $0["name"] as? String ?? $0["id"] as? String ?? "Node" }
        var selection = capture.selection
        let adoptNodeDefaults = selection.selectedNodeID.isEmpty || selection.nodeDefaultsPending
        if selection.selectedNodeID.isEmpty { selection.selectedNodeID = selected }
        if adoptNodeDefaults && selection.selectedNodeID == selected {
            if let profile = nodes.first(where: { $0["id"] as? String == selected }), let raw = profile["multihop_nodes"], !(raw is NSNull) {
                let members = try RouterVPNOrderedNodes.decode(raw, control: selected)
                let referenced = Set(members.compactMap { $0["id"] } + [selected])
                var payload = profile
                payload["multihop_nodes"] = raw; payload["selected_node_id"] = selected
                payload["profile_tokens"] = tokens.filter { referenced.contains($0.key) }
                selection = try validatedLoadedConnectionProfileSelection(payload, fromCatalog: true)
                _ = try RouterVPNOrderedNodes.connectBody(selection, current: ["selected_id": selected, "profiles": nodes])
                let mode = selection.orderedNodes.last!["mode"]!
                UserDefaults.standard.set(mode, forKey: macConnectionModeKey)
                refreshUnifiedModeMenu(preferred: mode)
                UserDefaults.standard.set(selection.multihopEnabled, forKey: macConnectionMultihopEnabledKey)
            }
            selection.nodeDefaultsPending = false
        }
        if selection.profileTokens[selection.selectedNodeID] == nil, let token = tokens[selection.selectedNodeID] {
            selection.profileTokens[selection.selectedNodeID] = token
        }
        let previousNode = routerIDs.indices.contains(nodePopup.indexOfSelectedItem) ? routerIDs[nodePopup.indexOfSelectedItem] : selection.selectedNodeID
        let previousEntry = routerIDs.indices.contains(externalEntryPopup.indexOfSelectedItem) ? routerIDs[externalEntryPopup.indexOfSelectedItem] : ""
        var secondary = selection
        let oldTokens = (try? connectionProfileCatalogTokens(profiles)) ?? [:]
        for id in [previousNode, previousEntry] where secondary.profileTokens[id] == nil { secondary.profileTokens[id] = oldTokens[id] }
        profiles = nodes; routerIDs = ids; connectionProfileCatalogSelectedID = selected
        connectionProfileSelection = selection
        for popup in [routerPopup, nodePopup, externalEntryPopup] {
            popup.removeAllItems(); populateIdentityPopup(popup, names: names, ids: ids); popup.selectItem(at: -1)
        }
        if selected == selection.selectedNodeID {
            routerPopup.selectItem(at: connectionProfileIdentityIndex(selection.selectedNodeID, ids: ids, tokens: tokens, selection: selection))
        }
        nodePopup.selectItem(at: connectionProfileIdentityIndex(previousNode, ids: ids, tokens: tokens, selection: secondary))
        externalEntryPopup.selectItem(at: connectionProfileIdentityIndex(previousEntry, ids: ids, tokens: tokens, selection: secondary))
        renderProfiles(selected: selected)
        return true
    }

    @discardableResult func applyConnectionProfileHopCatalog(_ payload: [String: Any], capture: RouterVPNConnectionProfileRefresh) throws -> Bool {
        guard ownsConnectionProfileRefresh(capture, hops: true) else { return false }
        guard let nodes = payload["nodes"] as? [[String: Any]] else {
            throw NSError(domain: "RouterVPN.ConnectionProfile", code: 8, userInfo: [NSLocalizedDescriptionKey: "The multihop node catalog response is incomplete."])
        }
        let tokens = try connectionProfileCatalogTokens(nodes)
        let ids = nodes.compactMap { $0["id"] as? String }
        let names = nodes.map { $0["name"] as? String ?? $0["id"] as? String ?? "Node" }
        var selection = capture.selection
        // Only a never-selected graph may adopt the controller's explicit
        // configured IDs. Missing loaded or user-owned IDs remain missing.
        if selection.orderedNodes.isEmpty && selection.entryID.isEmpty && selection.exitID.isEmpty {
            selection.entryID = payload["configured_entry_id"] as? String ?? payload["entry_id"] as? String ?? ""
            selection.exitID = payload["configured_exit_id"] as? String ?? payload["exit_id"] as? String ?? ""
        }
        for id in [selection.entryID, selection.exitID] where selection.profileTokens[id] == nil {
            selection.profileTokens[id] = tokens[id]
        }
        multihopNodeIDs = ids; multihopNodeTokens = tokens; connectionProfileSelection = selection
        for popup in [multihopEntryPopup, multihopExitPopup] {
            popup.removeAllItems(); populateIdentityPopup(popup, names: names, ids: ids); popup.selectItem(at: -1)
        }
        multihopEntryPopup.selectItem(at: connectionProfileIdentityIndex(selection.entryID, ids: ids, tokens: tokens, selection: selection))
        multihopExitPopup.selectItem(at: connectionProfileIdentityIndex(selection.exitID, ids: ids, tokens: tokens, selection: selection))
        refreshUnifiedHopOverlay()
        return true
    }

    func connectionProfileSetupExpectations(_ body: [String: Any], selection: RouterVPNConnectionProfileSelection, loading: Bool) throws -> [String: Any] {
        let selected = selection.selectedNodeID
        if loading && selected.isEmpty && connectionProfileCatalogSelectedID.isEmpty {
            return ["expected_selected_node_id": "", "expected_profile_tokens": [String: String]()]
        }
        let matches = profiles.filter { $0["id"] as? String == selected }
        guard selected.range(of: "\\A[A-Za-z0-9_-]{1,64}\\z", options: .regularExpression) != nil,
              connectionProfileCatalogSelectedID == selected, matches.count == 1,
              selection.profileTokens[selected] == matches[0]["profile_token"] as? String else {
            throw RouterVPNOrderedNodes.issue("The original selected node is unresolved or changed. Refresh before changing a connection profile.")
        }
        let external = matches[0]["node_kind"] as? String == "external"
        // Load protects the current saved selection, independently of the
        // target record or an unsaved ordered editor draft.
        let graph = loading || external ? matches[0] : body
        var ids = Set([selected])
        if graph["multihop_enabled"] as? Bool == true {
            if let raw = graph["multihop_nodes"], !(raw is NSNull) {
                ids.formUnion(try RouterVPNOrderedNodes.decode(raw, control: selected).compactMap { $0["id"] })
            } else {
                guard let entry = graph["multihop_entry_id"] as? String, let exit = graph["multihop_exit_id"] as? String,
                      !entry.isEmpty, !exit.isEmpty else {
                    throw RouterVPNOrderedNodes.issue("The original connection profile has an incomplete node selection.")
                }
                ids.formUnion([entry, exit])
            }
        }
        let catalog = try connectionProfileCatalogTokens(profiles)
        let originals = loading || external ? catalog : selection.profileTokens
        var tokens: [String: String] = [:]
        for id in ids {
            guard id.range(of: "\\A[A-Za-z0-9_-]{1,64}\\z", options: .regularExpression) != nil,
                  let token = originals[id], validConnectionProfileToken(token), catalog[id] == token else {
                throw RouterVPNOrderedNodes.issue("An original connection node changed or was relinked. Refresh before continuing.")
            }
            tokens[id] = token
        }
        return ["expected_selected_node_id": selected, "expected_profile_tokens": tokens]
    }

    func confirmedConnectionProfileSave(_ response: [String: Any], body: [String: Any], original: RouterVPNConnectionProfileSelection) throws -> RouterVPNConnectionProfileSelection {
        let finalized = try validatedLoadedConnectionProfileSelection(response)
        guard finalized.selectedNodeID == original.selectedNodeID,
              response["profile_tokens"] as? [String: String] == body["expected_profile_tokens"] as? [String: String] else {
            throw RouterVPNOrderedNodes.issue("The saved profile response replaced an original selected node or source.")
        }
        let wanted = body["multihop_nodes"] as? [[String: String]] ?? []
        guard finalized.orderedNodes == wanted, wanted.isEmpty || finalized.execution == body["multihop_execution"] as? String else {
            throw RouterVPNOrderedNodes.issue("The saved profile response changed the original ordered path.")
        }
        let external = (response["profile"] as? [String: Any])?["external_policy"] is [String: Any]
        if !external {
            guard finalized.multihopEnabled == (body["multihop_enabled"] as? Bool ?? false),
                  finalized.entryID == (body["multihop_entry_id"] as? String ?? ""),
                  finalized.exitID == (body["multihop_exit_id"] as? String ?? ""),
                  (response["profile"] as? [String: Any])?["mode"] as? String == body["mode"] as? String else {
                throw RouterVPNOrderedNodes.issue("The saved profile response changed the requested node selection.")
            }
            if finalized.multihopEnabled && wanted.isEmpty {
                let entryMode = body["multihop_entry_mode"] as? String ?? ""
                guard finalized.exitMode == body["multihop_exit_mode"] as? String,
                      finalized.execution == body["multihop_execution"] as? String,
                      entryMode.isEmpty || finalized.entryMode == entryMode else {
                    throw RouterVPNOrderedNodes.issue("The saved profile response changed the requested path transports.")
                }
            }
        }
        var retained = original
        retained.profileTokens.merge(finalized.profileTokens) { _, source in source }
        return retained
    }

    @objc func manageConnectionProfiles() {
        do { try recoverCoordinatedProfileLoad() } catch { showConnectionProfileMessage(error.localizedDescription, error: true); return }
        guard ensureMutationIdle("opening connection profiles") else { return }
        while true {
            do {
                let data = try api.request("/api/connection-profiles", timeout: 5)
                let list = try JSONDecoder().decode(MacConnectionProfileList.self, from: data)
                let alert = NSAlert()
                alert.messageText = "Connection profiles"
                alert.informativeText = "Save or restore the selected node, Mode/CUSTOM layers, DNS/settings and exact multihop entry → exit → exit transport. Node keys, API tokens and external credentials remain only in the private node store. Loading never connects automatically."
                alert.addButton(withTitle: "Load")
                alert.addButton(withTitle: "Add current")
                alert.addButton(withTitle: "Update")
                alert.addButton(withTitle: "Delete")
                alert.addButton(withTitle: "Close")

                let stack = NSStackView(); stack.orientation = .vertical; stack.spacing = 8; stack.frame = NSRect(x: 0, y: 0, width: 560, height: 90)
                let popup = NSPopUpButton(); popup.removeAllItems()
                for item in list.profiles {
                    popup.addItem(withTitle: "\(item.name) • \(item.mode) • \(item.nodeID)")
                    popup.lastItem?.representedObject = item.id
                }
                if list.profiles.isEmpty { popup.addItem(withTitle: "No saved profiles"); popup.lastItem?.isEnabled = false }
                let name = NSTextField(string: list.profiles.first?.name ?? "")
                name.placeholderString = "Profile name"
                stack.addArrangedSubview(popup); stack.addArrangedSubview(name)
                alert.accessoryView = stack

                let response = alert.runModal().rawValue - NSApplication.ModalResponse.alertFirstButtonReturn.rawValue
                if response == 4 { return }
                switch response {
                case 0:
                    guard let id = popup.selectedItem?.representedObject as? String, let profile = list.profiles.first(where: { $0.id == id }) else { showConnectionProfileMessage("Select a saved profile first.", error: true); continue }
                    let payload = try connectionProfilePOST("/api/connection-profile/setup/load", body: ["id": id, "expected_mode": profile.mode])
                    refreshAll(); refreshUnifiedModeMenu(preferred: payload["mode"] as? String); refreshUnifiedChrome()
                    let loadedName = (payload["profile"] as? [String: Any])?["name"] as? String ?? "profile"
                    showConnectionProfileMessage("Loaded \(loadedName). Connect separately so the selected dataplane is established and proved.", error: false)
                case 1:
                    let profileName = name.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
                    guard !profileName.isEmpty else { showConnectionProfileMessage("Enter a profile name.", error: true); continue }
                    let result = try connectionProfilePOST("/api/connection-profile/setup/save", body: connectionProfileSnapshot(name: profileName, id: nil))
                    let savedName = (result["profile"] as? [String: Any])?["name"] as? String ?? profileName
                    showConnectionProfileMessage("Saved \(savedName).", error: false)
                case 2:
                    guard let id = popup.selectedItem?.representedObject as? String, !id.isEmpty else { showConnectionProfileMessage("Select a saved profile first.", error: true); continue }
                    let profileName = name.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
                    guard !profileName.isEmpty else { showConnectionProfileMessage("Enter a profile name.", error: true); continue }
                    _ = try connectionProfilePOST("/api/connection-profile/setup/update", body: connectionProfileSnapshot(name: profileName, id: id))
                    showConnectionProfileMessage("Updated \(profileName).", error: false)
                case 3:
                    guard let id = popup.selectedItem?.representedObject as? String, !id.isEmpty else { showConnectionProfileMessage("Select a saved profile first.", error: true); continue }
                    let confirm = NSAlert(); confirm.alertStyle = .warning; confirm.messageText = "Delete saved connection profile?"; confirm.informativeText = "This removes only the reusable setup. Linked Router/custom node credentials are not deleted."; confirm.addButton(withTitle: "Delete"); confirm.addButton(withTitle: "Cancel")
                    if confirm.runModal() == .alertFirstButtonReturn {
                        _ = try connectionProfilePOST("/api/connection-profile/setup/delete", body: ["id": id])
                        showConnectionProfileMessage("Deleted the reusable connection profile. Linked nodes were not changed.", error: false)
                    }
                default:
                    return
                }
            } catch {
                showConnectionProfileMessage(error.localizedDescription, error: true)
            }
        }
    }

    func connectionProfileSnapshot(name: String, id: String?) throws -> [String: Any] {
        try requireMutationIdle("saving a connection profile")
        try requireResolvedConnectionProfileSelection()
        let selectedPath = captureConnectionProfileSelection()
        if selectedPath.multihopEnabled && !selectedPath.orderedNodes.isEmpty {
            var body: [String: Any] = ["name": name, "mode": selectedPath.orderedNodes.last!["mode"]!, "custom_layers": [String](),
                "multihop_enabled": true, "multihop_nodes": selectedPath.orderedNodes, "multihop_execution": selectedPath.execution]
            if let id { body["id"] = id }
            body.merge(try connectionProfileSetupExpectations(body, selection: selectedPath, loading: false)) { _, original in original }
            return body
        }
        let external = profiles.first(where: { $0["id"] as? String == selectedPath.selectedNodeID })?["node_kind"] as? String == "external"
        let (mode, layers) = try external ? ("external", [String]()) : macCurrentConnectionModeSnapshot()
        let multihop = !external && UserDefaults.standard.bool(forKey: macConnectionMultihopEnabledKey)
        let entryIndex = multihopEntryPopup.indexOfSelectedItem
        let exitIndex = multihopExitPopup.indexOfSelectedItem
        let entry = multihop && entryIndex >= 0 && entryIndex < multihopNodeIDs.count ? multihopNodeIDs[entryIndex] : ""
        let exit = multihop && exitIndex >= 0 && exitIndex < multihopNodeIDs.count ? multihopNodeIDs[exitIndex] : ""
        let entryMode = try (multihop ? RouterVPNNodeEntryModes.require(index: multihopEntryModePopup.indexOfSelectedItem) : "")
        let exitMode = try (multihop ? RouterVPNNodeExitModes.require(index: multihopExitModePopup.indexOfSelectedItem) : "")
        var body: [String: Any] = [
            "name": name, "mode": mode, "custom_layers": layers,
            "multihop_enabled": multihop, "multihop_entry_id": entry, "multihop_entry_mode": entryMode,
            "multihop_exit_id": exit, "multihop_exit_mode": exitMode,
            "multihop_execution": multihop ? multihopExecutionChoice() : "",
        ]
        if let id { body["id"] = id }
        body.merge(try connectionProfileSetupExpectations(body, selection: selectedPath, loading: false)) { _, original in original }
        return body
    }

    func connectionProfilePOST(_ path: String, body: [String: Any], transport: ProductAPI? = nil) throws -> [String: Any] {
        let original = captureConnectionProfileSelection()
        let generation = connectionProfileSelectionGeneration
        let mode = UserDefaults.standard.string(forKey: macConnectionModeKey)
        let presets = UserDefaults.standard.data(forKey: macConnectionCustomPresetsKey)
        try requireMutationIdle("changing a connection profile")
        let loading = path == "/api/connection-profile/setup/load"
        let writing = path == "/api/connection-profile/setup/save" || path == "/api/connection-profile/setup/update"
        var request = body
        if loading {
            guard let targetMode = body["expected_mode"] as? String else {
                throw RouterVPNOrderedNodes.issue("Refresh the profile list before loading its saved mode.")
            }
            if let targetName = macCustomPresetName(in: targetMode) {
                _ = try MacConnectionCustomPreset.target(targetName, in: MacConnectionCustomPreset.catalog(presets))
            }
        }
        if writing && !(profiles.first(where: { $0["id"] as? String == original.selectedNodeID })?["node_kind"] as? String == "external") {
            guard body["multihop_enabled"] as? Bool == original.multihopEnabled else {
                throw RouterVPNOrderedNodes.issue("The visible multihop choice changed before its setup request.")
            }
            if original.multihopEnabled {
                let ordered = body["multihop_nodes"] as? [[String: String]] ?? []
                guard ordered == original.orderedNodes, body["multihop_execution"] as? String == original.execution,
                      !ordered.isEmpty || (body["multihop_entry_id"] as? String == original.entryID &&
                        body["multihop_exit_id"] as? String == original.exitID &&
                        body["multihop_entry_mode"] as? String == original.entryMode &&
                        body["multihop_exit_mode"] as? String == original.exitMode &&
                        body["multihop_execution"] as? String == original.execution) else {
                    throw RouterVPNOrderedNodes.issue("The original path changed before its setup request.")
                }
            }
        }
        if loading || writing {
            let expected = try connectionProfileSetupExpectations(body, selection: original, loading: loading)
            if body["expected_selected_node_id"] != nil || body["expected_profile_tokens"] != nil {
                guard body["expected_selected_node_id"] as? String == expected["expected_selected_node_id"] as? String,
                      body["expected_profile_tokens"] as? [String: String] == expected["expected_profile_tokens"] as? [String: String] else {
                    throw RouterVPNOrderedNodes.issue("The original setup source capture changed before its request.")
                }
            }
            request.merge(expected) { _, original in original }
        }
        guard connectionProfileSelectionGeneration == generation, captureConnectionProfileSelection() == original,
              UserDefaults.standard.string(forKey: macConnectionModeKey) == mode,
              UserDefaults.standard.data(forKey: macConnectionCustomPresetsKey) == presets else {
            throw RouterVPNOrderedNodes.issue("The selected path changed before the profile request.")
        }
        if loading {
            let service = transport ?? api
            let previous = try MacProfileLoadTransaction.Local(defaults: .standard, selection: original)
            connectionProfileSelectionGeneration = UUID()
            let ticket = connectionProfileSelectionGeneration
            return try MacProfileLoadTransaction.load(body: request, previous: previous, store: .standard, defaults: .standard,
                send: { phase, fields in try service.request(MacProfileLoadTransaction.base + phase, method: "POST", body: fields, timeout: 15) },
                validate: { result in
                    try self.requireMutationIdle("adopting the prepared connection profile")
                    try previous.verify(in: .standard)
                    guard self.connectionProfileSelectionGeneration == ticket, self.captureConnectionProfileSelection() == original,
                          let expected = request["expected_mode"] as? String, let actual = result["mode"] as? String,
                          expected.utf8.elementsEqual(actual.utf8),
                          let originals = request["expected_profile_tokens"] as? [String:String] else {
                        throw RouterVPNOrderedNodes.issue("The selected source or saved mode changed before Load.")
                    }
                    let current = try self.connectionProfileCatalogTokens(self.profiles)
                    guard originals.allSatisfy({ id, token in current[id] == token }) else {
                        throw RouterVPNOrderedNodes.issue("An original node changed before loading this profile.")
                    }
                    return try self.validatedLoadedConnectionProfileSelection(result)
                }, checkPath: requireCoordinatedProfilePath, adopt: adoptCoordinatedProfileSelection)
        }
        let admittedGeneration = connectionProfileSelectionGeneration
        let data = try (transport ?? api).request(path, method: "POST", body: request, timeout: 15)
        guard let value = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw NSError(domain: "RouterVPN.ConnectionProfile", code: 1, userInfo: [NSLocalizedDescriptionKey: "Connection profile endpoint returned invalid JSON."]) }
        try requireMutationIdle("adopting the captured connection profile response")
        guard connectionProfileSelectionGeneration == admittedGeneration, captureConnectionProfileSelection() == original,
              UserDefaults.standard.string(forKey: macConnectionModeKey) == mode,
              UserDefaults.standard.data(forKey: macConnectionCustomPresetsKey) == presets else {
            throw RouterVPNOrderedNodes.issue("The displayed path changed while its profile request was completing. Refresh before continuing.")
        }
        if loading || writing {
            let originals = request["expected_profile_tokens"] as? [String: String] ?? [:]
            let current = try connectionProfileCatalogTokens(profiles)
            guard originals.allSatisfy({ current[$0.key] == $0.value }) else {
                throw RouterVPNOrderedNodes.issue("An original node changed while the profile request was completing.")
            }
        }
        if writing {
            let retained = try confirmedConnectionProfileSave(value, body: request, original: original)
            adoptLoadedConnectionProfileSelection(retained)
        }
        return value
    }

    private func showConnectionProfileMessage(_ text: String, error: Bool) {
        let alert = NSAlert(); alert.alertStyle = error ? .warning : .informational; alert.messageText = error ? "Connection profile" : "Connection profile"; alert.informativeText = text; alert.addButton(withTitle: "OK"); _ = alert.runModal()
    }
}

// macOS connection-profile contract: Add Load Update Delete; setup-aware endpoints; exact current mode/CUSTOM layers;
// exact visible multihop entry/exit/exit transport; load never auto-connects; linked node secrets stay only in the private node store.

final class RouterVPNOrderedNodeEditor: NSWindowController, NSMenuDelegate {
    private weak var owner: ProductWindowController?
    private var draft: RouterVPNOrderedNodeDraft
    private var revision = UUID()
    private var openedRevision: UUID?
    private let path = NSPopUpButton(frame: .zero, pullsDown: false)
    private let candidates = NSPopUpButton(frame: .zero, pullsDown: false)
    private let transport = NSPopUpButton(frame: .zero, pullsDown: false)
    private let status = NSTextField(wrappingLabelWithString: "")

    init(owner: ProductWindowController, draft: RouterVPNOrderedNodeDraft) {
        self.owner = owner; self.draft = draft
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 640, height: 380), styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        window.title = "Ordered multihop"; window.minSize = NSSize(width: 580, height: 360); window.isReleasedWhenClosed = false
        super.init(window: window)
        let root = NSStackView(); root.orientation = .vertical; root.alignment = .leading; root.spacing = 12
        root.edgeInsets = NSEdgeInsets(top: 18, left: 18, bottom: 18, right: 18)
        let note = NSTextField(wrappingLabelWithString: "Choose the entry and preceding hops. Longer Local packet paths use paired WireGuard nodes and a paired Shadowsocks 2022 final, all with Start Layer Off. Longer Local routes can also begin with paired WireGuard or AWG2 nodes followed by literal Shadowsocks 2022 imports. Keep every Start Layer Off. Each packet layer must fit the route MTU. Choose Shadowsocks 2022 or Hysteria2 for the selected final exit; Hysteria2 keeps its own Start Layer. An imported SS2022, SOCKS5, HTTP(S) CONNECT or OpenVPN middle requires a Shadowsocks 2022 final. With a paired entry, supported SS2022 imports can occupy any interior position. Server and Compare require support from every import and the native controller. An OpenVPN middle also needs its own private pairing. Each node keeps its own linked credentials and settings.")
        root.addArrangedSubview(note)
        path.setAccessibilityLabel("Ordered path"); path.target = self; path.action = #selector(selectedHopChanged); root.addArrangedSubview(path)
        transport.setAccessibilityLabel("Selected node transport")
        transport.target = self; transport.action = #selector(transportChanged); root.addArrangedSubview(transport)
        let move = NSStackView(); move.orientation = .horizontal; move.spacing = 8
        for (title, action) in [("Move up", #selector(moveUp)), ("Move down", #selector(moveDown)), ("Remove hop", #selector(removeHop))] { move.addArrangedSubview(NSButton(title: title, target: self, action: action)) }
        move.addArrangedSubview(NSButton(title: "Measure next hop…", target: self, action: #selector(measureNext)))
        root.addArrangedSubview(move)
        candidates.menu?.delegate = self
        candidates.setAccessibilityLabel("Available linked entry and hop nodes")
        for id in draft.candidates { candidates.addItem(withTitle: "\(draft.names[id] ?? id) · \(id)"); candidates.lastItem?.representedObject = id }
        let add = NSStackView(); add.orientation = .horizontal; add.spacing = 8; add.addArrangedSubview(candidates); add.addArrangedSubview(NSButton(title: "Add entry / hop", target: self, action: #selector(addHop))); root.addArrangedSubview(add)
        status.textColor = .secondaryLabelColor; root.addArrangedSubview(status)
        let finish = NSStackView(); finish.orientation = .horizontal; finish.spacing = 8
        finish.addArrangedSubview(NSButton(title: "Cancel", target: self, action: #selector(cancelEditing)))
        let apply = NSButton(title: "Apply path", target: self, action: #selector(applyPath)); apply.keyEquivalent = "\r"; finish.addArrangedSubview(apply); root.addArrangedSubview(finish)
        window.contentView = root; render()
    }
    required init?(coder: NSCoder) { nil }
    private func render(selected: Int? = nil) {
        revision = UUID()
        path.removeAllItems()
        for (index, row) in draft.nodes.enumerated() {
            let id = row["id"]!, role = index == draft.prefixes.count ? "Exit" : index == 0 ? "Entry" : "Hop \(index)"
            path.addItem(withTitle: "\(index + 1). \(role) · \(RouterVPNOrderedNodes.modeName(row["mode"]!)) · \(draft.names[id] ?? id) · \(id)")
        }
        path.selectItem(at: min(max(selected ?? 0, 0), draft.nodes.count - 1))
        selectedHopChanged()
        status.stringValue = "\(draft.nodes.count) nodes. Apply stages this selection; Connect starts it."
    }
    @objc private func selectedHopChanged() {
        let index = path.indexOfSelectedItem
        let modes = draft.allowedModes(at: index)
        transport.removeAllItems()
        for mode in modes { transport.addItem(withTitle: RouterVPNOrderedNodes.modeName(mode)); transport.lastItem?.representedObject = mode }
        transport.isEnabled = !modes.isEmpty
        transport.selectItem(at: draft.nodes.indices.contains(index) ? modes.firstIndex(of: draft.nodes[index]["mode"]!) ?? -1 : -1)
    }
    @objc private func transportChanged() {
        do {
            guard let mode = transport.selectedItem?.representedObject as? String else { throw RouterVPNOrderedNodes.issue("Choose a transport for the selected node.") }
            let index = path.indexOfSelectedItem; try draft.chooseMode(mode, at: index); render(selected: index)
        } catch { status.stringValue = error.localizedDescription }
    }
    @objc private func addHop() {
        do { guard let id = candidates.selectedItem?.representedObject as? String else { throw RouterVPNOrderedNodes.issue("Link another router node first.") }; try draft.add(id); render(selected: draft.prefixes.count - 1) }
        catch { status.stringValue = error.localizedDescription }
    }
    private func move(_ offset: Int) {
        do { let index = path.indexOfSelectedItem; try draft.move(index, by: offset); render(selected: index + offset) }
        catch { status.stringValue = error.localizedDescription }
    }
    @objc private func moveUp() { move(-1) }
    @objc private func moveDown() { move(1) }
    @objc private func removeHop() {
        do { let index = path.indexOfSelectedItem; try draft.remove(index); render(selected: index) }
        catch { status.stringValue = error.localizedDescription }
    }
    func menuWillOpen(_ menu: NSMenu) {
        guard menu === candidates.menu, openedRevision != revision, !draft.prefixes.isEmpty, draft.canMeasure(after: draft.prefixes.count - 1),
              draft.modes.last == "shadowsocks" || draft.execution != "local" || draft.modes.allSatisfy(RouterVPNOrderedNodes.prefixModes.contains) else { return }
        openedRevision = revision
        let original = revision
        menu.cancelTracking()
        DispatchQueue.main.async { [weak self] in
            guard let self, self.revision == original, self.window?.isVisible == true else { return }
            self.path.selectItem(at: self.draft.prefixes.count - 1)
            self.selectedHopChanged()
            self.measureNext()
        }
    }
    @objc private func measureNext() {
        do {
            let index = path.indexOfSelectedItem, original = revision
            guard let owner, draft.canMeasure(after: index) else {
                throw RouterVPNOrderedNodes.issue("Choose a supported packet or Local Shadowsocks prefix to measure its candidates.")
            }
            let selection = try draft.selection()
            let body = try RouterVPNOrderedNodes.connectBody(selection, current: ["profiles": draft.capturedCatalog, "selected_id": draft.control])
            owner.showOrderedPrefixCandidates(savedPrefix: true, draft: body, position: index) { [weak self, weak owner] response in
                guard let self, let owner, self.window?.isVisible == true, self.revision == original, self.path.indexOfSelectedItem == index,
                      owner.connectionProfileSelectionGeneration == self.draft.generation,
                      owner.captureConnectionProfileSelection().selectedNodeID == self.draft.control else {
                    throw RouterVPNOrderedNodes.issue("The editor changed. Reopen its current prefix.")
                }
                var updated = self.draft
                try updated.insertMeasured(response, after: index)
                let current = try owner.api.json("/api/profiles", timeout: 5) as? [String: Any] ?? [:]
                _ = try RouterVPNOrderedNodes.connectBody(updated.selection(), current: current)
                self.draft = updated
                self.render(selected: index + 1)
            }
        } catch { status.stringValue = error.localizedDescription }
    }
    @objc private func applyPath() {
        do { guard let owner else { throw RouterVPNOrderedNodes.issue("Reopen the editor from the current Router VPN window.") }; try owner.applyOrderedNodeDraft(draft); close() }
        catch { status.stringValue = error.localizedDescription }
    }
    @objc private func cancelEditing() { close() }
}
