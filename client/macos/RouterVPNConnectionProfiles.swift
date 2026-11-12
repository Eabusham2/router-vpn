import AppKit
import Foundation
import CoreFoundation

private let macConnectionModeKey = "routervpn.unified.selected-mode.v1"
private let macConnectionCustomPresetsKey = "routervpn.unified.custom-presets.v1"
private let macConnectionMultihopEnabledKey = "routervpn.unified.multihop-enabled.v1"

enum RouterVPNOrderedNodes {
    static let prefixModes = ["wg", "awg2-fast", "awg2-strong"]
    static let editorModes = prefixModes + ["shadowsocks"]
    static func importedMiddle(_ profile: [String: Any]) -> Bool {
        guard profile["node_kind"] as? String == "external", let value = (profile["external"] as? [String: Any])?["ordered_middle_supported"] as? NSNumber, CFGetTypeID(value) == CFBooleanGetTypeID() else { return false }
        return value.boolValue
    }
    static func modeName(_ mode: String) -> String {
        switch mode {
        case "wg": return "WireGuard"
        case "awg2-fast": return "AWG2 Fast"
        case "awg2-strong": return "AWG2 Strong"
        case "shadowsocks": return "Shadowsocks 2022"
        default: return "Unknown saved transport"
        }
    }
    static func issue(_ message: String) -> NSError {
        NSError(domain: "RouterVPN.OrderedNodes", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
    static func decode(_ raw: Any, control: String) throws -> [[String: String]] {
        guard let rows = raw as? [[String: String]], (2...8).contains(rows.count) else {
            throw issue("Choose between two and eight ordered nodes.")
        }
        var seen = Set<String>()
        for (position, row) in rows.enumerated() {
            guard Set(row.keys) == Set(["id", "mode"]), let id = row["id"],
                  id.range(of: "\\A[A-Za-z0-9_-]{1,64}\\z", options: .regularExpression) != nil,
                  seen.insert(id).inserted,
                  let mode = row["mode"],
                  position == rows.count - 1 ? mode == "shadowsocks" : prefixModes.contains(mode) || (rows.count == 3 && position == 1 && mode == "shadowsocks") else {
                throw issue("Choose paired WireGuard or AWG2 prefixes, optionally one imported SS2022 middle in a three-node path, and a paired Shadowsocks 2022 exit.")
            }
        }
        guard !control.isEmpty, rows.last?["id"] == control else {
            throw issue("The final ordered node must be the independently selected exit.")
        }
        return rows
    }
    static func connectBody(_ selection: RouterVPNConnectionProfileSelection, current: [String: Any]) throws -> [String: Any] {
        let rows = try decode(selection.orderedNodes, control: selection.selectedNodeID)
        guard selection.multihopEnabled, selection.execution == "local",
              selection.entryID.isEmpty, selection.exitID.isEmpty, selection.entryMode == "", selection.exitMode.isEmpty,
              current["selected_id"] as? String == selection.selectedNodeID,
              let profiles = current["profiles"] as? [[String: Any]] else {
            throw issue("The ordered path or selected exit changed. Reopen its editor.")
        }
        for (position, row) in rows.enumerated() {
            let id = row["id"]!
            let matches = profiles.filter { $0["id"] as? String == id }
            guard matches.count == 1 else { throw issue("An ordered source is missing.") }
            let imported = importedMiddle(matches[0])
            guard imported ? rows.count == 3 && position == 1 && row["mode"] == "shadowsocks" : ["", "router-vpn"].contains(matches[0]["node_kind"] as? String ?? "router-vpn") && (position == rows.count - 1 || prefixModes.contains(row["mode"]!)) else { throw issue("The ordered source kind or position changed.") }
            guard
                  let token = selection.profileTokens[id], token.range(of: "\\A[0-9a-f]{64}\\z", options: .regularExpression) != nil,
                  matches[0]["profile_token"] as? String == token else {
                throw issue("An ordered node is missing or has been relinked. Reopen its editor before connecting.")
            }
        }
        let tokens = Dictionary(uniqueKeysWithValues: rows.map { ($0["id"]!, selection.profileTokens[$0["id"]!]!) })
        return ["nodes": rows, "execution": "local", "expected_selected_node_id": selection.selectedNodeID,
                "expected_profile_tokens": tokens]
    }
}

// Public references only. Source tokens are opaque hashes produced by the
// controller; credentials remain in its private node store.
struct RouterVPNConnectionProfileSelection: Equatable, Sendable {
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
    private(set) var prefixes: [String]
    private(set) var modes: [String]

    init(selection: RouterVPNConnectionProfileSelection, generation: UUID, catalog: [[String: Any]]) throws {
        control = selection.selectedNodeID; self.generation = generation
        var names: [String: String] = [:], tokens: [String: String] = [:]
        var importedIDs = Set<String>()
        for row in catalog {
            guard let id = row["id"] as? String, names[id] == nil,
                  id.range(of: "\\A[A-Za-z0-9_-]{1,64}\\z", options: .regularExpression) != nil,
                  let token = row["profile_token"] as? String,
                  token.range(of: "\\A[0-9a-f]{64}\\z", options: .regularExpression) != nil else {
                throw RouterVPNOrderedNodes.issue("Refresh the node catalog before opening the ordered editor.")
            }
            let imported = RouterVPNOrderedNodes.importedMiddle(row)
            guard imported || ["", "router-vpn"].contains(row["node_kind"] as? String ?? "router-vpn") else { continue }
            if imported { importedIDs.insert(id) }
            names[id] = row["name"] as? String ?? id; tokens[id] = token
        }
        guard let selectedToken = selection.profileTokens[control], tokens[control] == selectedToken, !importedIDs.contains(control) else {
            throw RouterVPNOrderedNodes.issue("Select the linked final exit before opening the ordered editor.")
        }
        self.names = names; self.tokens = tokens; self.importedIDs = importedIDs
        candidates = names.keys.filter { $0 != selection.selectedNodeID }.sorted()
        if selection.orderedNodes.isEmpty { prefixes = []; modes = [] }
        else {
            let nodes = try RouterVPNOrderedNodes.decode(selection.orderedNodes, control: control)
            guard nodes.allSatisfy({ tokens[$0["id"]!] == selection.profileTokens[$0["id"]!] }) else {
                throw RouterVPNOrderedNodes.issue("A saved ordered node was relinked. Reload its profile before editing.")
            }
            prefixes = nodes.dropLast().map { $0["id"]! }
            modes = nodes.dropLast().map { $0["mode"]! }
        }
    }
    var nodes: [[String: String]] { prefixes.enumerated().map { ["id": $0.element, "mode": modes[$0.offset]] } + [["id": control, "mode": "shadowsocks"]] }
    mutating func add(_ id: String) throws {
        guard candidates.contains(id), !prefixes.contains(id), prefixes.count < 7 else {
            throw RouterVPNOrderedNodes.issue("Choose a different entry or hop. The path supports up to eight nodes.")
        }
        prefixes.append(id)
        modes.append(importedIDs.contains(id) ? "shadowsocks" : "wg")
    }
    mutating func chooseMode(_ mode: String, at index: Int) throws {
        guard prefixes.indices.contains(index), importedIDs.contains(prefixes[index]) ? mode == "shadowsocks" : RouterVPNOrderedNodes.prefixModes.contains(mode) else {
            throw RouterVPNOrderedNodes.issue("Choose WireGuard, AWG2 Fast or AWG2 Strong for an entry or hop. The final exit stays Shadowsocks 2022.")
        }
        modes[index] = mode
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
        for (index, id) in prefixes.enumerated() {
            guard importedIDs.contains(id) ? ordered.count == 3 && index == 1 && modes[index] == "shadowsocks" : RouterVPNOrderedNodes.prefixModes.contains(modes[index]) else { throw RouterVPNOrderedNodes.issue("An imported SS2022 member requires one middle position between a paired entry and final.") }
        }
        return RouterVPNConnectionProfileSelection(selectedNodeID: control, multihopEnabled: true, entryMode: "",
            execution: "local", profileTokens: tokens.filter { key, _ in ordered.contains { $0["id"] == key } }, orderedNodes: ordered)
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

private struct MacConnectionCustomPreset: Codable {
    var name: String
    var layers: [String]
}

extension ProductWindowController {
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
        UserDefaults.standard.set("shadowsocks", forKey: macConnectionModeKey)
        refreshUnifiedModeMenu(preferred: "shadowsocks")
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
            guard let enabled = capabilities["ordered_nodes_supported"] as? NSNumber,
                  CFGetTypeID(enabled) == CFBooleanGetTypeID(), enabled.boolValue else {
                throw RouterVPNOrderedNodes.issue("This controller has not enabled ordered-node execution on this device.")
            }
            let current = try self.api.json("/api/profiles", timeout: 5) as? [String: Any] ?? [:]
            let body = try RouterVPNOrderedNodes.connectBody(selection, current: current)
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
            value.entryID = ""; value.exitID = ""; value.entryMode = ""; value.exitMode = ""; value.execution = "local"
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

    func beginConnectionProfileLoad() {
        // A timed-out or malformed successful POST cannot establish whether
        // the controller still owns the old selection. Preserve references for
        // recovery, but retire the UI's authority before crossing that boundary.
        connectionProfileSelection = captureConnectionProfileSelection()
        connectionProfileSelectionGeneration = UUID()
        connectionProfileCatalogSelectedID = ""
        routerPopup.selectItem(at: -1); nodePopup.selectItem(at: -1)
        multihopEntryPopup.selectItem(at: -1); multihopExitPopup.selectItem(at: -1)
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
            guard !external, selection.multihopEnabled, selection.execution == "local",
                  selection.entryID.isEmpty, selection.exitID.isEmpty, selection.entryMode == "", selection.exitMode.isEmpty,
                  fromCatalog || stored?["mode"] as? String == "shadowsocks" else {
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

    func adoptLoadedConnectionProfileSelection(_ selection: RouterVPNConnectionProfileSelection) {
        connectionProfileSelectionGeneration = UUID()
        connectionProfileSelection = selection
        connectionProfileCatalogSelectedID = selection.selectedNodeID
        UserDefaults.standard.set(selection.multihopEnabled, forKey: macConnectionMultihopEnabledKey)
        UserDefaults.standard.set(selection.execution, forKey: "routervpn.multihop.execution.v1")
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
        guard finalized.orderedNodes == wanted else {
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
                    guard let id = popup.selectedItem?.representedObject as? String, !id.isEmpty else { showConnectionProfileMessage("Select a saved profile first.", error: true); continue }
                    let payload = try connectionProfilePOST("/api/connection-profile/setup/load", body: ["id": id])
                    try applyLoadedConnectionProfile(payload)
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
            var body: [String: Any] = ["name": name, "mode": "shadowsocks", "custom_layers": [String](),
                "multihop_enabled": true, "multihop_nodes": selectedPath.orderedNodes, "multihop_execution": "local"]
            if let id { body["id"] = id }
            body.merge(try connectionProfileSetupExpectations(body, selection: selectedPath, loading: false)) { _, original in original }
            return body
        }
        let mode = UserDefaults.standard.string(forKey: macConnectionModeKey) ?? "smart-auto"
        var layers: [String] = []
        if mode.hasPrefix("custom:"), let data = UserDefaults.standard.data(forKey: macConnectionCustomPresetsKey), let presets = try? JSONDecoder().decode([MacConnectionCustomPreset].self, from: data) {
            let presetName = String(mode.dropFirst("custom:".count))
            layers = presets.first(where: { $0.name == presetName })?.layers ?? []
        }
        var multihop = UserDefaults.standard.bool(forKey: macConnectionMultihopEnabledKey)
        let selectedIndex = routerPopup.indexOfSelectedItem
        if selectedIndex >= 0 && selectedIndex < profiles.count, (profiles[selectedIndex]["node_kind"] as? String ?? "router-vpn").lowercased() == "external" { multihop = false }
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
        if writing && !(profiles.first(where: { $0["id"] as? String == original.selectedNodeID })?["node_kind"] as? String == "external") {
            guard body["multihop_enabled"] as? Bool == original.multihopEnabled else {
                throw RouterVPNOrderedNodes.issue("The visible multihop choice changed before its setup request.")
            }
            if original.multihopEnabled {
                let ordered = body["multihop_nodes"] as? [[String: String]] ?? []
                guard ordered == original.orderedNodes,
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
        if loading { beginConnectionProfileLoad() }
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
        } else if loading {
            _ = try validatedLoadedConnectionProfileSelection(value)
        }
        return value
    }

    private func applyLoadedConnectionProfile(_ payload: [String: Any]) throws {
        try requireMutationIdle("loading a connection profile")
        let selection = try validatedLoadedConnectionProfileSelection(payload)
        let rawMode = (payload["mode"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let mode = rawMode.isEmpty ? "smart-auto" : rawMode
        if mode.hasPrefix("custom:"), let layers = payload["custom_layers"] as? [String], !layers.isEmpty {
            let name = String(mode.dropFirst("custom:".count))
            var presets: [MacConnectionCustomPreset] = []
            if let data = UserDefaults.standard.data(forKey: macConnectionCustomPresetsKey) { presets = (try? JSONDecoder().decode([MacConnectionCustomPreset].self, from: data)) ?? [] }
            presets.removeAll { $0.name.caseInsensitiveCompare(name) == .orderedSame }
            presets.append(MacConnectionCustomPreset(name: name, layers: layers))
            presets.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
            if let data = try? JSONEncoder().encode(presets) { UserDefaults.standard.set(data, forKey: macConnectionCustomPresetsKey) }
        }
        UserDefaults.standard.set(mode, forKey: macConnectionModeKey)
        adoptLoadedConnectionProfileSelection(selection)
        refreshAll()
        refreshUnifiedModeMenu(preferred: mode)
        refreshUnifiedChrome()
    }

    private func showConnectionProfileMessage(_ text: String, error: Bool) {
        let alert = NSAlert(); alert.alertStyle = error ? .warning : .informational; alert.messageText = error ? "Connection profile" : "Connection profile"; alert.informativeText = text; alert.addButton(withTitle: "OK"); _ = alert.runModal()
    }
}

// macOS connection-profile contract: Add Load Update Delete; setup-aware endpoints; exact current mode/CUSTOM layers;
// exact visible multihop entry/exit/exit transport; load never auto-connects; linked node secrets stay only in the private node store.

final class RouterVPNOrderedNodeEditor: NSWindowController {
    private weak var owner: ProductWindowController?
    private var draft: RouterVPNOrderedNodeDraft
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
        let note = NSTextField(wrappingLabelWithString: "Choose one to seven entry and hop nodes, each with WireGuard, AWG2 Fast or AWG2 Strong. The selected Shadowsocks 2022 exit stays last. Each node keeps its own linked credentials and settings.")
        root.addArrangedSubview(note)
        path.setAccessibilityLabel("Ordered path"); path.target = self; path.action = #selector(selectedHopChanged); root.addArrangedSubview(path)
        transport.setAccessibilityLabel("Selected entry or hop transport")
        for mode in RouterVPNOrderedNodes.editorModes { transport.addItem(withTitle: RouterVPNOrderedNodes.modeName(mode)); transport.lastItem?.representedObject = mode }
        transport.target = self; transport.action = #selector(transportChanged); root.addArrangedSubview(transport)
        let move = NSStackView(); move.orientation = .horizontal; move.spacing = 8
        for (title, action) in [("Move up", #selector(moveUp)), ("Move down", #selector(moveDown)), ("Remove hop", #selector(removeHop))] { move.addArrangedSubview(NSButton(title: title, target: self, action: action)) }
        root.addArrangedSubview(move)
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
        path.removeAllItems()
        for (index, row) in draft.nodes.enumerated() {
            let id = row["id"]!, role = index == draft.prefixes.count ? "Exit" : index == 0 ? "Entry" : "Hop \(index)"
            path.addItem(withTitle: "\(index + 1). \(role) · \(RouterVPNOrderedNodes.modeName(row["mode"]!)) · \(draft.names[id] ?? id) · \(id)")
        }
        path.selectItem(at: min(max(selected ?? 0, 0), draft.nodes.count - 1))
        selectedHopChanged()
        status.stringValue = "\(draft.nodes.count) of 8 nodes. Apply stages this selection; Connect starts it."
    }
    @objc private func selectedHopChanged() {
        let index = path.indexOfSelectedItem
        transport.isEnabled = draft.prefixes.indices.contains(index)
        transport.selectItem(at: transport.isEnabled ? RouterVPNOrderedNodes.editorModes.firstIndex(of: draft.modes[index]) ?? -1 : -1)
    }
    @objc private func transportChanged() {
        do {
            guard let mode = transport.selectedItem?.representedObject as? String else { throw RouterVPNOrderedNodes.issue("Choose an entry or hop transport.") }
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
    @objc private func applyPath() {
        do { guard let owner else { throw RouterVPNOrderedNodes.issue("Reopen the editor from the current Router VPN window.") }; try owner.applyOrderedNodeDraft(draft); close() }
        catch { status.stringValue = error.localizedDescription }
    }
    @objc private func cancelEditing() { close() }
}
