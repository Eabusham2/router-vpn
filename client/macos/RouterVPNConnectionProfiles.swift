import AppKit
import Foundation

private let macConnectionModeKey = "routervpn.unified.selected-mode.v1"
private let macConnectionCustomPresetsKey = "routervpn.unified.custom-presets.v1"
private let macConnectionMultihopEnabledKey = "routervpn.unified.multihop-enabled.v1"

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
        var selection = captureConnectionProfileSelection()
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

    func validatedLoadedConnectionProfileSelection(_ payload: [String: Any]) throws -> RouterVPNConnectionProfileSelection {
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
        if selection.multihopEnabled {
            guard !selection.entryID.isEmpty, !selection.exitID.isEmpty, selection.entryID != selection.exitID,
                  selection.entryMode.flatMap({ RouterVPNNodeEntryModes.index(for: $0) }) != nil,
                  RouterVPNNodeExitModes.index(for: selection.exitMode) != nil,
                  ["local", "server", "auto"].contains(selection.execution) else {
                throw NSError(domain: "RouterVPN.ConnectionProfile", code: 3, userInfo: [NSLocalizedDescriptionKey: "The loaded multihop setup is incomplete or unsupported. No replacement path was selected."])
            }
            referenced.formUnion([selection.entryID, selection.exitID])
        }
        guard !selection.selectedNodeID.isEmpty, referenced.allSatisfy({ validConnectionProfileToken(tokens[$0]) }) else {
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
        if selection.multihopEnabled {
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
        if selection.selectedNodeID.isEmpty { selection.selectedNodeID = selected }
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
        if selection.entryID.isEmpty && selection.exitID.isEmpty {
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

    private func connectionProfileSnapshot(name: String, id: String?) throws -> [String: Any] {
        try requireMutationIdle("saving a connection profile")
        try requireResolvedConnectionProfileSelection()
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
        return body
    }

    private func connectionProfilePOST(_ path: String, body: [String: Any]) throws -> [String: Any] {
        try requireMutationIdle("changing a connection profile")
        if path == "/api/connection-profile/setup/load" { beginConnectionProfileLoad() }
        let data = try api.request(path, method: "POST", body: body, timeout: 15)
        guard let value = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw NSError(domain: "RouterVPN.ConnectionProfile", code: 1, userInfo: [NSLocalizedDescriptionKey: "Connection profile endpoint returned invalid JSON."]) }
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
