import AppKit
import Foundation

private let macConnectionModeKey = "routervpn.unified.selected-mode.v1"
private let macConnectionCustomPresetsKey = "routervpn.unified.custom-presets.v1"
private let macConnectionMultihopEnabledKey = "routervpn.unified.multihop-enabled.v1"

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
    @objc func manageConnectionProfiles() {
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
                    applyLoadedConnectionProfile(payload)
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

    private func connectionProfileSnapshot(name: String, id: String?) -> [String: Any] {
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
        let exitMode = multihop ? (multihopExitModePopup.indexOfSelectedItem == 1 ? "hysteria2" : "shadowsocks") : ""
        var body: [String: Any] = [
            "name": name, "mode": mode, "custom_layers": layers,
            "multihop_enabled": multihop, "multihop_entry_id": entry,
            "multihop_exit_id": exit, "multihop_exit_mode": exitMode,
        ]
        if let id { body["id"] = id }
        return body
    }

    private func connectionProfilePOST(_ path: String, body: [String: Any]) throws -> [String: Any] {
        let data = try api.request(path, method: "POST", body: body, timeout: 15)
        guard let value = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw NSError(domain: "RouterVPN.ConnectionProfile", code: 1, userInfo: [NSLocalizedDescriptionKey: "Connection profile endpoint returned invalid JSON."]) }
        return value
    }

    private func applyLoadedConnectionProfile(_ payload: [String: Any]) {
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
        let enabled = payload["multihop_enabled"] as? Bool ?? false
        UserDefaults.standard.set(enabled, forKey: macConnectionMultihopEnabledKey)

        refreshAll()
        refreshUnifiedModeMenu(preferred: mode)
        if let entry = payload["multihop_entry_id"] as? String, let index = multihopNodeIDs.firstIndex(of: entry) { multihopEntryPopup.selectItem(at: index) }
        if let exit = payload["multihop_exit_id"] as? String, let index = multihopNodeIDs.firstIndex(of: exit) { multihopExitPopup.selectItem(at: index) }
        if (payload["multihop_exit_mode"] as? String) == "hysteria2", multihopExitModePopup.numberOfItems > 1 { multihopExitModePopup.selectItem(at: 1) }
        else if multihopExitModePopup.numberOfItems > 0 { multihopExitModePopup.selectItem(at: 0) }
        refreshUnifiedHopOverlay()
        refreshUnifiedChrome()
    }

    private func showConnectionProfileMessage(_ text: String, error: Bool) {
        let alert = NSAlert(); alert.alertStyle = error ? .warning : .informational; alert.messageText = error ? "Connection profile" : "Connection profile"; alert.informativeText = text; alert.addButton(withTitle: "OK"); _ = alert.runModal()
    }
}

// macOS connection-profile contract: Add Load Update Delete; setup-aware endpoints; exact current mode/CUSTOM layers;
// exact visible multihop entry/exit/exit transport; load never auto-connects; linked node secrets stay only in the private node store.
