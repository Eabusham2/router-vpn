import AppKit
import Foundation

private let macConnectionModeKey = "routervpn.unified.selected-mode.v1"
private let macConnectionCustomPresetsKey = "routervpn.unified.custom-presets.v1"

private struct RouterVPNProfileSettingsPayloadV2: Codable {
    var homeLANAccess: Bool
    var killSwitchPolicy: String
    var ipv6Mode: String
    var startupMode: String
    var autoConnect: Bool
    var autoRequireEncrypted: Bool
    var autoRequireObfuscation: Bool
    var baseTunnel: String
    var baseFallback: Bool
    var mtuPolicy: String
    var manualMTU: Int?
    var effectiveMTU: Int?
    var effectiveMTUSource: String?
    var daitaEnabled: Bool
    var jumboTUN: Bool
    var socksEnabled: Bool

    static let unavailableDefaults = RouterVPNProfileSettingsPayloadV2(
        homeLANAccess: false, killSwitchPolicy: "off", ipv6Mode: "on", startupMode: "smart-auto",
        autoConnect: false, autoRequireEncrypted: false, autoRequireObfuscation: false,
        baseTunnel: "auto", baseFallback: true, mtuPolicy: "auto", manualMTU: nil,
        effectiveMTU: nil, effectiveMTUSource: nil, daitaEnabled: false, jumboTUN: false, socksEnabled: false
    )

    enum CodingKeys: String, CodingKey {
        case homeLANAccess = "home_lan_access"
        case killSwitchPolicy = "kill_switch_policy"
        case ipv6Mode = "ipv6_mode"
        case startupMode = "startup_mode"
        case autoConnect = "auto_connect"
        case autoRequireEncrypted = "auto_require_encrypted"
        case autoRequireObfuscation = "auto_require_obfuscation"
        case baseTunnel = "base_tunnel"
        case baseFallback = "base_fallback"
        case mtuPolicy = "mtu_policy"
        case manualMTU = "manual_mtu"
        case effectiveMTU = "effective_mtu"
        case effectiveMTUSource = "effective_mtu_source"
        case daitaEnabled = "daita_enabled"
        case jumboTUN = "jumbo_tun"
        case socksEnabled = "socks_enabled"
    }
}

private struct MacConnectionPresetMirror: Codable {
    var name: String
    var layers: [String]
}

private func macCurrentConnectionModeSnapshot() -> (mode: String, layers: [String]) {
    let mode = UserDefaults.standard.string(forKey: macConnectionModeKey) ?? "smart-auto"
    guard mode.hasPrefix("custom:"),
          let data = UserDefaults.standard.data(forKey: macConnectionCustomPresetsKey),
          let values = try? JSONDecoder().decode([MacConnectionPresetMirror].self, from: data) else {
        return (mode, [])
    }
    let name = String(mode.dropFirst("custom:".count))
    let layers = values.first(where: { $0.name == name })?.layers ?? []
    return (mode, layers)
}

private func macApplyLoadedConnectionMode(_ root: [String: Any]) {
    let mode = (root["mode"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "smart-auto"
    UserDefaults.standard.set(mode.isEmpty ? "smart-auto" : mode, forKey: macConnectionModeKey)
    guard mode.hasPrefix("custom:"), let layers = root["custom_layers"] as? [String], !layers.isEmpty else { return }
    let name = String(mode.dropFirst("custom:".count))
    guard !name.isEmpty else { return }
    var values: [MacConnectionPresetMirror] = []
    if let data = UserDefaults.standard.data(forKey: macConnectionCustomPresetsKey),
       let current = try? JSONDecoder().decode([MacConnectionPresetMirror].self, from: data) { values = current }
    values.removeAll { $0.name == name }
    values.append(MacConnectionPresetMirror(name: name, layers: layers.sorted()))
    values.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    if let data = try? JSONEncoder().encode(values) { UserDefaults.standard.set(data, forKey: macConnectionCustomPresetsKey) }
}

private func macMutationBusy(_ api: ProductAPI) -> Bool {
    do {
        let state = try api.json("/api/status", timeout: 4) as? [String: Any] ?? [:]
        if state["connected"] as? Bool == true { return true }
        let phase = (state["phase"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return ["connecting", "starting", "checking", "trying", "proving", "disconnecting", "stopping", "switching", "reconnecting"].contains { phase.contains($0) }
    } catch {
        return true
    }
}

private final class MacConnectionProfileControls: NSObject {
    private let api: ProductAPI
    private weak var owner: ProductWindowController?
    let root = NSStackView()
    private let name = NSTextField(string: "")
    private let popup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let status = NSTextField(wrappingLabelWithString: "")
    private var mutationButtons: [NSButton] = []

    init(api: ProductAPI, owner: ProductWindowController) {
        self.api = api
        self.owner = owner
        super.init()
        build()
        refresh()
    }

    private func build() {
        root.orientation = .vertical; root.spacing = 6
        let separator = NSBox(); separator.boxType = .separator; root.addArrangedSubview(separator)
        let title = NSTextField(labelWithString: "Connection profiles"); title.font = .systemFont(ofSize: 15, weight: .semibold); root.addArrangedSubview(title)
        let note = NSTextField(wrappingLabelWithString: "Save/load the selected node plus current Mode/CUSTOM layers, DNS, kill switch, IPv6, WG/AWG base/fallback, AUTO encryption/obfuscation requirements, MTU and multihop choices. Node keys, API tokens and external credentials stay only in the linked node store and are never duplicated here.")
        note.font = .systemFont(ofSize: 11); note.textColor = .secondaryLabelColor; root.addArrangedSubview(note)
        name.placeholderString = "Profile name"; root.addArrangedSubview(name); root.addArrangedSubview(popup)
        let row = NSStackView(); row.orientation = .horizontal; row.spacing = 6
        for (label, action) in [("Add", #selector(addProfile)), ("Load", #selector(loadProfile)), ("Update", #selector(updateProfile)), ("Delete", #selector(deleteProfile)), ("Refresh", #selector(refreshAction))] {
            let button = NSButton(title: label, target: self, action: action); button.bezelStyle = .rounded; row.addArrangedSubview(button)
            if label != "Refresh" { mutationButtons.append(button) }
        }
        root.addArrangedSubview(row)
        status.font = .systemFont(ofSize: 11); status.textColor = .secondaryLabelColor; root.addArrangedSubview(status)
        popup.target = self; popup.action = #selector(selectionChanged)
    }

    private func mutationBusy() -> Bool { macMutationBusy(api) }

    @discardableResult private func syncMutationState() -> Bool {
        let busy = mutationBusy()
        name.isEnabled = !busy
        popup.isEnabled = !busy
        mutationButtons.forEach { $0.isEnabled = !busy }
        if busy { status.stringValue = "Disconnect Router VPN or let the active transition finish before Add / Load / Update / Delete. Refresh remains available." }
        return busy
    }

    private func requireIdle(_ action: String) throws {
        if syncMutationState() {
            throw NSError(domain: "RouterVPN.ConnectionProfiles", code: 3, userInfo: [NSLocalizedDescriptionKey: "Disconnect Router VPN before \(action)."])
        }
    }

    @objc private func selectionChanged() {
        if let value = popup.selectedItem?.representedObject as? [String: String] { name.stringValue = value["name"] ?? "" }
    }

    @objc private func refreshAction() { refresh() }

    private func refresh() {
        do {
            let rootJSON = try api.json("/api/connection-profiles", timeout: 5) as? [String: Any] ?? [:]
            let profiles = rootJSON["profiles"] as? [[String: Any]] ?? []
            popup.removeAllItems()
            for profile in profiles {
                let id = profile["id"] as? String ?? ""; guard !id.isEmpty else { continue }
                let profileName = profile["name"] as? String ?? id
                let mode = profile["mode"] as? String ?? "smart-auto"
                let node = profile["node_id"] as? String ?? ""
                let prefs = profile["preferences"] as? [String: Any]
                let encrypted = prefs?["auto_require_encrypted"] as? Bool ?? false
                let obfuscated = prefs?["auto_require_obfuscation"] as? Bool ?? false
                let requirements = prefs == nil ? "AUTO n/a" : encrypted && obfuscated ? "AUTO Encrypted+Obfuscation" : encrypted ? "AUTO Encrypted" : obfuscated ? "AUTO Obfuscation" : "AUTO Off"
                popup.addItem(withTitle: "\(profileName) • \(mode) • \(node) • \(requirements)")
                popup.lastItem?.representedObject = ["id": id, "name": profileName]
            }
            if popup.numberOfItems > 0 { popup.selectItem(at: 0); selectionChanged() }
            status.stringValue = "\(popup.numberOfItems) saved connection profile(s)."
            _ = syncMutationState()
        } catch {
            status.stringValue = "Profile refresh failed: \(error.localizedDescription)"
            _ = syncMutationState()
        }
    }

    private func selectedID() throws -> String {
        guard let value = popup.selectedItem?.representedObject as? [String: String], let id = value["id"], !id.isEmpty else {
            throw NSError(domain: "RouterVPN.ConnectionProfiles", code: 1, userInfo: [NSLocalizedDescriptionKey: "Select a saved connection profile first."])
        }
        return id
    }

    private func write(path: String, updating: Bool) throws -> [String: Any] {
        try requireIdle(updating ? "updating a connection profile" : "adding a connection profile")
        let clean = name.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !clean.isEmpty else { throw NSError(domain: "RouterVPN.ConnectionProfiles", code: 2, userInfo: [NSLocalizedDescriptionKey: "Enter a profile name."]) }
        let snapshot = macCurrentConnectionModeSnapshot()
        var body: [String: Any] = ["name": clean, "mode": snapshot.mode, "custom_layers": snapshot.layers]
        if updating { body["id"] = try selectedID() }
        let data = try api.request(path, method: "POST", body: body, timeout: 10)
        return try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
    }

    @objc private func addProfile() {
        do { let root = try write(path: "/api/connection-profile/save", updating: false); let p = root["profile"] as? [String: Any]; status.stringValue = "Added \(p?["name"] as? String ?? "profile")."; refresh() }
        catch { status.stringValue = "Add failed: \(error.localizedDescription)" }
    }

    @objc private func updateProfile() {
        do { let root = try write(path: "/api/connection-profile/update", updating: true); let p = root["profile"] as? [String: Any]; status.stringValue = "Updated \(p?["name"] as? String ?? "profile")."; refresh() }
        catch { status.stringValue = "Update failed: \(error.localizedDescription)" }
    }

    @objc private func loadProfile() {
        do {
            try requireIdle("loading a connection profile")
            let data = try api.request("/api/connection-profile/load", method: "POST", body: ["id": try selectedID()], timeout: 12)
            let rootJSON = try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
            macApplyLoadedConnectionMode(rootJSON)
            let loaded = rootJSON["profile"] as? [String: Any]
            status.stringValue = "Loaded \(loaded?["name"] as? String ?? "profile") • node \(rootJSON["selected_node_id"] as? String ?? "") • mode \(rootJSON["mode"] as? String ?? "smart-auto")."
            owner?.refreshAll(); owner?.refreshUnifiedModeMenu(preferred: rootJSON["mode"] as? String); owner?.refreshUnifiedChrome(); owner?.refreshUnifiedTelemetry()
        } catch { status.stringValue = "Load failed: \(error.localizedDescription)" }
    }

    @objc private func deleteProfile() {
        do { try requireIdle("deleting a connection profile"); _ = try api.request("/api/connection-profile/delete", method: "POST", body: ["id": try selectedID()], timeout: 10); status.stringValue = "Deleted saved connection profile."; refresh() }
        catch { status.stringValue = "Delete failed: \(error.localizedDescription)" }
    }
}

extension ProductWindowController {
    @objc func editProfileSettings() {
        asyncAction {
            let data = try? self.api.request("/api/profile/settings", timeout: 5)
            let decoded = data.flatMap { try? JSONDecoder().decode(RouterVPNProfileSettingsPayloadV2.self, from: $0) }
            let supportsNodeSettings = decoded != nil
            let settingsMutationBusy = macMutationBusy(self.api)
            var settings = decoded ?? .unavailableDefaults
            let semaphore = DispatchSemaphore(value: 0)
            var save = false
            var validationError = ""

            DispatchQueue.main.async {
                let alert = NSAlert()
                alert.messageText = "Settings"
                if supportsNodeSettings && settingsMutationBusy {
                    alert.informativeText = "Disconnect Router VPN or let the active transition finish before editing persistent node settings. Saved values are preferences, not runtime proof."
                } else {
                    alert.informativeText = supportsNodeSettings
                        ? "Selected Router node • persistent defaults for the next connection. Unsupported runtime features stay unavailable; saved values are not runtime proof."
                        : "Selected Custom/external node does not expose Router VPN node settings here. Connection-profile Add / Load / Update / Delete remains available."
                }
                alert.addButton(withTitle: supportsNodeSettings ? "Save" : "Close")
                alert.addButton(withTitle: "Cancel")

                let form = NSStackView()
                form.orientation = .vertical
                form.spacing = 8
                form.frame = NSRect(x: 0, y: 0, width: 570, height: 760)

                func popup(_ title: String, values: [(String,String)], selected: String) -> NSPopUpButton {
                    let row = NSStackView(); row.orientation = .horizontal; row.spacing = 8
                    let label = NSTextField(labelWithString: title); label.frame.size.width = 190
                    let p = NSPopUpButton()
                    for item in values { p.addItem(withTitle: item.0); p.lastItem?.representedObject = item.1 }
                    if let idx = values.firstIndex(where: { $0.1 == selected }) { p.selectItem(at: idx) }
                    row.addArrangedSubview(label); row.addArrangedSubview(p); form.addArrangedSubview(row); return p
                }
                func check(_ title: String, value: Bool) -> NSButton {
                    let b = NSButton(checkboxWithTitle: title, target: nil, action: nil); b.state = value ? .on : .off; form.addArrangedSubview(b); return b
                }

                let lan = check("Allow home LAN access", value: settings.homeLANAccess)
                let kill = popup("Kill switch", values: [("Off","off"),("On connect","on-connect"),("Always / strict","always")], selected: settings.killSwitchPolicy)
                let ipv6 = popup("IPv6", values: [("On — default","on"),("Auto","auto"),("Off","off")], selected: settings.ipv6Mode)
                let base = popup("WG / AWG base", values: [("Auto","auto"),("WireGuard","wg"),("AmneziaWG","awg")], selected: settings.baseTunnel)
                let fallback = check("Allow compatible WG / AWG base fallback", value: settings.baseFallback)
                let autoEncrypted = check("Require encrypted AUTO candidates", value: settings.autoRequireEncrypted)
                let autoObfuscated = check("Require obfuscation for AUTO candidates", value: settings.autoRequireObfuscation)
                let autoNote = NSTextField(wrappingLabelWithString: "Both AUTO requirements are Off by default. When enabled, candidates are filtered before connection attempts; SMART simplification cannot drop below the requirement.")
                autoNote.textColor = .secondaryLabelColor; autoNote.font = .systemFont(ofSize: 11); form.addArrangedSubview(autoNote)
                let mtu = popup("MTU", values: [("Auto measured — default","auto"),("Fixed / manual","manual"),("Runtime default","default")], selected: settings.mtuPolicy)
                let mtuRow = NSStackView(); mtuRow.orientation = .horizontal; mtuRow.spacing = 8; mtuRow.addArrangedSubview(NSTextField(labelWithString: "Fixed MTU 576–9000"))
                let manual = NSTextField(string: (settings.manualMTU ?? 0) > 0 ? String(settings.manualMTU!) : ""); mtuRow.addArrangedSubview(manual); form.addArrangedSubview(mtuRow)
                let effective = NSTextField(wrappingLabelWithString: "Effective MTU: \((settings.effectiveMTU ?? 0) > 0 ? String(settings.effectiveMTU!) : "not measured yet") • \(settings.effectiveMTUSource ?? "Auto will test/use a valid path-specific value")")
                effective.textColor = .secondaryLabelColor; effective.font = .systemFont(ofSize: 11); form.addArrangedSubview(effective)
                let daita = check("DAITA-like traffic padding (bounded; supported modes only)", value: settings.daitaEnabled)
                let jumbo = check("Jumbo TUN / jumbo packet mode (compatible paths only)", value: settings.jumboTUN)
                let socks = check("Private in-tunnel SOCKS5 utility", value: settings.socksEnabled)
                let startup = popup("Default mode on startup", values: [("SMART AUTO — recommended","smart-auto"),("AUTO","auto"),("Last proven mode","last"),("Manual / stay disconnected","manual")], selected: settings.startupMode)
                let auto = check("Auto-connect when Router VPN starts", value: settings.autoConnect)
                let forwarding = NSButton(title: "Port forwarding / Protected DMZ…", target: self, action: #selector(self.openUnifiedForwarding)); forwarding.bezelStyle = .rounded; form.addArrangedSubview(forwarding)
                let retest = NSButton(title: "Retest MTU for current config/path", target: self, action: #selector(self.retestMTU)); retest.bezelStyle = .rounded; form.addArrangedSubview(retest)

                let connectionProfiles = MacConnectionProfileControls(api: self.api, owner: self)
                form.addArrangedSubview(connectionProfiles.root)
                let nodePreferenceViews: [NSView] = [lan, kill, ipv6, base, fallback, autoEncrypted, autoObfuscated, mtu, manual, daita, jumbo, socks, startup, auto, forwarding, retest]
                if !supportsNodeSettings || settingsMutationBusy {
                    nodePreferenceViews.forEach { $0.isEnabled = false }
                }
                if supportsNodeSettings && settingsMutationBusy { alert.buttons.first?.isEnabled = false }

                alert.accessoryView = form
                if alert.runModal() == .alertFirstButtonReturn && supportsNodeSettings && !settingsMutationBusy {
                    settings.homeLANAccess = lan.state == .on
                    settings.killSwitchPolicy = (kill.selectedItem?.representedObject as? String) ?? "off"
                    settings.ipv6Mode = (ipv6.selectedItem?.representedObject as? String) ?? "on"
                    settings.baseTunnel = (base.selectedItem?.representedObject as? String) ?? "auto"
                    settings.baseFallback = fallback.state == .on
                    settings.autoRequireEncrypted = autoEncrypted.state == .on
                    settings.autoRequireObfuscation = autoObfuscated.state == .on
                    settings.mtuPolicy = (mtu.selectedItem?.representedObject as? String) ?? "auto"
                    let manualValue = Int(manual.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
                    if settings.mtuPolicy == "manual" && !(576...9000).contains(manualValue) { validationError = "Fixed MTU must be 576–9000." }
                    settings.manualMTU = settings.mtuPolicy == "manual" ? manualValue : nil
                    settings.daitaEnabled = daita.state == .on
                    settings.jumboTUN = jumbo.state == .on
                    settings.socksEnabled = socks.state == .on
                    settings.startupMode = (startup.selectedItem?.representedObject as? String) ?? "smart-auto"
                    settings.autoConnect = auto.state == .on
                    save = validationError.isEmpty
                }
                _ = connectionProfiles
                semaphore.signal()
            }

            semaphore.wait()
            if !validationError.isEmpty { throw NSError(domain: "RouterVPN.Settings", code: 1, userInfo: [NSLocalizedDescriptionKey: validationError]) }
            if !supportsNodeSettings { return "Connection profile manager closed; external node settings remain owned by that node's protocol configuration." }
            if !save { return settingsMutationBusy ? "Settings locked until Router VPN is fully disconnected." : "Settings unchanged." }
            if macMutationBusy(self.api) { throw NSError(domain: "RouterVPN.Settings", code: 2, userInfo: [NSLocalizedDescriptionKey: "VPN became active or began transitioning before settings save; disconnect and try again."]) }
            let payload = try JSONEncoder().encode(settings)
            _ = try self.api.requestRaw("/api/profile/settings", body: payload, timeout: 8)
            return "Settings saved for the next supported connection. Saved preferences are not runtime proof."
        }
    }
}

// Unified settings contract: SMART AUTO default, IPv6 On default, Auto measured MTU,
// fixed MTU override + Retest, DAITA-like traffic padding, Jumbo TUN, kill switch,
// AUTO Require encrypted / Require obfuscation, LAN access and forwarding entry point.
// /api/profile/settings only for Router-node preferences; connection-profile CRUD uses
// /api/connection-profiles + save/update/load/delete and never duplicates node secrets.
// Connection-profile mutation and persistent Settings Save both fail closed while controller status is connected/transitioning or unavailable.
