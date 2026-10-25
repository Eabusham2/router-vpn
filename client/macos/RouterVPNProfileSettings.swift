import AppKit
import Foundation

private let macConnectionModeKey = "routervpn.unified.selected-mode.v1"
private let macConnectionCustomPresetsKey = "routervpn.unified.custom-presets.v1"
private let macConnectionMultihopEnabledKey = "routervpn.unified.multihop-enabled.v1"

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
    var startLayer: String
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
        baseTunnel: "auto", baseFallback: true, startLayer: "off", mtuPolicy: "auto", manualMTU: nil,
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
        case startLayer = "start_layer"
        case mtuPolicy = "mtu_policy"
        case manualMTU = "manual_mtu"
        case effectiveMTU = "effective_mtu"
        case effectiveMTUSource = "effective_mtu_source"
        case daitaEnabled = "daita_enabled"
        case jumboTUN = "jumbo_tun"
        case socksEnabled = "socks_enabled"
    }
}

private struct MacProfileStartupSettings: Decodable, Sendable {
    let profileID: String
    let profileToken: String
    let nodeKind: String
    let startupMode: String
    let autoConnect: Bool

    enum CodingKeys: String, CodingKey {
        case profileID = "profile_id", profileToken = "profile_token", nodeKind = "node_kind"
        case startupMode = "startup_mode", autoConnect = "auto_connect"
    }

    func saveData(startupMode: String, autoConnect: Bool) throws -> Data {
        guard !profileID.isEmpty, !profileToken.isEmpty else {
            throw NSError(domain: "RouterVPN.Settings", code: 3, userInfo: [NSLocalizedDescriptionKey: "Reopen Settings to capture the selected node."])
        }
        let displayedStartup = self.startupMode == "smart-auto" ? "auto" : self.startupMode
        let savedStartup = startupMode == displayedStartup ? self.startupMode : startupMode
        return try JSONSerialization.data(withJSONObject: [
            "profile_id": profileID, "profile_token": profileToken,
            "startup_mode": savedStartup, "auto_connect": autoConnect
        ])
    }
}

struct MacProfileProtectionSettings: Decodable, Sendable {
    let profileID: String
    let profileToken: String
    let killSwitchPolicy: String

    enum CodingKeys: String, CodingKey {
        case profileID = "profile_id", profileToken = "profile_token"
        case killSwitchPolicy = "kill_switch_policy"
    }

    func saveData(displayedProfileID: String, enabled: Bool) throws -> Data {
        guard !displayedProfileID.isEmpty, profileID == displayedProfileID, !profileToken.isEmpty else {
            throw NSError(domain: "RouterVPN.Settings", code: 4, userInfo: [NSLocalizedDescriptionKey: "The selected node changed. Refresh before changing protection."])
        }
        return try JSONSerialization.data(withJSONObject: [
            "profile_id": profileID, "profile_token": profileToken,
            "kill_switch_policy": enabled ? "on-connect" : "off"
        ])
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
        try MacProfileDeviceSettings.requireIdle(api.request("/api/status", timeout: 4))
        return false
    } catch {
        return true
    }
}

private final class MacDevicePolicyControls: NSObject {
    let mtu: NSPopUpButton
    let manual: NSTextField
    let startup: NSPopUpButton
    let automatic: NSButton
    let commonEditable: Bool
    let startupEditable: Bool

    init(mtu: NSPopUpButton, manual: NSTextField, startup: NSPopUpButton, automatic: NSButton,
         commonEditable: Bool, startupEditable: Bool) {
        self.mtu = mtu; self.manual = manual; self.startup = startup; self.automatic = automatic
        self.commonEditable = commonEditable; self.startupEditable = startupEditable
        super.init()
        mtu.target = self; mtu.action = #selector(update)
        startup.target = self; startup.action = #selector(update)
        update()
    }

    @objc func update() {
        manual.isEnabled = commonEditable && mtu.selectedItem?.representedObject as? String == "manual"
        let stayDisconnected = startup.selectedItem?.representedObject as? String == "manual"
        if stayDisconnected { automatic.state = .off }
        automatic.isEnabled = startupEditable && !stayDisconnected
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
        let note = NSTextField(wrappingLabelWithString: "Save/load the selected node plus current Mode/CUSTOM layers, DNS, kill switch, IPv6, WG/AWG base/fallback, authenticated Start Layer, AUTO encryption/obfuscation requirements, MTU and multihop choices. Node keys, API tokens and external credentials stay only in the linked node store and are never duplicated here.")
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

    private func currentMultihopSnapshot() throws -> (enabled: Bool, entry: String, exit: String, exitMode: String, execution: String) {
        let enabled = UserDefaults.standard.bool(forKey: macConnectionMultihopEnabledKey)
        guard enabled, let owner else { return (false, "", "", "", "") }
        let entryIndex = owner.multihopEntryPopup.indexOfSelectedItem
        let exitIndex = owner.multihopExitPopup.indexOfSelectedItem
        guard entryIndex >= 0, exitIndex >= 0,
              entryIndex < owner.multihopNodeIDs.count, exitIndex < owner.multihopNodeIDs.count else {
            throw NSError(domain: "RouterVPN.ConnectionProfiles", code: 4, userInfo: [NSLocalizedDescriptionKey: "Multihop is enabled but entry/exit selection is incomplete."])
        }
        let entry = owner.multihopNodeIDs[entryIndex]
        let exit = owner.multihopNodeIDs[exitIndex]
        guard entry != exit else {
            throw NSError(domain: "RouterVPN.ConnectionProfiles", code: 5, userInfo: [NSLocalizedDescriptionKey: "Multihop entry and exit nodes must be different."])
        }
        let exitMode = owner.multihopExitModePopup.indexOfSelectedItem == 1 ? "hysteria2" : "shadowsocks"
        return (true, entry, exit, exitMode, owner.multihopExecutionChoice())
    }

    private func applyLoadedMultihop(_ root: [String: Any]) {
        let enabled = root["multihop_enabled"] as? Bool ?? false
        UserDefaults.standard.set(enabled, forKey: macConnectionMultihopEnabledKey)
        guard let owner else { return }
        if enabled {
            let entry = root["multihop_entry_id"] as? String ?? ""
            let exit = root["multihop_exit_id"] as? String ?? ""
            let exitMode = (root["multihop_exit_mode"] as? String ?? "shadowsocks").lowercased()
            if let index = owner.multihopNodeIDs.firstIndex(of: entry) { owner.multihopEntryPopup.selectItem(at: index) }
            if let index = owner.multihopNodeIDs.firstIndex(of: exit) { owner.multihopExitPopup.selectItem(at: index) }
            owner.multihopExitModePopup.selectItem(at: exitMode == "hysteria2" ? 1 : 0)
            let choice = root["multihop_execution"] as? String ?? "local"
            let execution = ["local", "server", "auto"].contains(choice) ? choice : "local"
            UserDefaults.standard.set(execution, forKey: "routervpn.multihop.execution.v1")
            owner.multihopExecutionPopup.selectItem(at: ["local", "server", "auto"].firstIndex(of: execution) ?? 0)
            owner.refreshAdvanced()
        }
        if let content = owner.window?.contentView {
            func find(_ view: NSView) -> NSButton? {
                if view.identifier?.rawValue == "unified-multihop-toggle" { return view as? NSButton }
                for child in view.subviews { if let found = find(child) { return found } }
                return nil
            }
            find(content)?.state = enabled ? .on : .off
        }
        owner.refreshUnifiedHopOverlay()
    }

    private func write(path: String, updating: Bool) throws -> [String: Any] {
        try requireIdle(updating ? "updating a connection profile" : "adding a connection profile")
        let clean = name.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !clean.isEmpty else { throw NSError(domain: "RouterVPN.ConnectionProfiles", code: 2, userInfo: [NSLocalizedDescriptionKey: "Enter a profile name."]) }
        let snapshot = macCurrentConnectionModeSnapshot()
        let hops = try currentMultihopSnapshot()
        var body: [String: Any] = [
            "name": clean, "mode": snapshot.mode, "custom_layers": snapshot.layers,
            "multihop_enabled": hops.enabled, "multihop_entry_id": hops.entry,
            "multihop_exit_id": hops.exit, "multihop_exit_mode": hops.exitMode, "multihop_execution": hops.execution
        ]
        if updating { body["id"] = try selectedID() }
        let data = try api.request(path, method: "POST", body: body, timeout: 10)
        return try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
    }

    @objc private func addProfile() {
        do { let root = try write(path: "/api/connection-profile/setup/save", updating: false); let p = root["profile"] as? [String: Any]; status.stringValue = "Added \(p?["name"] as? String ?? "profile")."; refresh() }
        catch { status.stringValue = "Add failed: \(error.localizedDescription)" }
    }

    @objc private func updateProfile() {
        do { let root = try write(path: "/api/connection-profile/setup/update", updating: true); let p = root["profile"] as? [String: Any]; status.stringValue = "Updated \(p?["name"] as? String ?? "profile")."; refresh() }
        catch { status.stringValue = "Update failed: \(error.localizedDescription)" }
    }

    @objc private func loadProfile() {
        do {
            try requireIdle("loading a connection profile")
            let data = try api.request("/api/connection-profile/setup/load", method: "POST", body: ["id": try selectedID()], timeout: 12)
            let rootJSON = try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
            macApplyLoadedConnectionMode(rootJSON)
            applyLoadedMultihop(rootJSON)
            let loaded = rootJSON["profile"] as? [String: Any]
            status.stringValue = "Loaded \(loaded?["name"] as? String ?? "profile") • node \(rootJSON["selected_node_id"] as? String ?? "") • mode \(rootJSON["mode"] as? String ?? "smart-auto") • exact multihop graph restored."
            owner?.refreshAll(); owner?.refreshUnifiedModeMenu(preferred: rootJSON["mode"] as? String); owner?.refreshUnifiedChrome(); owner?.refreshUnifiedTelemetry()
        } catch { status.stringValue = "Load failed: \(error.localizedDescription)" }
    }

    @objc private func deleteProfile() {
        do { try requireIdle("deleting a connection profile"); _ = try api.request("/api/connection-profile/setup/delete", method: "POST", body: ["id": try selectedID()], timeout: 10); status.stringValue = "Deleted saved connection profile."; refresh() }
        catch { status.stringValue = "Delete failed: \(error.localizedDescription)" }
    }
}

extension ProductWindowController {
    @objc func editProfileSettings() {
        let displayedProfileID = routerPopup.selectedItem?.representedObject as? String ?? ""
        let displayedNodeKind = (profiles.first(where: { ($0["id"] as? String) == displayedProfileID })?["node_kind"] as? String ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        asyncAction {
            // Route by the node the user opened. A changed controller selection
            // cannot turn an external edit into the Router-only settings path.
            let data: Data? = displayedNodeKind == "router-vpn" ? (try? self.api.request("/api/profile/settings", timeout: 5)) : nil
            let decoded = data.flatMap { try? JSONDecoder().decode(RouterVPNProfileSettingsPayloadV2.self, from: $0) }
            let supportsNodeSettings = decoded != nil
            let deviceData: Data? = displayedNodeKind == "external" ? (try? self.api.request("/api/profile/device", timeout: 5)) : nil
            let capturedDevice = deviceData.flatMap { try? MacProfileDeviceSettings.capture($0, displayedProfileID: displayedProfileID) }
            let supportsDeviceSettings = capturedDevice?.devicePolicySupported == true
            let supportsCommonSettings = supportsNodeSettings || supportsDeviceSettings
            // Unsupported protocols retain their separate startup transaction.
            // Its source token is different from the device-plus-entry token.
            let startupData: Data? = displayedNodeKind == "external" && !supportsDeviceSettings ? (try? self.api.request("/api/profile/startup", timeout: 5)) : nil
            let capturedStartup = startupData.flatMap { try? JSONDecoder().decode(MacProfileStartupSettings.self, from: $0) }
            let externalStartup = capturedStartup?.nodeKind == "external" && capturedStartup?.profileID == displayedProfileID &&
                MacProfileDeviceSettings.validToken(capturedStartup?.profileToken ?? "") &&
                ["auto", "smart-auto", "last", "manual"].contains(capturedStartup?.startupMode ?? "") ? capturedStartup : nil
            let supportsStartupSettings = supportsCommonSettings || externalStartup != nil
            let importedSettings = supportsDeviceSettings || externalStartup != nil
            let settingsMutationBusy = macMutationBusy(self.api)
            var settings = decoded ?? .unavailableDefaults
            if let capturedDevice {
                settings.homeLANAccess = capturedDevice.homeLANAccess
                settings.killSwitchPolicy = capturedDevice.killSwitchPolicy
                settings.ipv6Mode = capturedDevice.ipv6Mode
                settings.mtuPolicy = capturedDevice.mtuPolicy
                settings.manualMTU = capturedDevice.manualMTU
                settings.effectiveMTU = capturedDevice.effectiveMTU
                settings.effectiveMTUSource = capturedDevice.mtuSource
                if supportsDeviceSettings {
                    settings.startupMode = capturedDevice.displayedStartup
                    settings.autoConnect = capturedDevice.autoConnect
                }
            }
            if let externalStartup {
                settings.startupMode = externalStartup.startupMode == "smart-auto" ? "auto" : externalStartup.startupMode
                settings.autoConnect = externalStartup.autoConnect
            }
            let semaphore = DispatchSemaphore(value: 0)
            var save = false
            var validationError = ""
            var deviceEdits: MacProfileDeviceSettings.Edits?

            DispatchQueue.main.async {
                defer { semaphore.signal() }
                guard (self.routerPopup.selectedItem?.representedObject as? String ?? "") == displayedProfileID else {
                    validationError = "The selected node changed while Settings loaded. Reopen Settings."; return
                }
                let alert = NSAlert()
                alert.messageText = "Settings"
                if supportsStartupSettings && settingsMutationBusy {
                    alert.informativeText = "Disconnect Router VPN or let the active transition finish before editing persistent node settings. Saved values are preferences, not runtime proof."
                } else {
                    alert.informativeText = supportsNodeSettings
                        ? "Selected Router node • persistent defaults for the next connection. Unsupported runtime features stay unavailable; saved values are not runtime proof."
                        : supportsDeviceSettings
                            ? capturedDevice?.note ?? "Common device and startup settings for the captured imported node. DNS, independent entry policy, credentials and saved graph are retained. Fixed MTU is a requested interface value."
                            : externalStartup != nil
                                ? "Startup for the selected imported node. Saved connection uses its protocol and hop settings. Last keeps a still-valid proved Local/Server choice. \(capturedDevice?.devicePolicyReason ?? "Common device settings are unavailable for this runtime.")"
                                : "Node settings are unavailable. Connection-profile Add / Load / Update / Delete remains available."
                }
                alert.addButton(withTitle: supportsStartupSettings ? "Save" : "Close")
                alert.addButton(withTitle: "Cancel")

                let form = NSStackView()
                form.orientation = .vertical
                form.spacing = 8
                form.frame = NSRect(x: 0, y: 0, width: 570, height: 800)

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
                let startLayer = popup("Start layer", values: [("Off — default","off"),("AES-256-GCM — authenticated","aes-256-gcm"),("AES-256-GCM + XOR whitening","aes-256-gcm+xor-whitening")], selected: settings.startLayer)
                let startLayerNote = NSTextField(wrappingLabelWithString: "AES uses vetted Shadowsocks 2022 AES-256-GCM. XOR only whitens already-authenticated ciphertext and is never counted as encryption. Unsupported graphs fail closed.")
                startLayerNote.textColor = .secondaryLabelColor; startLayerNote.font = .systemFont(ofSize: 11); form.addArrangedSubview(startLayerNote)
                let mtu = popup("MTU", values: [("Auto — default","auto"),("Fixed / manual","manual"),("Runtime default","default")], selected: settings.mtuPolicy)
                let mtuRow = NSStackView(); mtuRow.orientation = .horizontal; mtuRow.spacing = 8; mtuRow.addArrangedSubview(NSTextField(labelWithString: capturedDevice != nil ? "Fixed MTU 1280–9000" : "Fixed MTU 576–9000"))
                let manual = NSTextField(string: (settings.manualMTU ?? 0) > 0 ? String(settings.manualMTU!) : ""); mtuRow.addArrangedSubview(manual); form.addArrangedSubview(mtuRow)
                let effective = NSTextField(wrappingLabelWithString: "Last recorded interface MTU: \((settings.effectiveMTU ?? 0) > 0 ? String(settings.effectiveMTU!) : "not recorded yet") • \(settings.effectiveMTUSource ?? "historical interface readback")")
                effective.textColor = .secondaryLabelColor; effective.font = .systemFont(ofSize: 11); form.addArrangedSubview(effective)
                let daita = check("DAITA-like traffic padding (bounded; supported modes only)", value: settings.daitaEnabled)
                let jumbo = check("Jumbo TUN / jumbo packet mode (compatible paths only)", value: settings.jumboTUN)
                let socks = check("Private in-tunnel SOCKS5 utility", value: settings.socksEnabled)
                let startupValues = importedSettings
                    ? [("Saved connection","auto"),("Last proven connection","last"),("Manual / stay disconnected","manual")]
                    : [("SMART AUTO — recommended","smart-auto"),("AUTO","auto"),("Last proven mode","last"),("Manual / stay disconnected","manual")]
                let startup = popup("Default mode on startup", values: startupValues, selected: settings.startupMode)
                let auto = check("Auto-connect when Router VPN starts", value: settings.autoConnect)
                let forwarding = NSButton(title: "Port forwarding / Protected DMZ…", target: self, action: #selector(self.openUnifiedForwarding)); forwarding.bezelStyle = .rounded; form.addArrangedSubview(forwarding)
                let retest = NSButton(title: "Retest MTU for current config/path", target: self, action: #selector(self.retestMTU)); retest.bezelStyle = .rounded; form.addArrangedSubview(retest)

                let connectionProfiles = MacConnectionProfileControls(api: self.api, owner: self)
                form.addArrangedSubview(connectionProfiles.root)
                let routerPreferenceViews: [NSControl] = [base, fallback, autoEncrypted, autoObfuscated, startLayer, daita, jumbo, socks, forwarding]
                routerPreferenceViews.forEach { $0.isEnabled = supportsNodeSettings && !settingsMutationBusy }
                let commonPreferenceViews: [NSControl] = [lan, kill, ipv6, mtu]
                commonPreferenceViews.forEach { $0.isEnabled = supportsCommonSettings && !settingsMutationBusy }
                startup.isEnabled = supportsStartupSettings && !settingsMutationBusy
                retest.isEnabled = supportsNodeSettings && !settingsMutationBusy
                let policyControls = MacDevicePolicyControls(mtu: mtu, manual: manual, startup: startup, automatic: auto,
                    commonEditable: supportsCommonSettings && !settingsMutationBusy,
                    startupEditable: supportsStartupSettings && !settingsMutationBusy)
                if supportsStartupSettings && settingsMutationBusy { alert.buttons.first?.isEnabled = false }

                alert.accessoryView = form
                let response = withExtendedLifetime((connectionProfiles, policyControls)) { alert.runModal() }
                if response == .alertFirstButtonReturn && supportsStartupSettings && !settingsMutationBusy {
                    guard (self.routerPopup.selectedItem?.representedObject as? String ?? "") == displayedProfileID else {
                        validationError = "The selected node changed before Save. Reopen Settings."; return
                    }
                    settings.homeLANAccess = lan.state == .on
                    settings.killSwitchPolicy = (kill.selectedItem?.representedObject as? String) ?? "off"
                    settings.ipv6Mode = (ipv6.selectedItem?.representedObject as? String) ?? "on"
                    settings.baseTunnel = (base.selectedItem?.representedObject as? String) ?? "auto"
                    settings.baseFallback = fallback.state == .on
                    settings.autoRequireEncrypted = autoEncrypted.state == .on
                    settings.autoRequireObfuscation = autoObfuscated.state == .on
                    settings.startLayer = (startLayer.selectedItem?.representedObject as? String) ?? "off"
                    settings.mtuPolicy = (mtu.selectedItem?.representedObject as? String) ?? "auto"
                    let manualValue = Int(manual.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
                    if supportsNodeSettings && settings.mtuPolicy == "manual" && !(576...9000).contains(manualValue) { validationError = "Fixed MTU must be 576–9000." }
                    settings.manualMTU = settings.mtuPolicy == "manual" ? manualValue : nil
                    settings.daitaEnabled = daita.state == .on
                    settings.jumboTUN = jumbo.state == .on
                    settings.socksEnabled = socks.state == .on
                    settings.startupMode = (startup.selectedItem?.representedObject as? String) ?? "smart-auto"
                    settings.autoConnect = auto.state == .on
                    if let capturedDevice, supportsDeviceSettings {
                        let edits = MacProfileDeviceSettings.Edits(homeLANAccess: settings.homeLANAccess,
                            killSwitchPolicy: settings.killSwitchPolicy, ipv6Mode: settings.ipv6Mode,
                            mtuPolicy: settings.mtuPolicy, manualMTUText: manual.stringValue,
                            startupMode: settings.startupMode, autoConnect: settings.autoConnect)
                        do { _ = try capturedDevice.saveData(displayedProfileID: displayedProfileID, edits: edits); deviceEdits = edits }
                        catch { validationError = error.localizedDescription }
                    }
                    save = validationError.isEmpty
                }
            }

            semaphore.wait()
            if !validationError.isEmpty { throw NSError(domain: "RouterVPN.Settings", code: 1, userInfo: [NSLocalizedDescriptionKey: validationError]) }
            if !supportsStartupSettings { return "Connection profile manager closed; node settings are unchanged." }
            if !save { return settingsMutationBusy ? "Settings locked until Router VPN is fully disconnected." : "Settings unchanged." }
            if let capturedDevice, supportsDeviceSettings, let deviceEdits {
                try capturedDevice.save(edits: deviceEdits, displayedProfileID: {
                    var current = ""
                    DispatchQueue.main.sync { current = self.routerPopup.selectedItem?.representedObject as? String ?? "" }
                    return current
                }, readStatus: { try self.api.request("/api/status", timeout: 4) }, persist: {
                    try self.api.requestRaw("/api/profile/device", body: $0, timeout: 8)
                })
                return "Device and startup settings saved for the captured imported node. The next connection will prove the selected policy."
            }
            if macMutationBusy(self.api) { throw NSError(domain: "RouterVPN.Settings", code: 2, userInfo: [NSLocalizedDescriptionKey: "VPN became active or began transitioning before settings save; disconnect and try again."]) }
            if let externalStartup {
                var current = ""
                DispatchQueue.main.sync { current = self.routerPopup.selectedItem?.representedObject as? String ?? "" }
                guard current == displayedProfileID else { throw MacProfileDeviceSettings.issue("The selected node changed before startup Save.") }
                let payload = try externalStartup.saveData(startupMode: settings.startupMode, autoConnect: settings.autoConnect)
                _ = try self.api.requestRaw("/api/profile/startup", body: payload, timeout: 8)
                return "Startup settings saved for this imported node."
            }
            let payload = try JSONEncoder().encode(settings)
            _ = try self.api.requestRaw("/api/profile/settings", body: payload, timeout: 8)
            return "Settings saved for the next supported connection. Saved preferences are not runtime proof."
        }
    }
}

// Unified settings contract: SMART AUTO default, IPv6 On default, authenticated AES/XOR-whitening Start Layer, Auto MTU,
// fixed MTU override + Retest, DAITA-like traffic padding, Jumbo TUN, kill switch,
// AUTO Require encrypted / Require obfuscation, LAN access and forwarding entry point.
// /api/profile/settings only for Router-node preferences; connection-profile CRUD uses
// /api/connection-profiles + setup save/update/load/delete and never duplicates node secrets.
// Imported common policy uses the captured /api/profile/device transaction; its
// optional startup pair is sent only when edited. Unsupported device runtimes
// retain the separately captured startup-only token and route.
// Connection-profile mutation and persistent Settings Save both fail closed while controller status is connected/transitioning or unavailable.
