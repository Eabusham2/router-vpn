import AppKit
import Foundation

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

extension ProductWindowController {
    @objc func editProfileSettings() {
        asyncAction {
            let data = try self.api.request("/api/profile/settings", timeout: 5)
            var settings = try JSONDecoder().decode(RouterVPNProfileSettingsPayloadV2.self, from: data)
            let semaphore = DispatchSemaphore(value: 0)
            var save = false
            var validationError = ""

            DispatchQueue.main.async {
                let alert = NSAlert()
                alert.messageText = "Settings"
                alert.informativeText = "Selected Router node • persistent defaults for the next connection. Unsupported runtime features stay unavailable; saved values are not runtime proof."
                alert.addButton(withTitle: "Save")
                alert.addButton(withTitle: "Cancel")

                let form = NSStackView()
                form.orientation = .vertical
                form.spacing = 8
                form.frame = NSRect(x: 0, y: 0, width: 540, height: 570)

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

                let autoEncrypted = check("AUTO / SMART: Require encrypted", value: settings.autoRequireEncrypted)
                let autoObfuscated = check("AUTO / SMART: Require obfuscation", value: settings.autoRequireObfuscation)
                let autoNote = NSTextField(wrappingLabelWithString: "Both AUTO requirements are Off by default. When enabled, candidates are filtered before connection attempts; SMART simplification cannot drop below the requirement.")
                autoNote.textColor = .secondaryLabelColor; autoNote.font = .systemFont(ofSize: 11); form.addArrangedSubview(autoNote)

                let mtu = popup("MTU", values: [("Auto measured — default","auto"),("Fixed / manual","manual"),("Runtime default","default")], selected: settings.mtuPolicy)
                let mtuRow = NSStackView(); mtuRow.orientation = .horizontal; mtuRow.spacing = 8
                mtuRow.addArrangedSubview(NSTextField(labelWithString: "Fixed MTU 576–9000"))
                let manual = NSTextField(string: (settings.manualMTU ?? 0) > 0 ? String(settings.manualMTU!) : "")
                mtuRow.addArrangedSubview(manual); form.addArrangedSubview(mtuRow)
                let effective = NSTextField(wrappingLabelWithString: "Effective MTU: \((settings.effectiveMTU ?? 0) > 0 ? String(settings.effectiveMTU!) : "not measured yet") • \(settings.effectiveMTUSource ?? "Auto will test/use a valid path-specific value")")
                effective.textColor = .secondaryLabelColor; effective.font = .systemFont(ofSize: 11); form.addArrangedSubview(effective)

                let daita = check("DAITA-like traffic padding (bounded; supported modes only)", value: settings.daitaEnabled)
                let jumbo = check("Jumbo TUN / jumbo packet mode (compatible paths only)", value: settings.jumboTUN)
                let socks = check("Private in-tunnel SOCKS5 utility", value: settings.socksEnabled)
                let startup = popup("Default mode on startup", values: [("SMART AUTO — recommended","smart-auto"),("AUTO","auto"),("Last proven mode","last"),("Manual / stay disconnected","manual")], selected: settings.startupMode)
                let auto = check("Auto-connect when Router VPN starts", value: settings.autoConnect)

                let forwarding = NSButton(title: "Port forwarding / Protected DMZ…", target: self, action: #selector(self.openUnifiedForwarding))
                forwarding.bezelStyle = .rounded; form.addArrangedSubview(forwarding)
                let retest = NSButton(title: "Retest MTU for current config/path", target: self, action: #selector(self.retestMTU))
                retest.bezelStyle = .rounded; form.addArrangedSubview(retest)

                alert.accessoryView = form
                if alert.runModal() == .alertFirstButtonReturn {
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
                semaphore.signal()
            }

            semaphore.wait()
            if !validationError.isEmpty { throw NSError(domain: "RouterVPN.Settings", code: 1, userInfo: [NSLocalizedDescriptionKey: validationError]) }
            if !save { return "Settings unchanged." }
            let payload = try JSONEncoder().encode(settings)
            _ = try self.api.requestRaw("/api/profile/settings", body: payload, timeout: 8)
            return "Settings saved for the next supported connection. Saved preferences are not runtime proof."
        }
    }
}

// Unified settings contract: SMART AUTO default, IPv6 On default, Auto measured MTU,
// fixed MTU override + Retest, DAITA-like traffic padding, Jumbo TUN, kill switch,
// AUTO Require encrypted / Require obfuscation, LAN access and forwarding entry point.
// /api/profile/settings only; no redacted full-profile POST.
