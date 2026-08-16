import AppKit
import Foundation

private struct RouterVPNProfileSettingsPayloadV2: Codable {
    var homeLANAccess: Bool
    var killSwitchPolicy: String
    var ipv6Mode: String
    var startupMode: String
    var autoConnect: Bool
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
                alert.messageText = "Router VPN profile settings"
                alert.informativeText = "Disconnect before saving. These are persistent settings for the selected Router VPN node; unsupported runtime features remain unavailable and saved values are not runtime proof."
                alert.addButton(withTitle: "Save for next connection")
                alert.addButton(withTitle: "Cancel")

                let form = NSStackView()
                form.orientation = .vertical
                form.spacing = 8
                form.frame = NSRect(x: 0, y: 0, width: 520, height: 470)

                func popup(_ title: String, values: [(String,String)], selected: String) -> NSPopUpButton {
                    let row = NSStackView(); row.orientation = .horizontal; row.spacing = 8
                    let label = NSTextField(labelWithString: title); label.frame.size.width = 180
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
                let ipv6 = popup("IPv6 policy", values: [("Auto","auto"),("On","on"),("Off","off")], selected: settings.ipv6Mode)
                let base = popup("WG/AWG base", values: [("Auto","auto"),("WireGuard","wg"),("AmneziaWG","awg")], selected: settings.baseTunnel)
                let fallback = check("Allow WG/AWG base fallback", value: settings.baseFallback)
                let mtu = popup("MTU policy", values: [("Default","default"),("Auto measured","auto"),("Manual","manual")], selected: settings.mtuPolicy)
                let mtuRow = NSStackView(); mtuRow.orientation = .horizontal; mtuRow.spacing = 8
                mtuRow.addArrangedSubview(NSTextField(labelWithString: "Manual MTU 576–9000"))
                let manual = NSTextField(string: (settings.manualMTU ?? 0) > 0 ? String(settings.manualMTU!) : "")
                mtuRow.addArrangedSubview(manual); form.addArrangedSubview(mtuRow)
                let daita = check("DAITA-like bounded cover traffic (supported modes only)", value: settings.daitaEnabled)
                let jumbo = check("Jumbo TUN (compatible TUN/proxy paths only)", value: settings.jumboTUN)
                let socks = check("Private in-tunnel SOCKS5 utility", value: settings.socksEnabled)
                let startup = popup("Startup behavior", values: [("Manual","manual"),("AUTO","auto"),("SMART AUTO","smart-auto"),("Last mode","last")], selected: settings.startupMode)
                let auto = check("Auto-connect when Router VPN starts", value: settings.autoConnect)
                let effective = NSTextField(wrappingLabelWithString: "Current effective MTU: \((settings.effectiveMTU ?? 0) > 0 ? String(settings.effectiveMTU!) : "default / not measured") • \(settings.effectiveMTUSource ?? "")")
                effective.textColor = .secondaryLabelColor; form.addArrangedSubview(effective)
                alert.accessoryView = form

                if alert.runModal() == .alertFirstButtonReturn {
                    settings.homeLANAccess = lan.state == .on
                    settings.killSwitchPolicy = (kill.selectedItem?.representedObject as? String) ?? "off"
                    settings.ipv6Mode = (ipv6.selectedItem?.representedObject as? String) ?? "auto"
                    settings.baseTunnel = (base.selectedItem?.representedObject as? String) ?? "auto"
                    settings.baseFallback = fallback.state == .on
                    settings.mtuPolicy = (mtu.selectedItem?.representedObject as? String) ?? "default"
                    let manualValue = Int(manual.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
                    if settings.mtuPolicy == "manual" && !(576...9000).contains(manualValue) {
                        validationError = "Manual MTU must be 576–9000."
                    }
                    settings.manualMTU = settings.mtuPolicy == "manual" ? manualValue : nil
                    settings.daitaEnabled = daita.state == .on
                    settings.jumboTUN = jumbo.state == .on
                    settings.socksEnabled = socks.state == .on
                    settings.startupMode = (startup.selectedItem?.representedObject as? String) ?? "manual"
                    settings.autoConnect = auto.state == .on
                    save = validationError.isEmpty
                }
                semaphore.signal()
            }

            semaphore.wait()
            if !validationError.isEmpty { throw NSError(domain: "RouterVPN.Settings", code: 1, userInfo: [NSLocalizedDescriptionKey: validationError]) }
            if !save { return "Profile settings unchanged." }
            let payload = try JSONEncoder().encode(settings)
            _ = try self.api.requestRaw("/api/profile/settings", body: payload, timeout: 8)
            return "Profile settings saved for the next supported connection. Saved preferences are not runtime proof."
        }
    }
}

// Safe native settings contract: omitted manual_mtu decodes cleanly for Default/Auto.
// /api/profile/settings only; no redacted full-profile POST.
