import AppKit
import Foundation

// Keep the provider's numeric strings and header ranges intact. The controller
// performs the native AWG bounds/overlap validation before saving the profile.
func externalAmneziaParameters(_ raw: String) throws -> [String: String] {
    let keys = Set(["jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4"])
    guard raw.utf8.count <= 4096 else {
        throw NSError(domain: "RouterVPN.ExternalNode", code: 1, userInfo: [NSLocalizedDescriptionKey: "AmneziaWG parameters are too long."])
    }
    var result: [String: String] = [:]
    for line in raw.components(separatedBy: CharacterSet(charactersIn: ";\r\n")) {
        let line = line.trimmingCharacters(in: .whitespacesAndNewlines)
        if line.isEmpty { continue }
        let parts = line.components(separatedBy: "=")
        guard parts.count == 2 else {
            throw NSError(domain: "RouterVPN.ExternalNode", code: 1, userInfo: [NSLocalizedDescriptionKey: "Use one AmneziaWG key=value per line or separate them with semicolons."])
        }
        let key = parts[0].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let value = parts[1].trimmingCharacters(in: .whitespacesAndNewlines)
        let pattern = key.hasPrefix("h") ? "^[0-9]+(-[0-9]+)?$" : "^[0-9]+$"
        guard keys.contains(key), result[key] == nil, value.range(of: pattern, options: .regularExpression) != nil else {
            throw NSError(domain: "RouterVPN.ExternalNode", code: 1, userInfo: [NSLocalizedDescriptionKey: "AmneziaWG parameters contain an unknown, duplicate or malformed value."])
        }
        result[key] = value
    }
    guard Set(result.keys) == keys else {
        throw NSError(domain: "RouterVPN.ExternalNode", code: 1, userInfo: [NSLocalizedDescriptionKey: "Supply all 11 provider values: Jc, Jmin, Jmax, S1–S4 and H1–H4."])
    }
    return result
}

extension ProductWindowController {
    private func externalMutationIdle() -> Bool {
        do {
            guard let status = try api.json("/api/status", timeout: 3) as? [String: Any] else { return false }
            let connected = (status["connected"] as? Bool) ?? false
            let phase = ((status["phase"] as? String) ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            return !connected && (phase.isEmpty || phase == "off" || phase == "failed")
        } catch {
            return false
        }
    }

    private func externalField(_ placeholder: String, secure: Bool = false) -> NSTextField {
        let field: NSTextField = secure ? NSSecureTextField(string: "") : NSTextField(string: "")
        field.placeholderString = placeholder
        field.controlSize = .regular
        return field
    }

    private func externalCSV(_ raw: String) -> [String] {
        raw.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
    }

    @objc func addExternalNode() {
        guard externalMutationIdle() else {
            appendHelp("Disconnect or let the current VPN transition finish before adding an external node. Unknown controller state fails closed.")
            return
        }

        let panel = NSAlert()
        panel.messageText = "Add external node"
        panel.informativeText = "Create a full-device external node. OpenVPN uses Import; Tor uses Tor Bridges. Home AdGuard is the default through a Router entry. For Direct, choose a resolver in DNS."
        panel.addButton(withTitle: "Save node")
        panel.addButton(withTitle: "Cancel")

        let protocolPopup = NSPopUpButton(frame: .zero, pullsDown: false)
        protocolPopup.addItems(withTitles: ["WireGuard", "AmneziaWG", "SOCKS5", "HTTP CONNECT", "HTTPS CONNECT", "Shadowsocks", "Hysteria2"])
        let name = externalField("Display name")
        let server = externalField("Server IP/hostname")
        let port = externalField("Port")
        let expectedIP = externalField("Expected public exit IP")
        let location = externalField("Location label (optional)")
        let latitude = externalField("Latitude -90..90 (optional)")
        let longitude = externalField("Longitude -180..180 (optional)")
        let username = externalField("Username (proxy only)")
        let password = externalField("Password / proxy credential", secure: true)
        let method = externalField("Shadowsocks method")
        let secret = externalField("Shadowsocks/Hysteria2 secret", secure: true)
        let tlsName = externalField("TLS server name / SNI")
        let wgPrivate = externalField("WireGuard private key", secure: true)
        let wgPeer = externalField("WireGuard peer public key")
        let wgPSK = externalField("WireGuard preshared key (optional)", secure: true)
        let wgAddresses = externalField("WG addresses, comma separated")
        let wgAllowed = externalField("WG AllowedIPs, comma separated")
        let wgDNS = externalField("WG DNS IPs, comma separated")
        let wgMTU = externalField("WG MTU (optional)")
        let wgKeepalive = externalField("Keepalive seconds 0–65535 (blank means disabled)")
        let awgParameters = externalField("Jc=…; Jmin=…; Jmax=…; S1=…; S2=…; S3=…; S4=…; H1=…; H2=…; H3=…; H4=…")
        awgParameters.toolTip = "Copy the exact 11 parameter values from the provider's AmneziaWG configuration, separated by semicolons. Header ranges such as H1=10-19 are preserved."

        let note = NSTextField(wrappingLabelWithString: "Relevant fields depend on the protocol. Optional coordinates are real values you provide. WireGuard and AmneziaWG use the peer fields below; AmneziaWG also requires all 11 values from your provider. Copy those values exactly from the provider's configuration.")
        note.textColor = .secondaryLabelColor
        let grid = NSGridView(views: [
            [NSTextField(labelWithString: "Protocol"), protocolPopup],
            [NSTextField(labelWithString: "Name"), name],
            [NSTextField(labelWithString: "Server"), server],
            [NSTextField(labelWithString: "Port"), port],
            [NSTextField(labelWithString: "Expected exit IP"), expectedIP],
            [NSTextField(labelWithString: "Location"), location],
            [NSTextField(labelWithString: "Latitude"), latitude],
            [NSTextField(labelWithString: "Longitude"), longitude],
            [NSTextField(labelWithString: "Username"), username],
            [NSTextField(labelWithString: "Password"), password],
            [NSTextField(labelWithString: "SS method"), method],
            [NSTextField(labelWithString: "Secret"), secret],
            [NSTextField(labelWithString: "TLS / SNI"), tlsName],
            [NSTextField(labelWithString: "WG private key"), wgPrivate],
            [NSTextField(labelWithString: "WG peer key"), wgPeer],
            [NSTextField(labelWithString: "WG PSK"), wgPSK],
            [NSTextField(labelWithString: "WG addresses"), wgAddresses],
            [NSTextField(labelWithString: "WG AllowedIPs"), wgAllowed],
            [NSTextField(labelWithString: "WG DNS"), wgDNS],
            [NSTextField(labelWithString: "WG MTU"), wgMTU],
            [NSTextField(labelWithString: "WG / AWG keepalive"), wgKeepalive],
            [NSTextField(labelWithString: "AWG parameters"), awgParameters],
        ])
        grid.rowSpacing = 5
        grid.columnSpacing = 10

        let content = NSStackView(views: [note, grid])
        content.orientation = .vertical
        content.alignment = .leading
        content.spacing = 8
        content.setFrameSize(NSSize(width: 660, height: 740))
        grid.widthAnchor.constraint(equalTo: content.widthAnchor).isActive = true
        let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 680, height: 580))
        scroll.hasVerticalScroller = true
        scroll.documentView = content
        scroll.contentView.scroll(to: NSPoint(x: 0, y: max(0, content.bounds.height - scroll.contentSize.height)))
        scroll.reflectScrolledClipView(scroll.contentView)
        panel.accessoryView = scroll

        guard panel.runModal() == .alertFirstButtonReturn else { return }
        guard externalMutationIdle() else {
            appendHelp("VPN state changed while the external-node dialog was open. Nothing was saved.")
            return
        }

        let protocols = ["wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2"]
        let index = max(0, min(protocolPopup.indexOfSelectedItem, protocols.count - 1))
        let selected = protocols[index]
        var body: [String: Any] = [
            "name": name.stringValue.trimmingCharacters(in: .whitespacesAndNewlines),
            "protocol": selected,
            "expected_public_ip": expectedIP.stringValue.trimmingCharacters(in: .whitespacesAndNewlines),
            "server": server.stringValue.trimmingCharacters(in: .whitespacesAndNewlines),
            "port": Int(port.stringValue) ?? 0,
        ]
        let locationValue = location.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        if !locationValue.isEmpty { body["location"] = locationValue }
        let latitudeText = latitude.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        let longitudeText = longitude.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        if latitudeText.isEmpty != longitudeText.isEmpty {
            appendHelp("Latitude and longitude must both be supplied or both left blank. Nothing was saved.")
            return
        }
        if !latitudeText.isEmpty {
            guard let lat = Double(latitudeText), let lon = Double(longitudeText), lat.isFinite, lon.isFinite,
                  (-90.0...90.0).contains(lat), (-180.0...180.0).contains(lon) else {
                appendHelp("Coordinates must be finite latitude -90..90 and longitude -180..180. Nothing was saved.")
                return
            }
            body["latitude"] = lat
            body["longitude"] = lon
        }
        let user = username.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        if !user.isEmpty || !password.stringValue.isEmpty {
            body["username"] = user
            body["password"] = password.stringValue
        }
        let ssMethod = method.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        if !ssMethod.isEmpty { body["method"] = ssMethod }
        if !secret.stringValue.isEmpty { body["secret"] = secret.stringValue }
        let sni = tlsName.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        if !sni.isEmpty { body["tls_server_name"] = sni }
        if selected == "wireguard" || selected == "amneziawg" {
            body["wg_private_key"] = wgPrivate.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            body["wg_peer_public_key"] = wgPeer.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            let psk = wgPSK.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            if !psk.isEmpty { body["wg_preshared_key"] = psk }
            body["wg_addresses"] = externalCSV(wgAddresses.stringValue)
            body["wg_allowed_ips"] = externalCSV(wgAllowed.stringValue)
            body["wg_dns"] = externalCSV(wgDNS.stringValue)
            let mtuText = wgMTU.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            if !mtuText.isEmpty {
                guard let mtu = Int(mtuText), (1280...9000).contains(mtu) else {
                    appendHelp("WireGuard / AmneziaWG MTU must be 1280–9000. Nothing was saved.")
                    return
                }
                body["wg_mtu"] = mtu
            }
            let keepaliveText = wgKeepalive.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            if !keepaliveText.isEmpty {
                guard let keepalive = Int(keepaliveText), (0...65535).contains(keepalive) else {
                    appendHelp("Keepalive must be 0–65535 seconds. Nothing was saved.")
                    return
                }
                body["wg_keepalive"] = keepalive
            }
            if selected == "amneziawg" {
                do { body["awg_parameters"] = try externalAmneziaParameters(awgParameters.stringValue) }
                catch { appendHelp(error.localizedDescription); return }
            }
        }

        asyncAction {
            let data = try self.api.request("/api/external-profile/create", method: "POST", body: body, timeout: 20)
            let response = String(data: data, encoding: .utf8) ?? "External node saved"
            return "External node saved and selected. Use a Router entry for Home AdGuard, or choose a resolver in DNS for Direct. \(response)"
        }
    }
}
