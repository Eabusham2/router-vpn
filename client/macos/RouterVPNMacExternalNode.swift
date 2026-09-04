import AppKit
import Foundation

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
        panel.informativeText = "Create a validated full-device external node. OpenVPN uses Import; Tor uses Tor Bridges. Secrets are stored only in the private controller store."
        panel.addButton(withTitle: "Save node")
        panel.addButton(withTitle: "Cancel")

        let protocolPopup = NSPopUpButton(frame: .zero, pullsDown: false)
        protocolPopup.addItems(withTitles: ["WireGuard", "SOCKS5", "HTTP CONNECT", "HTTPS CONNECT", "Shadowsocks", "Hysteria2"])
        let name = externalField("Display name")
        let server = externalField("Server IP/hostname")
        let port = externalField("Port")
        let expectedIP = externalField("Expected public exit IP")
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

        let note = NSTextField(wrappingLabelWithString: "Relevant fields depend on the protocol. HTTPS CONNECT and Hysteria2 require TLS/SNI. Plain HTTP CONNECT rejects TLS metadata. WireGuard requires keys, interface address and AllowedIPs. The controller re-validates everything before persistence.")
        note.textColor = .secondaryLabelColor
        let grid = NSGridView(views: [
            [NSTextField(labelWithString: "Protocol"), protocolPopup],
            [NSTextField(labelWithString: "Name"), name],
            [NSTextField(labelWithString: "Server"), server],
            [NSTextField(labelWithString: "Port"), port],
            [NSTextField(labelWithString: "Expected exit IP"), expectedIP],
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
        ])
        grid.rowSpacing = 5
        grid.columnSpacing = 10
        for row in 0..<grid.numberOfRows { grid.row(at: row).xPlacement = .fill }

        let content = NSStackView(views: [note, grid])
        content.orientation = .vertical
        content.alignment = .leading
        content.spacing = 8
        content.setFrameSize(NSSize(width: 660, height: 560))
        grid.widthAnchor.constraint(equalTo: content.widthAnchor).isActive = true
        panel.accessoryView = content

        guard panel.runModal() == .alertFirstButtonReturn else { return }
        guard externalMutationIdle() else {
            appendHelp("VPN state changed while the external-node dialog was open. Nothing was saved.")
            return
        }

        let protocols = ["wireguard", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2"]
        let index = max(0, min(protocolPopup.indexOfSelectedItem, protocols.count - 1))
        let selected = protocols[index]
        var body: [String: Any] = [
            "name": name.stringValue.trimmingCharacters(in: .whitespacesAndNewlines),
            "protocol": selected,
            "expected_public_ip": expectedIP.stringValue.trimmingCharacters(in: .whitespacesAndNewlines),
            "server": server.stringValue.trimmingCharacters(in: .whitespacesAndNewlines),
            "port": Int(port.stringValue) ?? 0,
        ]
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
        if selected == "wireguard" {
            body["wg_private_key"] = wgPrivate.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            body["wg_peer_public_key"] = wgPeer.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            let psk = wgPSK.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            if !psk.isEmpty { body["wg_preshared_key"] = psk }
            body["wg_addresses"] = externalCSV(wgAddresses.stringValue)
            body["wg_allowed_ips"] = externalCSV(wgAllowed.stringValue)
            body["wg_dns"] = externalCSV(wgDNS.stringValue)
            if let mtu = Int(wgMTU.stringValue), mtu > 0 { body["wg_mtu"] = mtu }
        }

        asyncAction {
            let data = try self.api.request("/api/external-profile/create", method: "POST", body: body, timeout: 20)
            let response = String(data: data, encoding: .utf8) ?? "External node saved"
            return "External node saved and selected. \(response)"
        }
    }
}
