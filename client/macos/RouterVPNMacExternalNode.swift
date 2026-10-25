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

func externalSavedExecution(_ profile: [String: Any]) throws -> String {
    let choice = profile["multihop_execution"] as? String ?? "local"
    if choice.isEmpty { return "local" }
    guard ["local", "server", "auto"].contains(choice) else {
        throw NSError(domain: "RouterVPN.ExternalNode", code: 1, userInfo: [NSLocalizedDescriptionKey: "The selected external node has an invalid saved execution choice."])
    }
    return choice
}

func externalConnectBody(profile: [String: Any], entryID: String = "", execution: String, direct: Bool = false) throws -> [String: Any] {
    guard let id = profile["id"] as? String, !id.isEmpty, profile["node_kind"] as? String == "external",
          ["local", "server", "auto"].contains(execution), entryID != id else {
        throw NSError(domain: "RouterVPN.ExternalNode", code: 1, userInfo: [NSLocalizedDescriptionKey: "Choose an external node, a different entry, and Local, Server or Compare both."])
    }
    if direct { return ["profile_id": id, "direct": true, "execution": "local"] }
    var body: [String: Any] = ["profile_id": id, "execution": execution]
    if !entryID.isEmpty { body["entry_id"] = entryID }
    return body
}

func externalPathIdentity(_ profile: [String: Any]) -> [String: Any] {
    let ext = profile["external"] as? [String: Any] ?? [:]
    return ["id": profile["id"] as? String ?? "", "node_kind": profile["node_kind"] as? String ?? "",
        "endpoint": profile["endpoint"] as? String ?? "", "start_layer": profile["start_layer"] as? String ?? "",
        "multihop_entry_mode": profile["multihop_entry_mode"] as? String ?? "",
        "protocol": ext["protocol"] as? String ?? "", "expected_public_ip": ext["expected_public_ip"] as? String ?? "",
        "has_response_probe": ext["has_response_probe"] as? Bool ?? false, "has_server_peer": ext["has_server_peer"] as? Bool ?? false,
        "has_openvpn_pairing": ext["has_openvpn_pairing"] as? Bool ?? false]
}

func externalEntryMode(captured: [String: Any], entry: [String: Any]?, selected: String,
    modes: [[String: Any]]) throws -> String {
    func fail(_ message: String) -> NSError { NSError(domain: "RouterVPN.ExternalNode", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }
    let kind = entry?["node_kind"] as? String ?? "router-vpn"
    guard let entry, kind.isEmpty || kind == "router-vpn" else {
        guard selected.isEmpty else { throw fail("An entry mode applies only to a Router VPN entry.") }
        return ""
    }
    var mode = selected
    if mode.isEmpty {
        var base = entry["base_tunnel"] as? String ?? ""
        if !["wg", "awg"].contains(base) { base = captured["base_tunnel"] as? String ?? "" }
        mode = base == "awg" ? "awg2-fast" : "wg"
    }
    guard modes.filter({ $0["id"] as? String == mode }).count == 1 else {
        throw fail("Choose an exact Router entry mode from the current native catalog.")
    }
    return mode
}

func externalPathConnectBody(captured: [String: Any], entryID: String, execution: String, direct: Bool,
    current: [[String: Any]], entryMode: String? = nil, entryModes: [[String: Any]] = []) throws -> [String: Any] {
    func fail(_ message: String) -> NSError { NSError(domain: "RouterVPN.ExternalNode", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }
    let id = captured["id"] as? String ?? ""
    let matches = current.filter { $0["id"] as? String == id }
    guard matches.count == 1, NSDictionary(dictionary: externalPathIdentity(matches[0])).isEqual(to: externalPathIdentity(captured)) else {
        throw fail("The external node changed while this dialog was open. Reopen its path settings.")
    }
    let entries = current.filter { $0["id"] as? String == entryID }
    guard direct || (!entryID.isEmpty && entries.count == 1) else { throw fail("The selected entry is missing or ambiguous. Choose it again.") }
    if execution != "local" {
        let ext = matches[0]["external"] as? [String: Any] ?? [:]
        let protocolID = ext["protocol"] as? String ?? ""
        guard ["wireguard", "amneziawg", "shadowsocks", "hysteria2", "socks5", "http-connect", "https-connect", "openvpn"].contains(protocolID) else { throw fail("Server / Compare requires a supported authenticated external transport.") }
        guard ext["has_response_probe"] as? Bool == true else { throw fail("Server / Compare requires this external node's HTTPS response probe.") }
        guard !["wireguard", "amneziawg"].contains(protocolID) || ext["has_server_peer"] as? Bool == true else { throw fail("WireGuard / AmneziaWG Server / Compare requires a separately provisioned server peer.") }
        guard protocolID != "openvpn" || ext["has_openvpn_pairing"] as? Bool == true else { throw fail("OpenVPN Server / Compare requires private pairing with independent provider credentials.") }
        guard !direct, entries[0]["node_kind"] as? String ?? "router-vpn" == "router-vpn" else { throw fail("Server / Compare requires a Router VPN entry.") }
    }
    var body = try externalConnectBody(profile: captured, entryID: entryID, execution: execution, direct: direct)
    if let entryMode {
        let mode = try externalEntryMode(captured: captured, entry: direct ? nil : entries[0], selected: entryMode, modes: entryModes)
        if !mode.isEmpty { body["entry_mode"] = mode }
    }
    return body
}

func externalServerPeerFields(protocolID: String, publicKey: String, addresses: String, mtu: String, keepalive: String) throws -> [String: Any] {
    func fail(_ message: String) -> NSError { NSError(domain: "RouterVPN.ExternalNode", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }
    let key = publicKey.trimmingCharacters(in: .whitespacesAndNewlines)
    let assigned = addresses.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
    let mtuText = mtu.trimmingCharacters(in: .whitespacesAndNewlines), keepaliveText = keepalive.trimmingCharacters(in: .whitespacesAndNewlines)
    if key.isEmpty && addresses.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && mtuText.isEmpty && keepaliveText.isEmpty { return [:] }
    guard ["wireguard", "amneziawg"].contains(protocolID) else { throw fail("Server peer fields apply only to WireGuard or AmneziaWG.") }
    guard let decoded = Data(base64Encoded: key), decoded.count == 32, decoded.base64EncodedString() == key,
          (1...2).contains(assigned.count), let value = Int(mtuText), (1280...9000).contains(value) else {
        throw fail("Supply the separate server peer canonical 32-byte public key, one CIDR per IP family, and MTU 1280–9000.")
    }
    var peer: [String: Any] = ["public_key": key, "addresses": assigned, "mtu": value]
    if !keepaliveText.isEmpty {
        guard let seconds = Int(keepaliveText), (0...65535).contains(seconds) else { throw fail("Server peer keepalive must be 0–65535 seconds.") }
        peer["persistent_keepalive_interval"] = seconds
    }
    return ["server_peer": peer]
}

func externalOpenVPNFields(protocolID: String, config: String, pairing: String, username: String, password: String, responseProbes: String = "", startLayers: String = "") throws -> [String: Any] {
    func fail(_ message: String) -> NSError { NSError(domain: "RouterVPN.ExternalNode", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }
    guard protocolID == "openvpn" else {
        guard config.isEmpty && pairing.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && responseProbes.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && startLayers.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { throw fail("OpenVPN profile, pairing, response-map, and layer-map fields belong only to OpenVPN.") }
        return [:]
    }
    guard !config.isEmpty, config.utf8.count <= 256 * 1024, !config.contains("\0"), pairing.utf8.count <= 512 * 1024, responseProbes.utf8.count <= 40 * 1024, startLayers.utf8.count <= 128 * 1024 else {
        throw fail("Paste a bounded inline OpenVPN profile and private pairing, response-map, or layer-map fields.")
    }
    var result: [String: Any] = ["openvpn": ["config": config, "username": username, "password": password]]
    if !pairing.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { result["openvpn_pairing_json"] = pairing }
    if !responseProbes.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { result["openvpn_response_probes_json"] = responseProbes }
    if !startLayers.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
        guard !responseProbes.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { throw fail("A per-host Start Layer map requires the complete response map for those same OpenVPN hosts.") }
        result["openvpn_start_layers_json"] = startLayers
    }
    return result
}

// These are private typed provision fields. The controller validates exact server,
// API, response endpoint and key ownership before saving or starting a runtime.
func externalOptionalTransportFields(protocolID: String, server: String, responseURL: String,
    responseServerName: String, startLayer: String, layerAPI: String, layerPort: String,
    layerKey: String, startLayers: String = "") throws -> [String: Any] {
    func fail(_ message: String) -> NSError { NSError(domain: "RouterVPN.ExternalNode", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }
    let probe = responseURL.trimmingCharacters(in: .whitespacesAndNewlines)
    let name = responseServerName.trimmingCharacters(in: .whitespacesAndNewlines)
    let api = layerAPI.trimmingCharacters(in: .whitespacesAndNewlines)
    let port = layerPort.trimmingCharacters(in: .whitespacesAndNewlines)
    guard ["off", "aes-256-gcm", "aes-256-gcm+xor-whitening"].contains(startLayer) else { throw fail("Choose a supported external Start Layer.") }
    if !startLayers.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
        guard protocolID == "openvpn", startLayer != "off", probe.isEmpty, name.isEmpty, api.isEmpty, port.isEmpty, layerKey.isEmpty else {
            throw fail("Choose the matching active Start Layer for the OpenVPN host map and leave single-server response and layer fields blank.")
        }
        return ["start_layer": startLayer]
    }
    let supplied = !probe.isEmpty || !name.isEmpty || startLayer != "off" || !api.isEmpty || !port.isEmpty || !layerKey.isEmpty
    guard !supplied || ["wireguard", "amneziawg", "shadowsocks", "hysteria2", "socks5", "http-connect", "https-connect", "openvpn"].contains(protocolID) else { throw fail("Response probes and external Start Layers require a supported external transport.") }
    guard name.isEmpty || !probe.isEmpty else { throw fail("Supply the HTTPS response URL with its certificate server name.") }
    var fields: [String: Any] = ["start_layer": startLayer]
    if !probe.isEmpty { fields["response_probe"] = ["url": probe, "server_name": name] }
    if startLayer == "off" {
        guard api.isEmpty && port.isEmpty && layerKey.isEmpty else { throw fail("Select a Start Layer before supplying its provisioned credentials.") }
    } else {
        guard !api.isEmpty, !layerKey.isEmpty, let value = Int(port), (1...65535).contains(value) else { throw fail("An active Start Layer requires its private API, AES port (1–65535), and key.") }
        fields["start_layer_provision"] = ["mode": startLayer, "api": api, "transport": [
            "type": "shadowsocks", "tag": "provisioned-exit-layer", "server": server.trimmingCharacters(in: .whitespacesAndNewlines),
            "server_port": value, "method": "2022-blake3-aes-256-gcm", "password": layerKey]]
    }
    return fields
}

extension ProductWindowController {
    // Popup title APIs deduplicate equal names. Identity menus retain every
    // imported node and carry the stable ID on the actual selected menu item.
    func populateIdentityPopup(_ popup: NSPopUpButton, names: [String], ids: [String]) {
        let menu = NSMenu(); menu.autoenablesItems = false
        guard names.count == ids.count else { popup.menu = menu; return }
        for (name, id) in zip(names, ids) {
            let item = NSMenuItem(title: name, action: nil, keyEquivalent: "")
            item.representedObject = id
            menu.addItem(item)
        }
        popup.menu = menu
    }

    @objc func openExternalPath() {
        let index = routerPopup.indexOfSelectedItem
        guard routerIDs.indices.contains(index) else { appendHelp("Select an external node first."); return }
        showExternalPath(profileID: routerIDs[index])
    }

    func showExternalPath(profileID: String, requireEntry: Bool = false) {
        guard ensureMutationIdle("choosing an external path") else { return }
        do {
            guard let store = try api.json("/api/nodes", timeout: 5) as? [String: Any],
                  let catalog = store["profiles"] as? [[String: Any]],
                  catalog.filter({ $0["id"] as? String == profileID }).count == 1,
                  let captured = catalog.first(where: { $0["id"] as? String == profileID }),
                  captured["node_kind"] as? String == "external" else {
                appendHelp("Select an external node first."); return
            }
            let choices = catalog.filter { ($0["id"] as? String) != profileID }
            guard let capabilities = try api.json("/api/external-profile/capabilities", timeout: 5) as? [String: Any],
                  let entryModes = capabilities["router_vpn_entry_modes"] as? [[String: Any]] else {
                appendHelp("The native Router entry mode catalog is unavailable."); return
            }
            let savedMode = captured["multihop_entry_mode"] as? String ?? ""
            guard savedMode.isEmpty || entryModes.filter({ $0["id"] as? String == savedMode }).count == 1 else {
                appendHelp("The saved Router entry mode is missing from the current native catalog."); return
            }
            let ids = [""] + choices.map { $0["id"] as? String ?? "" }
            let entry = NSPopUpButton(frame: .zero, pullsDown: false)
            populateIdentityPopup(entry, names: ["Direct — no entry"] + choices.map { $0["display_name"] as? String ?? $0["name"] as? String ?? "Node" }, ids: ids)
            let savedEntry = captured["multihop_enabled"] as? Bool == true ? captured["multihop_entry_id"] as? String ?? "" : ""
            guard let selectedEntry = ids.firstIndex(of: savedEntry) else { appendHelp("The saved external entry is missing. Relink it or use External direct explicitly."); return }
            entry.selectItem(at: selectedEntry)
            let execution = NSPopUpButton(frame: .zero, pullsDown: false)
            execution.addItems(withTitles: ["Local — exit runs on this device", "Server — exit runs on Router entry", "Compare both — lowest valid average"])
            execution.selectItem(at: savedEntry.isEmpty ? 0 : ["local", "server", "auto"].firstIndex(of: try externalSavedExecution(captured)) ?? 0)
            let entryMode = NSPopUpButton(frame: .zero, pullsDown: false)
            let modeIDs = [""] + entryModes.map { $0["id"] as? String ?? "" }
            populateIdentityPopup(entryMode, names: ["Use selected entry's saved base"] + entryModes.map { $0["name"] as? String ?? $0["id"] as? String ?? "Mode" }, ids: modeIDs)
            entryMode.selectItem(at: modeIDs.firstIndex(of: savedMode) ?? 0)
            let changed = ExternalPathEntrySelection {
                let selectedID = entry.selectedItem?.representedObject as? String ?? ""
                let selected = choices.first { $0["id"] as? String == selectedID }
                let kind = selected?["node_kind"] as? String ?? "router-vpn"
                let router = !selectedID.isEmpty && selected != nil && (kind.isEmpty || kind == "router-vpn")
                entryMode.isEnabled = router
                if !router { entryMode.selectItem(at: 0) }
                execution.isEnabled = !selectedID.isEmpty
                if selectedID.isEmpty { execution.selectItem(at: 0) }
            }
            entry.target = changed; entry.action = #selector(ExternalPathEntrySelection.changed)
            changed.changed(); defer { withExtendedLifetime(changed) {} }
            let hasProbe = (captured["external"] as? [String: Any])?["has_response_probe"] as? Bool == true
            let panel = NSAlert(); panel.messageText = "External path: \(captured["name"] as? String ?? profileID)"
            panel.informativeText = "Server / Compare requires a Router entry, an authenticated external exit, and its saved HTTPS response probe. WireGuard / AmneziaWG also needs a separately provisioned server peer. Pairing and actual path proof are checked when connecting. Direct uses Local. A successful connection saves this node's choice."
            panel.addButton(withTitle: "Connect selected path"); panel.addButton(withTitle: "Cancel")
            let note = NSTextField(wrappingLabelWithString: hasProbe ? "HTTPS response probe saved; server pairing and native proof remain pending." : "No HTTPS response probe saved. Import or create a provisioned external node before choosing Server / Compare.")
            note.textColor = .secondaryLabelColor
            let error = NSTextField(wrappingLabelWithString: ""); error.textColor = .systemRed
            let modeNote = NSTextField(wrappingLabelWithString: "The exact selected mode and the entry node's saved Start Layer are used. Compatibility and path proof are checked before Connected.")
            modeNote.textColor = .secondaryLabelColor
            let content = NSStackView(views: [NSGridView(views: [[NSTextField(labelWithString: "Entry"), entry], [NSTextField(labelWithString: "Router entry mode"), entryMode], [NSTextField(labelWithString: "External execution"), execution]]), modeNote, note, error])
            content.orientation = .vertical; content.alignment = .leading; content.spacing = 12
            content.setFrameSize(NSSize(width: 590, height: 240)); panel.accessoryView = content
            while panel.runModal() == .alertFirstButtonReturn {
                guard ensureMutationIdle("committing an external path") else { return }
                guard let entryID = entry.selectedItem?.representedObject as? String else { error.stringValue = "Choose an entry or Direct."; continue }
                let direct = entryID.isEmpty
                let executionIndex = execution.indexOfSelectedItem
                guard (0..<3).contains(executionIndex) else { error.stringValue = "Choose Local, Server or Compare both."; continue }
                let choice = ["local", "server", "auto"][executionIndex]
                if requireEntry && direct { error.stringValue = "Choose an entry for this via-entry connection."; continue }
                if direct && choice != "local" { error.stringValue = "Direct uses Local. Choose an entry for Server / Compare."; continue }
                let body: [String: Any]
                do {
                    guard let current = try api.json("/api/nodes", timeout: 5) as? [String: Any], let currentCatalog = current["profiles"] as? [[String: Any]] else { throw NSError(domain: "RouterVPN.ExternalNode", code: 1) }
                    guard let selectedMode = entryMode.selectedItem?.representedObject as? String else { throw NSError(domain: "RouterVPN.ExternalNode", code: 1, userInfo: [NSLocalizedDescriptionKey: "Choose a Router entry mode."]) }
                    body = try externalPathConnectBody(captured: captured, entryID: entryID, execution: choice, direct: direct, current: currentCatalog,
                        entryMode: selectedMode, entryModes: entryModes)
                } catch let failure { error.stringValue = failure.localizedDescription; continue }
                asyncAction {
                    try self.requireMutationIdle("starting an external selected path")
                    return String(data: try self.api.request("/api/external-profile/connect", method: "POST", body: body, timeout: 180), encoding: .utf8) ?? "External selected path connected"
                }
                return
            }
        } catch { appendHelp(error.localizedDescription) }
    }

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
        panel.informativeText = "Create a full-device external node. OpenVPN accepts its original inline profile; Tor uses Tor Bridges. Home AdGuard is the default through a Router entry. For Direct, choose a resolver in DNS."
        panel.addButton(withTitle: "Save node")
        panel.addButton(withTitle: "Cancel")

        let protocolPopup = NSPopUpButton(frame: .zero, pullsDown: false)
        protocolPopup.addItems(withTitles: ["WireGuard", "AmneziaWG", "SOCKS5", "HTTP CONNECT", "HTTPS CONNECT", "Shadowsocks", "Hysteria2", "OpenVPN"])
        let name = externalField("Display name")
        let server = externalField("Server IP/hostname")
        let port = externalField("Port")
        let expectedIP = externalField("Expected public exit IP")
        let location = externalField("Location label (optional)")
        let latitude = externalField("Latitude -90..90 (optional)")
        let longitude = externalField("Longitude -180..180 (optional)")
        let username = externalField("Username (proxy / OpenVPN)")
        let password = externalField("Password / proxy credential", secure: true)
        let method = externalField("Shadowsocks method")
        let secret = externalField("Shadowsocks/Hysteria2 secret", secure: true)
        let tlsName = externalField("TLS server name / SNI")
        let responseURL = externalField("HTTPS URL on this external server's public IP")
        let responseName = externalField("Response certificate server name (when needed)")
        let startLayer = NSPopUpButton(frame: .zero, pullsDown: false)
        startLayer.addItems(withTitles: ["Off", "AES-256-GCM", "AES-256-GCM + XOR whitening"])
        let layerAPI = externalField("Provisioned layer private API URL")
        let layerPort = externalField("Provisioned AES transport port")
        let layerKey = externalField("Provisioned AES key (32-byte Base64)", secure: true)
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
        let serverPeerPublic = externalField("Separate server-side client public key")
        let serverPeerAddresses = externalField("Server peer CIDRs, one per IP family, comma separated")
        let serverPeerMTU = externalField("Server peer MTU 1280–9000 (required with descriptor)")
        let serverPeerKeepalive = externalField("Server peer keepalive 0–65535 (optional)")

        let openVPNConfig = NSTextView(); let openVPNPairing = NSTextView(); let openVPNResponseProbes = NSTextView(); let openVPNStartLayers = NSTextView()
        let openVPNViews = [openVPNConfig, openVPNPairing, openVPNResponseProbes, openVPNStartLayers].map { view -> NSScrollView in
            view.isRichText = false; view.isAutomaticQuoteSubstitutionEnabled = false; view.isAutomaticDashSubstitutionEnabled = false
            view.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
            view.frame = NSRect(x: 0, y: 0, width: 420, height: 130); view.isVerticallyResizable = true; view.isHorizontallyResizable = false
            view.autoresizingMask = [.width]; view.textContainer?.widthTracksTextView = true
            let scroll = NSScrollView(); scroll.hasVerticalScroller = true; scroll.borderType = .bezelBorder; scroll.documentView = view
            scroll.heightAnchor.constraint(equalToConstant: 130).isActive = true
            return scroll
        }
        let note = NSTextField(wrappingLabelWithString: "Relevant fields depend on the protocol. Optional coordinates are real values you provide. AmneziaWG requires all 11 exact provider values. Server / Compare requires a Router entry and an HTTPS response probe on the external server. WG/AWG also requires the public descriptor of a separately provisioned server-side client peer, with addresses and public identity distinct from this device. Keep that peer's private key and preshared key on the server. The WG peer key identifies the remote provider. Start Layers require matching server provisioning; SOCKS5 / HTTP(S) needs authentication for Server / Compare. OpenVPN uses its original inline profile and private pairing with independent provider identities; server secrets remain on the Router entry.")
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
            [NSTextField(labelWithString: "HTTPS response URL"), responseURL],
            [NSTextField(labelWithString: "Response certificate name"), responseName],
            [NSTextField(labelWithString: "External Start Layer"), startLayer],
            [NSTextField(labelWithString: "Provisioned private API"), layerAPI],
            [NSTextField(labelWithString: "Provisioned AES port"), layerPort],
            [NSTextField(labelWithString: "Provisioned AES key"), layerKey],
            [NSTextField(labelWithString: "WG private key"), wgPrivate],
            [NSTextField(labelWithString: "WG peer key"), wgPeer],
            [NSTextField(labelWithString: "WG PSK"), wgPSK],
            [NSTextField(labelWithString: "WG addresses"), wgAddresses],
            [NSTextField(labelWithString: "WG AllowedIPs"), wgAllowed],
            [NSTextField(labelWithString: "WG DNS"), wgDNS],
            [NSTextField(labelWithString: "WG MTU"), wgMTU],
            [NSTextField(labelWithString: "WG / AWG keepalive"), wgKeepalive],
            [NSTextField(labelWithString: "AWG parameters"), awgParameters],
            [NSTextField(labelWithString: "Server-side client public key"), serverPeerPublic],
            [NSTextField(labelWithString: "Server peer addresses"), serverPeerAddresses],
            [NSTextField(labelWithString: "Server peer MTU"), serverPeerMTU],
            [NSTextField(labelWithString: "Server peer keepalive"), serverPeerKeepalive],
            [NSTextField(labelWithString: "Private inline OpenVPN profile"), openVPNViews[0]],
            [NSTextField(labelWithString: "Private OpenVPN pairing JSON"), openVPNViews[1]],
            [NSTextField(labelWithString: "Private OpenVPN per-remote response map JSON"), openVPNViews[2]],
            [NSTextField(labelWithString: "Private OpenVPN per-host Start Layer map JSON"), openVPNViews[3]],
        ])
        grid.rowSpacing = 5
        grid.columnSpacing = 10

        let mapNote = NSTextField(wrappingLabelWithString: "For multiple OpenVPN remote hosts, supply a response endpoint for every original remote IP. To add encryption or whitening, paste the matching per-host Start Layer map, choose its AES mode above, and leave single-server response and layer fields blank. Every host needs its own provisioned layer; the original OpenVPN fallback order and credentials are preserved.")
        mapNote.textColor = .secondaryLabelColor
        let content = NSStackView(views: [note, mapNote, grid])
        content.orientation = .vertical
        content.alignment = .leading
        content.spacing = 8
        content.setFrameSize(NSSize(width: 660, height: 1570))
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

        let protocols = ["wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn"]
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
        let user = username.stringValue
        if !user.isEmpty || !password.stringValue.isEmpty {
            body["username"] = user
            body["password"] = password.stringValue
        }
        let ssMethod = method.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        if !ssMethod.isEmpty { body["method"] = ssMethod }
        if !secret.stringValue.isEmpty { body["secret"] = secret.stringValue }
        let sni = tlsName.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        if !sni.isEmpty { body["tls_server_name"] = sni }
        do {
            body.merge(try externalOpenVPNFields(protocolID: selected, config: openVPNConfig.string, pairing: openVPNPairing.string,
                username: username.stringValue, password: password.stringValue, responseProbes: openVPNResponseProbes.string, startLayers: openVPNStartLayers.string)) { _, supplied in supplied }
            if selected == "openvpn" { body.removeValue(forKey: "username"); body.removeValue(forKey: "password") }
        } catch { appendHelp(error.localizedDescription); return }
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

        do {
            let layer = ["off", "aes-256-gcm", "aes-256-gcm+xor-whitening"][max(0, min(startLayer.indexOfSelectedItem, 2))]
            body.merge(try externalServerPeerFields(protocolID: selected, publicKey: serverPeerPublic.stringValue,
                addresses: serverPeerAddresses.stringValue, mtu: serverPeerMTU.stringValue, keepalive: serverPeerKeepalive.stringValue)) { _, supplied in supplied }
            let fields = try externalOptionalTransportFields(protocolID: selected, server: server.stringValue,
                responseURL: responseURL.stringValue, responseServerName: responseName.stringValue,
                startLayer: layer, layerAPI: layerAPI.stringValue, layerPort: layerPort.stringValue, layerKey: layerKey.stringValue, startLayers: openVPNStartLayers.string)
            body.merge(fields) { _, supplied in supplied }
        } catch { appendHelp(error.localizedDescription); return }

        asyncAction {
            let data = try self.api.request("/api/external-profile/create", method: "POST", body: body, timeout: 20)
            let response = String(data: data, encoding: .utf8) ?? "External node saved"
            return "External node saved and selected. Use a Router entry for Home AdGuard, or choose a resolver in DNS for Direct. \(response)"
        }
    }
}

private final class ExternalPathEntrySelection: NSObject {
    private let update: () -> Void
    init(_ update: @escaping () -> Void) { self.update = update }
    @objc func changed() { update() }
}
