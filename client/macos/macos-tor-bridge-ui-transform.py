#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import sys

if len(sys.argv) != 3:
    raise SystemExit("usage: macos-tor-bridge-ui-transform.py INPUT.swift OUTPUT.swift")

src, out = map(Path, sys.argv[1:3])
text = src.read_text(encoding="utf-8")

button_anchor = 'row.addArrangedSubview(button("Add external node…", #selector(addExternalNode))); content.addArrangedSubview(row)'
button_new = '''content.addArrangedSubview(row)
        let provisionRow = NSStackView(); provisionRow.orientation = .horizontal; provisionRow.spacing = 8
        provisionRow.addArrangedSubview(button("Add external node…", #selector(addExternalNode))); provisionRow.addArrangedSubview(button("Tor bridges…", #selector(openTorBridgeBuilder))); content.addArrangedSubview(provisionRow)'''
if button_anchor in text:
    text = text.replace(button_anchor, button_new, 1)
elif button_new not in text:
    raise SystemExit("macOS unified Nodes action row drifted; refusing blind Tor UI injection")

class_marker = "private final class RouterVPNTorBridgeBuilder: NSWindowController"
if class_marker not in text:
    extension_anchor = "extension ProductWindowController {"
    if text.count(extension_anchor) < 1:
        raise SystemExit("macOS ProductWindowController extension anchor missing")
    tor_class = r'''
func torBridgeUpdateProfile(_ opened: [String: Any]) -> [String: Any]? {
    guard let id = opened["selected_id"] as? String, !id.isEmpty,
          let profiles = opened["profiles"] as? [[String: Any]] else { return nil }
    let rows = profiles.filter { $0["id"] as? String == id }
    guard rows.count == 1, rows[0]["node_kind"] as? String == "external",
          ["tor", "tor-bridge"].contains((rows[0]["external"] as? [String: Any])?["protocol"] as? String ?? "") else { return nil }
    return rows[0]
}

func torBridgeHasRouterPath(_ opened: [String: Any], profile: [String: Any]) -> Bool {
    guard profile["multihop_enabled"] as? Bool == true, let id = profile["id"] as? String,
          profile["multihop_exit_id"] as? String == id, let entry = profile["multihop_entry_id"] as? String,
          !entry.isEmpty, entry != id, ["", "local", "server"].contains(profile["multihop_execution"] as? String ?? ""),
          let profiles = opened["profiles"] as? [[String: Any]] else { return false }
    let rows = profiles.filter { $0["id"] as? String == entry }
    return rows.count == 1 && ["", "router-vpn"].contains(rows[0]["node_kind"] as? String ?? "router-vpn") && rows[0]["external"] == nil
}

func torBridgeHasOrdinaryPath(_ opened: [String: Any], profile: [String: Any], body: [String: Any]) -> Bool {
    guard profile["multihop_enabled"] as? Bool == true, let id = profile["id"] as? String,
          profile["multihop_exit_id"] as? String == id, let entry = profile["multihop_entry_id"] as? String,
          !entry.isEmpty, entry != id, ["", "local"].contains(profile["multihop_execution"] as? String ?? ""),
          let profiles = opened["profiles"] as? [[String: Any]], let bridges = body["bridges"] as? [String] else { return false }
    let rows = profiles.filter { $0["id"] as? String == entry }
    guard rows.count == 1, rows[0]["node_kind"] as? String == "external", let external = rows[0]["external"] as? [String: Any],
          let mode = external["protocol"] as? String, ["wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn"].contains(mode),
          profile["multihop_entry_mode"] as? String == mode, let publicIP = external["expected_public_ip"] as? String, !publicIP.isEmpty else { return false }
    let udp = body["transport"] as? String == "snowflake" || bridges.contains {
        let words = $0.split(whereSeparator: { $0.isWhitespace }).map { $0.lowercased() }
        return (words.first == "bridge" ? words.dropFirst().first : words.first) == "snowflake"
    }
    return !udp || !["socks5", "http-connect", "https-connect"].contains(mode)
}

func torBridgeImportBody(_ body: [String: Any], opened: [String: Any], update: Bool,
                         capabilities: [String: Any], current: [String: Any]? = nil) throws -> [String: Any] {
    func fail(_ message: String) -> NSError { NSError(domain: "RouterVPN.TorEdit", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }
    guard let kill = body["kill_switch_policy"] as? String, ["off", "on-connect", "always"].contains(kill) else { throw fail("Choose a valid kill-switch policy before saving. The saved policy was not replaced with Off.") }
    guard let transport = body["transport"] as? String, let bridges = body["bridges"] as? [String] else { throw fail("Choose a Tor transport and its bridge lines.") }
    if transport == "tor" {
        guard bridges.isEmpty else { throw fail("Clear the bridge lines before choosing Plain Tor. No bridge configuration was discarded.") }
    } else {
        guard (1...8).contains(bridges.count) else { throw fail("Paste between one and eight Tor bridge lines, or choose Plain Tor with the bridge field empty.") }
    }
    var result = body
    var router = false, ordinary = false, throughEntry = false
    if update {
        guard let version = capabilities["profile_update_source_preconditions"] as? NSNumber,
              CFGetTypeID(version) == CFBooleanGetTypeID(), version.boolValue else { throw fail("Update the local controller before editing this captured Tor node.") }
        guard let profile = torBridgeUpdateProfile(opened), let id = profile["id"] as? String else { throw fail("Open Tor bridges with the Tor node you want to update selected.") }
        let capture = try externalCapturedBody(["profile_id": id], opened: opened, current: current)
        result["id"] = id; result["expected_selected_node_id"] = capture["expected_selected_node_id"]
        result["expected_profile_tokens"] = capture["expected_profile_tokens"]
        router = torBridgeHasRouterPath(opened, profile: profile)
        ordinary = torBridgeHasOrdinaryPath(opened, profile: profile, body: body)
        throughEntry = profile["multihop_enabled"] as? Bool == true
        let execution = profile["multihop_execution"] as? String ?? ""
        guard ["", "local", "server"].contains(execution), execution != "server" || router else {
            throw fail("Tor bridge updates require Local execution or explicit Server execution through a saved Router entry. Compare both requires separate measured candidate paths.")
        }
    }
    let rows = (capabilities["transports"] as? [[String: Any]] ?? []).filter { $0["id"] as? String == body["transport"] as? String }
    guard rows.count == 1 else { throw fail("Refresh Tor transport support before saving.") }
    let fixed = ["obfs4", "custom"].contains(transport) && (1...8).contains(bridges.count) && bridges.allSatisfy {
        let words = $0.split(whereSeparator: { $0.isWhitespace }).map { $0.lowercased() }
        return (words.first == "bridge" ? words.dropFirst().first : words.first) == "obfs4"
    }
    let direct = rows[0]["strict_kill_switch"] as? Bool == true && fixed && !throughEntry
    router = router && rows[0]["strict_router_entry_kill_switch"] as? Bool == true
    ordinary = ordinary && rows[0]["strict_external_entry_kill_switch"] as? Bool == true
    guard body["kill_switch_policy"] as? String == "off" || direct || router || ordinary else {
        throw fail("Strict protection requires a saved eligible entry. Ordinary entries use Local execution; Snowflake also needs bounded native UDP. Server requires a paired Router. For a new Direct dynamic node, choose Kill switch Off, then configure its entry in Settings.")
    }
    return result
}

private final class RouterVPNTorBridgeBuilder: NSWindowController {
    private weak var productOwner: ProductWindowController?
    private let api: ProductAPI
    private let opened: [String: Any]
    private let updateSelected = NSButton(checkboxWithTitle: "Update the Tor node selected when this dialog opened", target: nil, action: nil)
    private let nameField = NSTextField(string: "")
    private let transportPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let killSwitchPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let bridgeText = NSTextView()
    private let capabilityText = NSTextField(wrappingLabelWithString: "Checking Tor transport support…")
    private let status = NSTextField(wrappingLabelWithString: "")
    private var capabilities: [String: [String: Any]] = [:]
    private var capabilityRoot: [String: Any] = [:]
    private let transportIDs = ["obfs4", "meek_lite", "snowflake", "webtunnel", "custom", "tor"]

    init(owner: ProductWindowController, api: ProductAPI) {
        productOwner = owner
        self.api = api
        let selection: [String: Any] = ["selected_id": owner.selectedNodeID() ?? "", "profiles": owner.profiles]
        if let bytes = try? JSONSerialization.data(withJSONObject: selection), let copy = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any] { opened = copy }
        else { opened = [:] }
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 720, height: 640), styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        panel.title = "Tor censorship circumvention"
        panel.minSize = NSSize(width: 600, height: 520)
        panel.isReleasedWhenClosed = false
        super.init(window: panel)
        build()
        refreshCapabilities()
    }

    required init?(coder: NSCoder) { nil }

    private func build() {
        guard let content = window?.contentView else { return }
        let root = NSStackView(); root.orientation = .vertical; root.spacing = 10; root.edgeInsets = NSEdgeInsets(top: 18, left: 18, bottom: 18, right: 18); root.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(root)
        NSLayoutConstraint.activate([root.leadingAnchor.constraint(equalTo: content.leadingAnchor), root.trailingAnchor.constraint(equalTo: content.trailingAnchor), root.topAnchor.constraint(equalTo: content.topAnchor), root.bottomAnchor.constraint(equalTo: content.bottomAnchor)])

        let title = NSTextField(labelWithString: "Tor and bridges")
        title.font = .systemFont(ofSize: 24, weight: .bold)
        root.addArrangedSubview(title)
        let intro = NSTextField(wrappingLabelWithString: "Plain Tor connects without bridge lines. For censorship circumvention, obfs4 disguises bridge traffic and resists active probing; meek uses HTTPS/CDN-style fronts; Snowflake uses brokers plus short-lived volunteer WebRTC proxies; WebTunnel resembles normal HTTPS web traffic. Auto / Custom accepts validated Tor-issued lines from any supported family.")
        intro.textColor = .secondaryLabelColor
        root.addArrangedSubview(intro)

        updateSelected.isEnabled = torBridgeUpdateProfile(opened) != nil
        if let profile = torBridgeUpdateProfile(opened) { updateSelected.title = "Update \(profile["name"] as? String ?? "selected Tor node") (choose Plain Tor or replacement bridge lines)" }
        updateSelected.target = self; updateSelected.action = #selector(updateSelectionChanged)
        root.addArrangedSubview(updateSelected)

        nameField.placeholderString = "Node name (optional)"
        root.addArrangedSubview(nameField)
        transportPopup.addItems(withTitles: ["obfs4", "meek", "Snowflake", "WebTunnel", "Auto / Custom", "Plain Tor — no bridges"])
        transportPopup.target = self; transportPopup.action = #selector(transportChanged)
        killSwitchPopup.addItems(withTitles: ["Kill switch Off", "On connect", "Always / strict"])
        killSwitchPopup.target = self; killSwitchPopup.action = #selector(transportChanged)
        let grid = NSGridView(views: [[NSTextField(labelWithString: "Transport"), transportPopup], [NSTextField(labelWithString: "Kill switch"), killSwitchPopup]])
        grid.rowSpacing = 6; grid.columnSpacing = 10
        root.addArrangedSubview(grid)

        let bridgeLabel = NSTextField(labelWithString: "Tor bridge lines — leave empty for Plain Tor")
        bridgeLabel.font = .systemFont(ofSize: 14, weight: .semibold)
        root.addArrangedSubview(bridgeLabel)
        bridgeText.isEditable = true; bridgeText.isSelectable = true; bridgeText.font = .monospacedSystemFont(ofSize: 12, weight: .regular); bridgeText.textContainerInset = NSSize(width: 8, height: 8)
        let scroll = NSScrollView(); scroll.hasVerticalScroller = true; scroll.autohidesScrollers = true; scroll.borderType = .bezelBorder; scroll.documentView = bridgeText; scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 190).isActive = true
        root.addArrangedSubview(scroll)
        let hint = NSTextField(wrappingLabelWithString: "Paste current bridge lines from Tor or your trusted bridge source. Before connecting a new Tor node, choose Custom TCP, DoT, DoH or Rescue in DNS. Updating a saved node keeps its DNS choice.")
        hint.textColor = .secondaryLabelColor
        root.addArrangedSubview(hint)
        capabilityText.textColor = .secondaryLabelColor
        root.addArrangedSubview(capabilityText)
        status.textColor = .secondaryLabelColor
        root.addArrangedSubview(status)

        let buttons = NSStackView(); buttons.orientation = .horizontal; buttons.spacing = 8
        let save = NSButton(title: "Save Tor node", target: self, action: #selector(save)); save.bezelStyle = .rounded; save.keyEquivalent = "\r"
        let refresh = NSButton(title: "Refresh support", target: self, action: #selector(refreshSupport)); refresh.bezelStyle = .rounded
        let close = NSButton(title: "Close", target: self, action: #selector(closePanel)); close.bezelStyle = .rounded
        buttons.addArrangedSubview(save); buttons.addArrangedSubview(refresh); buttons.addArrangedSubview(NSView()); buttons.addArrangedSubview(close)
        root.addArrangedSubview(buttons)
    }

    private func selectedTransport() -> String { transportIDs[max(0, min(transportPopup.indexOfSelectedItem, transportIDs.count - 1))] }
    private func selectedKillSwitch() -> String {
        let policies = ["off", "on-connect", "always"]
        return policies.indices.contains(killSwitchPopup.indexOfSelectedItem) ? policies[killSwitchPopup.indexOfSelectedItem] : ""
    }

    private func refreshCapabilities() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            do {
                guard let root = try self.api.json("/api/tor-bridge/capabilities", timeout: 8) as? [String: Any], let rows = root["transports"] as? [[String: Any]] else { throw NSError(domain: "RouterVPNMac", code: 41, userInfo: [NSLocalizedDescriptionKey: "Tor capability response is invalid"]) }
                var mapped: [String: [String: Any]] = [:]
                for row in rows { if let id = row["id"] as? String { mapped[id] = row } }
                DispatchQueue.main.async { self.capabilities = mapped; self.capabilityRoot = root; self.renderCapability() }
            } catch {
                DispatchQueue.main.async { self.capabilityText.stringValue = "Tor support check failed: \(error.localizedDescription)" }
            }
        }
    }

    private func renderCapability() {
        let id = selectedTransport()
        guard let row = capabilities[id] else { capabilityText.stringValue = "Support details unavailable for \(id)."; return }
        let supported = row["supported"] as? Bool ?? false
        let strict = row["strict_kill_switch"] as? Bool ?? false
        let routerStrict = row["strict_router_entry_kill_switch"] as? Bool ?? false
        let ordinaryStrict = row["strict_external_entry_kill_switch"] as? Bool ?? false
        let description = row["description"] as? String ?? ""
        let reason = row["reason"] as? String ?? ""
        let protection = strict ? "Direct with 1–8 literal obfs4 bridges" : (ordinaryStrict ? "with an eligible Local entry; Server requires a paired Router" : (routerStrict ? "with a saved Router entry using Local or Server execution" : "unavailable for this transport"))
        capabilityText.stringValue = "\(supported ? "Available" : "Unavailable") • Strict protection \(protection)\n\(description)\(reason.isEmpty ? "" : "\nReason: \(reason)")"
        if !strict && killSwitchPopup.indexOfSelectedItem != 0 { status.stringValue = "Strict protection requires a saved eligible entry. Ordinary entries use Local; Server requires a paired Router. The complete captured path is checked when you save." }
        else { status.stringValue = "" }
    }

    @objc private func transportChanged() { renderCapability() }
    @objc private func updateSelectionChanged() {
        if updateSelected.state == .on {
            let profile = torBridgeUpdateProfile(opened)
            let policy = profile?["kill_switch_policy"] as? String ?? ""
            killSwitchPopup.selectItem(at: ["off", "on-connect", "always"].firstIndex(of: policy) ?? -1)
            if let name = profile?["name"] as? String { nameField.stringValue = name }
            if (profile?["external"] as? [String: Any])?["protocol"] as? String == "tor",
               let index = transportIDs.firstIndex(of: "tor") { transportPopup.selectItem(at: index) }
        } else { killSwitchPopup.selectItem(at: 0) }
        renderCapability()
        if selectedKillSwitch().isEmpty { status.stringValue = "The saved kill-switch policy is unavailable. Choose a policy explicitly before saving." }
    }
    @objc private func refreshSupport() { refreshCapabilities() }
    @objc private func closePanel() { close() }

    @objc private func save() {
        guard productOwner?.ensureMutationIdle("saving a Tor bridge node") == true else { status.stringValue = "Disconnect before adding or updating Tor bridge nodes."; return }
        let lines = bridgeText.string.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
        let transport = selectedTransport(), kill = selectedKillSwitch()
        if let row = capabilities[transport], (row["supported"] as? Bool) == false {
            status.stringValue = "This Mac cannot run \(transport) yet: \(row["reason"] as? String ?? "required Tor helper is missing")"
            return
        }
        let body: [String: Any]
        let updating = updateSelected.state == .on
        do { body = try torBridgeImportBody(["name": nameField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines), "transport": transport, "bridges": lines, "kill_switch_policy": kill], opened: opened, update: updating, capabilities: capabilityRoot) }
        catch { status.stringValue = error.localizedDescription; return }
        status.stringValue = "Validating and saving Tor node…"
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            do {
                guard let owner = self.productOwner else { throw NSError(domain: "RouterVPN.TorEdit", code: 3) }
                try owner.requireMutationIdle("saving a Tor bridge node")
                if updating {
                    guard let current = try self.api.json("/api/nodes", timeout: 5) as? [String: Any] else { throw NSError(domain: "RouterVPN.TorEdit", code: 2) }
                    try externalValidateCapturedBody(body, current: current)
                }
                let data = try self.api.request("/api/tor-bridge/import", method: "POST", body: body, timeout: 20)
                let message = String(data: data, encoding: .utf8) ?? "Tor node saved"
                DispatchQueue.main.async { self.status.stringValue = message; self.productOwner?.refreshAll() }
            } catch {
                DispatchQueue.main.async { self.status.stringValue = "Tor node rejected: \(error.localizedDescription)" }
            }
        }
    }
}

'''
    text = text.replace(extension_anchor, tor_class + extension_anchor, 1)

method_marker = "@objc func openTorBridgeBuilder()"
if method_marker not in text:
    method_anchor = "    @objc func openUnifiedNodes() {"
    if text.count(method_anchor) != 1:
        raise SystemExit("macOS openUnifiedNodes anchor drifted")
    method = '''    @objc func openTorBridgeBuilder() {\n        guard ensureMutationIdle("opening Tor bridge controls") else { return }\n        let builder = RouterVPNTorBridgeBuilder(owner: self, api: api)\n        retainUnifiedController(builder)\n        builder.showWindow(nil)\n        builder.window?.center()\n        builder.window?.makeKeyAndOrderFront(nil)\n        NSApp.activate(ignoringOtherApps: true)\n    }\n\n'''
    text = text.replace(method_anchor, method + method_anchor, 1)

required = (
    'button("Tor bridges…", #selector(openTorBridgeBuilder))',
    'Tor censorship circumvention',
    '/api/tor-bridge/capabilities',
    '/api/tor-bridge/import',
    '"obfs4", "meek_lite", "snowflake", "webtunnel", "custom", "tor"',
    'Snowflake uses brokers plus short-lived volunteer WebRTC proxies',
    'choose Custom TCP, DoT, DoH or Rescue in DNS',
    'Strict protection requires a saved eligible entry.',
)
for marker in required:
    if marker not in text:
        raise SystemExit(f"macOS Tor UI marker missing after transform: {marker}")

out.write_text(text, encoding="utf-8")
