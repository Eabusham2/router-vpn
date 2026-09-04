#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import sys

if len(sys.argv) != 3:
    raise SystemExit("usage: macos-tor-bridge-ui-transform.py INPUT.swift OUTPUT.swift")

src, out = map(Path, sys.argv[1:3])
text = src.read_text(encoding="utf-8")

button_anchor = 'row.addArrangedSubview(button("Pair Router node", #selector(pairNode))); row.addArrangedSubview(button("Import / add custom", #selector(importNode))); row.addArrangedSubview(button("Select", #selector(selectNode)));'
button_new = 'row.addArrangedSubview(button("Pair Router node", #selector(pairNode))); row.addArrangedSubview(button("Import / add custom", #selector(importNode))); row.addArrangedSubview(button("Tor bridges…", #selector(openTorBridgeBuilder))); row.addArrangedSubview(button("Select", #selector(selectNode)));'
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
private final class RouterVPNTorBridgeBuilder: NSWindowController {
    private weak var productOwner: ProductWindowController?
    private let api: ProductAPI
    private let nameField = NSTextField(string: "")
    private let transportPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let killSwitchPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let bridgeText = NSTextView()
    private let capabilityText = NSTextField(wrappingLabelWithString: "Checking Tor transport support…")
    private let status = NSTextField(wrappingLabelWithString: "")
    private var capabilities: [String: [String: Any]] = [:]
    private let transportIDs = ["obfs4", "meek_lite", "snowflake", "webtunnel", "custom"]

    init(owner: ProductWindowController, api: ProductAPI) {
        productOwner = owner
        self.api = api
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

        let title = NSTextField(labelWithString: "Tor bridges")
        title.font = .systemFont(ofSize: 24, weight: .bold)
        root.addArrangedSubview(title)
        let intro = NSTextField(wrappingLabelWithString: "Choose how Tor gets through censorship. obfs4 disguises bridge traffic and resists active probing; meek uses HTTPS/CDN-style fronts; Snowflake uses brokers plus short-lived volunteer WebRTC proxies; WebTunnel resembles normal HTTPS web traffic. Auto / Custom accepts validated Tor-issued lines from any supported family. Tor's proved circuit—not a homemade XOR layer—is the encrypted final path.")
        intro.textColor = .secondaryLabelColor
        root.addArrangedSubview(intro)

        nameField.placeholderString = "Node name (optional)"
        root.addArrangedSubview(nameField)
        transportPopup.addItems(withTitles: ["obfs4", "meek", "Snowflake", "WebTunnel", "Auto / Custom"])
        transportPopup.target = self; transportPopup.action = #selector(transportChanged)
        killSwitchPopup.addItems(withTitles: ["Kill switch Off", "On connect", "Always / strict"])
        let grid = NSGridView(views: [[NSTextField(labelWithString: "Transport"), transportPopup], [NSTextField(labelWithString: "Kill switch"), killSwitchPopup]])
        grid.rowSpacing = 6; grid.columnSpacing = 10
        root.addArrangedSubview(grid)

        let bridgeLabel = NSTextField(labelWithString: "Tor bridge lines — one per line")
        bridgeLabel.font = .systemFont(ofSize: 14, weight: .semibold)
        root.addArrangedSubview(bridgeLabel)
        bridgeText.isEditable = true; bridgeText.isSelectable = true; bridgeText.font = .monospacedSystemFont(ofSize: 12, weight: .regular); bridgeText.textContainerInset = NSSize(width: 8, height: 8)
        let scroll = NSScrollView(); scroll.hasVerticalScroller = true; scroll.autohidesScrollers = true; scroll.borderType = .bezelBorder; scroll.documentView = bridgeText; scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 190).isActive = true
        root.addArrangedSubview(scroll)
        let hint = NSTextField(wrappingLabelWithString: "Paste current bridge lines from Tor / your trusted bridge source. Router VPN accepts only obfs4, meek_lite, Snowflake, and WebTunnel syntax; profile data cannot inject ClientTransportPlugin commands, executable paths, or arbitrary torrc directives.")
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
    private func selectedKillSwitch() -> String { ["off", "on-connect", "always"][max(0, min(killSwitchPopup.indexOfSelectedItem, 2))] }

    private func refreshCapabilities() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            do {
                guard let root = try self.api.json("/api/tor-bridge/capabilities", timeout: 8) as? [String: Any], let rows = root["transports"] as? [[String: Any]] else { throw NSError(domain: "RouterVPNMac", code: 41, userInfo: [NSLocalizedDescriptionKey: "Tor capability response is invalid"]) }
                var mapped: [String: [String: Any]] = [:]
                for row in rows { if let id = row["id"] as? String { mapped[id] = row } }
                DispatchQueue.main.async { self.capabilities = mapped; self.renderCapability() }
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
        let description = row["description"] as? String ?? ""
        let reason = row["reason"] as? String ?? ""
        capabilityText.stringValue = "\(supported ? "Available" : "Unavailable") • Strict kill switch \(strict ? "supported for this path" : "not currently safe")\n\(description)\(reason.isEmpty ? "" : "\nReason: \(reason)")"
        if !strict && killSwitchPopup.indexOfSelectedItem != 0 { status.stringValue = "This transport has dynamic CDN/STUN/WebRTC/bootstrap egress. Choose Kill switch Off until Router VPN has process-scoped PT firewall ownership." }
        else { status.stringValue = "" }
    }

    @objc private func transportChanged() { renderCapability() }
    @objc private func refreshSupport() { refreshCapabilities() }
    @objc private func closePanel() { close() }

    @objc private func save() {
        let lines = bridgeText.string.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
        guard !lines.isEmpty else { status.stringValue = "Paste at least one Tor bridge line."; return }
        let transport = selectedTransport(), kill = selectedKillSwitch()
        if let row = capabilities[transport], (row["supported"] as? Bool) == false {
            status.stringValue = "This Mac cannot run \(transport) yet: \(row["reason"] as? String ?? "required Tor helper is missing")"
            return
        }
        if let row = capabilities[transport], (row["strict_kill_switch"] as? Bool) != true, kill != "off" {
            status.stringValue = "Dynamic Tor transports require Kill switch Off until process-scoped PT egress filtering is implemented."
            return
        }
        let body: [String: Any] = ["name": nameField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines), "transport": transport, "bridges": lines, "kill_switch_policy": kill]
        status.stringValue = "Validating and saving Tor node…"
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            do {
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
    method = '''    @objc func openTorBridgeBuilder() {\n        let builder = RouterVPNTorBridgeBuilder(owner: self, api: api)\n        retainUnifiedController(builder)\n        builder.showWindow(nil)\n        builder.window?.center()\n        builder.window?.makeKeyAndOrderFront(nil)\n        NSApp.activate(ignoringOtherApps: true)\n    }\n\n'''
    text = text.replace(method_anchor, method + method_anchor, 1)

required = (
    'button("Tor bridges…", #selector(openTorBridgeBuilder))',
    'Tor censorship circumvention',
    '/api/tor-bridge/capabilities',
    '/api/tor-bridge/import',
    '"obfs4", "meek_lite", "snowflake", "webtunnel", "custom"',
    'Snowflake uses brokers plus short-lived volunteer WebRTC proxies',
    'profile data cannot inject ClientTransportPlugin commands',
    'Dynamic Tor transports require Kill switch Off',
)
for marker in required:
    if marker not in text:
        raise SystemExit(f"macOS Tor UI marker missing after transform: {marker}")

out.write_text(text, encoding="utf-8")
