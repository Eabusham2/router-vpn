import AppKit
import Foundation
import MapKit

private let unifiedSelectedModeKey = "routervpn.unified.selected-mode.v1"
private let unifiedCustomPresetsKey = "routervpn.unified.custom-presets.v1"
private let unifiedMultihopEnabledKey = "routervpn.unified.multihop-enabled.v1"

private struct MacCustomPreset: Codable, Equatable {
    var name: String
    var layers: [String]
}

private enum UnifiedHopRole {
    case selected
    case entry
    case exit
    case external
    case normal
}

private final class RouterVPNCustomPresetBuilder: NSWindowController {
    private weak var owner: ProductWindowController?
    private let api: ProductAPI
    private let nameField = NSTextField(string: "")
    private let presetPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let layersStack = NSStackView()
    private let status = NSTextField(wrappingLabelWithString: "")
    private var layerButtons: [NSButton] = []
    private var presets: [MacCustomPreset] = []

    init(owner: ProductWindowController, api: ProductAPI) {
        self.owner = owner
        self.api = api
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 640, height: 620), styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        panel.title = "CUSTOM preset builder"
        panel.minSize = NSSize(width: 520, height: 470)
        super.init(window: panel)
        build()
        reloadPresets()
        loadLayers()
    }

    required init?(coder: NSCoder) { nil }

    private func build() {
        guard let content = window?.contentView else { return }
        let root = NSStackView()
        root.orientation = .vertical
        root.spacing = 12
        root.edgeInsets = NSEdgeInsets(top: 18, left: 18, bottom: 18, right: 18)
        root.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(root)
        NSLayoutConstraint.activate([
            root.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            root.trailingAnchor.constraint(equalTo: content.trailingAnchor),
            root.topAnchor.constraint(equalTo: content.topAnchor),
            root.bottomAnchor.constraint(equalTo: content.bottomAnchor)
        ])

        let title = NSTextField(labelWithString: "Build a validated CUSTOM mode")
        title.font = .systemFont(ofSize: 24, weight: .bold)
        root.addArrangedSubview(title)
        let note = NSTextField(wrappingLabelWithString: "Choose exact required layers. Router VPN will only try runnable stacks containing every selected layer, prefers fewer extra layers/less overhead, and fails closed when no compatible stack passes selected-node proof.")
        note.textColor = .secondaryLabelColor
        root.addArrangedSubview(note)

        let presetRow = NSStackView(); presetRow.orientation = .horizontal; presetRow.spacing = 8
        presetPopup.target = self; presetPopup.action = #selector(presetChanged)
        presetRow.addArrangedSubview(NSTextField(labelWithString: "Preset")); presetRow.addArrangedSubview(presetPopup)
        let newButton = NSButton(title: "New", target: self, action: #selector(newPreset)); newButton.bezelStyle = .rounded
        let deleteButton = NSButton(title: "Delete", target: self, action: #selector(deletePreset)); deleteButton.bezelStyle = .rounded
        presetRow.addArrangedSubview(newButton); presetRow.addArrangedSubview(deleteButton)
        root.addArrangedSubview(presetRow)

        nameField.placeholderString = "Preset name"
        root.addArrangedSubview(nameField)
        let layerTitle = NSTextField(labelWithString: "Required layers")
        layerTitle.font = .systemFont(ofSize: 15, weight: .semibold)
        root.addArrangedSubview(layerTitle)

        layersStack.orientation = .vertical
        layersStack.spacing = 4
        let layerScroll = NSScrollView(); layerScroll.hasVerticalScroller = true; layerScroll.autohidesScrollers = true
        layerScroll.documentView = layersStack
        layerScroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 260).isActive = true
        root.addArrangedSubview(layerScroll)

        status.textColor = .secondaryLabelColor
        root.addArrangedSubview(status)

        let buttons = NSStackView(); buttons.orientation = .horizontal; buttons.spacing = 8
        let save = NSButton(title: "Save preset", target: self, action: #selector(savePreset)); save.bezelStyle = .rounded
        let connect = NSButton(title: "Save & Connect", target: self, action: #selector(saveAndConnect)); connect.bezelStyle = .rounded; connect.keyEquivalent = "\r"
        let close = NSButton(title: "Close", target: self, action: #selector(closeBuilder)); close.bezelStyle = .rounded
        buttons.addArrangedSubview(save); buttons.addArrangedSubview(connect); buttons.addArrangedSubview(NSView()); buttons.addArrangedSubview(close)
        root.addArrangedSubview(buttons)
    }

    private func loadLayers() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            var values = Set<String>()
            if let modes = try? self.api.json("/api/logical-modes", timeout: 8) as? [[String: Any]] {
                for mode in modes {
                    guard let variants = mode["variants"] as? [String: Any] else { continue }
                    for value in variants.values {
                        guard let variant = value as? [String: Any], let raw = variant["mode"] as? [String: Any], let layers = raw["layers"] as? [String] else { continue }
                        values.formUnion(layers.filter { !$0.isEmpty })
                    }
                }
            }
            if values.isEmpty {
                values = ["wireguard", "amneziawg2", "rosenpass-pq", "light-obfuscation", "strong-obfuscation", "shadowsocks2022", "vless", "vless-pq", "reality", "xtls-vision", "utls-chrome", "hysteria2", "quic", "salamander", "v2ray-plugin", "websocket", "tls", "https", "http2", "http3", "naive", "xhttp", "finalmask", "protocol-split"]
            }
            let sorted = values.sorted()
            DispatchQueue.main.async { self.renderLayers(sorted); self.applyCurrentPreset() }
        }
    }

    private func renderLayers(_ values: [String]) {
        layersStack.arrangedSubviews.forEach { layersStack.removeArrangedSubview($0); $0.removeFromSuperview() }
        layerButtons.removeAll()
        for value in values {
            let b = NSButton(checkboxWithTitle: value, target: nil, action: nil)
            b.toolTip = "Require \(value) in the validated CUSTOM runtime"
            layerButtons.append(b)
            layersStack.addArrangedSubview(b)
        }
    }

    private func reloadPresets(select name: String? = nil) {
        presets = ProductWindowController.loadUnifiedCustomPresets()
        presetPopup.removeAllItems()
        presetPopup.addItem(withTitle: "New preset")
        for p in presets { presetPopup.addItem(withTitle: p.name) }
        if let name, let i = presets.firstIndex(where: { $0.name == name }) { presetPopup.selectItem(at: i + 1) }
        else { presetPopup.selectItem(at: 0) }
        applyCurrentPreset()
    }

    private func selectedLayers() -> [String] {
        layerButtons.filter { $0.state == .on }.map { $0.title }.sorted()
    }

    private func applyCurrentPreset() {
        guard presetPopup.indexOfSelectedItem > 0, presetPopup.indexOfSelectedItem - 1 < presets.count else {
            nameField.stringValue = ""
            layerButtons.forEach { $0.state = .off }
            status.stringValue = "Create a reusable preset or connect the current layer selection."
            return
        }
        let p = presets[presetPopup.indexOfSelectedItem - 1]
        nameField.stringValue = p.name
        let selected = Set(p.layers)
        layerButtons.forEach { $0.state = selected.contains($0.title) ? .on : .off }
        status.stringValue = "\(p.layers.count) exact layer requirement\(p.layers.count == 1 ? "" : "s") saved."
    }

    @objc private func presetChanged() { applyCurrentPreset() }
    @objc private func newPreset() { presetPopup.selectItem(at: 0); applyCurrentPreset() }

    @objc private func deletePreset() {
        guard presetPopup.indexOfSelectedItem > 0, presetPopup.indexOfSelectedItem - 1 < presets.count else { return }
        let target = presets[presetPopup.indexOfSelectedItem - 1]
        let alert = NSAlert(); alert.alertStyle = .warning; alert.messageText = "Delete CUSTOM preset \(target.name)?"; alert.addButton(withTitle: "Delete"); alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        presets.removeAll { $0.name == target.name }
        ProductWindowController.saveUnifiedCustomPresets(presets)
        owner?.refreshUnifiedModeMenu(preferred: "custom:new")
        reloadPresets()
    }

    private func persist() -> MacCustomPreset? {
        let name = nameField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        let layers = selectedLayers()
        guard !name.isEmpty else { status.stringValue = "Give this preset a name."; return nil }
        guard !layers.isEmpty else { status.stringValue = "Choose at least one required layer."; return nil }
        guard name.count <= 64 else { status.stringValue = "Preset names are limited to 64 characters."; return nil }
        let p = MacCustomPreset(name: name, layers: layers)
        presets.removeAll { $0.name.caseInsensitiveCompare(name) == .orderedSame }
        presets.append(p)
        presets.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        ProductWindowController.saveUnifiedCustomPresets(presets)
        owner?.refreshUnifiedModeMenu(preferred: "custom:\(name)")
        reloadPresets(select: name)
        status.stringValue = "Saved \(name) • \(layers.joined(separator: " • "))"
        return p
    }

    @objc private func savePreset() { _ = persist() }
    @objc private func saveAndConnect() {
        guard let preset = persist() else { return }
        owner?.connectUnifiedCustomPreset(preset.name, layers: preset.layers)
        close()
    }
    @objc private func closeBuilder() { close() }
}

extension ProductWindowController {
    static func loadUnifiedCustomPresets() -> [MacCustomPreset] {
        guard let data = UserDefaults.standard.data(forKey: unifiedCustomPresetsKey), let value = try? JSONDecoder().decode([MacCustomPreset].self, from: data) else { return [] }
        return value
    }

    static func saveUnifiedCustomPresets(_ value: [MacCustomPreset]) {
        if let data = try? JSONEncoder().encode(value) { UserDefaults.standard.set(data, forKey: unifiedCustomPresetsKey) }
    }

    func buildUnifiedUI() {
        guard let content = window?.contentView else { return }
        content.subviews.forEach { $0.removeFromSuperview() }
        window?.title = "Router VPN"
        window?.minSize = NSSize(width: 720, height: 560)
        window?.backgroundColor = .windowBackgroundColor

        let root = NSView(); root.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(root)
        NSLayoutConstraint.activate([
            root.leadingAnchor.constraint(equalTo: content.leadingAnchor), root.trailingAnchor.constraint(equalTo: content.trailingAnchor),
            root.topAnchor.constraint(equalTo: content.topAnchor), root.bottomAnchor.constraint(equalTo: content.bottomAnchor)
        ])

        map.delegate = self
        map.showsCompass = true
        map.showsScale = true
        map.pointOfInterestFilter = .excludingAll
        map.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(map)
        NSLayoutConstraint.activate([
            map.leadingAnchor.constraint(equalTo: root.leadingAnchor), map.trailingAnchor.constraint(equalTo: root.trailingAnchor),
            map.topAnchor.constraint(equalTo: root.topAnchor), map.bottomAnchor.constraint(equalTo: root.bottomAnchor)
        ])

        let nodeCard = NSVisualEffectView(); nodeCard.material = .hudWindow; nodeCard.blendingMode = .withinWindow; nodeCard.state = .active; nodeCard.wantsLayer = true; nodeCard.layer?.cornerRadius = 14; nodeCard.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(nodeCard)
        let nodeRow = NSStackView(); nodeRow.orientation = .horizontal; nodeRow.spacing = 8; nodeRow.edgeInsets = NSEdgeInsets(top: 9, left: 10, bottom: 9, right: 10); nodeRow.translatesAutoresizingMaskIntoConstraints = false
        nodeCard.addSubview(nodeRow)
        nodeRow.addArrangedSubview(routerPopup)
        let manageNode = NSButton(title: "Nodes", target: self, action: #selector(openUnifiedNodes)); manageNode.bezelStyle = .rounded; nodeRow.addArrangedSubview(manageNode)
        routerPopup.target = self; routerPopup.action = #selector(unifiedRouterChanged)
        NSLayoutConstraint.activate([nodeRow.leadingAnchor.constraint(equalTo: nodeCard.leadingAnchor), nodeRow.trailingAnchor.constraint(equalTo: nodeCard.trailingAnchor), nodeRow.topAnchor.constraint(equalTo: nodeCard.topAnchor), nodeRow.bottomAnchor.constraint(equalTo: nodeCard.bottomAnchor), nodeCard.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 16), nodeCard.topAnchor.constraint(equalTo: root.topAnchor, constant: 16), nodeCard.widthAnchor.constraint(lessThanOrEqualToConstant: 430)])

        let statusCard = NSVisualEffectView(); statusCard.material = .hudWindow; statusCard.blendingMode = .withinWindow; statusCard.state = .active; statusCard.wantsLayer = true; statusCard.layer?.cornerRadius = 14; statusCard.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(statusCard)
        let statusStack = NSStackView(); statusStack.orientation = .vertical; statusStack.spacing = 2; statusStack.edgeInsets = NSEdgeInsets(top: 8, left: 10, bottom: 8, right: 10); statusStack.translatesAutoresizingMaskIntoConstraints = false
        statusLabel.font = .systemFont(ofSize: 13, weight: .semibold); detailLabel.font = .systemFont(ofSize: 11); detailLabel.textColor = .secondaryLabelColor; detailLabel.maximumNumberOfLines = 2
        statusStack.addArrangedSubview(statusLabel); statusStack.addArrangedSubview(detailLabel); statusCard.addSubview(statusStack)
        NSLayoutConstraint.activate([statusStack.leadingAnchor.constraint(equalTo: statusCard.leadingAnchor), statusStack.trailingAnchor.constraint(equalTo: statusCard.trailingAnchor), statusStack.topAnchor.constraint(equalTo: statusCard.topAnchor), statusStack.bottomAnchor.constraint(equalTo: statusCard.bottomAnchor), statusCard.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -16), statusCard.topAnchor.constraint(equalTo: root.topAnchor, constant: 16), statusCard.widthAnchor.constraint(lessThanOrEqualToConstant: 390)])

        let sheet = NSVisualEffectView(); sheet.identifier = NSUserInterfaceItemIdentifier("unified-sheet"); sheet.material = .sidebar; sheet.blendingMode = .withinWindow; sheet.state = .active; sheet.wantsLayer = true; sheet.layer?.cornerRadius = 22; sheet.layer?.maskedCorners = [.layerMinXMaxYCorner, .layerMaxXMaxYCorner]; sheet.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(sheet)
        NSLayoutConstraint.activate([sheet.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 12), sheet.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -12), sheet.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -12), sheet.heightAnchor.constraint(greaterThanOrEqualToConstant: 285), sheet.heightAnchor.constraint(lessThanOrEqualToConstant: 390)])

        let scroll = NSScrollView(); scroll.hasVerticalScroller = true; scroll.autohidesScrollers = true; scroll.drawsBackground = false; scroll.translatesAutoresizingMaskIntoConstraints = false
        sheet.addSubview(scroll)
        NSLayoutConstraint.activate([scroll.leadingAnchor.constraint(equalTo: sheet.leadingAnchor), scroll.trailingAnchor.constraint(equalTo: sheet.trailingAnchor), scroll.topAnchor.constraint(equalTo: sheet.topAnchor), scroll.bottomAnchor.constraint(equalTo: sheet.bottomAnchor)])
        let controls = NSStackView(); controls.orientation = .vertical; controls.spacing = 9; controls.edgeInsets = NSEdgeInsets(top: 8, left: 18, bottom: 16, right: 18); controls.alignment = .leading
        scroll.documentView = controls
        controls.widthAnchor.constraint(equalTo: scroll.contentView.widthAnchor).isActive = true

        let handle = NSBox(); handle.boxType = .custom; handle.fillColor = .separatorColor; handle.borderWidth = 0; handle.wantsLayer = true; handle.layer?.cornerRadius = 2; handle.translatesAutoresizingMaskIntoConstraints = false; handle.widthAnchor.constraint(equalToConstant: 44).isActive = true; handle.heightAnchor.constraint(equalToConstant: 4).isActive = true
        let handleWrap = NSStackView(); handleWrap.orientation = .horizontal; handleWrap.addArrangedSubview(NSView()); handleWrap.addArrangedSubview(handle); handleWrap.addArrangedSubview(NSView()); controls.addArrangedSubview(handleWrap)

        let connectRow = NSStackView(); connectRow.orientation = .horizontal; connectRow.spacing = 9
        let connect = NSButton(title: "Connect", target: self, action: #selector(connectUnified)); connect.identifier = NSUserInterfaceItemIdentifier("unified-connect"); connect.bezelStyle = .rounded; connect.controlSize = .large; connect.keyEquivalent = "\r"; connect.contentTintColor = .controlAccentColor; connect.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let kill = NSButton(checkboxWithTitle: "Kill switch", target: self, action: #selector(toggleUnifiedKillSwitch)); kill.identifier = NSUserInterfaceItemIdentifier("unified-kill-switch")
        connectRow.addArrangedSubview(connect); connectRow.addArrangedSubview(kill); controls.addArrangedSubview(connectRow)
        connect.widthAnchor.constraint(greaterThanOrEqualToConstant: 260).isActive = true

        let multi = NSStackView(); multi.orientation = .horizontal; multi.spacing = 7
        let multiToggle = NSButton(checkboxWithTitle: "Multihop", target: self, action: #selector(unifiedMultihopChanged)); multiToggle.identifier = NSUserInterfaceItemIdentifier("unified-multihop-toggle"); multiToggle.state = UserDefaults.standard.bool(forKey: unifiedMultihopEnabledKey) ? .on : .off
        multi.addArrangedSubview(multiToggle)
        multi.addArrangedSubview(multihopEntryPopup); multi.addArrangedSubview(NSTextField(labelWithString: "→")); multi.addArrangedSubview(multihopExitPopup)
        let editHops = NSButton(title: "Edit hops", target: self, action: #selector(openUnifiedMultihop)); editHops.bezelStyle = .rounded; multi.addArrangedSubview(editHops)
        controls.addArrangedSubview(multi)

        let settingsRow = unifiedLabeledRow(title: "Settings", symbol: "slider.horizontal.3")
        let settingsButton = NSButton(title: "Open settings", target: self, action: #selector(openUnifiedSettings)); settingsButton.bezelStyle = .rounded; settingsRow.addArrangedSubview(settingsButton)
        let mtu = NSButton(title: "Retest MTU", target: self, action: #selector(retestMTU)); mtu.bezelStyle = .rounded; settingsRow.addArrangedSubview(mtu)
        controls.addArrangedSubview(settingsRow)

        let modeRow = unifiedLabeledRow(title: "Mode", symbol: "wand.and.stars")
        modePopup.target = self; modePopup.action = #selector(unifiedModeChanged); modeRow.addArrangedSubview(modePopup)
        let modeDetails = NSButton(title: "Presets", target: self, action: #selector(openUnifiedModes)); modeDetails.bezelStyle = .rounded; modeRow.addArrangedSubview(modeDetails)
        controls.addArrangedSubview(modeRow)

        if dnsModePopup.numberOfItems == 0 { dnsModePopup.addItems(withTitles: ["Home AdGuard", "Fastest measured", "Custom", "DoT", "DoH", "DoH3", "Rescue"]) }
        let dnsRow = unifiedLabeledRow(title: "DNS", symbol: "network")
        dnsModePopup.target = self; dnsModePopup.action = #selector(unifiedDNSChanged); dnsRow.addArrangedSubview(dnsModePopup)
        let dnsDetails = NSButton(title: "DNS details", target: self, action: #selector(openUnifiedDNS)); dnsDetails.bezelStyle = .rounded; dnsRow.addArrangedSubview(dnsDetails)
        controls.addArrangedSubview(dnsRow)

        errorLabel.textColor = .systemRed; errorLabel.font = .systemFont(ofSize: 11); errorLabel.maximumNumberOfLines = 2
        controls.addArrangedSubview(errorLabel)

        Timer.scheduledTimer(withTimeInterval: 1.5, repeats: true) { [weak self] _ in self?.refreshUnifiedChrome() }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) { [weak self] in self?.refreshUnifiedModeMenu(); self?.refreshUnifiedChrome() }
    }

    private func unifiedLabeledRow(title: String, symbol: String) -> NSStackView {
        let row = NSStackView(); row.orientation = .horizontal; row.spacing = 8
        let label = NSTextField(labelWithString: title); label.font = .systemFont(ofSize: 13, weight: .semibold); label.alignment = .right; label.widthAnchor.constraint(equalToConstant: 70).isActive = true
        row.addArrangedSubview(label)
        return row
    }

    @objc func unifiedRouterChanged() { selectRouter(); DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in self?.refreshUnifiedChrome() } }

    @objc func unifiedModeChanged() {
        let id = modePopup.selectedItem?.representedObject as? String ?? "smart-auto"
        if id == "custom:new" { openUnifiedCustomBuilder(); return }
        UserDefaults.standard.set(id, forKey: unifiedSelectedModeKey)
    }

    func refreshUnifiedModeMenu(preferred: String? = nil) {
        let wanted = preferred ?? UserDefaults.standard.string(forKey: unifiedSelectedModeKey) ?? "smart-auto"
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            let modes = (try? self.api.json("/api/logical-modes", timeout: 10) as? [[String: Any]]) ?? []
            let presets = Self.loadUnifiedCustomPresets()
            DispatchQueue.main.async {
                self.modePopup.removeAllItems()
                self.addUnifiedModeItem("SMART AUTO — recommended", id: "smart-auto", enabled: true)
                self.addUnifiedModeItem("AUTO — first proven path", id: "auto", enabled: true)
                for mode in modes {
                    let id = mode["id"] as? String ?? ""
                    guard !id.isEmpty else { continue }
                    let name = mode["name"] as? String ?? id
                    let available = mode["available"] as? Bool ?? false
                    let reason = (mode["reason"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
                    self.addUnifiedModeItem(available ? name : "\(name) — unavailable\(reason.isEmpty ? "" : ": \(reason)")", id: id, enabled: available)
                }
                if !presets.isEmpty {
                    self.modePopup.menu?.addItem(.separator())
                    for preset in presets { self.addUnifiedModeItem("CUSTOM • \(preset.name)", id: "custom:\(preset.name)", enabled: true) }
                }
                self.modePopup.menu?.addItem(.separator())
                self.addUnifiedModeItem("New CUSTOM preset…", id: "custom:new", enabled: true)
                if let item = self.modePopup.itemArray.first(where: { ($0.representedObject as? String) == wanted && $0.isEnabled }) { self.modePopup.select(item) }
                else if let smart = self.modePopup.itemArray.first(where: { ($0.representedObject as? String) == "smart-auto" }) { self.modePopup.select(smart); UserDefaults.standard.set("smart-auto", forKey: unifiedSelectedModeKey) }
            }
        }
    }

    private func addUnifiedModeItem(_ title: String, id: String, enabled: Bool) {
        modePopup.addItem(withTitle: title)
        guard let item = modePopup.lastItem else { return }
        item.representedObject = id
        item.isEnabled = enabled
        item.toolTip = enabled ? id : "This preset stays visible so readiness is truthful; open Presets for the full reason."
    }

    @objc func connectUnified() {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            do {
                let status = try self.api.json("/api/status") as? [String: Any] ?? [:]
                let connected = status["connected"] as? Bool ?? false
                let phase = (status["phase"] as? String ?? "").lowercased()
                if connected || phase.contains("trying") || phase == "starting" || phase == "checking" || phase.contains("proving") {
                    _ = try self.api.request("/api/disconnect", method: "POST", body: [:], timeout: 25)
                    DispatchQueue.main.async { self.appendHelp("Disconnected."); self.refreshAll(); self.refreshUnifiedChrome() }
                    return
                }
                DispatchQueue.main.async { self.startUnifiedSelectedMode() }
            } catch {
                DispatchQueue.main.async { self.errorLabel.stringValue = error.localizedDescription }
            }
        }
    }

    private func startUnifiedSelectedMode() {
        if UserDefaults.standard.bool(forKey: unifiedMultihopEnabledKey) {
            connectMultihop()
            return
        }
        let selectedNode = routerPopup.indexOfSelectedItem
        if selectedNode >= 0 && selectedNode < profiles.count {
            let profile = profiles[selectedNode]
            if (profile["node_kind"] as? String ?? "router-vpn").lowercased() == "external", let id = profile["id"] as? String {
                asyncAction { String(data: try self.api.request("/api/external-profile/connect", method: "POST", body: ["profile_id": id], timeout: 180), encoding: .utf8) ?? "External exit connected" }
                return
            }
        }
        let id = modePopup.selectedItem?.representedObject as? String ?? "smart-auto"
        UserDefaults.standard.set(id, forKey: unifiedSelectedModeKey)
        switch id {
        case "smart-auto":
            asyncAction { String(data: try self.api.request("/api/strategy/smart-auto", method: "POST", body: [:], timeout: 240), encoding: .utf8) ?? "SMART AUTO connected" }
        case "auto":
            asyncAction { String(data: try self.api.request("/api/strategy/auto", method: "POST", body: [:], timeout: 200), encoding: .utf8) ?? "AUTO connected" }
        case "custom:new":
            openUnifiedCustomBuilder()
        default:
            if id.hasPrefix("custom:") {
                let name = String(id.dropFirst("custom:".count))
                guard let p = Self.loadUnifiedCustomPresets().first(where: { $0.name == name }) else { errorLabel.stringValue = "CUSTOM preset \(name) no longer exists."; refreshUnifiedModeMenu(); return }
                connectUnifiedCustomPreset(p.name, layers: p.layers)
            } else {
                let base = ["auto", "wg", "awg"][max(0, min(basePopup.indexOfSelectedItem, 2))]
                asyncAction { String(data: try self.api.request("/api/connect-logical", method: "POST", body: ["mode": id, "base": base], timeout: 180), encoding: .utf8) ?? "Connected" }
            }
        }
    }

    func connectUnifiedCustomPreset(_ name: String, layers: [String]) {
        guard !layers.isEmpty else { errorLabel.stringValue = "CUSTOM preset \(name) has no required layers."; return }
        UserDefaults.standard.set("custom:\(name)", forKey: unifiedSelectedModeKey)
        asyncAction { String(data: try self.api.request("/api/strategy/custom", method: "POST", body: ["layers": layers], timeout: 240), encoding: .utf8) ?? "CUSTOM \(name) connected" }
    }

    @objc func openUnifiedCustomBuilder() {
        let builder = RouterVPNCustomPresetBuilder(owner: self, api: api)
        builder.showWindow(nil); builder.window?.center(); builder.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        objc_setAssociatedObject(self, Unmanaged.passUnretained(self).toOpaque(), builder, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)
    }

    @objc func openUnifiedNodes() { presentUnifiedDetail(title: "Nodes", view: nodesMapView(), width: 900, height: 590) }
    @objc func openUnifiedModes() { refreshModes(); presentUnifiedDetail(title: "Modes & presets", view: scroll(modesText), width: 760, height: 590, customBuilder: true) }
    @objc func openUnifiedDNS() { presentUnifiedDetail(title: "DNS", view: dnsView(), width: 760, height: 620) }
    @objc func openUnifiedMultihop() { refreshAdvanced(); presentUnifiedDetail(title: "Multihop", view: advancedView(), width: 820, height: 560) }
    @objc func openUnifiedSettings() { editProfileSettings() }

    private func presentUnifiedDetail(title: String, view: NSView, width: CGFloat, height: CGFloat, customBuilder: Bool = false) {
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: width, height: height), styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        panel.title = title; panel.minSize = NSSize(width: min(width, 560), height: min(height, 420))
        let root = NSStackView(); root.orientation = .vertical; root.spacing = 8; root.edgeInsets = NSEdgeInsets(top: 10, left: 10, bottom: 10, right: 10)
        if customBuilder { let b = NSButton(title: "New / edit CUSTOM preset…", target: self, action: #selector(openUnifiedCustomBuilder)); b.bezelStyle = .rounded; root.addArrangedSubview(b) }
        root.addArrangedSubview(view); panel.contentView = root; panel.center(); panel.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
    }

    @objc func unifiedMultihopChanged(_ sender: NSButton) {
        UserDefaults.standard.set(sender.state == .on, forKey: unifiedMultihopEnabledKey)
        refreshUnifiedHopOverlay()
    }

    @objc func toggleUnifiedKillSwitch(_ sender: NSButton) {
        let enabled = sender.state == .on
        asyncAction {
            _ = try self.api.request("/api/profile/settings", method: "POST", body: ["kill_switch_policy": enabled ? "on-connect" : "off"], timeout: 12)
            return enabled ? "Kill switch enabled for the selected Router VPN profile." : "Kill switch disabled for the selected Router VPN profile."
        }
    }

    @objc func unifiedDNSChanged() {
        let index = max(0, min(dnsModePopup.indexOfSelectedItem, dnsModeIDs.count - 1))
        let id = dnsModeIDs[index]
        if ["custom", "dot", "doh", "doh3"].contains(id) && dnsHostField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            openUnifiedDNS(); return
        }
        saveDNS()
    }

    func refreshUnifiedChrome() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            let status = (try? self.api.json("/api/status", timeout: 3) as? [String: Any]) ?? [:]
            let settings = (try? self.api.json("/api/profile/settings", timeout: 3) as? [String: Any]) ?? [:]
            DispatchQueue.main.async {
                let connected = status["connected"] as? Bool ?? false
                let phase = (status["phase"] as? String ?? "off")
                if let button = self.findUnifiedView("unified-connect") as? NSButton {
                    let transitioning = !connected && (phase.contains("trying") || phase == "starting" || phase == "checking" || phase.contains("proving"))
                    button.title = connected || transitioning ? "Disconnect" : "Connect"
                }
                if let kill = self.findUnifiedView("unified-kill-switch") as? NSButton {
                    let policy = (settings["kill_switch_policy"] as? String ?? "off").lowercased()
                    kill.state = policy == "off" ? .off : .on
                }
                self.refreshUnifiedHopOverlay()
            }
        }
    }

    private func findUnifiedView(_ id: String) -> NSView? {
        guard let content = window?.contentView else { return nil }
        func walk(_ view: NSView) -> NSView? {
            if view.identifier?.rawValue == id { return view }
            for child in view.subviews { if let found = walk(child) { return found } }
            return nil
        }
        return walk(content)
    }

    private func hopRole(for id: String) -> UnifiedHopRole {
        if UserDefaults.standard.bool(forKey: unifiedMultihopEnabledKey) {
            let ei = multihopEntryPopup.indexOfSelectedItem, xi = multihopExitPopup.indexOfSelectedItem
            if ei >= 0 && ei < multihopNodeIDs.count && multihopNodeIDs[ei] == id { return .entry }
            if xi >= 0 && xi < multihopNodeIDs.count && multihopNodeIDs[xi] == id { return .exit }
        }
        if let selected = routerIDs.indices.contains(routerPopup.indexOfSelectedItem) ? routerIDs[routerPopup.indexOfSelectedItem] : nil, selected == id { return .selected }
        if let profile = profiles.first(where: { ($0["id"] as? String) == id }), (profile["node_kind"] as? String ?? "router-vpn").lowercased() == "external" { return .external }
        return .normal
    }

    private func color(for role: UnifiedHopRole) -> NSColor {
        switch role {
        case .selected: return .systemPurple
        case .entry: return .systemBlue
        case .exit: return .systemOrange
        case .external: return .systemPink
        case .normal: return .systemTeal
        }
    }

    func refreshUnifiedHopOverlay() {
        map.removeOverlays(map.overlays)
        map.annotations.compactMap { $0 as? RouterAnnotation }.forEach { annotation in
            if let view = map.view(for: annotation) as? MKMarkerAnnotationView { view.markerTintColor = color(for: hopRole(for: annotation.routerID)) }
        }
        guard UserDefaults.standard.bool(forKey: unifiedMultihopEnabledKey) else { return }
        let ei = multihopEntryPopup.indexOfSelectedItem, xi = multihopExitPopup.indexOfSelectedItem
        guard ei >= 0, xi >= 0, ei < multihopNodeIDs.count, xi < multihopNodeIDs.count else { return }
        let ids = [multihopNodeIDs[ei], multihopNodeIDs[xi]]
        let coords: [CLLocationCoordinate2D] = ids.compactMap { id in
            guard let p = profiles.first(where: { ($0["id"] as? String) == id }) else { return nil }
            let lat = (p["latitude"] as? NSNumber)?.doubleValue ?? 0, lon = (p["longitude"] as? NSNumber)?.doubleValue ?? 0
            let c = CLLocationCoordinate2D(latitude: lat, longitude: lon)
            return CLLocationCoordinate2DIsValid(c) && !(lat == 0 && lon == 0) ? c : nil
        }
        guard coords.count == ids.count else { return }
        map.addOverlay(MKPolyline(coordinates: coords, count: coords.count))
    }

    public func mapView(_ mapView: MKMapView, viewFor annotation: MKAnnotation) -> MKAnnotationView? {
        guard let node = annotation as? RouterAnnotation else { return nil }
        let id = "RouterNode"
        let view = (mapView.dequeueReusableAnnotationView(withIdentifier: id) as? MKMarkerAnnotationView) ?? MKMarkerAnnotationView(annotation: annotation, reuseIdentifier: id)
        view.annotation = annotation; view.canShowCallout = true; view.markerTintColor = color(for: hopRole(for: node.routerID)); view.glyphImage = NSImage(systemSymbolName: hopRole(for: node.routerID) == .external ? "arrow.up.right.circle.fill" : "network", accessibilityDescription: nil)
        return view
    }

    public func mapView(_ mapView: MKMapView, rendererFor overlay: MKOverlay) -> MKOverlayRenderer {
        guard let line = overlay as? MKPolyline else { return MKOverlayRenderer(overlay: overlay) }
        let renderer = MKPolylineRenderer(polyline: line); renderer.strokeColor = .systemBlue; renderer.lineWidth = 4; renderer.lineCap = .round; renderer.lineJoin = .round; return renderer
    }
}

// Shipping unified UX markers:
// map-first bottom control sheet Connect Disconnect quick kill switch Multihop Settings Mode DNS
// SMART AUTO default AUTO first-class all logical presets unavailable reasons CUSTOM visual preset builder
// Router node Custom external real coordinates color-coded hop overlay DAITA-like traffic padding IPv6 MTU Retest Jumbo forwarding
