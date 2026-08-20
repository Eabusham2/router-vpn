import AppKit
import Foundation
import MapKit
import ObjectiveC

private let unifiedSelectedModeKey = "routervpn.unified.selected-mode.v1"
private let unifiedCustomPresetsKey = "routervpn.unified.custom-presets.v1"
private let unifiedMultihopEnabledKey = "routervpn.unified.multihop-enabled.v1"
private var unifiedRetainedControllersKey: UInt8 = 0

fileprivate struct MacCustomPreset: Codable, Equatable {
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
    private weak var productOwner: ProductWindowController?
    private let api: ProductAPI
    private let nameField = NSTextField(string: "")
    private let presetPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let layersStack = NSStackView()
    private let status = NSTextField(wrappingLabelWithString: "")
    private var layerButtons: [NSButton] = []
    private var presets: [MacCustomPreset] = []

    init(owner: ProductWindowController, api: ProductAPI) {
        self.productOwner = owner
        self.api = api
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 640, height: 620), styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        panel.title = "CUSTOM preset builder"
        panel.minSize = NSSize(width: 520, height: 470)
        panel.isReleasedWhenClosed = false
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
            root.leadingAnchor.constraint(equalTo: content.leadingAnchor), root.trailingAnchor.constraint(equalTo: content.trailingAnchor),
            root.topAnchor.constraint(equalTo: content.topAnchor), root.bottomAnchor.constraint(equalTo: content.bottomAnchor)
        ])

        let title = NSTextField(labelWithString: "Build a validated CUSTOM mode")
        title.font = .systemFont(ofSize: 24, weight: .bold)
        root.addArrangedSubview(title)
        let note = NSTextField(wrappingLabelWithString: "Choose exact required layers. Router VPN only tries runnable stacks containing every selected layer, prefers fewer extra layers/less overhead, and fails closed when no compatible stack passes selected-node proof.")
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
        layersStack.translatesAutoresizingMaskIntoConstraints = false
        let document = NSView()
        document.translatesAutoresizingMaskIntoConstraints = false
        document.addSubview(layersStack)
        NSLayoutConstraint.activate([
            layersStack.leadingAnchor.constraint(equalTo: document.leadingAnchor, constant: 8),
            layersStack.trailingAnchor.constraint(equalTo: document.trailingAnchor, constant: -8),
            layersStack.topAnchor.constraint(equalTo: document.topAnchor, constant: 8),
            layersStack.bottomAnchor.constraint(equalTo: document.bottomAnchor, constant: -8)
        ])
        let layerScroll = NSScrollView(); layerScroll.hasVerticalScroller = true; layerScroll.autohidesScrollers = true; layerScroll.drawsBackground = false
        layerScroll.documentView = document
        document.widthAnchor.constraint(equalTo: layerScroll.contentView.widthAnchor).isActive = true
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
        for view in layersStack.arrangedSubviews { layersStack.removeArrangedSubview(view); view.removeFromSuperview() }
        layerButtons.removeAll()
        for value in values {
            let button = NSButton(checkboxWithTitle: value, target: nil, action: nil)
            button.toolTip = "Require \(value) in the validated CUSTOM runtime"
            layerButtons.append(button)
            layersStack.addArrangedSubview(button)
        }
    }

    private func reloadPresets(select name: String? = nil) {
        presets = ProductWindowController.loadUnifiedCustomPresets()
        presetPopup.removeAllItems()
        presetPopup.addItem(withTitle: "New preset")
        for preset in presets { presetPopup.addItem(withTitle: preset.name) }
        if let name, let index = presets.firstIndex(where: { $0.name == name }) { presetPopup.selectItem(at: index + 1) }
        else { presetPopup.selectItem(at: 0) }
        applyCurrentPreset()
    }

    private func selectedLayers() -> [String] { layerButtons.filter { $0.state == .on }.map(\.title).sorted() }

    private func applyCurrentPreset() {
        guard presetPopup.indexOfSelectedItem > 0, presetPopup.indexOfSelectedItem - 1 < presets.count else {
            nameField.stringValue = ""
            layerButtons.forEach { $0.state = .off }
            status.stringValue = "Create a reusable preset or connect the current layer selection."
            return
        }
        let preset = presets[presetPopup.indexOfSelectedItem - 1]
        nameField.stringValue = preset.name
        let selected = Set(preset.layers)
        layerButtons.forEach { $0.state = selected.contains($0.title) ? .on : .off }
        status.stringValue = "\(preset.layers.count) exact layer requirement\(preset.layers.count == 1 ? "" : "s") saved."
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
        productOwner?.refreshUnifiedModeMenu(preferred: "custom:new")
        reloadPresets()
    }

    private func persist() -> MacCustomPreset? {
        let name = nameField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        let layers = selectedLayers()
        guard !name.isEmpty else { status.stringValue = "Give this preset a name."; return nil }
        guard !layers.isEmpty else { status.stringValue = "Choose at least one required layer."; return nil }
        guard name.count <= 64 else { status.stringValue = "Preset names are limited to 64 characters."; return nil }
        let preset = MacCustomPreset(name: name, layers: layers)
        presets.removeAll { $0.name.caseInsensitiveCompare(name) == .orderedSame }
        presets.append(preset)
        presets.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        ProductWindowController.saveUnifiedCustomPresets(presets)
        productOwner?.refreshUnifiedModeMenu(preferred: "custom:\(name)")
        reloadPresets(select: name)
        status.stringValue = "Saved \(name) • \(layers.joined(separator: " • "))"
        return preset
    }

    @objc private func savePreset() { _ = persist() }
    @objc private func saveAndConnect() {
        guard let preset = persist() else { return }
        productOwner?.connectUnifiedCustomPreset(preset.name, layers: preset.layers)
        close()
    }
    @objc private func closeBuilder() { close() }
}

extension ProductWindowController {
    fileprivate static func loadUnifiedCustomPresets() -> [MacCustomPreset] {
        guard let data = UserDefaults.standard.data(forKey: unifiedCustomPresetsKey), let value = try? JSONDecoder().decode([MacCustomPreset].self, from: data) else { return [] }
        return value
    }

    fileprivate static func saveUnifiedCustomPresets(_ value: [MacCustomPreset]) {
        if let data = try? JSONEncoder().encode(value) { UserDefaults.standard.set(data, forKey: unifiedCustomPresetsKey) }
    }

    private func retainUnifiedController(_ controller: NSWindowController) {
        let list: NSMutableArray
        if let existing = objc_getAssociatedObject(self, &unifiedRetainedControllersKey) as? NSMutableArray { list = existing }
        else { list = NSMutableArray(); objc_setAssociatedObject(self, &unifiedRetainedControllersKey, list, .OBJC_ASSOCIATION_RETAIN_NONATOMIC) }
        list.add(controller)
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

        map.delegate = self; map.showsCompass = true; map.showsScale = true; map.pointOfInterestFilter = .excludingAll; map.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(map)
        NSLayoutConstraint.activate([
            map.leadingAnchor.constraint(equalTo: root.leadingAnchor), map.trailingAnchor.constraint(equalTo: root.trailingAnchor),
            map.topAnchor.constraint(equalTo: root.topAnchor), map.bottomAnchor.constraint(equalTo: root.bottomAnchor)
        ])

        let nodeCard = unifiedGlassCard()
        root.addSubview(nodeCard)
        let nodeRow = NSStackView(); nodeRow.orientation = .horizontal; nodeRow.spacing = 8; nodeRow.edgeInsets = NSEdgeInsets(top: 9, left: 10, bottom: 9, right: 10); nodeRow.translatesAutoresizingMaskIntoConstraints = false
        nodeCard.addSubview(nodeRow)
        routerPopup.target = self; routerPopup.action = #selector(unifiedRouterChanged)
        nodeRow.addArrangedSubview(routerPopup)
        let manageNode = NSButton(title: "Nodes", target: self, action: #selector(openUnifiedNodes)); manageNode.bezelStyle = .rounded; nodeRow.addArrangedSubview(manageNode)
        NSLayoutConstraint.activate([
            nodeRow.leadingAnchor.constraint(equalTo: nodeCard.leadingAnchor), nodeRow.trailingAnchor.constraint(equalTo: nodeCard.trailingAnchor), nodeRow.topAnchor.constraint(equalTo: nodeCard.topAnchor), nodeRow.bottomAnchor.constraint(equalTo: nodeCard.bottomAnchor),
            nodeCard.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 16), nodeCard.topAnchor.constraint(equalTo: root.topAnchor, constant: 16), nodeCard.widthAnchor.constraint(lessThanOrEqualToConstant: 450)
        ])

        let statusCard = unifiedGlassCard()
        root.addSubview(statusCard)
        let statusStack = NSStackView(); statusStack.orientation = .vertical; statusStack.spacing = 2; statusStack.edgeInsets = NSEdgeInsets(top: 8, left: 10, bottom: 8, right: 10); statusStack.translatesAutoresizingMaskIntoConstraints = false
        statusLabel.font = .systemFont(ofSize: 13, weight: .semibold); detailLabel.font = .systemFont(ofSize: 11); detailLabel.textColor = .secondaryLabelColor; detailLabel.maximumNumberOfLines = 2
        statusStack.addArrangedSubview(statusLabel); statusStack.addArrangedSubview(detailLabel); statusCard.addSubview(statusStack)
        NSLayoutConstraint.activate([
            statusStack.leadingAnchor.constraint(equalTo: statusCard.leadingAnchor), statusStack.trailingAnchor.constraint(equalTo: statusCard.trailingAnchor), statusStack.topAnchor.constraint(equalTo: statusCard.topAnchor), statusStack.bottomAnchor.constraint(equalTo: statusCard.bottomAnchor),
            statusCard.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -16), statusCard.topAnchor.constraint(equalTo: root.topAnchor, constant: 16), statusCard.widthAnchor.constraint(lessThanOrEqualToConstant: 390)
        ])

        let sheet = NSVisualEffectView(); sheet.identifier = NSUserInterfaceItemIdentifier("unified-sheet"); sheet.material = .sidebar; sheet.blendingMode = .withinWindow; sheet.state = .active; sheet.wantsLayer = true; sheet.layer?.cornerRadius = 22; sheet.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(sheet)
        NSLayoutConstraint.activate([
            sheet.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 12), sheet.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -12), sheet.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -12),
            sheet.heightAnchor.constraint(greaterThanOrEqualToConstant: 285), sheet.heightAnchor.constraint(lessThanOrEqualToConstant: 390)
        ])

        let scroll = NSScrollView(); scroll.hasVerticalScroller = true; scroll.autohidesScrollers = true; scroll.drawsBackground = false; scroll.translatesAutoresizingMaskIntoConstraints = false
        sheet.addSubview(scroll)
        NSLayoutConstraint.activate([scroll.leadingAnchor.constraint(equalTo: sheet.leadingAnchor), scroll.trailingAnchor.constraint(equalTo: sheet.trailingAnchor), scroll.topAnchor.constraint(equalTo: sheet.topAnchor), scroll.bottomAnchor.constraint(equalTo: sheet.bottomAnchor)])
        let controls = NSStackView(); controls.orientation = .vertical; controls.spacing = 9; controls.edgeInsets = NSEdgeInsets(top: 8, left: 18, bottom: 16, right: 18); controls.alignment = .leading; controls.translatesAutoresizingMaskIntoConstraints = false
        let document = NSView(); document.translatesAutoresizingMaskIntoConstraints = false; document.addSubview(controls); scroll.documentView = document
        NSLayoutConstraint.activate([
            controls.leadingAnchor.constraint(equalTo: document.leadingAnchor), controls.trailingAnchor.constraint(equalTo: document.trailingAnchor), controls.topAnchor.constraint(equalTo: document.topAnchor), controls.bottomAnchor.constraint(equalTo: document.bottomAnchor),
            document.widthAnchor.constraint(equalTo: scroll.contentView.widthAnchor)
        ])

        let handle = NSBox(); handle.boxType = .custom; handle.fillColor = .separatorColor; handle.borderWidth = 0; handle.wantsLayer = true; handle.layer?.cornerRadius = 2; handle.translatesAutoresizingMaskIntoConstraints = false; handle.widthAnchor.constraint(equalToConstant: 44).isActive = true; handle.heightAnchor.constraint(equalToConstant: 4).isActive = true
        let handleWrap = NSStackView(); handleWrap.orientation = .horizontal; handleWrap.addArrangedSubview(NSView()); handleWrap.addArrangedSubview(handle); handleWrap.addArrangedSubview(NSView()); controls.addArrangedSubview(handleWrap)

        let connectRow = NSStackView(); connectRow.orientation = .horizontal; connectRow.spacing = 9
        let connect = NSButton(title: "Connect", target: self, action: #selector(connectUnified)); connect.identifier = NSUserInterfaceItemIdentifier("unified-connect"); connect.bezelStyle = .rounded; connect.controlSize = .large; connect.keyEquivalent = "\r"; connect.contentTintColor = .controlAccentColor; connect.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let kill = NSButton(checkboxWithTitle: "Kill switch", target: self, action: #selector(toggleUnifiedKillSwitch(_:))); kill.identifier = NSUserInterfaceItemIdentifier("unified-kill-switch")
        connectRow.addArrangedSubview(connect); connectRow.addArrangedSubview(kill); controls.addArrangedSubview(connectRow); connect.widthAnchor.constraint(greaterThanOrEqualToConstant: 260).isActive = true

        if multihopExitModePopup.numberOfItems == 0 { multihopExitModePopup.addItems(withTitles: ["Shadowsocks", "Hysteria2"]); multihopExitModePopup.selectItem(at: 0) }
        let multihopRow = NSStackView(); multihopRow.orientation = .horizontal; multihopRow.spacing = 7
        let multihopToggle = NSButton(checkboxWithTitle: "Multihop", target: self, action: #selector(unifiedMultihopChanged(_:))); multihopToggle.identifier = NSUserInterfaceItemIdentifier("unified-multihop-toggle"); multihopToggle.state = UserDefaults.standard.bool(forKey: unifiedMultihopEnabledKey) ? .on : .off
        multihopRow.addArrangedSubview(multihopToggle); multihopRow.addArrangedSubview(multihopEntryPopup); multihopRow.addArrangedSubview(NSTextField(labelWithString: "→")); multihopRow.addArrangedSubview(multihopExitPopup); multihopRow.addArrangedSubview(multihopExitModePopup)
        let editHops = NSButton(title: "Details", target: self, action: #selector(openUnifiedMultihop)); editHops.bezelStyle = .rounded; multihopRow.addArrangedSubview(editHops); controls.addArrangedSubview(multihopRow)

        let settingsRow = unifiedLabeledRow(title: "Settings")
        let settingsButton = NSButton(title: "Open settings", target: self, action: #selector(openUnifiedSettings)); settingsButton.bezelStyle = .rounded; settingsRow.addArrangedSubview(settingsButton)
        let mtu = NSButton(title: "Retest MTU", target: self, action: #selector(retestMTU)); mtu.bezelStyle = .rounded; settingsRow.addArrangedSubview(mtu); controls.addArrangedSubview(settingsRow)

        let compactMode = NSPopUpButton(frame: .zero, pullsDown: false); compactMode.identifier = NSUserInterfaceItemIdentifier("unified-mode-popup"); compactMode.target = self; compactMode.action = #selector(unifiedModeChanged(_:))
        let modeRow = unifiedLabeledRow(title: "Mode"); modeRow.addArrangedSubview(compactMode)
        let modeDetails = NSButton(title: "Presets", target: self, action: #selector(openUnifiedModes)); modeDetails.bezelStyle = .rounded; modeRow.addArrangedSubview(modeDetails); controls.addArrangedSubview(modeRow)

        let compactDNS = NSPopUpButton(frame: .zero, pullsDown: false); compactDNS.identifier = NSUserInterfaceItemIdentifier("unified-dns-popup"); compactDNS.addItems(withTitles: ["Home AdGuard", "Fastest measured", "Custom", "DoT", "DoH", "DoH3", "Rescue"]); compactDNS.target = self; compactDNS.action = #selector(unifiedDNSChanged(_:))
        let dnsRow = unifiedLabeledRow(title: "DNS"); dnsRow.addArrangedSubview(compactDNS)
        let dnsDetails = NSButton(title: "DNS details", target: self, action: #selector(openUnifiedDNS)); dnsDetails.bezelStyle = .rounded; dnsRow.addArrangedSubview(dnsDetails); controls.addArrangedSubview(dnsRow)

        errorLabel.textColor = .systemRed; errorLabel.font = .systemFont(ofSize: 11); errorLabel.maximumNumberOfLines = 2; controls.addArrangedSubview(errorLabel)

        Timer.scheduledTimer(withTimeInterval: 1.5, repeats: true) { [weak self] _ in self?.refreshUnifiedChrome() }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) { [weak self] in self?.refreshUnifiedModeMenu(); self?.refreshUnifiedChrome() }
    }

    private func unifiedGlassCard() -> NSVisualEffectView {
        let card = NSVisualEffectView(); card.material = .hudWindow; card.blendingMode = .withinWindow; card.state = .active; card.wantsLayer = true; card.layer?.cornerRadius = 14; card.translatesAutoresizingMaskIntoConstraints = false; return card
    }

    private func unifiedLabeledRow(title: String) -> NSStackView {
        let row = NSStackView(); row.orientation = .horizontal; row.spacing = 8
        let titleLabel = NSTextField(labelWithString: title); titleLabel.font = .systemFont(ofSize: 13, weight: .semibold); titleLabel.alignment = .right; titleLabel.widthAnchor.constraint(equalToConstant: 70).isActive = true
        row.addArrangedSubview(titleLabel); return row
    }

    @objc func unifiedRouterChanged() { selectRouter(); DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in self?.refreshUnifiedChrome() } }

    @objc func unifiedModeChanged(_ sender: NSPopUpButton) {
        let id = sender.selectedItem?.representedObject as? String ?? "smart-auto"
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
                guard let popup = self.findUnifiedView("unified-mode-popup") as? NSPopUpButton else { return }
                popup.removeAllItems()
                self.addUnifiedModeItem(to: popup, title: "SMART AUTO — recommended", id: "smart-auto", enabled: true)
                self.addUnifiedModeItem(to: popup, title: "AUTO — first proven path", id: "auto", enabled: true)
                for mode in modes {
                    let id = mode["id"] as? String ?? ""; guard !id.isEmpty else { continue }
                    let name = mode["name"] as? String ?? id; let available = mode["available"] as? Bool ?? false; let reason = (mode["reason"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
                    self.addUnifiedModeItem(to: popup, title: available ? name : "\(name) — unavailable\(reason.isEmpty ? "" : ": \(reason)")", id: id, enabled: available)
                }
                if !presets.isEmpty { popup.menu?.addItem(.separator()); for preset in presets { self.addUnifiedModeItem(to: popup, title: "CUSTOM • \(preset.name)", id: "custom:\(preset.name)", enabled: true) } }
                popup.menu?.addItem(.separator()); self.addUnifiedModeItem(to: popup, title: "New CUSTOM preset…", id: "custom:new", enabled: true)
                if let item = popup.itemArray.first(where: { ($0.representedObject as? String) == wanted && $0.isEnabled }) { popup.select(item) }
                else if let smart = popup.itemArray.first(where: { ($0.representedObject as? String) == "smart-auto" }) { popup.select(smart); UserDefaults.standard.set("smart-auto", forKey: unifiedSelectedModeKey) }
            }
        }
    }

    private func addUnifiedModeItem(to popup: NSPopUpButton, title: String, id: String, enabled: Bool) {
        popup.addItem(withTitle: title)
        guard let item = popup.lastItem else { return }
        item.representedObject = id; item.isEnabled = enabled; item.toolTip = enabled ? id : "Unavailable on the selected node/platform. Open Presets for complete readiness details."
    }

    @objc func connectUnified() {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            do {
                let status = try self.api.json("/api/status") as? [String: Any] ?? [:]
                let connected = status["connected"] as? Bool ?? false; let phase = (status["phase"] as? String ?? "").lowercased()
                if connected || phase.contains("trying") || phase == "starting" || phase == "checking" || phase.contains("proving") {
                    _ = try self.api.request("/api/disconnect", method: "POST", body: [:], timeout: 25)
                    DispatchQueue.main.async { self.appendHelp("Disconnected."); self.refreshAll(); self.refreshUnifiedChrome() }
                    return
                }
                DispatchQueue.main.async { self.startUnifiedSelectedMode() }
            } catch { DispatchQueue.main.async { self.errorLabel.stringValue = error.localizedDescription } }
        }
    }

    private func startUnifiedSelectedMode() {
        if UserDefaults.standard.bool(forKey: unifiedMultihopEnabledKey) { connectMultihop(); return }
        let selectedIndex = routerPopup.indexOfSelectedItem
        if selectedIndex >= 0 && selectedIndex < profiles.count {
            let profile = profiles[selectedIndex]
            if (profile["node_kind"] as? String ?? "router-vpn").lowercased() == "external", let id = profile["id"] as? String {
                asyncAction { String(data: try self.api.request("/api/external-profile/connect", method: "POST", body: ["profile_id": id], timeout: 180), encoding: .utf8) ?? "External exit connected" }
                return
            }
        }
        guard let popup = findUnifiedView("unified-mode-popup") as? NSPopUpButton else { return }
        let id = popup.selectedItem?.representedObject as? String ?? "smart-auto"; UserDefaults.standard.set(id, forKey: unifiedSelectedModeKey)
        switch id {
        case "smart-auto": asyncAction { String(data: try self.api.request("/api/strategy/smart-auto", method: "POST", body: [:], timeout: 240), encoding: .utf8) ?? "SMART AUTO connected" }
        case "auto": asyncAction { String(data: try self.api.request("/api/strategy/auto", method: "POST", body: [:], timeout: 200), encoding: .utf8) ?? "AUTO connected" }
        case "custom:new": openUnifiedCustomBuilder()
        default:
            if id.hasPrefix("custom:") {
                let name = String(id.dropFirst("custom:".count))
                guard let preset = Self.loadUnifiedCustomPresets().first(where: { $0.name == name }) else { errorLabel.stringValue = "CUSTOM preset \(name) no longer exists."; refreshUnifiedModeMenu(); return }
                connectUnifiedCustomPreset(preset.name, layers: preset.layers)
            } else {
                asyncAction { String(data: try self.api.request("/api/connect-logical", method: "POST", body: ["mode": id, "base": "auto"], timeout: 180), encoding: .utf8) ?? "Connected" }
            }
        }
    }

    func connectUnifiedCustomPreset(_ name: String, layers: [String]) {
        guard !layers.isEmpty else { errorLabel.stringValue = "CUSTOM preset \(name) has no required layers."; return }
        UserDefaults.standard.set("custom:\(name)", forKey: unifiedSelectedModeKey)
        asyncAction { String(data: try self.api.request("/api/strategy/custom", method: "POST", body: ["layers": layers], timeout: 240), encoding: .utf8) ?? "CUSTOM \(name) connected" }
    }

    @objc func openUnifiedCustomBuilder() {
        let builder = RouterVPNCustomPresetBuilder(owner: self, api: api); retainUnifiedController(builder); builder.showWindow(nil); builder.window?.center(); builder.window?.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
    }

    @objc func openUnifiedNodes() {
        let content = NSStackView(); content.orientation = .vertical; content.spacing = 8; content.edgeInsets = NSEdgeInsets(top: 10, left: 10, bottom: 10, right: 10)
        let note = NSTextField(wrappingLabelWithString: "One node is selected for normal connections. Router nodes and Custom / external exits share the catalog; nodes without real coordinates stay list-only and never receive a fabricated map pin."); note.textColor = .secondaryLabelColor; content.addArrangedSubview(note)
        content.addArrangedSubview(scroll(nodesText)); content.addArrangedSubview(nodePopup)
        let row = NSStackView(); row.orientation = .horizontal; row.spacing = 6
        row.addArrangedSubview(button("Pair Router node", #selector(pairNode))); row.addArrangedSubview(button("Import / add custom", #selector(importNode))); row.addArrangedSubview(button("Select", #selector(selectNode))); row.addArrangedSubview(button("Remove", #selector(removeNode))); row.addArrangedSubview(button("50-sample latency", #selector(latencySelected))); content.addArrangedSubview(row)
        presentUnifiedDetail(title: "Nodes", view: content, width: 820, height: 560)
    }

    @objc func openUnifiedModes() {
        refreshModes()
        let content = NSStackView(); content.orientation = .vertical; content.spacing = 8
        let newPreset = NSButton(title: "New / edit CUSTOM preset…", target: self, action: #selector(openUnifiedCustomBuilder)); newPreset.bezelStyle = .rounded; content.addArrangedSubview(newPreset); content.addArrangedSubview(scroll(modesText))
        presentUnifiedDetail(title: "Modes & presets", view: content, width: 780, height: 600)
    }

    @objc func openUnifiedDNS() {
        let view = dnsView(); refreshProfiles(); presentUnifiedDetail(title: "DNS", view: view, width: 760, height: 620)
    }

    @objc func openUnifiedMultihop() {
        refreshAdvanced()
        let content = NSStackView(); content.orientation = .vertical; content.spacing = 8
        let note = NSTextField(wrappingLabelWithString: "Choose entry → exit directly in the main control sheet. Each real-coordinate hop is color-coded on the map. The controller still decides platform/runtime support and fails closed rather than simulating a hop."); note.textColor = .secondaryLabelColor; content.addArrangedSubview(note)
        let refresh = NSButton(title: "Refresh readiness", target: self, action: #selector(refreshAdvancedAction)); refresh.bezelStyle = .rounded; content.addArrangedSubview(refresh); content.addArrangedSubview(scroll(advancedText))
        presentUnifiedDetail(title: "Multihop", view: content, width: 760, height: 520)
    }

    @objc func openUnifiedSettings() { editProfileSettings() }
    @objc func openUnifiedForwarding() { presentUnifiedDetail(title: "Port forwarding / Protected DMZ", view: forwardingView(), width: 760, height: 580) }

    private func presentUnifiedDetail(title: String, view: NSView, width: CGFloat, height: CGFloat) {
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: width, height: height), styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        panel.title = title; panel.minSize = NSSize(width: min(width, 560), height: min(height, 420)); panel.isReleasedWhenClosed = false
        let controller = NSWindowController(window: panel); retainUnifiedController(controller)
        let root = NSStackView(); root.orientation = .vertical; root.spacing = 8; root.edgeInsets = NSEdgeInsets(top: 10, left: 10, bottom: 10, right: 10); root.addArrangedSubview(view); panel.contentView = root; panel.center(); panel.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
    }

    @objc func unifiedMultihopChanged(_ sender: NSButton) { UserDefaults.standard.set(sender.state == .on, forKey: unifiedMultihopEnabledKey); refreshUnifiedHopOverlay() }

    @objc func toggleUnifiedKillSwitch(_ sender: NSButton) {
        let enabled = sender.state == .on
        asyncAction { _ = try self.api.request("/api/profile/settings", method: "POST", body: ["kill_switch_policy": enabled ? "on-connect" : "off"], timeout: 12); return enabled ? "Kill switch enabled for the selected Router VPN profile." : "Kill switch disabled for the selected Router VPN profile." }
    }

    @objc func unifiedDNSChanged(_ sender: NSPopUpButton) {
        let index = max(0, min(sender.indexOfSelectedItem, dnsModeIDs.count - 1)); let id = dnsModeIDs[index]
        if dnsModePopup.numberOfItems == 0 { _ = dnsView() }
        dnsModePopup.selectItem(at: index)
        if ["custom", "dot", "doh", "doh3"].contains(id) && dnsHostField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { openUnifiedDNS(); return }
        saveDNS()
    }

    func refreshUnifiedChrome() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            let status = (try? self.api.json("/api/status", timeout: 3) as? [String: Any]) ?? [:]
            let settings = (try? self.api.json("/api/profile/settings", timeout: 3) as? [String: Any]) ?? [:]
            DispatchQueue.main.async {
                let connected = status["connected"] as? Bool ?? false; let phase = status["phase"] as? String ?? "off"
                if let button = self.findUnifiedView("unified-connect") as? NSButton { let transitioning = !connected && (phase.contains("trying") || phase == "starting" || phase == "checking" || phase.contains("proving")); button.title = connected || transitioning ? "Disconnect" : "Connect" }
                if let kill = self.findUnifiedView("unified-kill-switch") as? NSButton { let policy = (settings["kill_switch_policy"] as? String ?? "off").lowercased(); kill.state = policy == "off" ? .off : .on }
                let selectedIndex = self.routerPopup.indexOfSelectedItem
                if selectedIndex >= 0 && selectedIndex < self.profiles.count {
                    let profile = self.profiles[selectedIndex]; let kind = (profile["node_kind"] as? String ?? "router-vpn").lowercased(); let name = profile["name"] as? String ?? profile["id"] as? String ?? "Node"; self.routerPopup.selectedItem?.title = (kind == "external" ? "Custom • " : "Router • ") + name
                    if let popup = self.findUnifiedView("unified-dns-popup") as? NSPopUpButton, let mode = profile["dns_mode"] as? String, let index = self.dnsModeIDs.firstIndex(of: mode) { popup.selectItem(at: index) }
                }
                self.refreshUnifiedHopOverlay()
            }
        }
    }

    private func findUnifiedView(_ id: String) -> NSView? {
        guard let content = window?.contentView else { return nil }
        func walk(_ view: NSView) -> NSView? { if view.identifier?.rawValue == id { return view }; for child in view.subviews { if let found = walk(child) { return found } }; return nil }
        return walk(content)
    }

    private func hopRole(for id: String) -> UnifiedHopRole {
        if UserDefaults.standard.bool(forKey: unifiedMultihopEnabledKey) {
            let entryIndex = multihopEntryPopup.indexOfSelectedItem, exitIndex = multihopExitPopup.indexOfSelectedItem
            if entryIndex >= 0 && entryIndex < multihopNodeIDs.count && multihopNodeIDs[entryIndex] == id { return .entry }
            if exitIndex >= 0 && exitIndex < multihopNodeIDs.count && multihopNodeIDs[exitIndex] == id { return .exit }
        }
        let selectedIndex = routerPopup.indexOfSelectedItem
        if selectedIndex >= 0 && selectedIndex < routerIDs.count && routerIDs[selectedIndex] == id { return .selected }
        if let profile = profiles.first(where: { ($0["id"] as? String) == id }), (profile["node_kind"] as? String ?? "router-vpn").lowercased() == "external" { return .external }
        return .normal
    }

    private func color(for role: UnifiedHopRole) -> NSColor {
        switch role { case .selected: return .systemPurple; case .entry: return .systemBlue; case .exit: return .systemOrange; case .external: return .systemPink; case .normal: return .systemTeal }
    }

    func refreshUnifiedHopOverlay() {
        map.removeOverlays(map.overlays)
        for annotation in map.annotations.compactMap({ $0 as? RouterAnnotation }) { if let view = map.view(for: annotation) as? MKMarkerAnnotationView { view.markerTintColor = color(for: hopRole(for: annotation.routerID)) } }
        guard UserDefaults.standard.bool(forKey: unifiedMultihopEnabledKey) else { return }
        let entryIndex = multihopEntryPopup.indexOfSelectedItem, exitIndex = multihopExitPopup.indexOfSelectedItem
        guard entryIndex >= 0, exitIndex >= 0, entryIndex < multihopNodeIDs.count, exitIndex < multihopNodeIDs.count else { return }
        let ids = [multihopNodeIDs[entryIndex], multihopNodeIDs[exitIndex]]
        let coordinates: [CLLocationCoordinate2D] = ids.compactMap { id in guard let profile = profiles.first(where: { ($0["id"] as? String) == id }) else { return nil }; let lat = (profile["latitude"] as? NSNumber)?.doubleValue ?? 0, lon = (profile["longitude"] as? NSNumber)?.doubleValue ?? 0; let coordinate = CLLocationCoordinate2D(latitude: lat, longitude: lon); return CLLocationCoordinate2DIsValid(coordinate) && !(lat == 0 && lon == 0) ? coordinate : nil }
        guard coordinates.count == ids.count else { return }
        map.addOverlay(MKPolyline(coordinates: coordinates, count: coordinates.count))
    }

    func mapView(_ mapView: MKMapView, viewFor annotation: MKAnnotation) -> MKAnnotationView? {
        guard let node = annotation as? RouterAnnotation else { return nil }
        let reuse = "RouterNode"
        let view = (mapView.dequeueReusableAnnotationView(withIdentifier: reuse) as? MKMarkerAnnotationView) ?? MKMarkerAnnotationView(annotation: annotation, reuseIdentifier: reuse)
        view.annotation = annotation; view.canShowCallout = true; view.markerTintColor = color(for: hopRole(for: node.routerID)); return view
    }

    func mapView(_ mapView: MKMapView, rendererFor overlay: MKOverlay) -> MKOverlayRenderer {
        guard let line = overlay as? MKPolyline else { return MKOverlayRenderer(overlay: overlay) }
        let renderer = MKPolylineRenderer(polyline: line); renderer.strokeColor = .systemBlue; renderer.lineWidth = 4; renderer.lineCap = .round; renderer.lineJoin = .round; return renderer
    }
}

// Shipping unified UX markers:
// map-first bottom control sheet Connect Disconnect quick kill switch Multihop Settings Mode DNS
// SMART AUTO default AUTO first-class all logical presets unavailable reasons CUSTOM visual preset builder
// Router node Custom external real coordinates color-coded hop overlay DAITA-like traffic padding IPv6 MTU Retest Jumbo forwarding
