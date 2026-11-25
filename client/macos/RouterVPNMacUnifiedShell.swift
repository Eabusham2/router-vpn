import AppKit
import Foundation
import CoreFoundation
import MapKit
import ObjectiveC

// A displayed retry owns one cleanup receipt, independent of later status polls.
final class MacUnifiedConnectButton: NSButton {
    var stopRetryToken: String?
}
func productStopRetryToken(_ status: [String: Any]?) throws -> String? {
    guard let status else { throw NSError(domain: "RouterVPN.StopRetry", code: 1) }
    guard let pending = status["stop_pending"] else { return nil }
    guard let boolean = pending as? NSNumber, CFGetTypeID(boolean) == CFBooleanGetTypeID() else { throw NSError(domain: "RouterVPN.StopRetry", code: 2) }
    guard boolean.boolValue else { return nil }
    guard let token = status["stop_token"] as? String, token.utf8.count == 32,
          token.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { throw NSError(domain: "RouterVPN.StopRetry", code: 3) }
    return token
}
func productStopRetryPresentation(_ status: [String: Any]?, busy: Bool) -> (title: String, enabled: Bool, token: String?) {
    do {
        let token = try productStopRetryToken(status)
        let phase = (status?["phase"] as? String ?? "").lowercased()
        if phase.contains("disconnecting") || phase.contains("stopping") { return ("Disconnecting…", false, nil) }
        if let token { return ("Retry Disconnect", true, token) }
        if !(status?["connected"] as? Bool ?? false), !phase.hasPrefix("candidate:"), MacViaEntryCandidateReservation.shared.active { return ("Review test", false, nil) }
        return ((status?["connected"] as? Bool ?? false) || busy ? "Disconnect" : "Connect", true, nil)
    } catch { return ("Checking…", false, nil) }
}

func productQuickDNSBody(captured: [String: Any]?, displayedProfileID: String, mode: String) throws -> [String: Any] {
    guard ["home", "rescue"].contains(mode) else {
        throw NSError(domain: "RouterVPN.DNS", code: 3, userInfo: [NSLocalizedDescriptionKey: "Open DNS details to configure or select a measured resolver."])
    }
    var fields: [String: Any] = ["mode": mode, "port": 0]
    if mode == "home", captured?["mode"] as? String == "home" {
        for key in ["protocol", "host", "port", "server_name", "path"] {
            if let value = captured?[key] { fields[key] = value }
        }
    }
    return try productDNSPolicyBody(captured: captured, displayedProfileID: displayedProfileID, fields: fields)
}

private let unifiedCreatePresetAction = "action:create-custom"
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
    case hop
    case exit
    case external
    case normal
}

private final class RouterVPNCustomPresetBuilder: NSWindowController {
    private weak var productOwner: ProductWindowController?
    private let openedRouterID: String?
    private let api: ProductAPI
    private let nameField = NSTextField(string: "")
    private let presetPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let layersStack = NSStackView()
    private let status = NSTextField(wrappingLabelWithString: "")
    private var layerButtons: [NSButton] = []
    private var presets: [MacCustomPreset] = []

    init(owner: ProductWindowController, api: ProductAPI) {
        self.productOwner = owner
        self.openedRouterID = owner.displayedCustomRouterID
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
        if let name, let index = presets.firstIndex(where: { $0.name.utf8.elementsEqual(name.utf8) }) { presetPopup.selectItem(at: index + 1) }
        else { presetPopup.selectItem(at: 0) }
        applyCurrentPreset()
    }

    private func selectedLayers() -> [String] { layerButtons.filter { $0.state == .on }.map(\.title).sorted() }

    private func editingPreset() -> MacCustomPreset? {
        guard presetPopup.indexOfSelectedItem > 0, presetPopup.indexOfSelectedItem - 1 < presets.count else { return nil }
        return presets[presetPopup.indexOfSelectedItem - 1]
    }

    private func preservedUnknownLayers() -> [String] {
        guard let preset = editingPreset() else { return [] }
        let known = Set(layerButtons.map(\.title))
        return preset.layers.filter { !known.contains($0) }
    }

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
        let known = Set(layerButtons.map(\.title))
        let hidden = preset.layers.filter { !known.contains($0) }
        status.stringValue = "\(preset.layers.count) exact layer requirement\(preset.layers.count == 1 ? "" : "s") saved." + (hidden.isEmpty ? "" : " \(hidden.count) unavailable compatibility layer\(hidden.count == 1 ? "" : "s") will be preserved on edit.")
    }

    @objc private func presetChanged() { applyCurrentPreset() }
    @objc private func newPreset() { presetPopup.selectItem(at: 0); applyCurrentPreset() }

    @objc private func deletePreset() {
        guard presetPopup.indexOfSelectedItem > 0, presetPopup.indexOfSelectedItem - 1 < presets.count else { return }
        let target = presets[presetPopup.indexOfSelectedItem - 1]
        let alert = NSAlert(); alert.alertStyle = .warning; alert.messageText = "Delete CUSTOM preset \(target.name)?"; alert.addButton(withTitle: "Delete"); alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        guard productOwner?.ensureMutationIdle("deleting a CUSTOM preset") == true else { return }
        do {
            var current = try ProductWindowController.readUnifiedCustomPresets()
            let matches = current.indices.filter { current[$0].name.utf8.elementsEqual(target.name.utf8) }
            guard matches.count == 1, current[matches[0]].layers == target.layers else {
                status.stringValue = "This CUSTOM preset changed. Reopen the builder before deleting."; return
            }
            current.remove(at: matches[0])
            ProductWindowController.saveUnifiedCustomPresets(current)
        } catch { status.stringValue = error.localizedDescription; return }
        if UserDefaults.standard.string(forKey: unifiedSelectedModeKey)?.utf8.elementsEqual("custom:\(target.name)".utf8) == true {
            UserDefaults.standard.set("smart-auto", forKey: unifiedSelectedModeKey)
        }
        productOwner?.refreshUnifiedModeMenu()
        reloadPresets()
    }

    private func persist() -> MacCustomPreset? {
        let name = nameField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        let editing = editingPreset()
        let layers = Array(Set(selectedLayers() + preservedUnknownLayers())).sorted()
        guard !name.isEmpty else { status.stringValue = "Give this preset a name."; return nil }
        guard !layers.isEmpty else { status.stringValue = "Choose at least one required layer."; return nil }
        guard name.unicodeScalars.count <= 64,
              !name.unicodeScalars.contains(where: { $0.value < 0x20 || (0x7f...0x9f).contains($0.value) }) else {
            status.stringValue = "Use up to 64 printable characters for the preset name."; return nil
        }
        let preset = MacCustomPreset(name: name, layers: layers)
        var rows: [MacCustomPreset]
        do { rows = try ProductWindowController.readUnifiedCustomPresets() }
        catch { status.stringValue = error.localizedDescription; return nil }
        if let editing {
            let matches = rows.indices.filter { rows[$0].name.utf8.elementsEqual(editing.name.utf8) }
            guard matches.count == 1, rows[matches[0]].layers == editing.layers else {
                status.stringValue = "This CUSTOM preset changed. Reopen the builder before saving."; return nil
            }
            rows.remove(at: matches[0])
        }
        if editing?.name.utf8.elementsEqual(name.utf8) != true,
           rows.contains(where: { $0.name.caseInsensitiveCompare(name) == .orderedSame }) {
            status.stringValue = "A CUSTOM preset already uses that name. Edit it or choose a different name."; return nil
        }
        rows.append(preset)
        rows.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        ProductWindowController.saveUnifiedCustomPresets(rows)
        UserDefaults.standard.set("custom:\(name)", forKey: unifiedSelectedModeKey)
        productOwner?.refreshUnifiedModeMenu()
        reloadPresets(select: name)
        status.stringValue = "Saved \(name) • \(layers.joined(separator: " • "))"
        return preset
    }

    @objc private func savePreset() { _ = persist() }
    @objc private func saveAndConnect() {
        guard let preset = persist() else { return }
        productOwner?.connectUnifiedCustomPreset(preset.name, layers: preset.layers, expectedRouterID: openedRouterID)
        close()
    }
    @objc private func closeBuilder() { close() }
}

extension ProductWindowController {
    fileprivate static func loadUnifiedCustomPresets() -> [MacCustomPreset] {
        (try? readUnifiedCustomPresets()) ?? []
    }

    fileprivate static func readUnifiedCustomPresets() throws -> [MacCustomPreset] {
        guard let data = UserDefaults.standard.data(forKey: unifiedCustomPresetsKey) else { return [] }
        return try JSONDecoder().decode([MacCustomPreset].self, from: data)
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
        routerPopup.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        nodeRow.addArrangedSubview(routerPopup)
        let manageNode = NSButton(title: "Add / manage nodes", target: self, action: #selector(openUnifiedNodes)); manageNode.bezelStyle = .rounded; manageNode.setContentCompressionResistancePriority(.defaultLow, for: .horizontal); nodeRow.addArrangedSubview(manageNode)
        NSLayoutConstraint.activate([
            nodeRow.leadingAnchor.constraint(equalTo: nodeCard.leadingAnchor), nodeRow.trailingAnchor.constraint(equalTo: nodeCard.trailingAnchor), nodeRow.topAnchor.constraint(equalTo: nodeCard.topAnchor), nodeRow.bottomAnchor.constraint(equalTo: nodeCard.bottomAnchor),
            nodeCard.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 16), nodeCard.topAnchor.constraint(equalTo: root.topAnchor, constant: 16), nodeCard.widthAnchor.constraint(lessThanOrEqualToConstant: 450)
        ])

        let statusCard = unifiedGlassCard()
        root.addSubview(statusCard)
        let statusStack = NSStackView(); statusStack.orientation = .vertical; statusStack.spacing = 2; statusStack.edgeInsets = NSEdgeInsets(top: 8, left: 10, bottom: 8, right: 10); statusStack.translatesAutoresizingMaskIntoConstraints = false
        statusLabel.font = .systemFont(ofSize: 13, weight: .semibold); detailLabel.font = .systemFont(ofSize: 11); detailLabel.textColor = .secondaryLabelColor; detailLabel.maximumNumberOfLines = 2
        statusLabel.setContentCompressionResistancePriority(.defaultLow, for: .horizontal); detailLabel.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        statusStack.addArrangedSubview(statusLabel); statusStack.addArrangedSubview(detailLabel); statusCard.addSubview(statusStack)
        NSLayoutConstraint.activate([
            statusStack.leadingAnchor.constraint(equalTo: statusCard.leadingAnchor), statusStack.trailingAnchor.constraint(equalTo: statusCard.trailingAnchor), statusStack.topAnchor.constraint(equalTo: statusCard.topAnchor), statusStack.bottomAnchor.constraint(equalTo: statusCard.bottomAnchor),
            statusCard.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -16), statusCard.topAnchor.constraint(equalTo: root.topAnchor, constant: 16), statusCard.widthAnchor.constraint(lessThanOrEqualToConstant: 390),
            nodeCard.trailingAnchor.constraint(lessThanOrEqualTo: statusCard.leadingAnchor, constant: -8)
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
        let connect = MacUnifiedConnectButton(title: "Connect", target: self, action: #selector(connectUnified)); connect.identifier = NSUserInterfaceItemIdentifier("unified-connect"); connect.bezelStyle = .rounded; connect.controlSize = .large; connect.keyEquivalent = "\r"; connect.contentTintColor = .controlAccentColor; connect.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let kill = NSButton(checkboxWithTitle: "Kill switch", target: self, action: #selector(toggleUnifiedKillSwitch(_:))); kill.identifier = NSUserInterfaceItemIdentifier("unified-kill-switch")
        connectRow.addArrangedSubview(kill); connectRow.addArrangedSubview(connect); controls.addArrangedSubview(connectRow); connect.widthAnchor.constraint(greaterThanOrEqualToConstant: 260).isActive = true

        if multihopExitModePopup.numberOfItems == 0 { multihopExitModePopup.addItems(withTitles: RouterVPNNodeExitModes.choices.map { $0.title }); multihopExitModePopup.selectItem(at: 0) }
        let multihopRow = NSStackView(); multihopRow.orientation = .horizontal; multihopRow.spacing = 7
        let multihopToggle = NSButton(checkboxWithTitle: "Multihop", target: self, action: #selector(unifiedMultihopChanged(_:))); multihopToggle.identifier = NSUserInterfaceItemIdentifier("unified-multihop-toggle"); multihopToggle.state = UserDefaults.standard.bool(forKey: unifiedMultihopEnabledKey) ? .on : .off
        multihopRow.addArrangedSubview(multihopToggle); multihopRow.addArrangedSubview(multihopEntryPopup); multihopRow.addArrangedSubview(NSTextField(labelWithString: "→")); multihopRow.addArrangedSubview(multihopExitPopup); multihopRow.addArrangedSubview(multihopExitModePopup)
        let editHops = NSButton(title: "Details", target: self, action: #selector(openUnifiedMultihop)); editHops.bezelStyle = .rounded; multihopRow.addArrangedSubview(editHops); controls.addArrangedSubview(multihopRow)

        let orderedRow = unifiedLabeledRow(title: "Order")
        orderedRow.addArrangedSubview(NSButton(title: "Edit ordered path…", target: self, action: #selector(openOrderedNodeEditor)))
        orderedRow.addArrangedSubview(NSButton(title: "Use entry / exit pair", target: self, action: #selector(useOrderedNodePair)))
        controls.addArrangedSubview(orderedRow)
        let orderedSummary = NSTextField(wrappingLabelWithString: "Entry / exit pair"); orderedSummary.identifier = NSUserInterfaceItemIdentifier("unified-ordered-summary"); orderedSummary.textColor = .secondaryLabelColor; controls.addArrangedSubview(orderedSummary)

        configureMultihopExecution()
        let entryModeRow = unifiedLabeledRow(title: "Entry mode")
        entryModeRow.addArrangedSubview(multihopEntryModePopup); controls.addArrangedSubview(entryModeRow)
        let baseRow = unifiedLabeledRow(title: "Entry base")
        basePopup.toolTip = "Auto follows the selected entry node's saved base. AmneziaWG retains its exact saved Fast or Strong configuration."
        baseRow.addArrangedSubview(basePopup); controls.addArrangedSubview(baseRow)
        let executionRow = unifiedLabeledRow(title: "Execution")
        executionRow.addArrangedSubview(multihopExecutionPopup); controls.addArrangedSubview(executionRow)
        controls.addArrangedSubview(multihopComparisonLabel)
        let externalRow = unifiedLabeledRow(title: "External path")
        externalRow.addArrangedSubview(button("Direct / entry · Local / Server / Compare…", #selector(openExternalPath)))
        controls.addArrangedSubview(externalRow)

        let settingsRow = unifiedLabeledRow(title: "Settings")
        let settingsButton = NSButton(title: "Open settings", target: self, action: #selector(openUnifiedSettings)); settingsButton.bezelStyle = .rounded; settingsRow.addArrangedSubview(settingsButton)
        let requirementsSummary = NSTextField(labelWithString: "AUTO requirements: Off"); requirementsSummary.identifier = NSUserInterfaceItemIdentifier("unified-auto-requirements"); requirementsSummary.textColor = .secondaryLabelColor; requirementsSummary.lineBreakMode = .byTruncatingTail; settingsRow.addArrangedSubview(requirementsSummary)
        let mtu = NSButton(title: "Retest MTU", target: self, action: #selector(retestMTU)); mtu.bezelStyle = .rounded; settingsRow.addArrangedSubview(mtu)
        let mtuStatus = NSButton(title: "Auto MTU status", target: self, action: #selector(observeMTU)); mtuStatus.bezelStyle = .rounded; settingsRow.addArrangedSubview(mtuStatus); controls.addArrangedSubview(settingsRow)

        let compactMode = NSPopUpButton(frame: .zero, pullsDown: false); compactMode.identifier = NSUserInterfaceItemIdentifier("unified-mode-popup"); compactMode.target = self; compactMode.action = #selector(unifiedModeChanged(_:))
        let modeRow = unifiedLabeledRow(title: "Mode"); modeRow.addArrangedSubview(compactMode)
        let modeDetails = NSButton(title: "Presets", target: self, action: #selector(openUnifiedModes)); modeDetails.identifier = NSUserInterfaceItemIdentifier("unified-mode-details"); modeDetails.bezelStyle = .rounded; modeRow.addArrangedSubview(modeDetails); controls.addArrangedSubview(modeRow)

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
        if id == unifiedCreatePresetAction { restoreUnifiedModeSelection(in: sender); openUnifiedCustomBuilder(); return }
        UserDefaults.standard.set(id, forKey: unifiedSelectedModeKey)
    }

    private func storedUnifiedModeID() -> String {
        let id = UserDefaults.standard.string(forKey: unifiedSelectedModeKey) ?? "smart-auto"
        if id == unifiedCreatePresetAction { return "smart-auto" }
        if id == "custom:new" && !Self.loadUnifiedCustomPresets().contains(where: { $0.name == "new" }) { return "smart-auto" }
        return id
    }

    private func restoreUnifiedModeSelection(in popup: NSPopUpButton, preferred: String? = nil) {
        let wanted = preferred ?? storedUnifiedModeID()
        popup.select(popup.itemArray.first { ($0.representedObject as? String)?.utf8.elementsEqual(wanted.utf8) == true && wanted != unifiedCreatePresetAction })
    }

    func refreshUnifiedModeMenu(preferred: String? = nil) {
        let previous = storedUnifiedModeID()
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            let modes = (try? self.api.json("/api/logical-modes", timeout: 10) as? [[String: Any]]) ?? []
            DispatchQueue.main.async {
                let presets = Self.loadUnifiedCustomPresets()
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
                popup.menu?.addItem(.separator()); self.addUnifiedModeItem(to: popup, title: "New CUSTOM preset…", id: unifiedCreatePresetAction, enabled: true)
                let current = self.storedUnifiedModeID()
                self.restoreUnifiedModeSelection(in: popup, preferred: current == previous ? preferred : current)
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
        let selectedIndex = routerPopup.indexOfSelectedItem
        guard selectedIndex >= 0 && selectedIndex < profiles.count, let selectedID = profiles[selectedIndex]["id"] as? String, !selectedID.isEmpty else { appendHelp("The selected node is unavailable. Refresh the node list before connecting."); return }
        guard ["", "router-vpn", "external"].contains((profiles[selectedIndex]["node_kind"] as? String ?? "router-vpn").lowercased()) else { appendHelp("The selected node type is invalid."); return }
        if selectedIndex >= 0 && selectedIndex < profiles.count {
            let profile = profiles[selectedIndex]
            if (profile["node_kind"] as? String ?? "router-vpn").lowercased() == "external" {
                do {
                    let opened: [String: Any] = ["selected_id": selectedID, "profiles": profiles]
                    let body = try externalCapturedBody(externalConnectBody(profile: profile, execution: externalSavedExecution(profile)), opened: opened)
                    let timeout = externalConnectionTimeout(body)
                    let progressOwner = startCapturedComparisonProgress(requestID: body["comparison_request_id"] as? String, timeout: timeout)
                    asyncAction {
                        defer { DispatchQueue.main.async { self.stopCapturedComparisonProgress(progressOwner) } }
                        try self.requireMutationIdle("starting an external saved path")
                        guard let capabilities = try self.api.json("/api/external-profile/capabilities", timeout: 5) as? [String: Any],
                              let current = try self.api.json("/api/nodes", timeout: 5) as? [String: Any] else { throw NSError(domain: "RouterVPN.ExternalNode", code: 1) }
                        try externalRequireSourceCapability(capabilities)
                        try externalValidateCapturedBody(body, current: current)
                        return String(data: try self.api.request("/api/external-profile/connect", method: "POST", body: body, timeout: timeout), encoding: .utf8) ?? "External exit connected"
                    }
                } catch { appendHelp(error.localizedDescription) }
                return
            }
        }
        if UserDefaults.standard.bool(forKey: unifiedMultihopEnabledKey) { connectMultihop(); return }
        guard let popup = findUnifiedView("unified-mode-popup") as? NSPopUpButton else { return }
        startUnifiedPopupMode(popup)
    }

    private func startUnifiedPopupMode(_ popup: NSPopUpButton) {
        let id = storedUnifiedModeID()
        switch id {
        case "smart-auto": asyncAction { String(data: try self.api.request("/api/strategy/smart-auto", method: "POST", body: [:], timeout: 240), encoding: .utf8) ?? "SMART AUTO connected" }
        case "auto": asyncAction { String(data: try self.api.request("/api/strategy/auto", method: "POST", body: [:], timeout: 200), encoding: .utf8) ?? "AUTO connected" }
        default:
            if let name = macCustomPresetName(in: id) {
                let exact = Self.loadUnifiedCustomPresets().filter { $0.name.utf8.elementsEqual(name.utf8) }
                guard exact.count == 1 else { errorLabel.stringValue = "Choose one saved CUSTOM preset with the exact name \(name)."; refreshUnifiedModeMenu(); return }
                let preset = exact[0]
                connectUnifiedCustomPreset(preset.name, layers: preset.layers, expectedRouterID: displayedCustomRouterID)
            } else {
                guard popup.itemArray.contains(where: { ($0.representedObject as? String) == id && $0.isEnabled }) else {
                    errorLabel.stringValue = "The selected mode is unavailable. Choose an available mode."
                    refreshUnifiedModeMenu()
                    return
                }
                asyncAction { String(data: try self.api.request("/api/connect-logical", method: "POST", body: ["mode": id, "base": "auto"], timeout: 180), encoding: .utf8) ?? "Connected" }
            }
        }
    }

    fileprivate var displayedCustomRouterID: String? {
        let index = routerPopup.indexOfSelectedItem
        guard routerIDs.indices.contains(index), profiles.indices.contains(index),
              let id = profiles[index]["id"] as? String, !id.isEmpty, routerIDs[index] == id,
              ["", "router-vpn"].contains((profiles[index]["node_kind"] as? String ?? "router-vpn").lowercased()) else { return nil }
        return id
    }

    func connectUnifiedCustomPreset(_ name: String, layers: [String], expectedRouterID: String?) {
        guard let id = expectedRouterID, displayedCustomRouterID == id else {
            errorLabel.stringValue = "Select the original Router VPN node before connecting this CUSTOM preset."
            return
        }
        guard !UserDefaults.standard.bool(forKey: unifiedMultihopEnabledKey) else {
            errorLabel.stringValue = "Turn Multihop off before connecting this single-node CUSTOM preset."
            return
        }
        guard !layers.isEmpty else { errorLabel.stringValue = "CUSTOM preset \(name) has no required layers."; return }
        UserDefaults.standard.set("custom:\(name)", forKey: unifiedSelectedModeKey)
        asyncAction { String(data: try self.api.request("/api/strategy/custom", method: "POST", body: ["expected_selected_node_id": id, "layers": layers], timeout: 240), encoding: .utf8) ?? "CUSTOM \(name) connected" }
    }

    @objc func openUnifiedCustomBuilder() {
        let builder = RouterVPNCustomPresetBuilder(owner: self, api: api); retainUnifiedController(builder); builder.showWindow(nil); builder.window?.center(); builder.window?.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
    }

    @objc func openUnifiedNodes() {
        let content = NSStackView(); content.orientation = .vertical; content.spacing = 8; content.edgeInsets = NSEdgeInsets(top: 10, left: 10, bottom: 10, right: 10)
        let note = NSTextField(wrappingLabelWithString: "One node is selected for normal connections. Router nodes and Custom / external exits share the catalog; nodes without real coordinates stay list-only and never receive a fabricated map pin."); note.textColor = .secondaryLabelColor; content.addArrangedSubview(note)
        content.addArrangedSubview(scroll(nodesText)); content.addArrangedSubview(nodePopup)
        let row = NSStackView(); row.orientation = .horizontal; row.spacing = 6
        row.addArrangedSubview(button("Pair Router node", #selector(pairNode))); row.addArrangedSubview(button("Import / add custom", #selector(importNode))); row.addArrangedSubview(button("Select", #selector(selectNode))); row.addArrangedSubview(button("Add external node…", #selector(addExternalNode))); content.addArrangedSubview(row)
        let pathRow = NSStackView(); pathRow.orientation = .horizontal; pathRow.spacing = 6
        pathRow.addArrangedSubview(button("External direct", #selector(connectExternalDirect))); pathRow.addArrangedSubview(button("External via entry…", #selector(connectExternalViaEntry))); pathRow.addArrangedSubview(button("Remove", #selector(removeNode))); pathRow.addArrangedSubview(button("50-sample latency", #selector(latencySelected))); content.addArrangedSubview(pathRow)
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
        let candidates = NSButton(title: "Retest exits via entry", target: self, action: #selector(openViaEntryCandidates)); candidates.bezelStyle = .rounded; content.addArrangedSubview(candidates)
        let refresh = NSButton(title: "Refresh readiness", target: self, action: #selector(refreshAdvancedAction)); refresh.bezelStyle = .rounded; content.addArrangedSubview(refresh); content.addArrangedSubview(scroll(advancedText))
        presentUnifiedDetail(title: "Multihop", view: content, width: 760, height: 520)
    }

    @objc func openOrderedNodeEditor() {
        do {
            let controller = RouterVPNOrderedNodeEditor(owner: self, draft: try makeOrderedNodeDraft())
            retainUnifiedController(controller); controller.showWindow(nil); controller.window?.center(); controller.window?.makeKeyAndOrderFront(nil)
        } catch { appendHelp(error.localizedDescription) }
    }

    @objc func useOrderedNodePair() {
        do { try clearOrderedNodeDraft(); refreshUnifiedChrome() }
        catch { appendHelp(error.localizedDescription) }
    }

    func refreshOrderedNodePresentation(busy: Bool) {
        let selection = captureConnectionProfileSelection()
        let ordered = selection.multihopEnabled && !selection.orderedNodes.isEmpty
        if let summary = findUnifiedView("unified-ordered-summary") as? NSTextField {
            summary.stringValue = selection.orderedNodes.isEmpty ? "Entry / exit pair" :
                (ordered ? "Ordered path (\(selection.execution)): " : "Saved ordered path (Multihop off): ") + selection.orderedNodes.enumerated().map { index, row in
                    let id = row["id"] ?? "", name = profiles.first(where: { $0["id"] as? String == id })?["name"] as? String ?? id
                    return "\(index + 1). \(name) · \(RouterVPNOrderedNodes.modeName(row["mode"] ?? ""))"
                }.joined(separator: " → ")
        }
        for popup in [multihopEntryPopup, multihopExitPopup, multihopEntryModePopup, multihopExitModePopup, basePopup] { popup.isEnabled = !ordered && !busy }
        multihopExecutionPopup.isEnabled = !busy
        if let popup = findUnifiedView("unified-mode-popup") as? NSPopUpButton { popup.isHidden = ordered }
        if let details = findUnifiedView("unified-mode-details") as? NSButton { details.isEnabled = !ordered && !busy }
    }

    @objc func openUnifiedSettings() { editProfileSettings() }
    @objc func openUnifiedForwarding() { presentUnifiedDetail(title: "Port forwarding / Protected DMZ", view: forwardingView(), width: 760, height: 580) }

    private func presentUnifiedDetail(title: String, view: NSView, width: CGFloat, height: CGFloat) {
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: width, height: height), styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        panel.title = title; panel.minSize = NSSize(width: min(width, 560), height: min(height, 420)); panel.isReleasedWhenClosed = false
        let controller = NSWindowController(window: panel); retainUnifiedController(controller)
        let root = NSStackView(); root.orientation = .vertical; root.spacing = 8; root.edgeInsets = NSEdgeInsets(top: 10, left: 10, bottom: 10, right: 10); root.addArrangedSubview(view); panel.contentView = root; panel.center(); panel.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
    }

    @objc func unifiedMultihopChanged(_ sender: NSButton) { UserDefaults.standard.set(sender.state == .on, forKey: unifiedMultihopEnabledKey); recordVisibleConnectionProfileSelection(); refreshUnifiedHopOverlay() }

    @objc func toggleUnifiedKillSwitch(_ sender: NSButton) {
        guard ensureMutationIdle("changing persistent kill-switch policy") else { refreshUnifiedChrome(); return }
        let index = routerPopup.indexOfSelectedItem
        guard index >= 0 && index < routerIDs.count else { refreshUnifiedChrome(); return }
        let displayedProfileID = routerIDs[index]
        let enabled = sender.state == .on
        asyncAction {
            try self.requireMutationIdle("changing persistent kill-switch policy")
            let data = try self.api.request("/api/profile/protection", timeout: 5)
            let captured = try JSONDecoder().decode(MacProfileProtectionSettings.self, from: data)
            let body = try captured.saveData(displayedProfileID: displayedProfileID, enabled: enabled)
            _ = try self.api.requestRaw("/api/profile/protection", body: body, timeout: 8)
            return enabled ? "Kill switch enabled for the selected node." : "Kill switch disabled for the selected node."
        }
    }

    @objc func unifiedDNSChanged(_ sender: NSPopUpButton) {
        let index = sender.indexOfSelectedItem
        guard index >= 0 && index < dnsModeIDs.count else { return }
        let mode = dnsModeIDs[index]
        if ["fastest", "custom", "dot", "doh", "doh3"].contains(mode) { openUnifiedDNS(); return }
        guard ensureMutationIdle("changing DNS policy") else { refreshUnifiedChrome(); return }
        let selectedIndex = routerPopup.indexOfSelectedItem
        guard selectedIndex >= 0 && selectedIndex < routerIDs.count else { refreshUnifiedChrome(); return }
        let displayedProfileID = routerIDs[selectedIndex]
        asyncAction {
            try self.requireMutationIdle("changing DNS policy")
            let captured = try self.api.json("/api/dns/policy", timeout: 5) as? [String: Any]
            let body = try productQuickDNSBody(captured: captured, displayedProfileID: displayedProfileID, mode: mode)
            _ = try self.api.request("/api/dns/policy", method: "POST", body: body, timeout: 10)
            return "DNS saved for the selected node. The next connection will prove its selected resolver."
        }
    }

    func refreshUnifiedChrome() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            let status = (try? self.api.json("/api/status", timeout: 3) as? [String: Any]) ?? [:]
            let settings = (try? self.api.json("/api/profile/settings", timeout: 3) as? [String: Any]) ?? [:]
            let protectionData = try? self.api.request("/api/profile/protection", timeout: 3)
            let protection = protectionData.flatMap { try? JSONDecoder().decode(MacProfileProtectionSettings.self, from: $0) }
            DispatchQueue.main.async {
                let connected = status["connected"] as? Bool ?? false; let phase = status["phase"] as? String ?? "off"
                if let button = self.findUnifiedView("unified-connect") as? NSButton { let transitioning = !connected && (phase.contains("trying") || phase == "starting" || phase == "checking" || phase.contains("proving")); button.title = connected || transitioning ? "Disconnect" : "Connect" }
                if let requirements = self.findUnifiedView("unified-auto-requirements") as? NSTextField {
                    var active: [String] = []; if settings["auto_require_encrypted"] as? Bool ?? false { active.append("Encrypted") }; if settings["auto_require_obfuscation"] as? Bool ?? false { active.append("Obfuscation") }; requirements.stringValue = active.isEmpty ? "AUTO requirements: Off" : "AUTO requirements: " + active.joined(separator: " + ")
                }
                if let kill = self.findUnifiedView("unified-kill-switch") as? NSButton {
                    let index = self.routerPopup.indexOfSelectedItem
                    let displayedID = index >= 0 && index < self.routerIDs.count ? self.routerIDs[index] : ""
                    let valid = protection?.profileID == displayedID && !displayedID.isEmpty && !(protection?.profileToken.isEmpty ?? true) && ["off", "on-connect", "always"].contains(protection?.killSwitchPolicy ?? "")
                    let known = status["connected"] is Bool
                    let stable = ["", "off", "failed"].contains(phase.trimmingCharacters(in: .whitespacesAndNewlines).lowercased())
                    kill.isEnabled = valid && known && !connected && stable
                    kill.allowsMixedState = !valid
                    kill.state = valid ? (protection?.killSwitchPolicy == "off" ? .off : .on) : .mixed
                }
                let selectedIndex = self.routerPopup.indexOfSelectedItem
                if selectedIndex >= 0 && selectedIndex < self.profiles.count {
                    let profile = self.profiles[selectedIndex]; let kind = (profile["node_kind"] as? String ?? "router-vpn").lowercased(); let name = profile["name"] as? String ?? profile["id"] as? String ?? "Node"; self.routerPopup.selectedItem?.title = (kind == "external" ? "Custom • " : "Router • ") + name
                    if let popup = self.findUnifiedView("unified-dns-popup") as? NSPopUpButton, let mode = profile["dns_mode"] as? String, let index = self.dnsModeIDs.firstIndex(of: mode) { popup.selectItem(at: index) }
                }
                self.refreshUnifiedHopOverlay()
                self.refreshOrderedNodePresentation(busy: self.mutationBusy(from: status))
            }
        }
    }

    private func findUnifiedView(_ id: String) -> NSView? {
        guard let content = window?.contentView else { return nil }
        func walk(_ view: NSView) -> NSView? { if view.identifier?.rawValue == id { return view }; for child in view.subviews { if let found = walk(child) { return found } }; return nil }
        return walk(content)
    }

    private var displayedMapIDs: [String] {
        if let active = activeMapNodeIDs { return active }
        guard UserDefaults.standard.bool(forKey: unifiedMultihopEnabledKey) else { return [] }
        let ordered = captureConnectionProfileSelection().orderedNodes.compactMap { $0["id"] }
        if !ordered.isEmpty { return ordered }
        let entry = multihopEntryPopup.indexOfSelectedItem, exit = multihopExitPopup.indexOfSelectedItem
        guard multihopNodeIDs.indices.contains(entry), multihopNodeIDs.indices.contains(exit), entry != exit else { return [] }
        return [multihopNodeIDs[entry], multihopNodeIDs[exit]]
    }

    nonisolated static func unifiedMapCoordinate(_ profile: [String: Any]) -> CLLocationCoordinate2D? {
        // The public profile omits zero-valued components. Both absent denotes
        // an unknown coordinate; one absent can lie on the equator/meridian.
        let lat = (profile["latitude"] as? NSNumber)?.doubleValue ?? 0
        let lon = (profile["longitude"] as? NSNumber)?.doubleValue ?? 0
        let coordinate = CLLocationCoordinate2D(latitude: lat, longitude: lon)
        return CLLocationCoordinate2DIsValid(coordinate) && !(lat == 0 && lon == 0) ? coordinate : nil
    }

    private func hopRole(for id: String) -> UnifiedHopRole {
        let ids = displayedMapIDs
        if ids.first == id { return .entry }
        if ids.last == id { return .exit }
        if ids.contains(id) { return .hop }
        let selectedIndex = routerPopup.indexOfSelectedItem
        if selectedIndex >= 0 && selectedIndex < routerIDs.count && routerIDs[selectedIndex] == id { return .selected }
        if let profile = profiles.first(where: { ($0["id"] as? String) == id }), (profile["node_kind"] as? String ?? "router-vpn").lowercased() == "external" { return .external }
        return .normal
    }

    private func color(for role: UnifiedHopRole) -> NSColor {
        switch role { case .selected: return .systemPurple; case .entry: return .systemBlue; case .hop: return .systemGreen; case .exit: return .systemOrange; case .external: return .systemPink; case .normal: return .systemTeal }
    }

    private func mapColor(at index: Int, count: Int) -> NSColor {
        if index == 0 { return .systemBlue }
        if index == count - 1 { return .systemOrange }
        let colors: [NSColor] = [.systemGreen, .systemPurple, .systemYellow, .systemTeal, .systemPink, .systemIndigo]
        return colors[(index - 1) % colors.count]
    }

    private func styleMapNode(_ view: MKMarkerAnnotationView, id: String, ids: [String]) {
        if let index = ids.firstIndex(of: id) {
            view.markerTintColor = mapColor(at: index, count: ids.count)
            view.glyphText = String(index + 1)
        } else {
            view.markerTintColor = color(for: hopRole(for: id))
            view.glyphText = nil
        }
    }

    func refreshUnifiedHopOverlay() {
        let ids = displayedMapIDs
        RouterVPNVectorMap.clearRoutes(on: map)
        for node in map.annotations.compactMap({ $0 as? RouterAnnotation }) {
            if let view = map.view(for: node) as? MKMarkerAnnotationView { styleMapNode(view, id: node.routerID, ids: ids) }
        }
        for (index, pair) in zip(ids, ids.dropFirst()).enumerated() {
            func coordinate(_ id: String) -> CLLocationCoordinate2D? {
                if activeMapNodeIDs != nil { return activeMapCoordinate(id) }
                return profiles.first(where: { $0["id"] as? String == id }).flatMap(Self.unifiedMapCoordinate)
            }
            guard let first = coordinate(pair.0), let second = coordinate(pair.1) else { continue }
            let lines = RouterVPNVectorMap.routes(from: first, to: second)
            for line in lines { line.subtitle = String(index + 1) }
            map.addOverlays(lines, level: .aboveLabels)
        }
    }

    func mapView(_ mapView: MKMapView, viewFor annotation: MKAnnotation) -> MKAnnotationView? {
        guard let node = annotation as? RouterAnnotation else { return nil }
        let reuse = "RouterNode"
        let view = (mapView.dequeueReusableAnnotationView(withIdentifier: reuse) as? MKMarkerAnnotationView) ?? MKMarkerAnnotationView(annotation: annotation, reuseIdentifier: reuse)
        view.annotation = annotation; view.canShowCallout = true; styleMapNode(view, id: node.routerID, ids: displayedMapIDs); return view
    }

    func selectUnifiedMapNode(_ nodeID: String) -> Bool {
        guard let index = routerIDs.firstIndex(of: nodeID) else { return false }
        if routerPopup.indexOfSelectedItem == index { return true }
        guard ensureMutationIdle("selecting a map node") else { return false }
        routerPopup.selectItem(at: index)
        nodePopup.selectItem(at: index)
        // The existing controller transaction rechecks idle state and saves the
        // selection. A marker tap never invokes Connect or changes a live path.
        selectRouter()
        return true
    }

    func mapView(_ mapView: MKMapView, didSelect view: MKAnnotationView) {
        guard let node = view.annotation as? RouterAnnotation else { return }
        if !selectUnifiedMapNode(node.routerID) { mapView.deselectAnnotation(node, animated: false) }
    }

    func mapView(_ mapView: MKMapView, rendererFor overlay: MKOverlay) -> MKOverlayRenderer {
        if let base = overlay as? RouterVPNVectorMapOverlay { return RouterVPNVectorMapRenderer(overlay: base) }
        guard let line = overlay as? MKPolyline else { return MKOverlayRenderer(overlay: overlay) }
        let renderer = MKPolylineRenderer(polyline: line); renderer.strokeColor = mapColor(at: Int(line.subtitle ?? "") ?? 0, count: displayedMapIDs.count); renderer.lineWidth = 4; renderer.lineCap = .round; renderer.lineJoin = .round; return renderer
    }
}

// Shipping unified UX markers:
// map-first bottom control sheet Connect Disconnect quick kill switch Multihop Settings Mode DNS
// SMART AUTO default AUTO first-class all logical presets unavailable reasons CUSTOM visual preset builder
// Router node Custom external real coordinates color-coded hop overlay DAITA-like traffic padding IPv6 MTU Retest Jumbo forwarding
