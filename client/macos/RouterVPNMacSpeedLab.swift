import AppKit
import Foundation
import CoreFoundation
import ObjectiveC

private var macSpeedLabButtonKey: UInt8 = 0
private var macSpeedLabControllerKey: UInt8 = 0

private enum RouterVPNMacSpeedLabPathPolicy {
    static func activeSelection(_ selection: RouterVPNConnectionProfileSelection) -> RouterVPNConnectionProfileSelection {
        var value = selection
        if !value.multihopEnabled {
            value.entryID = ""; value.exitID = ""; value.exitMode = ""; value.execution = ""
            value.profileTokens = value.profileTokens.filter { $0.key == value.selectedNodeID }
        }
        return value
    }
    static func find(_ values: [[String: Any]], _ id: String) -> [String: Any]? {
        guard !id.isEmpty else { return nil }
        let matches = values.filter { $0["id"] as? String == id }
        return matches.count == 1 ? matches[0] : nil
    }
    static func kind(_ node: [String: Any]?) -> String { node == nil ? "" : (node?["node_kind"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? "router-vpn" }
    static func entryMode(_ node: [String: Any]?, _ entry: [String: Any]?) -> String {
        guard kind(entry) == "router-vpn" else { return "" }
        if node?["multihop_entry_id"] as? String == entry?["id"] as? String, let saved = node?["multihop_entry_mode"] as? String, !saved.isEmpty { return saved }
        var base = entry?["base_tunnel"] as? String ?? ""
        if !["wg", "awg"].contains(base) { base = node?["base_tunnel"] as? String ?? "" }
        return base == "awg" ? "awg2-fast" : "wg"
    }
    static func serverReady(_ node: [String: Any]) -> Bool {
        guard node["has_response_probe"] as? Bool == true else { return false }
        let proto = node["external_protocol"] as? String ?? ""
        if ["wireguard", "amneziawg"].contains(proto) { return node["has_server_peer"] as? Bool == true }
        if proto == "openvpn" { return node["has_openvpn_pairing"] as? Bool == true }
        return ["shadowsocks", "hysteria2", "socks5", "http-connect", "https-connect"].contains(proto)
    }
    static func validate(nodes: [[String: Any]], entryModes: [[String: Any]], executions: [[String: Any]],
                         topology: String, nodeID: String, entryID: String, exitID: String, entryMode: String, execution: String) throws {
        func reject(_ text: String) throws { throw NSError(domain: "RouterVPNSpeedLab", code: 1, userInfo: [NSLocalizedDescriptionKey: text]) }
        if topology == "system-direct" { return }
        let node = find(nodes, nodeID), entry = find(nodes, entryID)
        if topology == "router" { if kind(node) != "router-vpn" { try reject("Select a linked Router VPN node.") }; return }
        if topology == "multihop" {
            if kind(entry) != "router-vpn" || kind(find(nodes, exitID)) != "router-vpn" || entryID == exitID { try reject("Select two different linked Router VPN nodes.") }
        } else if topology == "external" {
            guard let node, kind(node) == "external" else { try reject("Select a linked external exit."); return }
            if !entryID.isEmpty && (entry == nil || entryID == nodeID) { try reject("Select a different linked entry, or Direct.") }
            if kind(entry) == "router-vpn" {
                if find(entryModes, entryMode) == nil { try reject("Select a supported Router entry mode.") }
                if execution != "local" && !serverReady(node) { try reject("Server/Compare requires this exit's response probe and independent server pairing where required.") }
            } else if execution != "local" { try reject("Direct and ordinary external entry paths use Local execution.") }
        } else { try reject("Select a supported test topology.") }
        if !["local", "server", "auto"].contains(execution) || find(executions, execution) == nil { try reject("Select Local, Server, or Compare both from current capabilities.") }
    }
}

private final class RouterVPNMacSpeedLabController: NSWindowController, NSWindowDelegate {
    private weak var product: ProductWindowController?
    private let api: ProductAPI
    private let capturedSelection: RouterVPNConnectionProfileSelection
    private let selectionGeneration: UUID
    private let scope = NSPopUpButton()
    private let topology = NSPopUpButton()
    private let node = NSPopUpButton()
    private let entry = NSPopUpButton()
    private let exit = NSPopUpButton()
    private let mode = NSPopUpButton()
    private let base = NSPopUpButton()
    private let exitMode = NSPopUpButton()
    private let entryMode = NSPopUpButton()
    private let execution = NSPopUpButton()
    private let layers = NSTextField(string: "")
    private let durationMode = NSPopUpButton()
    private let minTime = NSSlider(value: 4, minValue: 1, maxValue: 60, target: nil, action: nil)
    private let maxTime = NSSlider(value: 12, minValue: 1, maxValue: 60, target: nil, action: nil)
    private let minLabel = NSTextField(labelWithString: "Min 4 s")
    private let maxLabel = NSTextField(labelWithString: "Max 12 s")
    private let daita = NSButton(checkboxWithTitle: "DAITA-like", target: nil, action: nil)
    private let jumbo = NSButton(checkboxWithTitle: "Jumbo", target: nil, action: nil)
    private let encrypted = NSButton(checkboxWithTitle: "Require encrypted AUTO", target: nil, action: nil)
    private let obfuscated = NSButton(checkboxWithTitle: "Require obfuscation AUTO", target: nil, action: nil)
    private let idle = NSTextField(labelWithString: "-- ms")
    private let download = NSTextField(labelWithString: "-- Mbps")
    private let upload = NSTextField(labelWithString: "-- Mbps")
    private let idleDetail = NSTextField(labelWithString: "p90 / max / jitter after test")
    private let downloadDetail = NSTextField(labelWithString: "loaded -- ms")
    private let uploadDetail = NSTextField(labelWithString: "loaded -- ms")
    private let status = NSTextField(labelWithString: "Cloudflare Speed Test edge • no Mbps derived from RTT")
    private let detail = NSTextView()
    private let runButton = NSButton(title: "Run Speed Lab", target: nil, action: nil)
    private var nodes: [[String: Any]] = []
    private var entryModes: [[String: Any]] = []
    private var exitModes: [String] = []
    private var currentPath: [String: Any] = [:]
    private var executions: [[String: Any]] = []
    private var updatingChoices = false
    private var optionsReady = false
    private var closed = false
    private var cancelled = false
    private var loadingOptions = false
    private var generation: UInt64 = 0
    private var request: RouterVPNMacSpeedLabTransport?

    init(api: ProductAPI, product: ProductWindowController) {
        self.api = api
        self.product = product
        self.capturedSelection = RouterVPNMacSpeedLabPathPolicy.activeSelection(product.captureConnectionProfileSelection())
        self.selectionGeneration = product.connectionProfileSelectionGeneration
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 950, height: 740), styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        window.title = "Router VPN Speed Lab"
        window.minSize = NSSize(width: 760, height: 600)
        super.init(window: window)
        window.delegate = self
        buildUI()
        loadOptions()
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    deinit { request?.cancel() }

    private func label(_ value: String) -> NSTextField {
        let v = NSTextField(labelWithString: value)
        v.textColor = .secondaryLabelColor
        return v
    }

    private func popup(_ items: [(String, String)]) -> NSPopUpButton {
        let p = NSPopUpButton()
        for (title, value) in items { p.addItem(withTitle: title); p.lastItem?.representedObject = value }
        return p
    }

    private func selected(_ popup: NSPopUpButton) -> String {
        popup.selectedItem?.representedObject as? String ?? ""
    }

    private func buildUI() {
        guard let content = window?.contentView else { return }
        let root = NSStackView(); root.orientation = .vertical; root.spacing = 12; root.edgeInsets = NSEdgeInsets(top: 20, left: 20, bottom: 20, right: 20); root.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(root)
        NSLayoutConstraint.activate([root.leadingAnchor.constraint(equalTo: content.leadingAnchor), root.trailingAnchor.constraint(equalTo: content.trailingAnchor), root.topAnchor.constraint(equalTo: content.topAnchor), root.bottomAnchor.constraint(equalTo: content.bottomAnchor)])

        let eyebrow = NSTextField(labelWithString: "SPEED LAB"); eyebrow.textColor = .systemCyan; eyebrow.font = .systemFont(ofSize: 12, weight: .semibold)
        let title = NSTextField(labelWithString: "Router VPN path performance"); title.font = .systemFont(ofSize: 28, weight: .bold)
        let subtitle = NSTextField(wrappingLabelWithString: "Real HTTPS throughput plus idle, download-loaded and upload-loaded latency. Current path is the default; Temporary builds a proven test-only path and restores saved settings afterward."); subtitle.textColor = .secondaryLabelColor
        root.addArrangedSubview(eyebrow); root.addArrangedSubview(title); root.addArrangedSubview(subtitle)

        for value in [idle, download, upload] { value.font = .monospacedDigitSystemFont(ofSize: 26, weight: .bold) }
        let cards = NSStackView(); cards.orientation = .horizontal; cards.distribution = .fillEqually; cards.spacing = 10
        func card(_ heading: String, _ big: NSTextField, _ small: NSTextField) -> NSView {
            let box = NSBox(); box.boxType = .custom; box.cornerRadius = 12; box.borderColor = .separatorColor; box.fillColor = NSColor.controlBackgroundColor.withAlphaComponent(0.7); box.contentViewMargins = NSSize(width: 12, height: 12)
            let stack = NSStackView(); stack.orientation = .vertical; stack.spacing = 4; let h = label(heading); h.font = .systemFont(ofSize: 11, weight: .semibold); small.textColor = .secondaryLabelColor; stack.addArrangedSubview(h); stack.addArrangedSubview(big); stack.addArrangedSubview(small); box.contentView = stack; return box
        }
        cards.addArrangedSubview(card("IDLE LATENCY", idle, idleDetail)); cards.addArrangedSubview(card("DOWNLOAD", download, downloadDetail)); cards.addArrangedSubview(card("UPLOAD", upload, uploadDetail)); root.addArrangedSubview(cards)

        scope.addItems(withTitles: ["Current path", "Temporary config"]); scope.item(at: 0)?.representedObject = "current"; scope.item(at: 1)?.representedObject = "temporary"
        topology.addItems(withTitles: ["System direct", "Router VPN node", "Multihop", "External exit / hop"]); for (i, value) in ["system-direct","router","multihop","external"].enumerated() { topology.item(at: i)?.representedObject = value }; topology.selectItem(at: 1)
        base.addItems(withTitles: ["Auto", "WireGuard", "AmneziaWG"]); for (i, value) in ["auto","wg","awg"].enumerated() { base.item(at: i)?.representedObject = value }
        for choice in RouterVPNNodeExitModes.choices { exitMode.addItem(withTitle: choice.title); exitMode.lastItem?.representedObject = choice.id }
        durationMode.addItems(withTitles: ["Auto timing", "Custom timing"]); durationMode.item(at: 0)?.representedObject = "auto"; durationMode.item(at: 1)?.representedObject = "custom"
        minTime.numberOfTickMarks = 60; minTime.allowsTickMarkValuesOnly = true; maxTime.numberOfTickMarks = 60; maxTime.allowsTickMarkValuesOnly = true

        let grid = NSGridView(views: [
            [label("Test"), scope, label("Topology"), topology, label("Mode"), mode],
            [label("Node / exit"), node, label("Entry"), entry, label("Exit"), exit],
            [label("Base"), base, label("Exit transport"), exitMode, label("CUSTOM layers"), layers],
            [label("Entry mode"), entryMode, label("Execution"), execution, label(""), NSView()],
            [label("Duration"), durationMode, minLabel, minTime, maxLabel, maxTime]
        ])
        grid.rowSpacing = 7; grid.columnSpacing = 8; root.addArrangedSubview(grid)
        let flags = NSStackView(views: [daita, jumbo, encrypted, obfuscated]); flags.orientation = .horizontal; flags.spacing = 14; root.addArrangedSubview(flags)

        detail.isEditable = false; detail.isRichText = false; detail.font = .monospacedSystemFont(ofSize: 11, weight: .regular); detail.string = "Ready. Temporary tests capture and restore the complete connected path and its proved execution choice."
        let scroll = NSScrollView(); scroll.hasVerticalScroller = true; scroll.borderType = .bezelBorder; scroll.documentView = detail; scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 150).isActive = true; root.addArrangedSubview(scroll)

        let actions = NSStackView(); actions.orientation = .horizontal; actions.spacing = 8; actions.addArrangedSubview(status); let spacer = NSView(); spacer.setContentHuggingPriority(.defaultLow, for: .horizontal); actions.addArrangedSubview(spacer); runButton.target = self; runButton.action = #selector(runSpeedLab); runButton.bezelStyle = .rounded; actions.addArrangedSubview(runButton); let close = NSButton(title: "Close", target: self, action: #selector(closePanel)); actions.addArrangedSubview(close); root.addArrangedSubview(actions)

        scope.target = self; scope.action = #selector(refreshControls); topology.target = self; topology.action = #selector(pathChanged(_:)); node.target = self; node.action = #selector(pathChanged(_:)); entry.target = self; entry.action = #selector(pathChanged(_:)); mode.target = self; mode.action = #selector(refreshControls); durationMode.target = self; durationMode.action = #selector(refreshControls); minTime.target = self; minTime.action = #selector(timeChanged); maxTime.target = self; maxTime.action = #selector(timeChanged)
        execution.toolTip = "Server/Compare requires a Router entry, this exit’s response probe, and separate packet/OpenVPN pairing. The controller proves the captured path before testing."
        refreshControls(); timeChanged()
    }

    private func populate(_ popup: NSPopUpButton, values: [[String: Any]], kind: String? = nil) {
        popup.removeAllItems()
        for item in values {
            let nodeKind = ((item["node_kind"] as? String) ?? "router-vpn").lowercased()
            if let kind, nodeKind != kind { continue }
            let id = item["id"] as? String ?? ""; guard !id.isEmpty else { continue }
            let name = item["name"] as? String ?? id
            let ms = (item["latency_trimmed_mean_ms"] as? NSNumber)?.doubleValue ?? 0
            popup.addItem(withTitle: ms > 0 ? String(format: "%@ • %.1f ms", name, ms) : name); popup.lastItem?.representedObject = id
        }
        if popup.numberOfItems > 0 { popup.selectItem(at: 0) }
    }

    private func selectPreserving(_ popup: NSPopUpButton, _ id: String) {
        if let index = (0..<popup.numberOfItems).first(where: { popup.item(at: $0)?.representedObject as? String == id }) { popup.selectItem(at: index) }
        else { popup.addItem(withTitle: "Unavailable saved choice: \(id)"); popup.lastItem?.representedObject = id; popup.selectItem(at: popup.numberOfItems - 1) }
    }

    private func validateCapturedSelection(_ options: [String: Any]) throws {
        func reject(_ reason: String) throws { throw NSError(domain: "RouterVPNSpeedLab", code: 1, userInfo: [NSLocalizedDescriptionKey: reason]) }
        guard let product, product.connectionProfileSelectionGeneration == selectionGeneration,
            RouterVPNMacSpeedLabPathPolicy.activeSelection(product.captureConnectionProfileSelection()) == capturedSelection else {
            try reject("The visible connection profile changed while Speed Lab loaded. Reopen Speed Lab for that selection."); return
        }
        let catalog = options["nodes"] as? [[String: Any]] ?? []
        if !capturedSelection.selectedNodeID.isEmpty {
            let selected = catalog.filter { $0["selected"] as? Bool == true }
            guard selected.count == 1, selected[0]["id"] as? String == capturedSelection.selectedNodeID,
                RouterVPNMacSpeedLabPathPolicy.find(catalog, capturedSelection.selectedNodeID) != nil else {
                try reject("The selected node changed or disappeared while Speed Lab loaded. Reopen Speed Lab."); return
            }
        }
        for (id, token) in capturedSelection.profileTokens where !token.isEmpty {
            guard let node = RouterVPNMacSpeedLabPathPolicy.find(catalog, id), node["profile_token"] as? String == token else {
                try reject("A captured node was removed or relinked while Speed Lab loaded. Reopen Speed Lab for its current identity."); return
            }
        }
    }

    private func applyCapturedSelection() throws {
        guard capturedSelection.multihopEnabled else { return }
        guard RouterVPNMacSpeedLabPathPolicy.kind(RouterVPNMacSpeedLabPathPolicy.find(nodes, capturedSelection.selectedNodeID)) == "router-vpn" else {
            throw NSError(domain: "RouterVPNSpeedLab", code: 1, userInfo: [NSLocalizedDescriptionKey: "The captured multihop profile no longer belongs to a linked Router VPN node."])
        }
        updatingChoices = true; defer { updatingChoices = false }
        selectPreserving(topology, "multihop"); selectPreserving(node, capturedSelection.selectedNodeID)
        selectPreserving(entry, capturedSelection.entryID); selectPreserving(exit, capturedSelection.exitID)
        selectPreserving(exitMode, capturedSelection.exitMode); selectPreserving(execution, capturedSelection.execution)
    }

    private func applyPathDefaults() {
        guard !updatingChoices, let value = RouterVPNMacSpeedLabPathPolicy.find(nodes, selected(node)) else { return }
        updatingChoices = true; defer { updatingChoices = false }
        let saved = value["multihop_enabled"] as? Bool == true
        let rawBase = value["base_tunnel"] as? String ?? ""
        selectPreserving(base, rawBase.isEmpty ? "auto" : rawBase)
        let top = selected(topology)
        if top == "external" {
            selectPreserving(entry, saved ? value["multihop_entry_id"] as? String ?? "" : "")
            let choice = saved ? value["multihop_execution"] as? String ?? "local" : "local"
            selectPreserving(execution, choice.isEmpty ? "local" : choice)
            setEntryModeDefault()
        } else if top == "multihop" {
            let savedEntry = saved ? value["multihop_entry_id"] as? String ?? "" : ""
            selectPreserving(entry, savedEntry.isEmpty ? selected(node) : savedEntry)
            if saved, let id = value["multihop_exit_id"] as? String, !id.isEmpty { selectPreserving(exit, id) }
            if currentPath["entry_id"] as? String == selected(entry), currentPath["exit_id"] as? String == selected(exit), let mode = currentPath["exit_mode"] as? String { selectPreserving(exitMode, mode) }
            let choice = saved ? value["multihop_execution"] as? String ?? "local" : "local"
            selectPreserving(execution, choice.isEmpty ? "local" : choice)
        }
    }

    private func setEntryModeDefault() {
        let value = RouterVPNMacSpeedLabPathPolicy.entryMode(RouterVPNMacSpeedLabPathPolicy.find(nodes, selected(node)), RouterVPNMacSpeedLabPathPolicy.find(nodes, selected(entry)))
        if value.isEmpty { entryMode.selectItem(at: -1) } else { selectPreserving(entryMode, value) }
    }

    @objc private func pathChanged(_ sender: NSPopUpButton) {
        guard !updatingChoices else { return }
        if sender === entry {
            updatingChoices = true; setEntryModeDefault()
            if RouterVPNMacSpeedLabPathPolicy.kind(RouterVPNMacSpeedLabPathPolicy.find(nodes, selected(entry))) != "router-vpn" { selectPreserving(execution, "local") }
            updatingChoices = false
        } else {
            if sender === topology {
                let kind = selected(topology) == "external" ? "external" : "router-vpn"
                if RouterVPNMacSpeedLabPathPolicy.kind(RouterVPNMacSpeedLabPathPolicy.find(nodes, selected(node))) != kind {
                    if let first = nodes.first(where: { RouterVPNMacSpeedLabPathPolicy.kind($0) == kind }), let id = first["id"] as? String { selectPreserving(node, id) }
                    else { node.selectItem(at: -1) }
                }
            }
            applyPathDefaults()
        }
        refreshControls()
    }

    private func performLocalRequest(_ path: String, body: [String: Any]?, timeout: TimeInterval, completion: @escaping (Result<Data, Error>) -> Void) throws {
        guard !closed, request == nil, let url = URL(string: path, relativeTo: routerVPNProductBaseURL)?.absoluteURL else { throw NSError(domain: "RouterVPNSpeedLab", code: 1, userInfo: [NSLocalizedDescriptionKey: "Another Speed Lab request is active."]) }
        generation &+= 1; let owner = generation; cancelled = false
        let transport = try RouterVPNMacSpeedLabTransport(url: url, body: body, timeout: timeout) { [weak self] result in
            DispatchQueue.main.async {
                guard let self, !self.closed, self.generation == owner else { return }
                self.request = nil; self.loadingOptions = false
                self.runButton.title = "Run Speed Lab"
                self.refreshControls()
                if self.cancelled {
                    self.status.stringValue = "Test request cancelled."
                    self.detail.string = "The controller owns teardown and restoration of the captured path. A replacement connection remains protected."
                    return
                }
                completion(result)
            }
        }
        request = transport; transport.start(); refreshControls()
    }

    private func loadOptions() {
        optionsReady = false; loadingOptions = true; status.stringValue = "Loading Speed Lab paths…"
        do {
            try performLocalRequest("/api/speed-lab/options", body: nil, timeout: 10) { [weak self] result in
                guard let self, !self.closed else { return }
                do {
                    let data = try result.get()
                    guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw NSError(domain: "RouterVPNSpeedLab", code: 1) }
                    try self.validateCapturedSelection(root)
                    self.updatingChoices = true
                    self.nodes = root["nodes"] as? [[String: Any]] ?? []
                    self.entryModes = root["router_vpn_entry_modes"] as? [[String: Any]] ?? []
                    self.exitModes = root["supported_exit_modes"] as? [String] ?? []
                    self.currentPath = root["current"] as? [String: Any] ?? [:]
                    self.executions = root["execution_choices"] as? [[String: Any]] ?? []
                    self.populate(self.node, values: self.nodes); self.populate(self.entry, values: self.nodes); self.populate(self.exit, values: self.nodes, kind: "router-vpn")
                    self.entry.insertItem(withTitle: "Direct / no entry", at: 0); self.entry.item(at: 0)?.representedObject = ""
                    self.populate(self.mode, values: root["logical_modes"] as? [[String: Any]] ?? [])
                    self.selectPreserving(self.mode, "smart-auto")
                    self.populate(self.entryMode, values: self.entryModes); self.populate(self.execution, values: self.executions); self.selectPreserving(self.execution, "local")
                    let selectedNodes = self.nodes.filter { $0["selected"] as? Bool == true }
                    if selectedNodes.count == 1, let id = selectedNodes[0]["id"] as? String { self.selectPreserving(self.node, id) }
                    let selectedNode = RouterVPNMacSpeedLabPathPolicy.find(self.nodes, self.selected(self.node))
                    self.selectPreserving(self.topology, RouterVPNMacSpeedLabPathPolicy.kind(selectedNode) == "external" ? "external" : selectedNode?["multihop_enabled"] as? Bool == true ? "multihop" : "router")
                    self.updatingChoices = false; self.applyPathDefaults(); try self.applyCapturedSelection(); self.optionsReady = true
                    self.status.stringValue = "Ready • current configuration selected; no saved preferences changed"
                    self.refreshControls()
                } catch {
                    self.updatingChoices = false; self.detail.string = "Could not load Speed Lab options: \(error.localizedDescription)"; self.status.stringValue = "Speed Lab options unavailable."; self.refreshControls()
                }
            }
        } catch { loadingOptions = false; detail.string = error.localizedDescription; refreshControls() }
    }

    @objc private func refreshControls() {
        let available = !closed && optionsReady && request == nil
        let temporary = available && selected(scope) == "temporary"
        let controls: [NSControl] = [topology,node,entry,exit,mode,base,exitMode,entryMode,execution,layers,daita,jumbo,encrypted,obfuscated]
        controls.forEach { $0.isEnabled = temporary }
        scope.isEnabled = available; durationMode.isEnabled = available
        runButton.isEnabled = !closed && (request != nil ? !loadingOptions && !cancelled : optionsReady)
        let top = selected(topology)
        entry.isEnabled = temporary && (top == "multihop" || top == "external")
        exit.isEnabled = temporary && top == "multihop"; exitMode.isEnabled = temporary && top == "multihop"
        layers.isEnabled = temporary && top == "router" && selected(mode) == "custom"
        mode.isEnabled = temporary && top == "router"; node.isEnabled = temporary && ["router", "external"].contains(top)
        base.isEnabled = temporary && ["router", "multihop"].contains(top)
        let routerEntry = RouterVPNMacSpeedLabPathPolicy.kind(RouterVPNMacSpeedLabPathPolicy.find(nodes, selected(entry))) == "router-vpn"
        entryMode.isEnabled = temporary && top == "external" && routerEntry
        execution.isEnabled = temporary && (top == "multihop" || top == "external" && routerEntry)
        let customTime = available && selected(durationMode) == "custom"; minTime.isEnabled = customTime; maxTime.isEnabled = customTime
    }

    @objc private func timeChanged() {
        if minTime.doubleValue > maxTime.doubleValue { maxTime.doubleValue = minTime.doubleValue }
        if maxTime.doubleValue < minTime.doubleValue { minTime.doubleValue = maxTime.doubleValue }
        minLabel.stringValue = String(format: "Min %.0f s", minTime.doubleValue); maxLabel.stringValue = String(format: "Max %.0f s", maxTime.doubleValue)
    }

    private func bindCapturedProfiles(_ request: [String: Any]) throws -> [String: Any] {
        var body = request
        var ids = Set(capturedSelection.profileTokens.keys)
        if !capturedSelection.selectedNodeID.isEmpty { ids.insert(capturedSelection.selectedNodeID) }
        if capturedSelection.multihopEnabled { ids.insert(capturedSelection.entryID); ids.insert(capturedSelection.exitID) }
        if body["scope"] as? String == "temporary" {
            if body["topology"] as? String != "system-direct" {
                for key in ["node_id", "entry_id", "exit_id"] { if let id = body[key] as? String, !id.isEmpty { ids.insert(id) } }
            }
        } else if currentPath["connected"] as? Bool == true {
            for key in ["router_id", "entry_id", "exit_id"] { if let id = currentPath[key] as? String, !id.isEmpty { ids.insert(id) } }
        }
        var tokens: [String: String] = [:]
        for id in ids where !id.isEmpty {
            guard let record = RouterVPNMacSpeedLabPathPolicy.find(nodes, id), let token = record["profile_token"] as? String,
                token.count == 64, token.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
                throw NSError(domain: "RouterVPNSpeedLab", code: 1, userInfo: [NSLocalizedDescriptionKey: "A test node has no current identity. Reopen Speed Lab before running this path."])
            }
            tokens[id] = token
        }
        body["expected_selected_node_id"] = capturedSelection.selectedNodeID; body["expected_profile_tokens"] = tokens
        return body
    }

    private func requestBody() throws -> [String: Any] {
        try validateCapturedSelection(["nodes": nodes])
        var body: [String: Any] = ["scope": selected(scope), "duration_mode": selected(durationMode)]
        if selected(durationMode) == "custom" { body["min_seconds"] = minTime.doubleValue; body["max_seconds"] = maxTime.doubleValue }
        guard selected(scope) == "temporary" else { return try bindCapturedProfiles(body) }
        let top = selected(topology)
        try RouterVPNMacSpeedLabPathPolicy.validate(nodes: nodes, entryModes: entryModes, executions: executions, topology: top, nodeID: selected(node), entryID: selected(entry), exitID: selected(exit), entryMode: selected(entryMode), execution: selected(execution))
        body["topology"] = top
        if top == "system-direct" { return try bindCapturedProfiles(body) }
        if ["router", "external"].contains(top) { body["node_id"] = selected(node) }
        if top == "router" {
            body["mode"] = selected(mode); body["base"] = selected(base)
            if selected(mode) == "custom" { body["custom_layers"] = layers.stringValue.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty } }
        }
        if top == "multihop" {
            guard exitModes.contains(selected(exitMode)) else {
                throw NSError(domain: "RouterVPNSpeedLab", code: 1, userInfo: [NSLocalizedDescriptionKey: "Select an exit transport supported by the installed runtime."])
            }
            body["entry_id"] = selected(entry); body["exit_id"] = selected(exit); body["base"] = selected(base); body["exit_mode"] = selected(exitMode); body["execution"] = selected(execution)
        }
        if top == "external" {
            body["entry_id"] = selected(entry); body["execution"] = selected(execution)
            if RouterVPNMacSpeedLabPathPolicy.kind(RouterVPNMacSpeedLabPathPolicy.find(nodes, selected(entry))) == "router-vpn" { body["entry_mode"] = selected(entryMode) }
        }
        body["daita"] = daita.state == .on; body["jumbo"] = jumbo.state == .on; body["require_encrypted"] = encrypted.state == .on; body["require_obfuscation"] = obfuscated.state == .on
        return try bindCapturedProfiles(body)
    }

    private func hopSummary(_ root: [String: Any]) -> String {
        guard let hops = root["hops"] as? [[String: Any]], !hops.isEmpty else { return "" }
        let lines = hops.map { hop -> String in
            let role = ((hop["role"] as? String) ?? "hop").uppercased()
            let name = (hop["name"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? (hop["router_id"] as? String ?? "node")
            var latency = "RTT unavailable"
            if let stats = hop["latency"] as? [String: Any], let value = (stats["median_ms"] as? NSNumber)?.doubleValue {
                latency = String(format: "%.1f ms", value)
            } else if let reason = hop["latency_error"] as? String, !reason.isEmpty {
                latency = "RTT unavailable: \(reason)"
            }
            var speed = "speed unavailable"
            if let stats = hop["speed"] as? [String: Any], let down = (stats["download_mbps"] as? NSNumber)?.doubleValue, let up = (stats["upload_mbps"] as? NSNumber)?.doubleValue {
                speed = String(format: "↓ %.1f / ↑ %.1f Mbps", down, up)
            } else if let reason = hop["speed_error"] as? String, !reason.isEmpty {
                speed = "speed unavailable: \(reason)"
            }
            return "\(role) • \(name) • \(latency) • \(speed)"
        }
        return "PER-HOP — SAME PROVED GRAPH\n" + lines.joined(separator: "\n")
    }

    @objc private func runSpeedLab() {
        guard !closed else { return }
        if let request {
            if !loadingOptions { cancelled = true; request.cancel(); status.stringValue = "Cancelling test request…"; refreshControls() }
            return
        }
        guard optionsReady else { return }
        do {
            let body = try requestBody(); let maxSeconds = selected(durationMode) == "custom" ? maxTime.doubleValue : 12
            status.stringValue = "Building/proving path and measuring…"; detail.string = "Speed Lab running. The controller restores the complete captured path after a temporary test."
            for field in [idle,download,upload,idleDetail,downloadDetail,uploadDetail] { field.stringValue = "--" }
            runButton.title = "Cancel test"
            try performLocalRequest("/api/speed-lab/run", body: body, timeout: max(100, maxSeconds * 2 + 80)) { [weak self] result in
                guard let self else { return }
                do {
                let data = try result.get()
                guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any], root["ok"] as? Bool == true,
                      let summary = root["summary"] as? [String: Any], let measurement = root["measurement"] as? [String: Any],
                      ["idle_ms", "download_mbps", "upload_mbps", "download_loaded_ms", "upload_loaded_ms", "download_bufferbloat_ms", "upload_bufferbloat_ms"].allSatisfy({ key in
                          guard let value = summary[key] as? NSNumber, CFGetTypeID(value) != CFBooleanGetTypeID() else { return false }
                          return value.doubleValue.isFinite && value.doubleValue >= 0
                      }) else { throw NSError(domain: "RouterVPNSpeedLab", code: 1, userInfo: [NSLocalizedDescriptionKey: "Speed Lab returned an invalid measurement."]) }
                let down = measurement["download"] as? [String: Any] ?? [:], up = measurement["upload"] as? [String: Any] ?? [:], idleStats = measurement["idle_latency"] as? [String: Any] ?? [:]
                let downLoaded = down["loaded_latency"] as? [String: Any] ?? [:], upLoaded = up["loaded_latency"] as? [String: Any] ?? [:]
                let pretty = String(data: try JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys]), encoding: .utf8) ?? ""
                let hops = self.hopSummary(root)
                    self.idle.stringValue = String(format: "%.1f ms", (summary["idle_ms"] as? NSNumber)?.doubleValue ?? 0); self.download.stringValue = String(format: "%.1f Mbps", (summary["download_mbps"] as? NSNumber)?.doubleValue ?? 0); self.upload.stringValue = String(format: "%.1f Mbps", (summary["upload_mbps"] as? NSNumber)?.doubleValue ?? 0)
                    self.idleDetail.stringValue = String(format: "p90 %.1f • max %.1f • jitter %.1f ms", (idleStats["p90_ms"] as? NSNumber)?.doubleValue ?? 0, (idleStats["max_ms"] as? NSNumber)?.doubleValue ?? 0, (idleStats["jitter_ms"] as? NSNumber)?.doubleValue ?? 0)
                    self.downloadDetail.stringValue = String(format: "loaded %.1f ms • +%.1f bloat • p90 %.1f", (summary["download_loaded_ms"] as? NSNumber)?.doubleValue ?? 0, (summary["download_bufferbloat_ms"] as? NSNumber)?.doubleValue ?? 0, (downLoaded["p90_ms"] as? NSNumber)?.doubleValue ?? 0)
                    self.uploadDetail.stringValue = String(format: "loaded %.1f ms • +%.1f bloat • p90 %.1f", (summary["upload_loaded_ms"] as? NSNumber)?.doubleValue ?? 0, (summary["upload_bufferbloat_ms"] as? NSNumber)?.doubleValue ?? 0, (upLoaded["p90_ms"] as? NSNumber)?.doubleValue ?? 0)
                    self.detail.string = hops.isEmpty ? pretty : hops + "\n\nFULL RESULT\n" + pretty
                    let hopCount = (root["hops"] as? [[String: Any]])?.count ?? 0
                    let hopSuffix = hopCount > 0 ? " • \(hopCount) hop measurements" : ""
                    self.status.stringValue = "Finished • \((root["path"] as? [String:Any])?["topology"] as? String ?? "path") • \(measurement["provider"] as? String ?? "Speed Lab")\(hopSuffix)"
                } catch { self.detail.string = error.localizedDescription; self.status.stringValue = "Speed Lab failed closed; see details." }
            }
        } catch { runButton.title = "Run Speed Lab"; detail.string = error.localizedDescription; status.stringValue = "Speed Lab failed closed; see details."; refreshControls() }
    }

    func windowWillClose(_ notification: Notification) {
        closed = true; generation &+= 1; cancelled = true; request?.cancel(); request = nil
    }
    @objc private func closePanel() { close() }

}

extension ProductWindowController {
    func installUnifiedSpeedLabUI() {
        if objc_getAssociatedObject(self, &macSpeedLabButtonKey) != nil { return }
        guard let sheet = window?.contentView?.subviewsRecursive().first(where: { $0.identifier?.rawValue == "unified-sheet" }) else { return }
        let button = NSButton(title: "Speed Lab", target: self, action: #selector(openUnifiedSpeedLab))
        button.identifier = NSUserInterfaceItemIdentifier("unified-speed-lab")
        button.bezelStyle = .rounded; button.controlSize = .small; button.toolTip = "Ookla-style Router VPN test: real throughput plus idle/download-loaded/upload-loaded latency, current or temporary paths."
        button.translatesAutoresizingMaskIntoConstraints = false; sheet.addSubview(button)
        NSLayoutConstraint.activate([button.trailingAnchor.constraint(equalTo: sheet.trailingAnchor, constant: -18), button.topAnchor.constraint(equalTo: sheet.topAnchor, constant: 42)])
        objc_setAssociatedObject(self, &macSpeedLabButtonKey, button, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)
    }

    @objc func openUnifiedSpeedLab() {
        let controller = RouterVPNMacSpeedLabController(api: api, product: self)
        objc_setAssociatedObject(self, &macSpeedLabControllerKey, controller, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)
        controller.showWindow(nil); controller.window?.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
    }
}

private extension NSView {
    func subviewsRecursive() -> [NSView] { subviews + subviews.flatMap { $0.subviewsRecursive() } }
}
