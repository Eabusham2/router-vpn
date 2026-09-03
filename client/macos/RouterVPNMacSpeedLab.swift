import AppKit
import Foundation
import ObjectiveC

private var macSpeedLabButtonKey: UInt8 = 0
private var macSpeedLabControllerKey: UInt8 = 0

private final class RouterVPNMacSpeedLabController: NSWindowController {
    private weak var product: ProductWindowController?
    private let api: ProductAPI
    private let scope = NSPopUpButton()
    private let topology = NSPopUpButton()
    private let node = NSPopUpButton()
    private let entry = NSPopUpButton()
    private let exit = NSPopUpButton()
    private let mode = NSPopUpButton()
    private let base = NSPopUpButton()
    private let exitMode = NSPopUpButton()
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

    init(api: ProductAPI, product: ProductWindowController) {
        self.api = api
        self.product = product
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 950, height: 740), styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        window.title = "Router VPN Speed Lab"
        window.minSize = NSSize(width: 760, height: 600)
        super.init(window: window)
        buildUI()
        loadOptions()
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

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
        exitMode.addItems(withTitles: ["Shadowsocks", "Hysteria2"]); exitMode.item(at: 0)?.representedObject = "shadowsocks"; exitMode.item(at: 1)?.representedObject = "hysteria2"
        durationMode.addItems(withTitles: ["Auto timing", "Custom timing"]); durationMode.item(at: 0)?.representedObject = "auto"; durationMode.item(at: 1)?.representedObject = "custom"
        minTime.numberOfTickMarks = 60; minTime.allowsTickMarkValuesOnly = true; maxTime.numberOfTickMarks = 60; maxTime.allowsTickMarkValuesOnly = true

        let grid = NSGridView(views: [
            [label("Test"), scope, label("Topology"), topology, label("Mode"), mode],
            [label("Node / exit"), node, label("Entry"), entry, label("Exit"), exit],
            [label("Base"), base, label("Exit transport"), exitMode, label("CUSTOM layers"), layers],
            [label("Duration"), durationMode, minLabel, minTime, maxLabel, maxTime]
        ])
        grid.rowSpacing = 7; grid.columnSpacing = 8; root.addArrangedSubview(grid)
        let flags = NSStackView(views: [daita, jumbo, encrypted, obfuscated]); flags.orientation = .horizontal; flags.spacing = 14; root.addArrangedSubview(flags)

        detail.isEditable = false; detail.isRichText = false; detail.font = .monospacedSystemFont(ofSize: 11, weight: .regular); detail.string = "Ready. Temporary configurations require Router VPN to be disconnected."
        let scroll = NSScrollView(); scroll.hasVerticalScroller = true; scroll.borderType = .bezelBorder; scroll.documentView = detail; scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 150).isActive = true; root.addArrangedSubview(scroll)

        let actions = NSStackView(); actions.orientation = .horizontal; actions.spacing = 8; actions.addArrangedSubview(status); let spacer = NSView(); spacer.setContentHuggingPriority(.defaultLow, for: .horizontal); actions.addArrangedSubview(spacer); runButton.target = self; runButton.action = #selector(runSpeedLab); runButton.bezelStyle = .rounded; actions.addArrangedSubview(runButton); let close = NSButton(title: "Close", target: self, action: #selector(closePanel)); actions.addArrangedSubview(close); root.addArrangedSubview(actions)

        scope.target = self; scope.action = #selector(refreshControls); topology.target = self; topology.action = #selector(refreshControls); mode.target = self; mode.action = #selector(refreshControls); durationMode.target = self; durationMode.action = #selector(refreshControls); minTime.target = self; minTime.action = #selector(timeChanged); maxTime.target = self; maxTime.action = #selector(timeChanged)
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

    private func loadOptions() {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            do {
                let root = try self.api.json("/api/speed-lab/options", timeout: 10) as? [String: Any] ?? [:]
                let nodeValues = root["nodes"] as? [[String: Any]] ?? []
                let modes = root["logical_modes"] as? [[String: Any]] ?? []
                DispatchQueue.main.async {
                    self.nodes = nodeValues; self.populate(self.node, values: nodeValues); self.populate(self.entry, values: nodeValues); self.populate(self.exit, values: nodeValues, kind: "router-vpn")
                    self.mode.removeAllItems(); for m in modes { let id=m["id"] as? String ?? ""; if id.isEmpty { continue }; self.mode.addItem(withTitle: m["name"] as? String ?? id); self.mode.lastItem?.representedObject=id }; if let idx=(0..<self.mode.numberOfItems).first(where:{ self.mode.item(at:$0)?.representedObject as? String == "smart-auto" }) { self.mode.selectItem(at: idx) }
                    self.refreshControls()
                }
            } catch { DispatchQueue.main.async { self.detail.string = "Could not load Speed Lab options: \(error.localizedDescription)"; self.runButton.isEnabled = false } }
        }
    }

    @objc private func refreshControls() {
        let temporary = selected(scope) == "temporary"
        let controls: [NSControl] = [topology,node,entry,exit,mode,base,exitMode,layers,daita,jumbo,encrypted,obfuscated]
        controls.forEach { $0.isEnabled = temporary }
        let top = selected(topology); entry.isEnabled = temporary && (top == "multihop" || top == "external"); exit.isEnabled = temporary && top == "multihop"; exitMode.isEnabled = temporary && top == "multihop"; layers.isEnabled = temporary && selected(mode) == "custom"
        let customTime = selected(durationMode) == "custom"; minTime.isEnabled = customTime; maxTime.isEnabled = customTime
    }

    @objc private func timeChanged() {
        if minTime.doubleValue > maxTime.doubleValue { maxTime.doubleValue = minTime.doubleValue }
        if maxTime.doubleValue < minTime.doubleValue { minTime.doubleValue = maxTime.doubleValue }
        minLabel.stringValue = String(format: "Min %.0f s", minTime.doubleValue); maxLabel.stringValue = String(format: "Max %.0f s", maxTime.doubleValue)
    }

    private func requestBody() -> [String: Any] {
        var body: [String: Any] = ["scope": selected(scope), "duration_mode": selected(durationMode)]
        if selected(durationMode) == "custom" { body["min_seconds"] = minTime.doubleValue; body["max_seconds"] = maxTime.doubleValue }
        if selected(scope) == "temporary" {
            body["topology"] = selected(topology); body["node_id"] = selected(node); body["entry_id"] = selected(entry); body["exit_id"] = selected(exit); body["mode"] = selected(mode); body["base"] = selected(base); body["exit_mode"] = selected(exitMode)
            if selected(mode) == "custom" { body["custom_layers"] = layers.stringValue.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty } }
            body["daita"] = daita.state == .on; body["jumbo"] = jumbo.state == .on; body["require_encrypted"] = encrypted.state == .on; body["require_obfuscation"] = obfuscated.state == .on
        }
        return body
    }

    @objc private func runSpeedLab() {
        let body = requestBody(); let maxSeconds = selected(durationMode) == "custom" ? maxTime.doubleValue : 12
        runButton.isEnabled = false; status.stringValue = "Building/proving path and measuring…"; detail.string = "Speed Lab running. Temporary path state will be restored after completion."
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            do {
                let data = try self.api.request("/api/speed-lab/run", method: "POST", body: body, timeout: max(100, maxSeconds * 2 + 80))
                guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any], let summary = root["summary"] as? [String: Any], let measurement = root["measurement"] as? [String: Any] else { throw NSError(domain: "RouterVPNSpeedLab", code: 1, userInfo: [NSLocalizedDescriptionKey: "Speed Lab returned invalid JSON."]) }
                let down = measurement["download"] as? [String: Any] ?? [:], up = measurement["upload"] as? [String: Any] ?? [:], idleStats = measurement["idle_latency"] as? [String: Any] ?? [:]
                let downLoaded = down["loaded_latency"] as? [String: Any] ?? [:], upLoaded = up["loaded_latency"] as? [String: Any] ?? [:]
                let pretty = String(data: try JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys]), encoding: .utf8) ?? ""
                DispatchQueue.main.async {
                    self.idle.stringValue = String(format: "%.1f ms", (summary["idle_ms"] as? NSNumber)?.doubleValue ?? 0); self.download.stringValue = String(format: "%.1f Mbps", (summary["download_mbps"] as? NSNumber)?.doubleValue ?? 0); self.upload.stringValue = String(format: "%.1f Mbps", (summary["upload_mbps"] as? NSNumber)?.doubleValue ?? 0)
                    self.idleDetail.stringValue = String(format: "p90 %.1f • max %.1f • jitter %.1f ms", (idleStats["p90_ms"] as? NSNumber)?.doubleValue ?? 0, (idleStats["max_ms"] as? NSNumber)?.doubleValue ?? 0, (idleStats["jitter_ms"] as? NSNumber)?.doubleValue ?? 0)
                    self.downloadDetail.stringValue = String(format: "loaded %.1f ms • +%.1f bloat • p90 %.1f", (summary["download_loaded_ms"] as? NSNumber)?.doubleValue ?? 0, (summary["download_bufferbloat_ms"] as? NSNumber)?.doubleValue ?? 0, (downLoaded["p90_ms"] as? NSNumber)?.doubleValue ?? 0)
                    self.uploadDetail.stringValue = String(format: "loaded %.1f ms • +%.1f bloat • p90 %.1f", (summary["upload_loaded_ms"] as? NSNumber)?.doubleValue ?? 0, (summary["upload_bufferbloat_ms"] as? NSNumber)?.doubleValue ?? 0, (upLoaded["p90_ms"] as? NSNumber)?.doubleValue ?? 0)
                    self.detail.string = pretty; self.status.stringValue = "Finished • \((root["path"] as? [String:Any])?["topology"] as? String ?? "path") • \(measurement["provider"] as? String ?? "Speed Lab")"; self.runButton.isEnabled = true
                }
            } catch { DispatchQueue.main.async { self.detail.string = error.localizedDescription; self.status.stringValue = "Speed Lab failed closed; see details."; self.runButton.isEnabled = true } }
        }
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
