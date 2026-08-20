import AppKit
import Foundation
import MapKit
import ObjectiveC

private var telemetryInstalledKey: UInt8 = 0
private var telemetryFastPopupKey: UInt8 = 0
private var telemetryLiveLabelKey: UInt8 = 0
private var telemetryHopLabelKey: UInt8 = 0
private var telemetryPerformanceControllerKey: UInt8 = 0

extension ProductWindowController {
    private func telemetryFind(_ id: String) -> NSView? {
        guard let content = window?.contentView else { return nil }
        func walk(_ view: NSView) -> NSView? {
            if view.identifier?.rawValue == id { return view }
            for child in view.subviews { if let found = walk(child) { return found } }
            return nil
        }
        return walk(content)
    }

    private var telemetryFastPopup: NSPopUpButton? {
        get { objc_getAssociatedObject(self, &telemetryFastPopupKey) as? NSPopUpButton }
        set { objc_setAssociatedObject(self, &telemetryFastPopupKey, newValue, .OBJC_ASSOCIATION_RETAIN_NONATOMIC) }
    }
    private var telemetryLiveLabel: NSTextField? {
        get { objc_getAssociatedObject(self, &telemetryLiveLabelKey) as? NSTextField }
        set { objc_setAssociatedObject(self, &telemetryLiveLabelKey, newValue, .OBJC_ASSOCIATION_RETAIN_NONATOMIC) }
    }
    private var telemetryHopLabel: NSTextField? {
        get { objc_getAssociatedObject(self, &telemetryHopLabelKey) as? NSTextField }
        set { objc_setAssociatedObject(self, &telemetryHopLabelKey, newValue, .OBJC_ASSOCIATION_RETAIN_NONATOMIC) }
    }

    func installUnifiedTelemetryUI() {
        if (objc_getAssociatedObject(self, &telemetryInstalledKey) as? Bool) == true { return }
        guard let connect = telemetryFind("unified-connect") as? NSButton, let connectRow = connect.superview as? NSStackView else { return }
        objc_setAssociatedObject(self, &telemetryInstalledKey, true, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)

        let fast = NSPopUpButton(frame: .zero, pullsDown: false)
        fast.identifier = NSUserInterfaceItemIdentifier("unified-fastest-node")
        fast.controlSize = .small
        fast.target = self
        fast.action = #selector(unifiedFastConnectChanged(_:))
        fast.toolTip = "Connect the fastest measured Router VPN node, or choose a node directly."
        telemetryFastPopup = fast
        connectRow.insertArrangedSubview(fast, at: min(1, connectRow.arrangedSubviews.count))

        let live = NSTextField(labelWithString: "-- ms")
        live.identifier = NSUserInterfaceItemIdentifier("unified-live-latency")
        live.font = .monospacedDigitSystemFont(ofSize: 12, weight: .semibold)
        live.textColor = .secondaryLabelColor
        live.alignment = .right
        live.toolTip = "Live RTT through the active private tunnel path."
        telemetryLiveLabel = live
        connectRow.addArrangedSubview(live)

        let forwarding = NSButton(title: "Forward", target: self, action: #selector(openUnifiedForwarding))
        forwarding.controlSize = .small
        forwarding.bezelStyle = .rounded
        forwarding.toolTip = "Master port-forward controls for supported tunnel modes."
        connectRow.addArrangedSubview(forwarding)

        if let multi = telemetryFind("unified-multihop-toggle") as? NSButton, let row = multi.superview as? NSStackView {
            let hop = NSTextField(labelWithString: "")
            hop.identifier = NSUserInterfaceItemIdentifier("unified-multihop-latency")
            hop.font = .monospacedDigitSystemFont(ofSize: 11, weight: .regular)
            hop.textColor = .secondaryLabelColor
            hop.toolTip = "Entry/exit live direct RTT; when multihop is connected, PATH is measured through the actual tunnel."
            telemetryHopLabel = hop
            row.addArrangedSubview(hop)
        }

        if let sheet = telemetryFind("unified-sheet") {
            let performance = NSButton(title: "Performance", target: self, action: #selector(openUnifiedPerformance))
            performance.bezelStyle = .rounded
            performance.controlSize = .small
            performance.toolTip = "Live latency, durable node benchmark and path throughput/MTU test."
            performance.translatesAutoresizingMaskIntoConstraints = false
            sheet.addSubview(performance)
            NSLayoutConstraint.activate([
                performance.trailingAnchor.constraint(equalTo: sheet.trailingAnchor, constant: -18),
                performance.topAnchor.constraint(equalTo: sheet.topAnchor, constant: 10)
            ])
        }

        refreshUnifiedFastNodeMenu()
        refreshUnifiedTelemetry()
        Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in self?.refreshUnifiedTelemetry() }
    }

    func refreshUnifiedFastNodeMenu() {
        guard let popup = telemetryFastPopup else { return }
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            let root = (try? self.api.json("/api/profiles", timeout: 4) as? [String: Any]) ?? [:]
            let values = root["profiles"] as? [[String: Any]] ?? []
            let selected = root["selected_id"] as? String ?? ""
            let routers = values.filter { (($0["node_kind"] as? String) ?? "router-vpn").lowercased() != "external" }
                .sorted {
                    let a = ($0["latency_trimmed_mean_ms"] as? NSNumber)?.doubleValue ?? Double.greatestFiniteMagnitude
                    let b = ($1["latency_trimmed_mean_ms"] as? NSNumber)?.doubleValue ?? Double.greatestFiniteMagnitude
                    return a == b ? (($0["name"] as? String) ?? "") < (($1["name"] as? String) ?? "") : a < b
                }
            DispatchQueue.main.async {
                popup.removeAllItems()
                popup.addItem(withTitle: "⚡ Fastest")
                popup.lastItem?.representedObject = "fastest"
                for p in routers {
                    let id = p["id"] as? String ?? ""; guard !id.isEmpty else { continue }
                    let name = p["name"] as? String ?? id
                    let ms = (p["latency_trimmed_mean_ms"] as? NSNumber)?.doubleValue ?? 0
                    let label = ms > 0 ? String(format: "%@  %.1f ms", name, ms) : name
                    popup.addItem(withTitle: label)
                    popup.lastItem?.representedObject = id
                    if id == selected { popup.lastItem?.state = .on }
                }
                popup.selectItem(at: 0)
            }
        }
    }

    @objc private func unifiedFastConnectChanged(_ sender: NSPopUpButton) {
        let id = sender.selectedItem?.representedObject as? String ?? "fastest"
        sender.selectItem(at: 0)
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            do {
                if id == "fastest" {
                    _ = try self.api.request("/api/profile/fastest", method: "POST", body: ["samples": 5, "select": true], timeout: 35)
                } else {
                    _ = try self.api.request("/api/profile/select", method: "POST", body: ["id": id], timeout: 8)
                }
                DispatchQueue.main.async {
                    self.refreshAll(); self.refreshUnifiedChrome(); self.refreshUnifiedFastNodeMenu()
                    self.startUnifiedSelectedMode()
                }
            } catch { DispatchQueue.main.async { self.errorLabel.stringValue = "Fast connect failed: \(error.localizedDescription)" } }
        }
    }

    func refreshUnifiedTelemetry() {
        refreshUnifiedFastNodeMenu()
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            if let value = try? self.api.json("/api/connection/live-latency", timeout: 4) as? [String: Any],
               let ms = (value["median_ms"] as? NSNumber)?.doubleValue {
                DispatchQueue.main.async { self.telemetryLiveLabel?.stringValue = String(format: "%.1f ms", ms); self.telemetryLiveLabel?.textColor = .labelColor }
            } else {
                DispatchQueue.main.async { self.telemetryLiveLabel?.stringValue = "-- ms"; self.telemetryLiveLabel?.textColor = .secondaryLabelColor }
            }

            guard UserDefaults.standard.bool(forKey: unifiedMultihopEnabledKey),
                  self.multihopEntryPopup.indexOfSelectedItem >= 0, self.multihopExitPopup.indexOfSelectedItem >= 0,
                  self.multihopEntryPopup.indexOfSelectedItem < self.multihopNodeIDs.count,
                  self.multihopExitPopup.indexOfSelectedItem < self.multihopNodeIDs.count else {
                DispatchQueue.main.async { self.telemetryHopLabel?.stringValue = "" }; return
            }
            let entry = self.multihopNodeIDs[self.multihopEntryPopup.indexOfSelectedItem]
            let exit = self.multihopNodeIDs[self.multihopExitPopup.indexOfSelectedItem]
            guard entry != exit else { return }
            if let value = try? self.api.request("/api/multihop/live-latency", method: "POST", body: ["entry_id": entry, "exit_id": exit, "samples": 2], timeout: 8),
               let root = try? JSONSerialization.jsonObject(with: value) as? [String: Any] {
                let e = ((root["entry"] as? [String: Any])?["median_ms"] as? NSNumber)?.doubleValue
                let x = ((root["exit"] as? [String: Any])?["median_ms"] as? NSNumber)?.doubleValue
                let p = ((root["current_path"] as? [String: Any])?["median_ms"] as? NSNumber)?.doubleValue
                var parts: [String] = []
                if let e { parts.append(String(format: "IN %.1f", e)) }
                if let x { parts.append(String(format: "OUT %.1f", x)) }
                if let p { parts.append(String(format: "PATH %.1f ms", p)) }
                DispatchQueue.main.async { self.telemetryHopLabel?.stringValue = parts.joined(separator: " • ") }
            }
        }
    }

    @objc private func openUnifiedPerformance() {
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 620, height: 430), styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        panel.title = "Router VPN Performance"
        panel.minSize = NSSize(width: 520, height: 360)
        let controller = NSWindowController(window: panel)
        objc_setAssociatedObject(self, &telemetryPerformanceControllerKey, controller, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)
        let stack = NSStackView(); stack.orientation = .vertical; stack.spacing = 10; stack.edgeInsets = NSEdgeInsets(top: 18, left: 18, bottom: 18, right: 18)
        let title = NSTextField(labelWithString: "Latency & path performance")
        title.font = .systemFont(ofSize: 22, weight: .bold); stack.addArrangedSubview(title)
        let note = NSTextField(wrappingLabelWithString: "Live RTT uses a lightweight private-path probe. The durable node benchmark remains 50 samples. Path throughput is measured by MTU Retest's bounded private-node loss/RTT/throughput comparison; it can update Auto MTU, so it is labeled explicitly rather than pretending to be a passive speed test.")
        note.textColor = .secondaryLabelColor; stack.addArrangedSubview(note)
        let result = NSTextField(wrappingLabelWithString: "Select a test."); result.font = .monospacedSystemFont(ofSize: 12, weight: .regular); result.isSelectable = true; stack.addArrangedSubview(result)
        let row = NSStackView(); row.orientation = .horizontal; row.spacing = 8
        let live = NSButton(title: "Live path RTT", target: nil, action: nil); live.bezelStyle = .rounded
        live.action = #selector(telemetryLivePerformance(_:)); live.target = self; live.identifier = NSUserInterfaceItemIdentifier("telemetry-live-performance")
        let durable = NSButton(title: "50-sample selected node", target: self, action: #selector(latencySelected)); durable.bezelStyle = .rounded
        let throughput = NSButton(title: "Throughput + Auto MTU", target: self, action: #selector(retestMTU)); throughput.bezelStyle = .rounded
        row.addArrangedSubview(live); row.addArrangedSubview(durable); row.addArrangedSubview(throughput); stack.addArrangedSubview(row)
        result.identifier = NSUserInterfaceItemIdentifier("telemetry-performance-result")
        panel.contentView = stack; panel.center(); controller.showWindow(nil); panel.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
    }

    @objc private func telemetryLivePerformance(_ sender: NSButton) {
        guard let panel = sender.window, let result = telemetryWalk(panel.contentView, id: "telemetry-performance-result") as? NSTextField else { return }
        result.stringValue = "Measuring current tunnel RTT…"
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            do {
                let data = try self.api.request("/api/connection/live-latency", method: "POST", body: ["samples": 5], timeout: 10)
                let text = String(data: data, encoding: .utf8) ?? "No result"
                DispatchQueue.main.async { result.stringValue = text }
            } catch { DispatchQueue.main.async { result.stringValue = error.localizedDescription } }
        }
    }

    private func telemetryWalk(_ view: NSView?, id: String) -> NSView? {
        guard let view else { return nil }
        if view.identifier?.rawValue == id { return view }
        for child in view.subviews { if let found = telemetryWalk(child, id: id) { return found } }
        return nil
    }
}
