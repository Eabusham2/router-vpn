import AppKit
import Foundation
import MapKit
import ObjectiveC

private var telemetryInstalledKey: UInt8 = 0
private var telemetryFastPopupKey: UInt8 = 0
private var telemetryLiveLabelKey: UInt8 = 0
private var telemetryHopLabelKey: UInt8 = 0
private var telemetryForwardButtonKey: UInt8 = 0
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
    private var telemetryForwardButton: NSButton? {
        get { objc_getAssociatedObject(self, &telemetryForwardButtonKey) as? NSButton }
        set { objc_setAssociatedObject(self, &telemetryForwardButtonKey, newValue, .OBJC_ASSOCIATION_RETAIN_NONATOMIC) }
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
        fast.toolTip = "Test and connect the fastest Router VPN node, or choose a node directly."
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

        let forwarding = NSButton(title: "Forward ?", target: self, action: #selector(toggleUnifiedForwardingMaster(_:)))
        forwarding.identifier = NSUserInterfaceItemIdentifier("unified-forward-master")
        forwarding.controlSize = .small
        forwarding.bezelStyle = .rounded
        forwarding.state = .mixed
        forwarding.allowsMixedState = true
        forwarding.toolTip = "Real server forwarding master on the active Router VPN home node."
        telemetryForwardButton = forwarding
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
            performance.toolTip = "Live latency, durable node benchmark, real path/routed-hop Mbps and Auto-MTU retest."
            performance.translatesAutoresizingMaskIntoConstraints = false
            sheet.addSubview(performance)
            NSLayoutConstraint.activate([
                performance.trailingAnchor.constraint(equalTo: sheet.trailingAnchor, constant: -18),
                performance.topAnchor.constraint(equalTo: sheet.topAnchor, constant: 10)
            ])
        }

        refreshUnifiedFastNodeMenu()
        refreshUnifiedTelemetry()
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
                    self.connectUnified()
                }
            } catch { DispatchQueue.main.async { self.errorLabel.stringValue = "Fast connect failed: \(error.localizedDescription)" } }
        }
    }

    private func setUnifiedForwardState(_ enabled: Bool?, name: String? = nil) {
        guard let button = telemetryForwardButton else { return }
        button.isEnabled = true
        if let enabled {
            button.state = enabled ? .on : .off
            button.title = enabled ? "Forward ON" : "Forward OFF"
            let suffix = (name?.isEmpty == false) ? " on \(name!)" : ""
            button.toolTip = "Real server forwarding master\(suffix)."
        } else {
            button.state = .mixed
            button.title = "Forward ?"
            button.toolTip = "Connect a Router VPN home-node path to verify the real forwarding master."
        }
    }

    private func refreshUnifiedForwardingMaster() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            do {
                let root = try self.api.json("/api/forwarding/master", timeout: 4) as? [String: Any] ?? [:]
                guard let enabled = root["enabled"] as? Bool else { throw NSError(domain: "RouterVPNMac", code: 71, userInfo: [NSLocalizedDescriptionKey: "Forwarding-master response did not contain a verified state."]) }
                let name = root["name"] as? String
                DispatchQueue.main.async { self.setUnifiedForwardState(enabled, name: name) }
            } catch {
                DispatchQueue.main.async { self.setUnifiedForwardState(nil) }
            }
        }
    }

    @objc private func toggleUnifiedForwardingMaster(_ sender: NSButton) {
        sender.isEnabled = false
        sender.title = "Forward …"
        DispatchQueue.global(qos: .userInitiated).async { [weak self, weak sender] in
            guard let self, let sender else { return }
            do {
                let current = try self.api.json("/api/forwarding/master", timeout: 5) as? [String: Any] ?? [:]
                guard let currentEnabled = current["enabled"] as? Bool else { throw NSError(domain: "RouterVPNMac", code: 72, userInfo: [NSLocalizedDescriptionKey: "Could not verify the current forwarding-master state."]) }
                let wanted = !currentEnabled
                let data = try self.api.request("/api/forwarding/master", method: "PUT", body: ["enabled": wanted], timeout: 10)
                guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any], let actual = root["enabled"] as? Bool, actual == wanted else {
                    throw NSError(domain: "RouterVPNMac", code: 73, userInfo: [NSLocalizedDescriptionKey: "Forwarding master did not reach the requested state."])
                }
                let name = root["name"] as? String
                DispatchQueue.main.async {
                    self.setUnifiedForwardState(actual, name: name)
                    self.errorLabel.stringValue = "Forwarding master \(actual ? "ON" : "OFF")\(name?.isEmpty == false ? " on \(name!)" : "")."
                }
            } catch {
                DispatchQueue.main.async {
                    sender.isEnabled = true
                    self.setUnifiedForwardState(nil)
                    self.errorLabel.stringValue = "Forwarding master failed: \(error.localizedDescription)"
                }
            }
        }
    }

    func refreshUnifiedTelemetry() {
        refreshUnifiedFastNodeMenu()
        refreshUnifiedForwardingMaster()
        let multihopOn = (telemetryFind("unified-multihop-toggle") as? NSButton)?.state == .on
        let entryIndex = multihopEntryPopup.indexOfSelectedItem
        let exitIndex = multihopExitPopup.indexOfSelectedItem
        let ids = multihopNodeIDs
        let hopIDs: (String, String)?
        if multihopOn, entryIndex >= 0, exitIndex >= 0, entryIndex < ids.count, exitIndex < ids.count, ids[entryIndex] != ids[exitIndex] {
            hopIDs = (ids[entryIndex], ids[exitIndex])
        } else {
            hopIDs = nil
            telemetryHopLabel?.stringValue = ""
        }

        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            if let value = try? self.api.json("/api/connection/live-latency", timeout: 4) as? [String: Any],
               let ms = (value["median_ms"] as? NSNumber)?.doubleValue {
                DispatchQueue.main.async { self.telemetryLiveLabel?.stringValue = String(format: "%.1f ms", ms); self.telemetryLiveLabel?.textColor = .labelColor }
            } else {
                DispatchQueue.main.async { self.telemetryLiveLabel?.stringValue = "-- ms"; self.telemetryLiveLabel?.textColor = .secondaryLabelColor }
            }

            guard let (entry, exit) = hopIDs else { return }
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
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 760, height: 470), styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        panel.title = "Router VPN Performance"
        panel.minSize = NSSize(width: 600, height: 380)
        let controller = NSWindowController(window: panel)
        objc_setAssociatedObject(self, &telemetryPerformanceControllerKey, controller, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)
        let stack = NSStackView(); stack.orientation = .vertical; stack.spacing = 10; stack.edgeInsets = NSEdgeInsets(top: 18, left: 18, bottom: 18, right: 18)
        let title = NSTextField(labelWithString: "Latency & path performance")
        title.font = .systemFont(ofSize: 22, weight: .bold); stack.addArrangedSubview(title)
        let note = NSTextField(wrappingLabelWithString: "Live RTT measures the active private tunnel. Real path speed transfers to the active exit. Routed hop speed independently transfers to the selected entry and exit private router-agents through the actual multihop routing graph; unreachable hops keep their error instead of receiving a calculated value. Auto MTU remains separate.")
        note.textColor = .secondaryLabelColor; stack.addArrangedSubview(note)
        let result = NSTextField(wrappingLabelWithString: "Choose a real measurement."); result.font = .monospacedSystemFont(ofSize: 12, weight: .regular); result.isSelectable = true; result.identifier = NSUserInterfaceItemIdentifier("telemetry-performance-result"); stack.addArrangedSubview(result)
        let row = NSStackView(); row.orientation = .horizontal; row.spacing = 8
        let live = NSButton(title: "Live path RTT", target: self, action: #selector(telemetryLivePerformance(_:))); live.bezelStyle = .rounded
        let durable = NSButton(title: "50-sample selected node", target: self, action: #selector(telemetryDurablePerformance(_:))); durable.bezelStyle = .rounded
        let speed = NSButton(title: "Real path speed", target: self, action: #selector(telemetrySpeedPerformance(_:))); speed.bezelStyle = .rounded
        let hops = NSButton(title: "Routed hop speeds", target: self, action: #selector(telemetryHopSpeedPerformance(_:))); hops.bezelStyle = .rounded
        let mtu = NSButton(title: "Throughput + Auto MTU", target: self, action: #selector(telemetryMtuPerformance(_:))); mtu.bezelStyle = .rounded
        row.addArrangedSubview(live); row.addArrangedSubview(durable); row.addArrangedSubview(speed); row.addArrangedSubview(hops); row.addArrangedSubview(mtu); stack.addArrangedSubview(row)
        panel.contentView = stack; panel.center(); controller.showWindow(nil); panel.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
    }

    private func telemetryResult(_ sender: NSButton) -> NSTextField? {
        telemetryWalk(sender.window?.contentView, id: "telemetry-performance-result") as? NSTextField
    }

    private func telemetryAsync(_ sender: NSButton, label: String, work: @escaping () throws -> Data) {
        guard let result = telemetryResult(sender) else { return }
        result.stringValue = label
        sender.isEnabled = false
        DispatchQueue.global(qos: .userInitiated).async { [weak sender] in
            do {
                let data = try work()
                let text = String(data: data, encoding: .utf8) ?? "No result"
                DispatchQueue.main.async { result.stringValue = text; sender?.isEnabled = true }
            } catch {
                DispatchQueue.main.async { result.stringValue = error.localizedDescription; sender?.isEnabled = true }
            }
        }
    }

    @objc private func telemetryLivePerformance(_ sender: NSButton) {
        telemetryAsync(sender, label: "Measuring current tunnel RTT…") { try self.api.request("/api/connection/live-latency", method: "POST", body: ["samples": 5], timeout: 12) }
    }

    @objc private func telemetryDurablePerformance(_ sender: NSButton) {
        telemetryAsync(sender, label: "Running 50-sample selected-node benchmark…") {
            let root = try self.api.json("/api/profiles", timeout: 5) as? [String: Any] ?? [:]
            guard let id = root["selected_id"] as? String, !id.isEmpty else { throw NSError(domain: "RouterVPNMac", code: 41, userInfo: [NSLocalizedDescriptionKey: "Select a Router VPN node first."]) }
            return try self.api.request("/api/profile/latency", method: "POST", body: ["id": id, "samples": 50], timeout: 180)
        }
    }

    @objc private func telemetrySpeedPerformance(_ sender: NSButton) {
        telemetryAsync(sender, label: "Transferring 8 MiB down and 8 MiB up through the current VPN path…") { try self.api.request("/api/connection/speed-test", method: "POST", body: ["bytes": 8 * 1024 * 1024], timeout: 45) }
    }

    @objc private func telemetryHopSpeedPerformance(_ sender: NSButton) {
        let entryIndex = multihopEntryPopup.indexOfSelectedItem
        let exitIndex = multihopExitPopup.indexOfSelectedItem
        guard entryIndex >= 0, exitIndex >= 0, entryIndex < multihopNodeIDs.count, exitIndex < multihopNodeIDs.count else {
            telemetryResult(sender)?.stringValue = "Choose multihop entry and exit nodes first."
            return
        }
        let entry = multihopNodeIDs[entryIndex]
        let exit = multihopNodeIDs[exitIndex]
        guard entry != exit else {
            telemetryResult(sender)?.stringValue = "Multihop entry and exit must be different."
            return
        }
        telemetryAsync(sender, label: "Testing routed entry and exit throughput through the active multihop graph…") {
            try self.api.request("/api/multihop/speed-test", method: "POST", body: ["entry_id": entry, "exit_id": exit, "bytes": 4 * 1024 * 1024], timeout: 70)
        }
    }

    @objc private func telemetryMtuPerformance(_ sender: NSButton) {
        telemetryAsync(sender, label: "Retesting current path MTU and bounded MTU throughput…") { try self.api.request("/api/mtu/retest", method: "POST", body: [:], timeout: 130) }
    }

    private func telemetryWalk(_ view: NSView?, id: String) -> NSView? {
        guard let view else { return nil }
        if view.identifier?.rawValue == id { return view }
        for child in view.subviews { if let found = telemetryWalk(child, id: id) { return found } }
        return nil
    }
}
