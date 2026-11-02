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
private var telemetryExternalComparisonControllerKey: UInt8 = 0

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
        fast.toolTip = "Select the fastest measured Router VPN node or choose a specific node. Use Connect separately."
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
                popup.addItem(withTitle: "⚡ Fastest Router · TCP")
                popup.lastItem?.representedObject = "fastest"
                popup.addItem(withTitle: "Compare external paths · 50 responses…")
                popup.lastItem?.representedObject = "external-comparison"
                var selectedIndex = 0
                for p in routers {
                    let id = p["id"] as? String ?? ""; guard !id.isEmpty else { continue }
                    let name = p["name"] as? String ?? id
                    let ms = (p["latency_trimmed_mean_ms"] as? NSNumber)?.doubleValue ?? 0
                    let label = ms > 0 ? String(format: "%@  %.1f ms", name, ms) : name
                    popup.addItem(withTitle: label)
                    popup.lastItem?.representedObject = id
                    if id == selected { selectedIndex = popup.numberOfItems - 1 }
                }
                popup.selectItem(at: selectedIndex)
            }
        }
    }

    @objc private func unifiedFastConnectChanged(_ sender: NSPopUpButton) {
        let id = sender.selectedItem?.representedObject as? String ?? "fastest"
        if id == "external-comparison" { openExternalComparison(); refreshUnifiedFastNodeMenu(); return }
        sender.isEnabled = false
        DispatchQueue.global(qos: .userInitiated).async { [weak self, weak sender] in
            guard let self else { return }
            do {
                if id == "fastest" {
                    _ = try self.api.request("/api/profile/fastest", method: "POST", body: ["samples": 5, "select": true], timeout: 35)
                } else {
                    _ = try self.api.request("/api/profile/select", method: "POST", body: ["id": id], timeout: 8)
                }
                DispatchQueue.main.async {
                    sender?.isEnabled = true
                    self.refreshAll(); self.refreshUnifiedChrome(); self.refreshUnifiedFastNodeMenu()
                    self.errorLabel.stringValue = id == "fastest" ? "Selected the fastest measured Router VPN node. Press Connect when ready." : "Selected Router VPN node. Press Connect when ready."
                }
            } catch {
                DispatchQueue.main.async {
                    sender?.isEnabled = true
                    self.refreshUnifiedFastNodeMenu()
                    self.errorLabel.stringValue = "Node selection failed: \(error.localizedDescription)"
                }
            }
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
        let external = NSButton(title: "Compare external paths / connect fastest", target: self, action: #selector(openExternalComparison))
        external.bezelStyle = .rounded; stack.addArrangedSubview(external)
        panel.contentView = stack; panel.center(); controller.showWindow(nil); panel.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
    }

    @objc private func openExternalComparison() {
        if let existing = objc_getAssociatedObject(self, &telemetryExternalComparisonControllerKey) as? RouterVPNMacExternalComparisonController, !existing.closed {
            existing.showWindow(nil); existing.window?.makeKeyAndOrderFront(nil); return
        }
        let controller = RouterVPNMacExternalComparisonController(api: api, product: self)
        objc_setAssociatedObject(self, &telemetryExternalComparisonControllerKey, controller, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)
        controller.window?.center(); controller.showWindow(nil); controller.window?.makeKeyAndOrderFront(nil)
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
        showMTUPanel(retest: true)
    }

    private func telemetryWalk(_ view: NSView?, id: String) -> NSView? {
        guard let view else { return nil }
        if view.identifier?.rawValue == id { return view }
        for child in view.subviews { if let found = telemetryWalk(child, id: id) { return found } }
        return nil
    }
}

// This display parser contains no connection authority. Only a matching,
// complete controller result may show a score or a committed winner.
private enum RouterVPNExternalComparisonDisplay {
    static func token(_ value: Any?, count: Int) -> String? {
        guard let text = value as? String, text.count == count,
              text.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { return nil }
        return text
    }
    static func matches(_ value: [String: Any], request: String, cohort: String) -> Bool {
        token(value["request_id"], count: 32) == request && token(value["cohort_id"], count: 64) == cohort
    }
    static func score(_ row: [String: Any]) -> Double? {
        guard row["status"] as? String == "complete", let b = row["benchmark"] as? [String: Any],
              (b["schema"] as? NSNumber)?.intValue == 1,
              b["measurement"] as? String == "routed-https-response-after-tls",
              b["endpoint"] as? String == "https://speed.cloudflare.com/__down?bytes=1",
              (b["attempts"] as? NSNumber)?.intValue == 50,
              (b["failed"] as? NSNumber)?.intValue == 0,
              let d = b["distribution"] as? [String: Any], (d["samples"] as? NSNumber)?.intValue == 50,
              let value = (b["trimmed_mean_ms"] as? NSNumber)?.doubleValue, value.isFinite, value > 0 else { return nil }
        return value
    }
    static func rows(_ values: [[String: Any]], historical: Bool) -> String {
        var lines = [historical ? "Saved history — these values are not a current winner." : "50 routed HTTPS responses · 10% trimmed mean"]
        for row in values {
            let name = row["name"] as? String ?? row["id"] as? String ?? "External path"
            let entry = row["entry_name"] as? String ?? row["entry_id"] as? String ?? ""
            let route = entry.isEmpty ? "Direct saved path" : "Via \(entry)"
            if let ms = score(row) {
                let execution = row["execution"] as? String ?? ""
                lines.append(String(format: "%@ · %@ · %@ · %.2f ms", name, route, execution.capitalized, ms))
            } else {
                let state = row["failure"] as? String ?? row["status"] as? String ?? "Not measured"
                lines.append("\(name) · \(route) · \(state)")
            }
        }
        return lines.joined(separator: "\n")
    }
    static func state(_ value: [String: Any]) -> String {
        let stage = value["stage"] as? String ?? "Working"
        let progress = value["progress"] as? String ?? ""
        var text = stage.replacingOccurrences(of: "-", with: " ").capitalized
        if !progress.isEmpty { text += " · \(progress)" }
        if value["complete"] as? Bool == true {
            if value["committed"] as? Bool == true { text += value["stage"] as? String == "connected" ? "\nThe freshly proved winner is connected and selected." : "\nThe winner selection was saved. Check the current connection status." }
            else if value["restored"] as? Bool == true { text += "\nYour original connection state was restored." }
            else { text += "\nRestoration is unresolved; check the main connection status." }
            if value["drained"] as? Bool != true { text += "\nCleanup is pending. Retry Cancel." }
        }
        for key in ["failure", "warning"] { if let note = value[key] as? String, !note.isEmpty { text += "\n" + note } }
        return text
    }
}

private final class RouterVPNMacExternalComparisonController: NSWindowController, NSWindowDelegate {
    private let api: ProductAPI
    private weak var product: ProductWindowController?
    private let status = NSTextField(wrappingLabelWithString: "Loading saved external paths…")
    private let detail = NSTextView()
    private let compare = NSButton(title: "Compare external paths", target: nil, action: nil)
    private let fastest = NSButton(title: "Compare + connect fastest", target: nil, action: nil)
    private let cancel = NSButton(title: "Cancel", target: nil, action: nil)
    private var timer: Timer?
    private var inflight = false
    private var requestID = "", cohortID = ""
    private var choice: Bool?
    private var started = false, finished = true, cancelWanted = false, cancelAccepted = false, closeWanted = false
    private(set) var closed = false
    private var generation: UInt64 = 0
    private var nextPoll = Date.distantPast

    init(api: ProductAPI, product: ProductWindowController) {
        self.api = api; self.product = product
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 820, height: 560), styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        window.title = "Compare external paths"; window.minSize = NSSize(width: 640, height: 440)
        super.init(window: window); window.delegate = self
        let stack = NSStackView(); stack.orientation = .vertical; stack.spacing = 12
        stack.edgeInsets = NSEdgeInsets(top: 18, left: 18, bottom: 18, right: 18)
        let title = NSTextField(labelWithString: "Find the fastest saved external path")
        title.font = .systemFont(ofSize: 22, weight: .bold); stack.addArrangedSubview(title)
        let note = NSTextField(wrappingLabelWithString: "Each saved path uses its own entry, DNS and protection. Every valid path sends 50 HTTPS responses through its proved exit to the same Cloudflare endpoint. Timing starts after TLS; lowest 10% trimmed mean wins. Router TCP reachability is separate. Compare restores your original connection between trials; connecting the winner requires the explicit second action.")
        note.textColor = .secondaryLabelColor; stack.addArrangedSubview(note)
        stack.addArrangedSubview(status)
        let scroll = NSScrollView(); scroll.hasVerticalScroller = true
        detail.isEditable = false; detail.isSelectable = true; detail.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        scroll.documentView = detail; detail.isVerticallyResizable = true; detail.autoresizingMask = [.width]
        scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 240).isActive = true; stack.addArrangedSubview(scroll)
        let row = NSStackView(); row.orientation = .horizontal; row.spacing = 8
        for button in [compare, fastest, cancel] { button.target = self; button.bezelStyle = .rounded; row.addArrangedSubview(button) }
        compare.action = #selector(comparePaths); fastest.action = #selector(connectFastest); cancel.action = #selector(cancelComparison)
        stack.addArrangedSubview(row); window.contentView = stack
        controls(); timer = Timer.scheduledTimer(withTimeInterval: 0.4, repeats: true) { [weak self] _ in self?.tick() }
        send("offer", path: "/api/speed-lab/external-comparison")
    }
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    deinit { timer?.invalidate() }
    private func controls() {
        compare.isEnabled = !inflight && (!started || finished)
        fastest.isEnabled = compare.isEnabled
        cancel.isEnabled = started && !finished
    }
    @objc private func comparePaths() { begin(false) }
    @objc private func connectFastest() { begin(true) }
    private func begin(_ connect: Bool) {
        guard !closed, !inflight, !started || finished else { return }
        generation &+= 1; choice = connect; requestID = ""; cohortID = ""
        started = false; finished = true; cancelWanted = false; cancelAccepted = false
        status.stringValue = "Capturing the current saved paths…"
        send("offer", path: "/api/speed-lab/external-comparison")
    }
    @objc private func cancelComparison() {
        guard started, !finished else { return }
        cancelWanted = true; cancelAccepted = false
        status.stringValue = "Cancelling this comparison; waiting for its workers and original-state restoration."
        tick()
    }
    func windowShouldClose(_ sender: NSWindow) -> Bool {
        if started && !finished { closeWanted = true; cancelComparison(); return false }
        return true
    }
    func windowWillClose(_ notification: Notification) {
        closed = true; generation &+= 1; timer?.invalidate(); timer = nil
    }
    private func tick() {
        guard !closed, !inflight, started, !finished, Date() >= nextPoll else { return }
        if cancelWanted && !cancelAccepted {
            send("cancel", path: "/api/speed-lab/external-comparison/cancel", body: ["request_id": requestID, "cohort_id": cohortID])
        } else {
            send("poll", path: "/api/speed-lab/external-comparison?request_id=" + requestID)
        }
    }
    private func send(_ phase: String, path: String, body: [String: Any]? = nil) {
        guard !closed, !inflight else { return }
        inflight = true; controls(); let captured = generation
        let needsIdle = phase == "offer" && choice != nil
        DispatchQueue.global(qos: .utility).async { [self] in
            let outcome: Result<[String: Any], Error>
            do {
                if needsIdle { try product?.requireMutationIdle("comparing saved external paths") }
                let data = try api.request(path, method: body == nil ? "GET" : "POST", body: body, timeout: 10)
                guard let value = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw NSError(domain: "RouterVPNExternalComparison", code: 1) }
                outcome = .success(value)
            } catch { outcome = .failure(error) }
            DispatchQueue.main.async { [self] in
                guard !closed, generation == captured else { return }
                inflight = false; nextPoll = Date().addingTimeInterval(0.6)
                switch outcome {
                case .success(let value): receive(value, phase: phase)
                case .failure(let error):
                    status.stringValue = "Comparison request failed: \(error.localizedDescription)"
                    if started && !finished { cancelWanted = true; cancelAccepted = false; status.stringValue += "\nCancellation will be retried; cleanup is not confirmed." }
                    else { choice = nil }
                }
                controls()
            }
        }
    }
    private func receive(_ value: [String: Any], phase: String) {
        if phase == "offer" {
            guard let request = RouterVPNExternalComparisonDisplay.token(value["request_id"], count: 32),
                  let cohort = RouterVPNExternalComparisonDisplay.token(value["cohort_id"], count: 64),
                  let candidates = value["candidates"] as? [[String: Any]], !candidates.isEmpty, candidates.count <= 128 else {
                status.stringValue = "Saved external paths could not be captured. Refresh and try again."; choice = nil; return
            }
            requestID = request; cohortID = cohort
            let history = (value["history"] as? [String: Any])?["rows"] as? [[String: Any]] ?? []
            detail.string = candidates.map { row in
                let name = row["name"] as? String ?? row["id"] as? String ?? "External path"
                let entry = row["has_entry"] as? Bool == true ? row["entry_id"] as? String ?? "saved entry" : "Direct"
                return "\(name) · \(entry) · \(row["protocol"] as? String ?? "")"
            }.joined(separator: "\n") + (history.isEmpty ? "" : "\n\n" + RouterVPNExternalComparisonDisplay.rows(history, historical: true))
            status.stringValue = "\(candidates.count) saved external paths. Choose Compare, or explicitly compare and connect the winner."
            if let warning = value["warning"] as? String, !warning.isEmpty { status.stringValue += "\n" + warning }
            if let connect = choice {
                started = true; finished = false
                send("start", path: "/api/speed-lab/external-comparison", body: ["request_id": requestID, "cohort_id": cohortID, "connect_fastest": connect])
            }
            return
        }
        guard RouterVPNExternalComparisonDisplay.matches(value, request: requestID, cohort: cohortID) else {
            status.stringValue = "A response belongs to another comparison. This result was discarded; cancelling only the captured request."
            cancelWanted = true; cancelAccepted = false; return
        }
        if phase == "cancel" { cancelAccepted = true }
        status.stringValue = RouterVPNExternalComparisonDisplay.state(value)
        detail.string = RouterVPNExternalComparisonDisplay.rows(value["rows"] as? [[String: Any]] ?? [], historical: false)
        finished = value["complete"] as? Bool == true && value["drained"] as? Bool == true
        if finished {
            choice = nil; product?.refreshAll(); product?.refreshUnifiedChrome(); product?.refreshUnifiedFastNodeMenu()
            if closeWanted { window?.performClose(nil) }
        } else if value["complete"] as? Bool == true && value["drained"] as? Bool != true {
            cancelWanted = true; cancelAccepted = false
        }
    }
}
