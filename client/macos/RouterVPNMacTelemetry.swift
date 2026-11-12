import AppKit
import Foundation
import CoreFoundation
import MapKit
import ObjectiveC

private var telemetryInstalledKey: UInt8 = 0
private var telemetryFastPopupKey: UInt8 = 0
private var telemetryLiveLabelKey: UInt8 = 0
private var telemetryHopLabelKey: UInt8 = 0
private var telemetryForwardButtonKey: UInt8 = 0
private var telemetryPerformanceControllerKey: UInt8 = 0
private var telemetryExternalComparisonControllerKey: UInt8 = 0
private var telemetryFastestControllerKey: UInt8 = 0
private var telemetryLiveDeliveryKey: UInt8 = 0

// A response remains usable only for this exact native request and its short
// monotonic delivery deadline. The controller revalidates the request before
// this value enters the main queue; the UI checks again after queueing.
private struct RouterVPNLiveHTTPSReceipt {
    let binding: [String: String]
    let median: Double
    let deadline: TimeInterval
    let response: NSDictionary
    static func number(_ object: [String: Any], _ key: String) -> Double? {
        guard let n = object[key] as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID(), n.doubleValue.isFinite else { return nil }; return n.doubleValue
    }
    static func decode(_ value: [String: Any], now: TimeInterval = Date().timeIntervalSince1970 * 1000, uptime: TimeInterval = ProcessInfo.processInfo.systemUptime, started: TimeInterval) -> Self? {
        guard value["measurement"] as? String == "routed-https-response-after-tls",
              let connected = value["connected"] as? NSNumber, CFGetTypeID(connected) == CFBooleanGetTypeID(), connected.boolValue,
              let r = value["response"] as? [String: Any], Set(r.keys) == Set(["schema","measurement","endpoint","attempts","distribution"]),
              number(r,"schema") == 1, number(r,"attempts") == 3, r["measurement"] as? String == "routed-https-response-after-tls", r["endpoint"] as? String == "https://speed.cloudflare.com/__down?bytes=1",
              let d = r["distribution"] as? [String: Any], Set(d.keys) == Set(["samples","min_ms","median_ms","average_ms","p90_ms","max_ms","jitter_ms"]), number(d,"samples") == 3,
              let min = number(d,"min_ms"), let median = number(d,"median_ms"), let avg = number(d,"average_ms"), let p90 = number(d,"p90_ms"), let max = number(d,"max_ms"), let jitter = number(d,"jitter_ms"),
              min > 0, min <= median, median <= p90, p90 <= max, max <= 10000, avg >= min, avg <= max, jitter >= 0, jitter <= max-min,
              let measured = number(value,"measured_at"), let remaining = number(value,"expires_in_ms"), remaining > 0, remaining <= 10000, now >= measured, now-measured < 10000, uptime >= started,
              !["median_ms","benchmark","idle","download","upload"].contains(where: { value[$0] != nil }) else { return nil }
        var binding: [String: String] = [:]
        for key in ["profile_id","profile_token","session_id","request_id","source_sha256","config_sha256","network_sha256"] {
            guard let text = value[key] as? String, !text.isEmpty else { return nil }
            if key != "profile_id" { let length = key == "session_id" || key == "request_id" ? 32 : 64; guard text.utf8.count == length, text.utf8.allSatisfy({(48...57).contains($0)||(97...102).contains($0)}) else {return nil} }
            binding[key] = text
        }
        let lifetime = Swift.min(remaining/1000 - (uptime-started), (10000-(now-measured))/1000)
        guard lifetime > 0 else { return nil }
        return Self(binding:binding,median:median,deadline:uptime+lifetime,response:r as NSDictionary)
    }
    func matches(_ other: Self) -> Bool { binding == other.binding && response.isEqual(other.response) }
    func current(_ uptime: TimeInterval = ProcessInfo.processInfo.systemUptime) -> Bool { uptime < deadline }
}

private final class RouterVPNLiveTelemetryDelivery {
    var generation = UUID()
    var running = false
    var receipt: RouterVPNLiveHTTPSReceipt?
    var mutations: Set<UUID> = []
}

extension ProductWindowController {
    private var liveTelemetryDelivery: RouterVPNLiveTelemetryDelivery {
        if let value = objc_getAssociatedObject(self,&telemetryLiveDeliveryKey) as? RouterVPNLiveTelemetryDelivery {return value}
        let value = RouterVPNLiveTelemetryDelivery();objc_setAssociatedObject(self,&telemetryLiveDeliveryKey,value,.OBJC_ASSOCIATION_RETAIN_NONATOMIC);return value
    }
    private func clearLiveHTTPS() {
        let owner = liveTelemetryDelivery
        if let id = owner.receipt?.binding["profile_id"] {for node in map.annotations.compactMap({$0 as? RouterAnnotation}) where node.routerID == id {node.subtitle = node.storedSubtitle}}
        owner.receipt = nil;telemetryLiveLabel?.stringValue = "-- ms"
    }
    private func liveHTTPSPaused() -> Bool {
        let performance = objc_getAssociatedObject(self,&telemetryPerformanceControllerKey) as? RouterVPNMacPerformanceController
        let comparison = objc_getAssociatedObject(self,&telemetryExternalComparisonControllerKey) as? RouterVPNMacExternalComparisonController
        return !liveTelemetryDelivery.mutations.isEmpty || window?.attachedSheet != nil || performance?.window?.isVisible == true || comparison?.window?.isVisible == true || unifiedSpeedLabPresented()
    }
    // The shipping transform calls these on the main queue at mutation entry
    // and after its background work completes. Same-profile reconnects do not
    // change the selection UUID, so they require their own captured lease.
    func beginLiveHTTPSMutation() -> UUID {
        let token = UUID();liveTelemetryDelivery.mutations.insert(token)
        liveTelemetryDelivery.generation = UUID();clearLiveHTTPS();return token
    }
    func endLiveHTTPSMutation(_ token: UUID) {
        guard liveTelemetryDelivery.mutations.remove(token) != nil else {return}
        liveTelemetryDelivery.generation = UUID();clearLiveHTTPS()
    }
    private func showLiveHTTPS(_ receipt: RouterVPNLiveHTTPSReceipt, owner: RouterVPNLiveTelemetryDelivery, generation: UUID, selection: UUID) {
        guard owner.generation == generation, window?.isVisible == true, !liveHTTPSPaused(), connectionProfileSelectionGeneration == selection, receipt.current(),
              (telemetryFind("unified-connect") as? NSButton)?.title == "Disconnect",
              routerPopup.indexOfSelectedItem >= 0, routerPopup.indexOfSelectedItem < routerIDs.count, routerIDs[routerPopup.indexOfSelectedItem] == receipt.binding["profile_id"] else {clearLiveHTTPS();return}
        owner.receipt = receipt
        let label = String(format:"%.1f ms HTTPS",receipt.median)
        telemetryLiveLabel?.stringValue = label;telemetryLiveLabel?.textColor = .labelColor
        telemetryLiveLabel?.toolTip = "3 responses through the current proved VPN path and selected DNS, timed after DNS/TCP/TLS preparation. Expires after 10 seconds; separate from ICMP, private-node RTT and saved50."
        for node in map.annotations.compactMap({$0 as? RouterAnnotation}) where node.routerID == receipt.binding["profile_id"] {node.subtitle = label}
        DispatchQueue.main.asyncAfter(deadline:.now()+Swift.max(0,receipt.deadline-ProcessInfo.processInfo.systemUptime)) { [weak self,weak owner] in
            guard let self, let owner, owner.generation == generation, owner.receipt?.binding == receipt.binding else {return};self.clearLiveHTTPS()
        }
    }
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
    private var telemetryFastestController: RouterVPNMacFastestController? {
        get { objc_getAssociatedObject(self, &telemetryFastestControllerKey) as? RouterVPNMacFastestController }
        set { objc_setAssociatedObject(self, &telemetryFastestControllerKey, newValue, .OBJC_ASSOCIATION_RETAIN_NONATOMIC) }
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
        live.toolTip = "Current private-node HTTP RTT or explicitly labelled external HTTPS response."
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
        guard let popup = telemetryFastPopup, telemetryFastestController?.isRunning != true else { return }
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
                guard self.telemetryFastestController?.isRunning != true else { return }
                popup.removeAllItems()
                popup.addItem(withTitle: "⚡ Fastest Router · 50 TCP samples")
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
        if let owned = telemetryFastestController, owned.isRunning { owned.showWindow(nil); owned.window?.makeKeyAndOrderFront(nil); return }
        let id = sender.selectedItem?.representedObject as? String ?? "fastest"
        if id == "external-comparison" { openExternalComparison(); refreshUnifiedFastNodeMenu(); return }
        sender.isEnabled = false
        if id == "fastest" {
            telemetryFastestController?.close()
            let owned = RouterVPNMacFastestController { [weak self, weak sender] message in
                guard let self else { return }
                sender?.isEnabled = true
                self.refreshAll(); self.refreshUnifiedChrome(); self.refreshUnifiedFastNodeMenu()
                self.errorLabel.stringValue = message
            }
            telemetryFastestController = owned
            owned.showWindow(nil); owned.window?.makeKeyAndOrderFront(nil); owned.start()
            return
        }
        DispatchQueue.global(qos: .userInitiated).async { [weak self, weak sender] in
            guard let self else { return }
            do {
                _ = try self.api.request("/api/profile/select", method: "POST", body: ["id": id], timeout: 8)
                DispatchQueue.main.async {
                    sender?.isEnabled = true
                    self.refreshAll(); self.refreshUnifiedChrome(); self.refreshUnifiedFastNodeMenu()
                    self.errorLabel.stringValue = "Selected Router VPN node. Press Connect when ready."
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
        let delivery = liveTelemetryDelivery
        if delivery.receipt?.current() == false {clearLiveHTTPS()}
        if liveHTTPSPaused() {delivery.generation = UUID();clearLiveHTTPS();return}
        guard !delivery.running else {return}
        delivery.running = true;delivery.generation = UUID();let generation = delivery.generation
        let selection = connectionProfileSelectionGeneration
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
            let started = ProcessInfo.processInfo.systemUptime
            let value = (try? self.api.json("/api/connection/live-latency", timeout:4)) as? [String:Any]
            var receipt: RouterVPNLiveHTTPSReceipt?
            if let value, let first = RouterVPNLiveHTTPSReceipt.decode(value,started:started),let request = first.binding["request_id"],
               let checked = (try? self.api.json("/api/connection/live-latency?request_id="+request,timeout:3)) as? [String:Any],
               let next = RouterVPNLiveHTTPSReceipt.decode(checked,started:started),first.matches(next) {receipt=next}
            let captured = receipt
            DispatchQueue.main.async {
                delivery.running = false
                guard delivery.generation == generation,self.window?.isVisible == true,self.connectionProfileSelectionGeneration == selection else {return}
                if let captured {self.showLiveHTTPS(captured,owner:delivery,generation:generation,selection:selection)}
                else if value?["measurement"] == nil,let value,let ms=RouterVPNLiveHTTPSReceipt.number(value,"median_ms"),ms>0 {self.clearLiveHTTPS();self.telemetryLiveLabel?.stringValue=String(format:"%.1f ms",ms);self.telemetryLiveLabel?.toolTip="HTTP RTT through the current private Router-node path."}
                else {self.clearLiveHTTPS();self.telemetryLiveLabel?.textColor = .secondaryLabelColor}
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
        if let existing = objc_getAssociatedObject(self, &telemetryPerformanceControllerKey) as? RouterVPNMacPerformanceController, !existing.closed {
            existing.showWindow(nil); existing.window?.makeKeyAndOrderFront(nil); return
        }
        let controller = RouterVPNMacPerformanceController(product: self)
        objc_setAssociatedObject(self, &telemetryPerformanceControllerKey, controller, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)
        controller.window?.center(); controller.showWindow(nil); controller.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    @objc private func openExternalComparison() {
        if let existing = objc_getAssociatedObject(self, &telemetryExternalComparisonControllerKey) as? RouterVPNMacExternalComparisonController, !existing.closed {
            existing.showWindow(nil); existing.window?.makeKeyAndOrderFront(nil); return
        }
        let controller = RouterVPNMacExternalComparisonController(api: api, product: self)
        objc_setAssociatedObject(self, &telemetryExternalComparisonControllerKey, controller, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)
        controller.window?.center(); controller.showWindow(nil); controller.window?.makeKeyAndOrderFront(nil)
    }

    fileprivate func showPerformanceMTU() { showMTUPanel(retest: true) }
    fileprivate func showPerformanceExternalComparison() { openExternalComparison() }

}

// Main-thread owner shared by the panel and its cancellable native request.
// HTTP cancellation retires the client task; backend admission remains held
// independently until transfers, the captured path observer and MTU work drain.
private final class RouterVPNMacPerformanceMeasurement {
    enum Kind { case live, node, speed, hops }
    let baseURL: URL
    private(set) var running = false
    private(set) var cancelled = false
    private(set) var closed = false
    private var generation: UInt64 = 0
    private var request: RouterVPNMacSpeedLabTransport?
    var changed: ((String) -> Void)?

    init(baseURL: URL) { self.baseURL = baseURL }
    deinit { request?.cancel() }

    @discardableResult func start(_ kind: Kind) -> Bool {
        guard !closed, !running else { return false }
        generation &+= 1
        let owner = generation
        running = true; cancelled = false
        switch kind {
        case .live:
            changed?("Measuring current tunnel RTT…")
            perform("/api/connection/live-latency", body: ["samples": 5], timeout: 12, owner: owner)
        case .node:
            changed?("Running 50-sample selected-node benchmark…")
            perform("/api/profiles", body: nil, timeout: 5, owner: owner) { [weak self] data in
                guard let self else { return }
                guard let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
                      let id = root["selected_id"] as? String, !id.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                    self.finish(.failure(Self.issue("Select a Router VPN node first.")), owner: owner); return
                }
                self.perform("/api/profile/latency", body: ["id": id, "samples": 50], timeout: 180, owner: owner)
            }
        case .speed:
            changed?("Transferring 8 MiB down and 8 MiB up through the current VPN path; Auto MTU is held during the transfer…")
            perform("/api/connection/speed-test", body: ["bytes": 8 * 1024 * 1024], timeout: 45, owner: owner)
        case .hops:
            changed?("Checking the complete active multihop graph before measuring every cumulative prefix…")
            perform("/api/multihop/status", body: nil, timeout: 5, owner: owner) { [weak self] data in
                guard let self else { return }
                guard let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
                      let connected = root["connected"] as? NSNumber,
                      CFGetTypeID(connected) == CFBooleanGetTypeID(), connected.boolValue,
                      let entry = root["entry_id"] as? String, let exit = root["exit_id"] as? String,
                      !entry.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                      !exit.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, entry != exit else {
                    self.finish(.failure(Self.issue("Connect an actual multihop graph with different entry and exit nodes first.")), owner: owner); return
                }
                var body: [String: Any] = ["entry_id": entry, "exit_id": exit, "bytes": 4 * 1024 * 1024]
                var timeout: TimeInterval = 70
                if root["ordered_capture"] != nil || root["ordered_nodes"] != nil {
                    guard let capture = root["ordered_capture"] as? String, capture.utf8.count == 64,
                          capture.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil,
                          let count = root["ordered_nodes"] as? NSNumber, CFGetTypeID(count) != CFBooleanGetTypeID(),
                          count.doubleValue.rounded() == count.doubleValue, (2...8).contains(count.intValue) else {
                        self.finish(.failure(Self.issue("The ordered native route has no complete measurement capture.")), owner: owner); return
                    }
                    body["ordered_capture"] = capture; body["bytes"] = 8 * 1024 * 1024; timeout = 100
                }
                self.perform("/api/multihop/speed-test", body: body, timeout: timeout, owner: owner)
            }
        }
        return true
    }

    func cancel() {
        guard running, !cancelled else { return }
        cancelled = true
        if !closed { changed?("Cancelling the owned request…") }
        request?.cancel()
    }

    func close() {
        closed = true
        cancel()
        // Keep the request until its completion. Forced teardown still cancels
        // real network work; a stale callback cannot publish into another panel.
    }

    private static func issue(_ message: String) -> Error {
        NSError(domain: "RouterVPNPerformance", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }

    private func perform(_ path: String, body: [String: Any]?, timeout: TimeInterval, owner: UInt64,
                         next: ((Data) -> Void)? = nil) {
        guard !closed, !cancelled, running, generation == owner else { return }
        do {
            guard let url = URL(string: path, relativeTo: baseURL)?.absoluteURL else { throw Self.issue("The local controller endpoint is unavailable.") }
            let owned = try RouterVPNMacSpeedLabTransport(url: url, body: body, timeout: timeout) { [weak self] result in
                DispatchQueue.main.async { [weak self] in
                    guard let self, self.generation == owner, self.running else { return }
                    self.request = nil
                    if self.closed { self.running = false; return }
                    if self.cancelled { self.finish(result, owner: owner); return }
                    if case .success(let data) = result, let next { next(data) }
                    else { self.finish(result, owner: owner) }
                }
            }
            request = owned; owned.start()
        } catch { finish(.failure(error), owner: owner) }
    }

    private func finish(_ result: Result<Data, Error>, owner: UInt64) {
        guard generation == owner, running else { return }
        request = nil; running = false
        guard !closed else { return }
        if cancelled {
            changed?("Client request cancelled. Controller cleanup may still be pending; another throughput test may remain unavailable until that work retires.")
            return
        }
        switch result {
        case .success(let data): changed?(String(data: data, encoding: .utf8) ?? "No result")
        case .failure(let error): changed?(error.localizedDescription)
        }
    }
}

private final class RouterVPNMacPerformanceController: NSWindowController, NSWindowDelegate {
    fileprivate private(set) var closed = false
    private var closeWanted = false
    private weak var product: ProductWindowController?
    private let measurement = RouterVPNMacPerformanceMeasurement(baseURL: routerVPNProductBaseURL)
    private let result = NSTextField(wrappingLabelWithString: "Choose a real measurement.")
    private let cancelButton = NSButton(title: "Cancel measurement", target: nil, action: nil)
    private var actions: [NSButton] = []

    init(product: ProductWindowController) {
        self.product = product
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 760, height: 470), styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        super.init(window: panel)
        panel.title = "Router VPN Performance"; panel.minSize = NSSize(width: 600, height: 380); panel.delegate = self
        let stack = NSStackView(); stack.orientation = .vertical; stack.spacing = 10
        stack.edgeInsets = NSEdgeInsets(top: 18, left: 18, bottom: 18, right: 18)
        let title = NSTextField(labelWithString: "Latency & path performance"); title.font = .systemFont(ofSize: 22, weight: .bold); stack.addArrangedSubview(title)
        let note = NSTextField(wrappingLabelWithString: "Private-node RTT measures the active private tunnel. External live response measures three HTTPS responses after TLS through the proved path and expires after ten seconds. Real path speed transfers to the active exit. Routed hop speeds measure the active entry and exit independently through the actual graph; unreachable hops keep their error. Each transfer reports actual bytes and elapsed time. Auto MTU is held during throughput measurements.")
        note.textColor = .secondaryLabelColor; stack.addArrangedSubview(note)
        result.font = .monospacedSystemFont(ofSize: 12, weight: .regular); result.isSelectable = true
        result.identifier = NSUserInterfaceItemIdentifier("telemetry-performance-result"); stack.addArrangedSubview(result)
        let row = NSStackView(); row.orientation = .horizontal; row.spacing = 8
        for (tag, title) in ["Live path response", "50-sample selected node", "Real path speed", "Routed hop speeds", "Throughput + Auto MTU"].enumerated() {
            let button = NSButton(title: title, target: self, action: #selector(measure(_:)))
            button.tag = tag; button.bezelStyle = .rounded; actions.append(button); row.addArrangedSubview(button)
        }
        stack.addArrangedSubview(row)
        let external = NSButton(title: "Compare external paths / connect fastest", target: self, action: #selector(compareExternal))
        external.bezelStyle = .rounded; actions.append(external); stack.addArrangedSubview(external)
        cancelButton.target = self; cancelButton.action = #selector(cancelMeasurement); cancelButton.bezelStyle = .rounded
        cancelButton.isEnabled = false; stack.addArrangedSubview(cancelButton)
        measurement.changed = { [weak self] text in self?.render(text) }
        panel.contentView = stack
    }
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    @objc private func measure(_ sender: NSButton) {
        guard !closed, !measurement.running else { return }
        switch sender.tag {
        case 0: measurement.start(.live)
        case 1: measurement.start(.node)
        case 2: measurement.start(.speed)
        case 3: measurement.start(.hops)
        case 4: product?.showPerformanceMTU()
        default: break
        }
    }
    @objc private func compareExternal() { if !closed, !measurement.running { product?.showPerformanceExternalComparison() } }
    @objc private func cancelMeasurement() { measurement.cancel() }
    private func render(_ text: String) {
        guard !closed else { return }
        result.stringValue = text
        for action in actions { action.isEnabled = !measurement.running }
        cancelButton.isEnabled = measurement.running && !measurement.cancelled
        if closeWanted, !measurement.running { window?.performClose(nil) }
    }
    func windowShouldClose(_ sender: NSWindow) -> Bool {
        if measurement.running { closeWanted = true; measurement.cancel(); return false }
        return true
    }
    func windowWillClose(_ notification: Notification) { closed = true; measurement.close() }
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


// One panel retains its actual loopback task through cancellation completion.
// Reopening it cannot cancel another request or install an older result.
private final class RouterVPNMacFastestController: NSWindowController, NSWindowDelegate {
    private let status = NSTextField(wrappingLabelWithString: "Collecting 50 TCP samples per Router node. Incomplete candidates receive no score. Ranking uses the 10% trimmed mean.")
    private let progress = NSProgressIndicator()
    private let cancelButton = NSButton(title: "Cancel measurement", target: nil, action: nil)
    private var request: RouterVPNMacSpeedLabTransport?
    private var completed: ((String) -> Void)?
    private var started = false
    private var closeWanted = false
    private(set) var isRunning = false

    init(completed: @escaping (String) -> Void) {
        self.completed = completed
        let panel = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 520, height: 190), styleMask: [.titled, .closable], backing: .buffered, defer: false)
        panel.title = "Find fastest Router node"
        panel.isReleasedWhenClosed = false
        super.init(window: panel)
        panel.delegate = self
        let stack = NSStackView(views: [status, progress, cancelButton])
        stack.orientation = .vertical; stack.alignment = .leading; stack.spacing = 16
        stack.translatesAutoresizingMaskIntoConstraints = false
        let content = NSView(); panel.contentView = content; content.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            stack.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -20),
            stack.topAnchor.constraint(equalTo: content.topAnchor, constant: 20),
            stack.bottomAnchor.constraint(lessThanOrEqualTo: content.bottomAnchor, constant: -20),
            status.widthAnchor.constraint(equalTo: stack.widthAnchor),
            progress.widthAnchor.constraint(equalTo: stack.widthAnchor)
        ])
        progress.style = .bar; progress.isIndeterminate = true
        cancelButton.target = self; cancelButton.action = #selector(cancelOrClose)
        panel.center()
    }
    required init?(coder: NSCoder) { fatalError("init(coder:) is not supported") }
    deinit { request?.cancel() }

    func start() {
        guard !started else { return }
        started = true; isRunning = true; progress.startAnimation(nil)
        do {
            guard let url = URL(string: "/api/profile/fastest", relativeTo: routerVPNProductBaseURL)?.absoluteURL else {
                throw NSError(domain: "RouterVPNMac", code: 1, userInfo: [NSLocalizedDescriptionKey: "The local controller endpoint is unavailable."])
            }
            let owned = try RouterVPNMacSpeedLabTransport(url: url, body: ["samples": 50, "select": true], timeout: 185) { [weak self] result in
                DispatchQueue.main.async { [weak self] in self?.finish(result) }
            }
            request = owned; owned.start()
        } catch { finish(.failure(error)) }
    }

    @objc private func cancelOrClose() {
        if isRunning {
            cancelButton.isEnabled = false
            status.stringValue = "Cancelling this measurement; waiting for the owned request to finish. The current selection will be refreshed."
            request?.cancel()
        } else { window?.performClose(nil) }
    }
    func windowShouldClose(_ sender: NSWindow) -> Bool {
        if isRunning { closeWanted = true; cancelOrClose(); return false }
        return true
    }
    func windowWillClose(_ notification: Notification) { request?.cancel() }

    private func finish(_ result: Result<Data, Error>) {
        guard isRunning else { return }
        isRunning = false; request = nil; progress.stopAnimation(nil)
        cancelButton.title = "Close"; cancelButton.isEnabled = true
        let message: String
        switch result {
        case .success(let data):
            // JSON booleans bridge to NSNumber too. Keep counts and timing values
            // numeric, and require an actual true boolean for selection.
            func number(_ value: Any?) -> Double? {
                guard let value = value as? NSNumber,
                      CFGetTypeID(value) != CFBooleanGetTypeID(), value.doubleValue.isFinite else { return nil }
                return value.doubleValue
            }
            if let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
               let selected = root["selected"] as? NSNumber,
               CFGetTypeID(selected) == CFBooleanGetTypeID(), selected.boolValue,
               let winner = root["winner"] as? [String: Any],
               let id = winner["id"] as? String, !id.isEmpty, root["selected_id"] as? String == id,
               number(winner["samples"]) == 50, number(winner["failed"]) == 0,
               let ms = number(winner["trimmed_mean_ms"]), ms > 0 {
                let name = winner["name"] as? String ?? id
                message = String(format: "Selected %@ · %.1f ms trimmed mean from 50 TCP samples. Press Connect when ready.", name, ms)
            } else { message = "The controller did not confirm a complete 50-sample winner. Refresh the current selection and retest." }
        case .failure(let error):
            message = "Fastest selection did not complete: \(error.localizedDescription) Current selection refreshed."
        }
        status.stringValue = message
        let callback = completed; completed = nil; callback?(message)
        if closeWanted { window?.performClose(nil) }
    }
}
