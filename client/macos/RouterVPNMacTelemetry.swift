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
private var telemetryForwardRequestKey: UInt8 = 0
private var telemetryPerformanceControllerKey: UInt8 = 0
private var telemetryExternalComparisonControllerKey: UInt8 = 0
private var telemetryFastestControllerKey: UInt8 = 0
private var telemetryOrderedCandidatesKey: UInt8 = 0
private var telemetryLiveDeliveryKey: UInt8 = 0

private struct RouterVPNMacForwardingState {
    let router: String
    let path: String
    let enabled: Bool
    let name: String

    init?(_ value: [String: Any]?) {
        guard let value, let ok = value["ok"] as? NSNumber, CFGetTypeID(ok) == CFBooleanGetTypeID(), ok.boolValue,
              let number = value["enabled"] as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID(),
              let router = value["router_id"] as? String, !router.isEmpty,
              let path = value["path_token"] as? String, path.utf8.count == 64,
              path.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { return nil }
        self.router = router
        self.path = path
        self.enabled = number.boolValue
        self.name = value["name"] as? String ?? router
    }
}

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

struct RouterVPNMacLiveRouteReceipt {
    let externalFinal: Bool
    let token: String
    let entry: Double?
    let exit: Double
    let deadline: TimeInterval

    static func decode(_ value: [String: Any], token: String, ids: [String], started: TimeInterval,
                       now: Date = Date(), uptime: TimeInterval = ProcessInfo.processInfo.systemUptime) -> Self? {
        guard let first = ids.first, let last = ids.last, first != last,
              value["active_route_id"] as? String == token, value["entry_id"] as? String == first,
              value["exit_id"] as? String == last, let path = value["current_path"] as? [String: Any],
              let connected = path["connected"] as? NSNumber, CFGetTypeID(connected) == CFBooleanGetTypeID(), connected.boolValue,
              path["mode"] as? String == "multihop", path["router_id"] as? String == last,
              let measured = path["measured_at"] as? String, let proof = path["proof"] as? String, !proof.isEmpty,
              value["current_path_error"] == nil, value["exit_error"] == nil,
              let exitRow = value["exit"] as? [String: Any], exitRow["id"] as? String == last,
              exitRow["measured_at"] as? String == measured, exitRow["description"] as? String == proof else { return nil }
        func median(_ row: [String: Any]) -> Double? {
            guard let succeeded = RouterVPNLiveHTTPSReceipt.number(row, "samples"),
                  let failed = RouterVPNLiveHTTPSReceipt.number(row, "failed"),
                  (1...2).contains(succeeded), succeeded.rounded() == succeeded, failed == 2 - succeeded,
                  let ms = RouterVPNLiveHTTPSReceipt.number(row, "median_ms"), ms > 0, ms <= 10000 else { return nil }
            return ms
        }
        guard let exit = median(path), median(exitRow) == exit, uptime >= started else { return nil }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let at = formatter.date(from: measured) ?? ISO8601DateFormatter().date(from: measured)
        guard let at, now >= at else { return nil }
        let remaining = min(10 - now.timeIntervalSince(at), 10 - (uptime - started))
        guard remaining > 0 else { return nil }
        var entry: Double?
        if let entryValue = value["entry"] {
            guard let row = entryValue as? [String: Any], row["id"] as? String == first, value["entry_error"] == nil, let ms = median(row) else { return nil }
            entry = ms
        } else if ids.count > 8 {
            // Longer original routes begin with the paired WireGuard node.
            return nil
        }
        return Self(externalFinal: proof.hasSuffix(" · HTTPS response after TLS through the captured external exit"), token: token, entry: entry, exit: exit, deadline: uptime + remaining)
    }
}

private final class RouterVPNLiveTelemetryDelivery {
    let probe = NSLock()
    var mapGeneration = UUID()
    var generation = UUID()
    var running = false
    var receipt: RouterVPNLiveHTTPSReceipt?
    var liveRoute: RouterVPNMacLiveRouteReceipt?
    var mutations: Set<UUID> = []
}

extension ProductWindowController {
    private var liveTelemetryDelivery: RouterVPNLiveTelemetryDelivery {
        if let value = objc_getAssociatedObject(self,&telemetryLiveDeliveryKey) as? RouterVPNLiveTelemetryDelivery {return value}
        let value = RouterVPNLiveTelemetryDelivery();objc_setAssociatedObject(self,&telemetryLiveDeliveryKey,value,.OBJC_ASSOCIATION_RETAIN_NONATOMIC);return value
    }
    var unifiedLiveProbe: NSLock { liveTelemetryDelivery.probe }

    private func clearLiveHTTPS() {
        let owner = liveTelemetryDelivery
        if let id = owner.receipt?.binding["profile_id"] {for node in map.annotations.compactMap({$0 as? RouterAnnotation}) where node.routerID == id {node.subtitle = node.storedSubtitle}}
        owner.receipt = nil;telemetryLiveLabel?.stringValue = "-- ms"
    }
    func liveHTTPSPaused() -> Bool {
        let performance = objc_getAssociatedObject(self,&telemetryPerformanceControllerKey) as? RouterVPNMacPerformanceController
        let comparison = objc_getAssociatedObject(self,&telemetryExternalComparisonControllerKey) as? RouterVPNMacExternalComparisonController
        let candidates = objc_getAssociatedObject(self,&telemetryOrderedCandidatesKey) as? RouterVPNMacOrderedCandidates
        return !liveTelemetryDelivery.mutations.isEmpty || window?.attachedSheet != nil || performance?.window?.isVisible == true || comparison?.window?.isVisible == true || candidates?.window?.isVisible == true || unifiedSpeedLabPresented() || orderedLatencyPresented()
    }
    // The shipping transform calls these on the main queue at mutation entry
    // and after its background work completes. Same-profile reconnects do not
    // change the selection UUID, so they require their own captured lease.
    var mapMutationGeneration: UUID? {
        let owner = liveTelemetryDelivery
        return owner.mutations.isEmpty && !MacViaEntryCandidateReservation.shared.active ? owner.mapGeneration : nil
    }

    func beginLiveHTTPSMutation() -> UUID {
        liveTelemetryDelivery.mapGeneration = UUID()
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
        fast.isHidden = true
        fast.controlSize = .small
        fast.target = self
        fast.action = #selector(unifiedFastConnectChanged(_:))
        fast.toolTip = "Select the fastest measured Router VPN node or choose a specific node. Use Connect separately."
        telemetryFastPopup = fast
        connectRow.insertArrangedSubview(fast, at: min(2, connectRow.arrangedSubviews.count))

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
        forwarding.isEnabled = false
        forwarding.state = .mixed
        forwarding.allowsMixedState = true
        forwarding.toolTip = "Real server forwarding master on the active Router VPN home node."
        telemetryForwardButton = forwarding
        connectRow.insertArrangedSubview(forwarding, at: min(3, connectRow.arrangedSubviews.count))

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
            let externals = values.filter { $0["node_kind"] as? String == "external" }
            let externalEligible = externals.count <= 128 && externals.filter {
                ($0["external"] as? [String: Any])?["https_comparison_supported"] as? Bool == true
            }.count >= 2
            let routers = values.filter {
                let kind = ($0["node_kind"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                return ["", "router-vpn"].contains(kind) && !($0["id"] as? String ?? "").isEmpty
            }
                .sorted {
                    let a = ($0["latency_trimmed_mean_ms"] as? NSNumber)?.doubleValue ?? Double.greatestFiniteMagnitude
                    let b = ($1["latency_trimmed_mean_ms"] as? NSNumber)?.doubleValue ?? Double.greatestFiniteMagnitude
                    return a == b ? (($0["name"] as? String) ?? "") < (($1["name"] as? String) ?? "") : a < b
                }
            DispatchQueue.main.async {
                guard self.telemetryFastestController?.isRunning != true else { return }
                popup.removeAllItems()
                popup.isHidden = routers.count < 2 && !externalEligible
                if routers.count > 1 {
                    popup.addItem(withTitle: "⚡ Fastest Router · 50 TCP samples")
                    popup.lastItem?.representedObject = "fastest"
                }
                if externalEligible {
                    popup.addItem(withTitle: "Compare external paths · 50 responses…")
                    popup.lastItem?.representedObject = "external-comparison"
                }
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

    private func setUnifiedForwardState(_ state: RouterVPNMacForwardingState?) {
        guard let button = telemetryForwardButton else { return }
        button.cell?.representedObject = state
        button.isEnabled = state != nil
        button.state = state.map { $0.enabled ? .on : .off } ?? .mixed
        button.title = state.map { $0.enabled ? "Forward ON" : "Forward OFF" } ?? "Forward ?"
        button.toolTip = state.map { "Server forwarding master on \($0.name)." }
            ?? "Connect a Router VPN home-node path to verify the forwarding master."
    }

    private func refreshUnifiedForwardingMaster() {
        guard objc_getAssociatedObject(self, &telemetryForwardRequestKey) == nil else { return }
        let request = NSUUID()
        objc_setAssociatedObject(self, &telemetryForwardRequestKey, request, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            let value = (try? self.api.json("/api/forwarding/master", timeout: 4)) as? [String: Any]
            let state = RouterVPNMacForwardingState(value)
            DispatchQueue.main.async {
                guard objc_getAssociatedObject(self, &telemetryForwardRequestKey) as? NSUUID == request else { return }
                objc_setAssociatedObject(self, &telemetryForwardRequestKey, nil, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)
                self.setUnifiedForwardState(state)
            }
        }
    }

    @objc private func toggleUnifiedForwardingMaster(_ sender: NSButton) {
        guard let original = sender.cell?.representedObject as? RouterVPNMacForwardingState else { return }
        let request = NSUUID()
        objc_setAssociatedObject(self, &telemetryForwardRequestKey, request, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)
        sender.isEnabled = false
        sender.title = "Forward …"
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            do {
                let data = try self.api.request("/api/forwarding/master", method: "PUT",
                    body: ["enabled": !original.enabled, "router_id": original.router, "path_token": original.path], timeout: 10)
                let value = try JSONSerialization.jsonObject(with: data) as? [String: Any]
                guard let updated = RouterVPNMacForwardingState(value), updated.router == original.router,
                      updated.path == original.path, updated.enabled != original.enabled else {
                    throw NSError(domain: "RouterVPNMac", code: 73,
                        userInfo: [NSLocalizedDescriptionKey: "The forwarding response did not verify the displayed connection and requested state."])
                }
                DispatchQueue.main.async {
                    objc_setAssociatedObject(self, &telemetryForwardRequestKey, nil, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)
                    self.setUnifiedForwardState(updated)
                    self.errorLabel.stringValue = "Forwarding master \(updated.enabled ? "ON" : "OFF") on \(updated.name)."
                }
            } catch {
                DispatchQueue.main.async {
                    objc_setAssociatedObject(self, &telemetryForwardRequestKey, nil, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)
                    self.setUnifiedForwardState(nil)
                    self.errorLabel.stringValue = "Forwarding master failed: \(error.localizedDescription)"
                }
            }
        }
    }

    func displayUnifiedLiveRoute(_ route: RouterVPNMacLiveRouteReceipt?) {
        let owner = liveTelemetryDelivery
        let previous = owner.liveRoute
        owner.liveRoute = nil
        guard let route, route.deadline > ProcessInfo.processInfo.systemUptime,
              window?.isVisible == true, !liveHTTPSPaused() else {
            if previous != nil { clearLiveHTTPS(); telemetryHopLabel?.stringValue = "" }
            return
        }
        clearLiveHTTPS()
        owner.liveRoute = route
        telemetryLiveLabel?.stringValue = String(format: "%.1f ms", route.exit)
        telemetryLiveLabel?.textColor = .labelColor
        telemetryLiveLabel?.toolTip = route.externalFinal ? "HTTPS response after TLS through the captured external exit." : "Authenticated private HTTP response through the current multihop route."
        var labels: [String] = []
        if let entry = route.entry { labels.append(String(format: "IN %.1f", entry)) }
        labels.append(String(format: "OUT %.1f", route.exit))
        labels.append(String(format: "PATH %.1f ms", route.exit))
        telemetryHopLabel?.stringValue = labels.joined(separator: " • ")
        DispatchQueue.main.asyncAfter(deadline: .now() + max(0, route.deadline - ProcessInfo.processInfo.systemUptime)) { [weak self] in
            guard let self, let current = owner.liveRoute, current.token == route.token, current.deadline == route.deadline else { return }
            self.displayUnifiedLiveRoute(nil)
        }
    }

    func refreshUnifiedTelemetry() {
        let delivery = liveTelemetryDelivery
        if delivery.receipt?.current() == false {clearLiveHTTPS()}
        if liveHTTPSPaused() {displayUnifiedLiveRoute(nil);delivery.generation = UUID();clearLiveHTTPS();return}
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
            if delivery.liveRoute == nil { telemetryHopLabel?.stringValue = "" }
        }

        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            defer { DispatchQueue.main.async { delivery.running = false } }
            // The globe observer owns the sole active multihop request and publishes
            // its proved final response to the Connect, hop and globe labels together.
            let route = (try? self.api.json("/api/multihop/status", timeout: 4)) as? [String: Any]
            guard let connected = route?["connected"] as? Bool, !connected else {
                DispatchQueue.main.async {
                    if delivery.generation == generation && delivery.liveRoute == nil { self.clearLiveHTTPS() }
                }
                return
            }
            guard delivery.probe.try() else { return }
            defer { delivery.probe.unlock() }
            let started = ProcessInfo.processInfo.systemUptime
            let value = (try? self.api.json("/api/connection/live-latency", timeout:4)) as? [String:Any]
            var receipt: RouterVPNLiveHTTPSReceipt?
            if let value, let first = RouterVPNLiveHTTPSReceipt.decode(value,started:started),let request = first.binding["request_id"],
               let checked = (try? self.api.json("/api/connection/live-latency?request_id="+request,timeout:3)) as? [String:Any],
               let next = RouterVPNLiveHTTPSReceipt.decode(checked,started:started),first.matches(next) {receipt=next}
            let currentRoute = (try? self.api.json("/api/multihop/status", timeout: 4)) as? [String: Any]
            let outsideMultihop = currentRoute?["connected"] as? Bool == false
            let captured = receipt
            DispatchQueue.main.async {
                guard outsideMultihop,delivery.generation == generation,delivery.liveRoute == nil,self.window?.isVisible == true,self.connectionProfileSelectionGeneration == selection else {return}
                if let captured {self.showLiveHTTPS(captured,owner:delivery,generation:generation,selection:selection)}
                else if value?["measurement"] == nil,value?["mode"] as? String != "multihop",let value,let ms=RouterVPNLiveHTTPSReceipt.number(value,"median_ms"),ms>0 {self.clearLiveHTTPS();self.telemetryLiveLabel?.stringValue=String(format:"%.1f ms",ms);self.telemetryLiveLabel?.toolTip="HTTP RTT through the current private Router-node path."}
                else {self.clearLiveHTTPS();self.telemetryLiveLabel?.textColor = .secondaryLabelColor}
            }

            guard outsideMultihop, let (entry, exit) = hopIDs,
                  let data = try? self.api.request("/api/multihop/live-latency", method: "POST", body: ["entry_id": entry, "exit_id": exit, "samples": 2], timeout: 8),
                  let draft = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  draft["entry_id"] as? String == entry, draft["exit_id"] as? String == exit,
                  draft["active_route_id"] == nil, draft["current_path"] == nil else { return }
            var parts: [String] = []
            for (key, expected, label) in [("entry", entry, "IN"), ("exit", exit, "OUT")] {
                if let row = draft[key] as? [String: Any], row["id"] as? String == expected,
                   let ms = RouterVPNLiveHTTPSReceipt.number(row, "median_ms"), ms > 0 {
                    parts.append(String(format: "%@ %.1f", label, ms))
                }
            }
            let summary = parts.joined(separator: " • ")
            DispatchQueue.main.async {
                guard delivery.generation == generation, delivery.liveRoute == nil, self.window?.isVisible == true,
                      self.connectionProfileSelectionGeneration == selection, !self.liveHTTPSPaused() else { return }
                self.telemetryHopLabel?.stringValue = summary
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

    func showOrderedPrefixCandidates(savedPath: Bool = false, savedPrefix: Bool = false,
                                     draft: [String: Any]? = nil, position: Int = 0,
                                     choose: (([String: Any]) throws -> Void)? = nil) {
        if let existing = objc_getAssociatedObject(self,&telemetryOrderedCandidatesKey) as? RouterVPNMacOrderedCandidates, !existing.closed {
            if (draft == nil && existing.matchesPurpose(savedPath: savedPath, savedPrefix: savedPrefix)) || !existing.closeForPurposeChange() {
                existing.showWindow(nil); existing.window?.makeKeyAndOrderFront(nil); return
            }
        }
        let controller=RouterVPNMacOrderedCandidates(savedPath: savedPath, savedPrefix: savedPrefix, draft: draft, position: position, choose: choose);objc_setAssociatedObject(self,&telemetryOrderedCandidatesKey,controller,.OBJC_ASSOCIATION_RETAIN_NONATOMIC);controller.showWindow(nil)
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

    private struct ExtendedRoute: Equatable {
        let source, config, token: String
        let selected, generation: String?
        let ids: [String]
        let pairedWireGuard: Bool
        let externalFinal: String?
        let pairedPrefixNodes: Int?
        let localRoles: [String]?
        init?(_ root: [String: Any], count: Int, token: String, entry: String, exit: String) {
            func digest(_ value: Any?) -> String? {
                guard let text = value as? String, text.utf8.count == 64,
                      text.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { return nil }
                return text
            }
            let selectedSource = root["ordered_original_source"] != nil
            let key = selectedSource ? "ordered_original_source" : "ordered_local_source"
            guard (3...96).contains(count), root[selectedSource ? "ordered_local_source" : "ordered_original_source"] == nil,
                  let record = root[key] as? [String: Any] else { return nil }
            if record.keys.contains("external_final_node_id") {
                guard !selectedSource, let id = record["external_final_node_id"] as? String, id == exit, id != entry,
                      root["execution"] as? String == "local", Set(record.keys) == ["source_sha256","config_sha256","node_ids","external_final_node_id"] else { return nil }
                externalFinal = id
            } else {
                guard count >= 9 else { return nil }
                externalFinal = nil
            }
            if selectedSource {
                var fields: Set<String> = ["source_sha256", "config_sha256", "generation_sha256", "selected_execution", "node_ids"]
                if record.keys.contains("selected_roles_json") {
                    guard let roles = RouterVPNSelectedPublicInventory.localRoles(record["selected_roles_json"], count: count),
                          RouterVPNSelectedPublicInventory.selectedPrivateRoles(roles) else { return nil }
                    fields.insert("selected_roles_json"); localRoles = roles
                } else { localRoles = nil }
                guard Set(record.keys) == fields,
                      let winner = record["selected_execution"] as? String, ["local", "server"].contains(winner),
                      let epoch = digest(record["generation_sha256"]) else { return nil }
                selected = winner; generation = epoch; pairedWireGuard = false; pairedPrefixNodes = nil
            } else {
                var fields: Set<String> = ["source_sha256", "config_sha256", "node_ids"]
                if externalFinal != nil { fields.insert("external_final_node_id") }
                if let value = record["paired_wireguard"] {
                    guard let flag = value as? NSNumber, CFGetTypeID(flag) == CFBooleanGetTypeID(), flag.boolValue else { return nil }
                    fields.insert("paired_wireguard")
                    pairedWireGuard = true
                } else { pairedWireGuard = false }
                if let raw = record["paired_prefix_nodes"] {
                    guard !pairedWireGuard, let number = raw as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
                          let packets = Int(number.stringValue), (1..<count-1).contains(packets) else { return nil }
                    fields.insert("paired_prefix_nodes"); pairedPrefixNodes = packets
                } else { pairedPrefixNodes = nil }
                if record.keys.contains("local_roles_json") {
                    guard !pairedWireGuard, pairedPrefixNodes == nil,
                          let roles = RouterVPNSelectedPublicInventory.localRoles(record["local_roles_json"], count: count) else { return nil }
                    fields.insert("local_roles_json"); localRoles = roles
                } else { localRoles = nil }
                guard Set(record.keys) == fields else { return nil }
                selected = nil; generation = nil
            }
            guard let source = digest(record["source_sha256"]), let config = digest(record["config_sha256"]),
                  let ids = record["node_ids"] as? [String], ids.count == count, Set(ids).count == count,
                  ids.first == entry, ids.last == exit, ids.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 128 && $0.rangeOfCharacter(from: .controlCharacters) == nil }) else { return nil }
            if externalFinal != nil && !ids.allSatisfy({ $0.range(of: #"\A[A-Za-z0-9_-]{1,64}\z"#, options: .regularExpression) != nil }) { return nil }
            self.source = source; self.config = config; self.ids = ids; self.token = token
        }
        func matches(_ data: Data) -> Bool {
            guard let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
                  let connected = root["connected"] as? NSNumber, CFGetTypeID(connected) == CFBooleanGetTypeID(), connected.boolValue,
                  root["mode"] as? String == "multihop", selected == nil || root["execution"] as? String == selected, root["entry_id"] as? String == ids.first, root["exit_id"] as? String == ids.last,
                  root["ordered_capture"] as? String == token, root["ordered_nodes"] as? NSNumber == NSNumber(value: ids.count),
                  root["bytes"] as? NSNumber == 8388608, let rows = root["hops"] as? [[String: Any]], rows.count == ids.count,
                  ExtendedRoute(root, count: ids.count, token: token, entry: ids[0], exit: ids[ids.count-1]) == self else { return false }
            for (i, row) in rows.enumerated() {
                let interior = i > 0 && i < ids.count - 1
                let role = i == 0 ? "entry" : interior ? "intermediate" : "exit"
                let publicPath = externalFinal != nil ? i > 0 : localRoles.map { $0[i] == "public-path" } ?? (interior && !pairedWireGuard && i >= (pairedPrefixNodes ?? 1))
                let prefix = (selected.map { "Cumulative " + $0 + " path through node " } ?? "Cumulative path through node ") + "\(i+1) of \(ids.count)" + (publicPath ? " to the public benchmark" : "")
                guard row["role"] as? String == role, row["router_id"] as? String == ids[i],
                      row["speed_label"] as? String == prefix + " transfer", row["latency_label"] as? String == prefix + " HTTP response",
                      let speed = row["speed"] as? [String: Any], speed["router_id"] as? String == ids[i], speed["bytes"] as? NSNumber == 8388608,
                      let latency = row["latency"] as? [String: Any], latency["router_id"] as? String == ids[i] else { return false }
            }
            return true
        }
    }

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
                var extended: ExtendedRoute?
                if root["ordered_capture"] != nil || root["ordered_nodes"] != nil || root["ordered_local_source"] != nil || root["ordered_original_source"] != nil {
                    guard let capture = root["ordered_capture"] as? String, capture.utf8.count == 64,
                          capture.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil,
                          let count = root["ordered_nodes"] as? NSNumber, CFGetTypeID(count) != CFBooleanGetTypeID(),
                          count.doubleValue.rounded() == count.doubleValue, (2...96).contains(count.intValue) else {
                        self.finish(.failure(Self.issue("The ordered native route has no complete measurement capture.")), owner: owner); return
                    }
                    if count.intValue > 8 || root["ordered_local_source"] != nil {
                        extended = ExtendedRoute(root, count: count.intValue, token: capture, entry: entry, exit: exit)
                        guard let route = extended, root["execution"] as? String == (route.selected ?? "local") else {
                            self.finish(.failure(Self.issue("The ordered native route has no complete measurement capture.")), owner: owner); return
                        }
                    } else if root["ordered_local_source"] != nil || root["ordered_original_source"] != nil {
                        self.finish(.failure(Self.issue("The ordered native route has no complete measurement capture.")), owner: owner); return
                    }
                    body["ordered_capture"] = capture; body["bytes"] = 8 * 1024 * 1024; timeout = 100
                }
                if let extended {
                    self.perform("/api/multihop/speed-test", body: body, timeout: timeout, owner: owner) { data in
                        self.finish(extended.matches(data) ? .success(data) : .failure(Self.issue("The throughput result belongs to another ordered route.")), owner: owner)
                    }
                } else {
                    self.perform("/api/multihop/speed-test", body: body, timeout: timeout, owner: owner) { data in
                        let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
                        let unexpected = root?["ordered_local_source"] != nil || root?["ordered_original_source"] != nil || ((root?["ordered_nodes"] as? NSNumber)?.intValue ?? 0) > 8
                        self.finish(unexpected ? .failure(Self.issue("The throughput result belongs to another ordered route.")) : .success(data), owner: owner)
                    }
                }
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
        let candidates = NSButton(title: "Candidates through connected prefix", target: self, action: #selector(prefixCandidates))
        candidates.bezelStyle = .rounded; actions.append(candidates); stack.addArrangedSubview(candidates)
        let savedCandidates = NSButton(title: "Test saved Local path", target: self, action: #selector(savedPathCandidates))
        savedCandidates.bezelStyle = .rounded; actions.append(savedCandidates)
        let prefixOnly = NSButton(title: "Test selected prefix only", target: self, action: #selector(savedPrefixCandidates))
        prefixOnly.bezelStyle = .rounded; actions.append(prefixOnly)
        let savedRow = NSStackView(views: [savedCandidates, prefixOnly]); savedRow.orientation = .horizontal; savedRow.spacing = 8; stack.addArrangedSubview(savedRow)
        let orderedLatency = NSButton(title: "50 responses per hop", target: self, action: #selector(measureOrderedLatency))
        orderedLatency.bezelStyle = .rounded; actions.append(orderedLatency); stack.addArrangedSubview(orderedLatency)
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
    @objc private func prefixCandidates() { if !closed, !measurement.running {product?.showOrderedPrefixCandidates()} }
    @objc private func savedPathCandidates() { if !closed, !measurement.running {product?.showOrderedPrefixCandidates(savedPath: true)} }
    @objc private func savedPrefixCandidates() { if !closed, !measurement.running {product?.showOrderedPrefixCandidates(savedPrefix: true)} }
    @objc private func measureOrderedLatency() { if !closed, !measurement.running { product?.showOrderedLatency() } }
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

// Original completion timestamps survive every UI refresh. These timings prove
// TCP reachability through a captured prefix, not candidate authentication.
private enum RouterVPNOrderedCandidateDisplay {
    static func number(_ value: [String: Any], _ key: String) -> Double? {
        guard let n = value[key] as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID(), n.doubleValue.isFinite else { return nil }; return n.doubleValue
    }
    static func flag(_ value: [String: Any], _ key: String) -> Bool {
        guard let n = value[key] as? NSNumber, CFGetTypeID(n) == CFBooleanGetTypeID() else { return false }; return n.boolValue
    }
    static func falseFlag(_ value: [String: Any], _ key: String) -> Bool {
        guard let n = value[key] as? NSNumber, CFGetTypeID(n) == CFBooleanGetTypeID() else { return false }; return !n.boolValue
    }
    static func purpose(_ value: [String: Any], scope: String) -> Bool {
        guard ["saved-complete-local","saved-prefix-local","draft-complete-selected"].contains(scope), value["scope"] as? String == scope else { return false }
        return scope != "saved-prefix-local" || (falseFlag(value,"application_open") && falseFlag(value,"dns_open") && value["proof_scope"] as? String == "selected-prefix")
    }
    static func responseSource(_ value: [String: Any], position: Int, draft: [String: Any]?) -> [[String: String]]? {
        guard let rows = value["response_source_nodes"] as? [[String: String]], ((value.keys.contains("response_executions") ? 3 : 4)...96).contains(rows.count),
              number(value,"prefix_position") == Double(position),
              position >= 1, position <= rows.count - 2, position == rows.count - 2 || rows.count < 96 else { return nil }
        var ids = Set<String>()
        for (i, row) in rows.enumerated() {
            let boundary = i == 0 || i == rows.count - 1
            let paired = row["kind"] == "router-vpn"
            if !boundary && paired {
                guard i >= 2 else { return nil }
            }
            guard row.count == 3, let id = row["id"], (1...64).contains(id.utf8.count),
                  id.utf8.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45 || $0 == 95 }),
                  ids.insert(id).inserted, (i == 0 ? ["wg", "awg2-fast", "awg2-strong"].contains(row["mode"] ?? "") : row["mode"] == "shadowsocks"),
                  (boundary ? paired : paired || row["kind"] == "external") else { return nil }
        }
        if let draft {
            guard draft["execution"] as? String == "auto" || (value.keys.contains("response_executions") && draft["execution"] as? String == "server"), let nodes = draft["nodes"] as? [[String:String]],
                  nodes == rows.map({ ["id":$0["id"]!, "mode":$0["mode"]!] }) else { return nil }
        }
        return rows
    }
    // Connected three-node Compare catalogs predate the original-source map.
    static func legacyConnectedResponse(_ value: [String: Any], choices: [[String: Any]]) -> Bool {
        guard responseWinner(value, position: 1, draft: nil),
              let prefixes = value["prefixes"] as? [[String: Any]], prefixes.count == 2,
              number(prefixes[0], "position") == 0, let entryMode = prefixes[0]["mode"] as? String, ["wg", "awg2-fast", "awg2-strong"].contains(entryMode),
              number(prefixes[1], "position") == 1, prefixes[1]["mode"] as? String == "shadowsocks",
              let entry = prefixes[0]["id"] as? String, let middle = prefixes[1]["id"] as? String,
              !entry.isEmpty, !middle.isEmpty, entry != middle else { return false }
        return choices.allSatisfy { choice in
            guard choice["proposal_action"] == nil, choice["kind"] as? String == "router-vpn",
                  let id = choice["id"] as? String, !id.isEmpty, id != entry, id != middle else { return false }
            if choice["proposed_path"] == nil { return !(choice["save_reason"] as? String ?? "").isEmpty }
            return choice["proposed_path"] as? [[String:String]] == [
                ["id":entry,"mode":entryMode], ["id":middle,"mode":"shadowsocks"], ["id":id,"mode":"shadowsocks"]]
        }
    }
    static func responseDraft(_ draft: [String: Any]?, position: Int, view: [String:Any] = [:]) -> Bool {
        if view.keys.contains("response_source_nodes") { return responseSource(view,position:position,draft:draft) != nil }
        guard position == 1, draft?["execution"] as? String == "auto",
              let nodes = draft?["nodes"] as? [[String: String]] else { return false }
        return nodes.count == 3 && ["wg", "awg2-fast", "awg2-strong"].contains(nodes[0]["mode"] ?? "") && nodes.dropFirst().allSatisfy { $0["mode"] == "shadowsocks" }
    }
    static func responseProposal(_ choice: [String:Any], source: [[String:String]], position: Int) -> Bool {
        guard choice["kind"] as? String == "router-vpn", let id = choice["id"] as? String, id.range(of: #"\A[A-Za-z0-9_-]{1,64}\z"#,options:.regularExpression) != nil,
              !source.contains(where: { $0["id"] == id }), let proposal = choice["proposed_path"] as? [[String:String]] else { return false }
        let replacesFinal = position == source.count - 2
        guard choice["proposal_action"] as? String == (replacesFinal ? "save-final-profile" : "save-intermediate-profile") else { return false }
        var expected = source.map { ["id":$0["id"]!, "mode":$0["mode"]!] }
        if replacesFinal { expected.removeLast() }
        expected.insert(["id":id,"mode":"shadowsocks"], at: position + 1)
        return proposal == expected
    }
    static func responseWinner(_ value: [String: Any], position: Int, draft: [String: Any]?) -> Bool {
        if value.keys.contains("response_executions") {
            guard let owners = value["response_executions"] as? [String], let requested = value["requested_execution"] as? String,
                  requested == "server" ? owners == ["server"] : requested == "auto" && [["local"],["local","server"]].contains(owners),
                  (draft == nil || draft?["execution"] as? String == requested),
                  responseSource(value,position:position,draft:draft) != nil else { return false }
            if value["selected_execution"] == nil && value["selection_epoch"] == nil {
                guard draft != nil, value["scope"] as? String == "draft-complete-selected" else { return false }
                return owners.count == 1 ? value["required_selected_execution"] as? String == owners[0] : value["required_selected_execution"] == nil
            }
            guard let winner = value["selected_execution"] as? String, owners.contains(winner),
                  value["required_selected_execution"] as? String == winner, let raw = value["selection_epoch"] as? NSNumber,
                  CFGetTypeID(raw) != CFBooleanGetTypeID(), let epoch = UInt64(raw.stringValue) else { return false }
            return epoch > 0
        }
        let eligible = value.keys.contains("response_source_nodes") ? responseSource(value,position:position,draft:draft) != nil : position == 1
        guard eligible, value["requested_execution"] as? String == "auto",
              value["required_selected_execution"] as? String == "local", draft == nil || responseDraft(draft, position: position, view: value) else { return false }
        if value["selected_execution"] == nil && value["selection_epoch"] == nil {
            return draft != nil && value["scope"] as? String == "draft-complete-selected"
        }
        guard value["selected_execution"] as? String == "local", let raw = value["selection_epoch"] as? NSNumber,
              CFGetTypeID(raw) != CFBooleanGetTypeID(), let epoch = UInt64(raw.stringValue) else { return false }
        return epoch > 0
    }
    static func draftExecution(_ value: [String: Any], draft: [String: Any]?, position: Int,
                               catalog: Bool, winner: String, epoch: UInt64) -> Bool {
        guard let draft, let requested = draft["execution"] as? String, ["server","auto"].contains(requested) else { return true }
        guard value["requested_execution"] as? String == requested else { return false }
        if value.keys.contains("response_executions") && !responseWinner(value,position:position,draft:draft) { return false }
        if catalog {
            guard value["selected_execution"] == nil, value["selection_epoch"] == nil,
                  let nodes = draft["nodes"] as? [[String:String]], nodes.indices.contains(position),
                  let prefix = nodes[position]["id"], let mode = nodes[position]["mode"],
                  ["wg","awg2-fast","awg2-strong"].contains(mode) || (value["measurement"] as? String == "routed-candidate-response" && responseWinner(value,position: position,draft: draft)),
                  let prefixes = value["prefixes"] as? [[String:Any]] else { return false }
            let rows = prefixes.filter { number($0,"position") == Double(position) }
            return rows.count == 1 && rows[0]["id"] as? String == prefix && rows[0]["mode"] as? String == mode
        }
        if value["selected_execution"] == nil, value["selection_epoch"] == nil {
            return winner.isEmpty && !flag(value,"accepted") && !flag(value,"reviewing") && !flag(value,"chosen") &&
                ((value["results"] as? [[String:Any]])?.isEmpty ?? true)
        }
        guard !flag(value,"admission_cancelled"), let selected = value["selected_execution"] as? String, ["local","server"].contains(selected),
              requested == "auto" || selected == "server", let raw = value["selection_epoch"] as? NSNumber,
              CFGetTypeID(raw) != CFBooleanGetTypeID(), let generation = UInt64(raw.stringValue), generation > 0 else { return false }
        if value["measurement"] as? String == "routed-candidate-response" && !responseWinner(value,position: position,draft: draft) {
            guard selected == "server", requested == "auto", value["required_selected_execution"] as? String == "local",
                  responseSource(value,position:position,draft:draft) != nil, flag(value,"native_down"),
                  ["running","accepted","reviewing"].allSatisfy({ falseFlag(value,$0) }), !flag(value,"chosen"), !flag(value,"saved"),
                  value["saved_profile_id"] as? String == "", let results = value["results"] as? [[String:Any]], results.isEmpty,
                  flag(value,"cancelled") || !(value["failure"] as? String ?? "").isEmpty else { return false }
        }
        return winner.isEmpty || (selected == winner && generation == epoch)
    }
    static func review(_ value: [String: Any], savedPath: Bool, scope: String = "saved-complete-local") -> Bool {
        guard flag(value, "accepted") else { return false }
        return !savedPath || (purpose(value,scope:scope) &&
            flag(value, "native_down") && flag(value, "reviewing") && falseFlag(value, "cleanup_pending") &&
            falseFlag(value, "running") && falseFlag(value, "cancelled") && falseFlag(value, "drained") && (value["saved_profile_id"] as? String) == "")
    }
    static func savesMeasuredFinal(_ choice: [String: Any], draft: [String: Any]?, position: Int, metric: String, view: [String:Any] = [:]) -> Bool {
        if view.keys.contains("response_source_nodes") {
            guard let draft, metric == "routed-candidate-response",
                  let source = responseSource(view,position:position,draft:draft) else { return false }
            return responseProposal(choice,source:source,position:position)
        }
        if choice["proposal_action"] as? String == "save-intermediate-profile" {
            guard metric == "routed-candidate-response", let draft, draft["execution"] as? String == "local",
                  let original = draft["nodes"] as? [[String: String]], original.count < 96,
                  position >= 1, position + 2 < original.count, original[position]["mode"] == "shadowsocks",
                  original[position + 1]["mode"] == "shadowsocks", original.last?["mode"] == "shadowsocks",
                  choice["kind"] as? String == "router-vpn", let id = choice["id"] as? String, !id.isEmpty,
                  !original.contains(where: { $0["id"] == id }),
                  let proposed = choice["proposed_path"] as? [[String: String]] else { return false }
            var expected = original
            expected.insert(["id": id, "mode": "shadowsocks"], at: position + 1)
            return expected == proposed
        }
        guard metric == "routed-candidate-response", choice["proposal_action"] as? String == "save-final-profile",
              let draft, draft["execution"] as? String == "local" || responseDraft(draft,position: position, view: view), let original = draft["nodes"] as? [[String: String]],
              position > 0, position == original.count - 2, original[position]["mode"] == "shadowsocks",
              original.last?["mode"] == "shadowsocks", let id = choice["id"] as? String, choice["kind"] as? String == "router-vpn",
              !original.contains(where: { $0["id"] == id }), let proposed = choice["proposed_path"] as? [[String: String]] else { return false }
        return proposed == Array(original.dropLast()) + [["id": id, "mode": "shadowsocks"]]
    }
    static func responseDraftPath(_ choice: [String:Any], draft: [String:Any]?, position: Int, view: [String:Any]) -> [[String:String]]? {
        guard let draft, metric(view, position: position, draft: draft) == "routed-candidate-response",
              choice["draft_action"] as? String == "insert-measured-hop", choice["kind"] as? String == "router-vpn",
              let id = choice["id"] as? String, id.range(of: #"\A[A-Za-z0-9_-]{1,64}\z"#,options:.regularExpression) != nil,
              let original = draft["nodes"] as? [[String:String]], original.count < 96,
              position >= 1, position + 1 < original.count, !original.contains(where: { $0["id"] == id }),
              let path = choice["draft_path"] as? [[String:String]] else { return nil }
        if draft["execution"] as? String == "auto", original.count > 3 {
            guard responseSource(view,position:position,draft:draft) != nil else { return nil }
        }
        var expected = original
        expected.insert(["id":id,"mode":"shadowsocks"], at:position+1)
        return path == expected ? path : nil
    }
    static func sampleLabel(_ measurement: String) -> String {
        measurement == "routed-candidate-response" ? "private-agent responses" : "TCP connections"
    }
    static func metric(_ value: [String: Any], position: Int, draft: [String: Any]? = nil) -> String? {
        guard let measurement = value["measurement"] as? String,
              let prefixes = value["prefixes"] as? [[String: Any]] else { return nil }
        let selected = prefixes.filter { number($0, "position") == Double(position) }
        guard selected.count == 1, let mode = selected[0]["mode"] as? String else { return nil }
        let prefixMetric = selected[0]["measurement"] as? String
        guard selected[0]["measurement"] == nil || prefixMetric == measurement else { return nil }
        switch measurement {
        case "routed-tcp-connect": return ["wg", "awg2-fast", "awg2-strong"].contains(mode) ? measurement : nil
        case "routed-candidate-response":
            guard prefixMetric == measurement, (1..<(96 - 1)).contains(position), mode == "shadowsocks", value["requested_execution"] == nil || value["requested_execution"] as? String == "local" || responseWinner(value,position: position,draft: draft),
                  let id = selected[0]["id"] as? String, id.range(of: #"\A[A-Za-z0-9_-]{1,64}\z"#, options: .regularExpression) != nil,
                  let candidates = value["candidates"] as? [[String: Any]],
                  candidates.allSatisfy({ $0["kind"] as? String == "router-vpn" }) else { return nil }
            if let draft {
                guard draft["execution"] as? String == "local" || responseWinner(value,position: position,draft: draft), let nodes = draft["nodes"] as? [[String: String]],
                      nodes.indices.contains(position), position < nodes.count - 1, nodes[position]["id"] == id,
                      nodes[position]["mode"] == mode else { return nil }
            }
            return measurement
        default: return nil
        }
    }
    static func score(_ row: [String: Any], measurement: String = "routed-tcp-connect", now: Double = Date().timeIntervalSince1970 * 1000) -> Double? {
        guard ["routed-tcp-connect", "routed-candidate-response"].contains(measurement),
              row["measurement"] as? String == measurement, row["stage"] as? String == "complete", flag(row,"complete"), flag(row,"drained"),
              let at = number(row,"measured_at"), let expires = number(row,"expires_at"), at > 0, at <= now, expires == at + 120000, expires > now,
              let values = row["results"] as? [[String: Any]], values.count == 1, let value = values.first, !value.keys.contains("candidate_disposition"),
              value["node_id"] as? String == row["candidate_id"] as? String, value["role"] as? String == "candidate", value["kind"] as? String == (measurement == "routed-candidate-response" ? "private-agent-response" : "tcp-connect"), flag(value,"ready"),
              let b = value["benchmark"] as? [String: Any], b["measurement"] as? String == measurement, number(b,"attempts") == 50, number(b,"failed") == 0,
              let d = b["distribution"] as? [String: Any], number(d,"samples") == 50, let min = number(d,"min_ms"), let max = number(d,"max_ms"), let score = number(b,"trimmed_mean_ms"), min > 0, score >= min, score <= max else { return nil }
        return score
    }
    static func path(_ nodes: [[String: Any]]) -> String { nodes.map { ($0["id"] as? String ?? "?") + " (" + ($0["mode"] as? String ?? "?") + ")" }.joined(separator: " → ") }
}

private final class RouterVPNMacOrderedCandidates: NSWindowController, NSWindowDelegate, NSTableViewDataSource, NSTableViewDelegate {
    private let savedPath: Bool
    private let savedPrefix: Bool
    private var selectedWinner = ""
    private var selectedEpoch: UInt64 = 0
    private var savedScope: String { if ["server","auto"].contains(draft?["execution"] as? String ?? "") { return "draft-complete-selected" }; return savedPrefix ? "saved-prefix-local" : "saved-complete-local" }
    private var catalogSuffix: String {
        let scope = savedPrefix ? "&scope="+savedScope : ""
        let requestServer = !savedPath || ["server","auto"].contains(draft?["execution"] as? String ?? "")
        return scope + (requestServer ? "&server_response=true" : "")
    }
    private let draft: [String: Any]?
    private let choose: (([String: Any]) throws -> Void)?
    private var chosenID = ""
    private var endpoint: String { draft != nil ? "/api/multihop/draft-candidates" : savedPath ? "/api/multihop/saved-candidates" : "/api/multihop/prefix-candidates" }
    private let prefix = NSPopUpButton(frame: .zero, pullsDown: false)
    private let table = NSTableView()
    private let status = NSTextField(wrappingLabelWithString: "Capturing original saved candidate sources…")
    private let preview = NSTextField(wrappingLabelWithString: "Select a result to preview its complete next-connection path.")
    private let profileName = NSTextField()
    private let refresh = NSButton(title: "Capture this prefix", target: nil, action: nil)
    private let test = NSButton(title: "Test selected candidates", target: nil, action: nil)
    private let useDraft = NSButton(title: "Use in draft", target: nil, action: nil)
    private let save = NSButton(title: "Save next-connection profile", target: nil, action: nil)
    private let cancel = NSButton(title: "Cancel test", target: nil, action: nil)
    private var request: RouterVPNMacSpeedLabTransport?
    private var phase = ""
    private var requestID = ""
    private var position = 0
    private var view: [String: Any]?
    private var measurement: String { view?["measurement"] as? String ?? "" }
    private var receipt: [String: Any]?
    private var choices: [[String: Any]] = []
    private var rows: [[String: Any]] = []
    private var receipts: [String: [String: Any]] = [:]
    private var savedProfileID = "", savedProfileName = ""
    private var savedNativeDown = false
    private var savedAdmitted = false
    private var editLease: UUID?
    private var pendingDrain = false
    private var cancelWanted = false
    private var closeWanted = false
    private var generation: UInt64 = 0
    private var nextRetry = Date()
    private var timer: Timer?
    fileprivate private(set) var closed = false

    init(savedPath: Bool = false, savedPrefix: Bool = false, draft: [String: Any]? = nil, position: Int = 0,
         choose: (([String: Any]) throws -> Void)? = nil) {
        self.draft = draft; self.position = position; self.choose = choose
        self.savedPath = savedPath || savedPrefix; self.savedPrefix = savedPrefix
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 820, height: 570), styleMask: [.titled,.closable,.resizable], backing: .buffered, defer: false)
        super.init(window: panel); panel.title = draft != nil ? "Measure the next hop" : savedPrefix ? "Test saved prefix" : self.savedPath ? "Test saved Local path" : "Candidates through connected prefix"; panel.delegate = self; panel.isReleasedWhenClosed = false
        let stack = NSStackView(); stack.orientation = .vertical; stack.alignment = .leading; stack.spacing = 12; stack.edgeInsets = NSEdgeInsets(top: 18,left: 18,bottom: 18,right: 18)
        stack.addArrangedSubview(NSTextField(wrappingLabelWithString: "WireGuard and AWG prefixes measure TCP connection time. Shadowsocks 2022 prefixes time authenticated responses from paired candidates. A Server trial requires a separately provisioned candidate. Each score uses 50 samples of the metric shown in the table."))
        let top = NSStackView(views: [prefix,refresh]); top.orientation = .horizontal; stack.addArrangedSubview(top)
        for (id,title,width) in [("name","Saved candidate",360.0),("timing","Measured time",300.0)] {let column = NSTableColumn(identifier:NSUserInterfaceItemIdentifier(id));column.title=title;column.width=width;table.addTableColumn(column)}
        table.dataSource=self;table.delegate=self;table.allowsMultipleSelection=true;table.usesAlternatingRowBackgroundColors=true
        let scroll=NSScrollView();scroll.documentView=table;scroll.hasVerticalScroller=true;stack.addArrangedSubview(scroll);scroll.heightAnchor.constraint(greaterThanOrEqualToConstant:230).isActive=true;scroll.widthAnchor.constraint(greaterThanOrEqualToConstant:700).isActive=true
        stack.addArrangedSubview(preview);profileName.placeholderString="Explicit next-connection profile name";stack.addArrangedSubview(profileName);profileName.widthAnchor.constraint(greaterThanOrEqualToConstant:400).isActive=true;stack.addArrangedSubview(status)
        let actions=NSStackView(views:[test,useDraft,save,cancel]);actions.orientation = .horizontal;stack.addArrangedSubview(actions)
        for button in [refresh,test,useDraft,save,cancel] {button.target=self;button.bezelStyle = .rounded}
        refresh.action = #selector(capture);test.action = #selector(measure);useDraft.action = #selector(useInDraft);save.action = #selector(saveProfile);cancel.action = #selector(cancelTest)
        if draft != nil { profileName.isHidden = true; save.title = "Add measured hop to draft" }
        panel.contentView=stack;controls()
        timer=Timer.scheduledTimer(withTimeInterval:0.25,repeats:true){[weak self] _ in self?.tick()}
        capture()
    }
    required init?(coder:NSCoder){nil}
    deinit {timer?.invalidate();request?.cancel()}
    fileprivate func matchesPurpose(savedPath: Bool, savedPrefix: Bool) -> Bool {
        draft == nil && self.savedPath == (savedPath || savedPrefix) && self.savedPrefix == savedPrefix
    }
    fileprivate func closeForPurposeChange() -> Bool {
        guard request == nil, !pendingDrain else {
            status.stringValue = "Finish or cancel the current candidate test before opening a different test."
            return false
        }
        controls()
        guard editLease == nil, let window else { return false }
        window.performClose(nil)
        return closed
    }
    func numberOfRows(in tableView:NSTableView)->Int {rows.count}
    func tableView(_ tableView:NSTableView,objectValueFor column:NSTableColumn?,row:Int)->Any? {
        guard rows.indices.contains(row) else{return nil};let value=rows[row];let id=value["id"] as? String ?? ""
        if column?.identifier.rawValue=="name" {return value["name"] as? String ?? id}
        guard let result=receipts[id] else{return "Not tested"};guard let score=RouterVPNOrderedCandidateDisplay.score(result, measurement: measurement) else{return "Expired or incomplete"};return String(format:"%.2f ms · 50/50 %@",score,RouterVPNOrderedCandidateDisplay.sampleLabel(measurement))
    }
    func tableViewSelectionDidChange(_ notification:Notification){
        if rows.indices.contains(table.selectedRow) {
            let row=rows[table.selectedRow]
            if let path=RouterVPNOrderedCandidateDisplay.responseDraftPath(row,draft:draft,position:position,view:view ?? [:]) {
                preview.stringValue="Use in draft · "+RouterVPNOrderedCandidateDisplay.path(path)
                if let named=row["proposed_path"] as? [[String:String]], named != path {
                    preview.stringValue += "\nNamed profile · "+RouterVPNOrderedCandidateDisplay.path(named)
                }
            } else if let nodes=row["proposed_path"] as? [[String:Any]], nodes.count>=2 {
                preview.stringValue="Proposed complete path: "+RouterVPNOrderedCandidateDisplay.path(nodes)
            } else { preview.stringValue=row["save_reason"] as? String ?? "No supported next-connection path" }
        }
        controls()
    }
    private func controls(){
        if !pendingDrain,request == nil,let lease=editLease {MacViaEntryCandidateReservation.shared.release(lease);editLease=nil}
        let namedFinal = draft != nil && measurement == "routed-candidate-response"
        let selectedPath = rows.indices.contains(table.selectedRow) ? RouterVPNOrderedCandidateDisplay.responseDraftPath(rows[table.selectedRow],draft:draft,position:position,view:view ?? [:]) : nil
        useDraft.isHidden = selectedPath == nil
        useDraft.isEnabled = false
        if draft != nil {
            profileName.isHidden = !namedFinal
            let intermediate = position + 2 < ((draft?["nodes"] as? [[String:String]])?.count ?? 0)
            save.title = namedFinal ? (intermediate ? "Save profile with this hop" : "Save profile with this final") : "Add measured hop to draft"
        }
        let idle=request==nil && !pendingDrain;let captured=prefix.selectedItem?.representedObject as? Int == position;refresh.isEnabled=idle;prefix.isEnabled=idle && draft == nil;test.isEnabled=idle && captured && view != nil;cancel.isEnabled=pendingDrain;save.isEnabled=false
        let reviewIdle = request == nil && !cancelWanted && !closeWanted && savedProfileID.isEmpty && (savedPath || !pendingDrain)
        if reviewIdle,captured,let receipt,RouterVPNOrderedCandidateDisplay.review(receipt,savedPath:savedPath,scope:savedScope),rows.indices.contains(table.selectedRow),let id=rows[table.selectedRow]["id"] as? String,let result=receipts[id],RouterVPNOrderedCandidateDisplay.score(result, measurement: measurement) != nil {
            useDraft.isEnabled = selectedPath != nil
            guard let nodes = rows[table.selectedRow]["proposed_path"] as? [[String:Any]], nodes.count >= 2 else { return }
            save.isEnabled = !namedFinal || RouterVPNOrderedCandidateDisplay.savesMeasuredFinal(rows[table.selectedRow], draft: draft, position: position, metric: measurement, view: view ?? [:])
        }
    }
    @objc private func capture(){guard request==nil,!pendingDrain else{return};position=prefix.selectedItem?.representedObject as? Int ?? position;view=nil;receipt=nil;receipts=[:];savedProfileID="";savedProfileName="";savedNativeDown=false;send("catalog",path:endpoint+"/catalog?prefix_position=\(position)"+catalogSuffix,body:draft)}
    @objc private func measure(){
        controls();guard test.isEnabled,let view else{return};guard let expires=RouterVPNOrderedCandidateDisplay.number(view,"expires_at"),expires>Date().timeIntervalSince1970*1000 else{status.stringValue="The catalog expired. Capture this prefix again before testing.";return};let ids=table.selectedRowIndexes.compactMap{rows.indices.contains($0) ? rows[$0]["id"] as? String:nil};guard !ids.isEmpty else{status.stringValue="Select at least one candidate row.";return}
        if savedPath {guard let lease=MacViaEntryCandidateReservation.shared.acquire() else{status.stringValue="Another candidate transaction still owns editing; finish its Save or Cancel first.";return};editLease=lease}
        selectedWinner="";selectedEpoch=0
        requestID=UUID().uuidString.replacingOccurrences(of:"-",with:"").lowercased();receipt=nil;pendingDrain=true;cancelWanted=false;savedProfileID="";savedProfileName="";savedNativeDown=false;savedAdmitted=false
        send("run",path:endpoint,body:["request_id":requestID,"view_token":view["view_token"] ?? "","prefix_position":position,"candidate_ids":ids,"samples":50])
    }
    @objc private func useInDraft() {
        controls()
        guard useDraft.isEnabled, let view, rows.indices.contains(table.selectedRow),
              let path = RouterVPNOrderedCandidateDisplay.responseDraftPath(rows[table.selectedRow],draft:draft,position:position,view:view),
              let id = rows[table.selectedRow]["id"] as? String else { return }
        chosenID = id
        send("choose",path:endpoint+"/choose",body:["request_id":requestID,"view_token":view["view_token"] ?? "","candidate_id":id,"proposed_path":path])
    }
    @objc private func saveProfile(){
        controls();guard save.isEnabled,let view,rows.indices.contains(table.selectedRow) else{return};let row=rows[table.selectedRow]
        guard let id = row["id"] as? String else { return }
        chosenID = id
        if draft != nil {
            if measurement == "routed-candidate-response" {
                let name = profileName.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !name.isEmpty else { status.stringValue = "Enter a name for the measured path."; return }
                guard RouterVPNOrderedCandidateDisplay.savesMeasuredFinal(row, draft: draft, position: position, metric: measurement, view: view) else { return }
                send("save", path: endpoint + "/save-profile", body: ["request_id": requestID, "view_token": view["view_token"] ?? "", "candidate_id": id, "proposed_path": row["proposed_path"] ?? [], "name": name])
                return
            }
            send("save", path: endpoint + "/choose", body: ["request_id": requestID, "view_token": view["view_token"] ?? "", "candidate_id": id, "proposed_path": row["proposed_path"] ?? []])
            return
        }
        let name=profileName.stringValue.trimmingCharacters(in:.whitespacesAndNewlines);guard !name.isEmpty else{status.stringValue="Enter an explicit profile name.";return}
        send("save",path:endpoint+"/save-profile",body:["request_id":requestID,"view_token":view["view_token"] ?? "","candidate_id":row["id"] ?? "","name":name,"proposed_path":row["proposed_path"] ?? []])
    }
    @objc private func cancelTest(){cancelWanted=true;receipt=nil;if phase=="run" {request?.cancel()};status.stringValue="Cancelling the original job; waiting for native cleanup.";tick()}
    func windowShouldClose(_ sender:NSWindow)->Bool {if request != nil || pendingDrain {closeWanted=true;cancelTest();return false};return true}
    func windowWillClose(_ notification:Notification){closed=true;timer?.invalidate();timer=nil}
    private func tick(){
        guard !closed else{return}
        if request==nil,cancelWanted,pendingDrain,Date()>=nextRetry {
            var body:[String:Any]=["request_id":requestID]
            if savedPath || view?["response_source_nodes"] != nil {body["view_token"]=view?["view_token"] ?? ""}
            send("cancel",path:endpoint+"/cancel",body:body)
        }
        if closeWanted,request==nil,!pendingDrain {controls();window?.close();return}
        let observe = savedPath ? pendingDrain : (!pendingDrain && receipt.map{RouterVPNOrderedCandidateDisplay.flag($0,"accepted")} == true)
        if request==nil,!cancelWanted,observe,Date()>=nextRetry {send("poll",path:endpoint+"?request_id="+requestID)}
        table.reloadData();controls()
    }
    private func savedStatus() -> String {
        var text = "Saved " + (savedProfileName.isEmpty ? savedProfileID : savedProfileName) + " as a separate future profile."
        text += savedNativeDown ? " The temporary VPN is DOWN." : " Original native DOWN is not yet confirmed."
        if pendingDrain { text += " Original observer cleanup remains pending; Cancel retries cleanup without another Save." }
        return text
    }
    private static func issue(_ message:String)->Error {NSError(domain:"RouterVPNOrderedCandidates",code:1,userInfo:[NSLocalizedDescriptionKey:message])}
    private func send(_ action:String,path:String,body:[String:Any]?=nil){
        guard request==nil,!closed else{return};phase=action;generation &+= 1;let original=generation
        do {
            guard let url=URL(string:path,relativeTo:routerVPNProductBaseURL)?.absoluteURL else{throw Self.issue("Controller URL unavailable")}
            var capturedBody=body
            if savedPrefix, action != "catalog", capturedBody != nil {capturedBody?["scope"]=savedScope}
            request=try RouterVPNMacSpeedLabTransport(url:url,body:capturedBody,timeout:action=="run" ? 180:25){[weak self] result in DispatchQueue.main.async {[weak self] in
                guard let self,!self.closed,self.generation==original else{return};self.request=nil;self.nextRetry=Date().addingTimeInterval(1)
                do {let data=try result.get();guard let value=try JSONSerialization.jsonObject(with:data) as? [String:Any] else{throw Self.issue("Invalid candidate response")};try self.receive(value,action:action)}catch{
                    self.receipt=nil
                    if action=="run" || action=="poll" || self.savedPath && ["save","choose"].contains(action) {self.receipts=[:];self.rows=[];self.table.reloadData()}
                    if action=="run" || action=="cancel" {self.pendingDrain=true;self.cancelWanted=true}
                    if self.savedPath && ["save","choose"].contains(action) {self.pendingDrain=true}
                    self.status.stringValue = self.savedProfileID.isEmpty ? error.localizedDescription : self.savedStatus()+" "+error.localizedDescription
                }
                self.tick()
            }}
            request?.start()
        }catch{status.stringValue=error.localizedDescription;if action=="run" {pendingDrain=true;cancelWanted=true}}
        controls()
    }
    private func receive(_ value:[String:Any],action:String)throws {
        if action == "catalog" && value.keys.contains("response_executions") &&
            !RouterVPNOrderedCandidateDisplay.responseWinner(value,position:position,draft:draft) {
            throw Self.issue("The candidate catalog lost its original response owners.")
        }
        if draft != nil, value["origin"] as? String != "editor-draft" { throw Self.issue("The response belongs to another editor capture") }
        if action=="catalog" {
            guard RouterVPNOrderedCandidateDisplay.metric(value, position: position, draft: draft) != nil else { throw Self.issue("This capture cannot measure candidates through the selected prefix.") }
            if savedPath {guard RouterVPNOrderedCandidateDisplay.purpose(value,scope:savedScope), RouterVPNOrderedCandidateDisplay.draftExecution(value,draft:draft,position:position,catalog:true,winner:"",epoch:0),RouterVPNOrderedCandidateDisplay.number(value,"schema")==1,RouterVPNOrderedCandidateDisplay.number(value,"samples")==50 else{throw Self.issue("Catalog belongs to another candidate purpose")}}
            guard let token=value["view_token"] as? String,token.range(of:"^[a-f0-9]{64}$",options:.regularExpression) != nil,RouterVPNOrderedCandidateDisplay.number(value,"prefix_position")==Double(position),let expires=RouterVPNOrderedCandidateDisplay.number(value,"expires_at"),expires>Date().timeIntervalSince1970*1000,let candidates=value["candidates"] as? [[String:Any]],!candidates.isEmpty else{throw Self.issue("Catalog expired or changed prefix")}
            if value.keys.contains("response_source_nodes") {
                guard value["measurement"] as? String == "routed-candidate-response",
                      let source = RouterVPNOrderedCandidateDisplay.responseSource(value,position:position,draft:draft),
                      RouterVPNOrderedCandidateDisplay.responseWinner(value,position:position,draft:draft),
                      let prefix = (value["prefixes"] as? [[String:Any]])?.filter({ RouterVPNOrderedCandidateDisplay.number($0,"position") == Double(position) }),
                      prefix.count == 1, prefix[0]["id"] as? String == source[position]["id"], prefix[0]["mode"] as? String == "shadowsocks",
                      candidates.allSatisfy({ choice in
                          if choice["proposed_path"] != nil || choice["proposal_action"] != nil {
                              return RouterVPNOrderedCandidateDisplay.responseProposal(choice,source:source,position:position)
                          }
                          return RouterVPNOrderedCandidateDisplay.responseDraftPath(choice,draft:draft,position:position,view:value) != nil
                      }) else { throw Self.issue("The private response differs from its captured route.") }
            } else if !savedPath, draft == nil, value["measurement"] as? String == "routed-candidate-response",
                      value["requested_execution"] as? String == "auto" || value["required_selected_execution"] as? String == "local" {
                guard position == 1, RouterVPNOrderedCandidateDisplay.legacyConnectedResponse(value, choices: candidates) else {
                    throw Self.issue("The original route is missing from this candidate catalog.")
                }
            }
            view=value;choices=candidates;rows=candidates;receipts=[:];prefix.removeAllItems();for item in value["prefixes"] as? [[String:Any]] ?? [] {guard let p=RouterVPNOrderedCandidateDisplay.number(item,"position") else{continue};prefix.addItem(withTitle:"After node \(Int(p)+1) · \(item["name"] as? String ?? "") · \(item["mode"] as? String ?? "")");prefix.lastItem?.representedObject=Int(p);if Int(p)==position{prefix.select(prefix.lastItem)}};table.reloadData();status.stringValue="Select saved candidates and test through this captured prefix."
            if draft != nil, !closeWanted, !cancelWanted {
                let eligible = IndexSet(rows.indices.filter { measurement == "routed-candidate-response" || ((rows[$0]["proposed_path"] as? [[String: Any]])?.count ?? 0) >= 3 })
                if !eligible.isEmpty { table.selectRowIndexes(eligible, byExtendingSelection: false); measure() }
                else { status.stringValue = "No linked next hop can be inserted after this prefix." }
            }
            return
        }
        if value.keys.contains("response_executions") || view?.keys.contains("response_executions") == true {
            guard let original = view, let owners = original["response_executions"] as? [String],
                  value["response_executions"] as? [String] == owners,
                  value["requested_execution"] as? String == original["requested_execution"] as? String,
                  RouterVPNOrderedCandidateDisplay.responseWinner(value,position:position,draft:draft),
                  draft != nil || value["selected_execution"] as? String == original["selected_execution"] as? String else {
                throw Self.issue("The authenticated response owner changed.")
            }
        }
        if view?["response_source_nodes"] != nil || value["response_source_nodes"] != nil {
            guard let view, let original = RouterVPNOrderedCandidateDisplay.responseSource(view, position:position, draft:draft),
                  RouterVPNOrderedCandidateDisplay.responseSource(value, position:position, draft:draft) == original,
                  value["view_token"] as? String == view["view_token"] as? String else { throw Self.issue("The private response source changed.") }
            if draft == nil {
                guard RouterVPNOrderedCandidateDisplay.responseWinner(value,position:position,draft:nil),
                      (value["selection_epoch"] as? NSNumber)?.stringValue == (view["selection_epoch"] as? NSNumber)?.stringValue else { throw Self.issue("The selected route changed.") }
                guard value["request_id"] as? String == requestID else { throw Self.issue("The private response belongs to another request.") }
                if action == "cancel" {
                    let started = RouterVPNOrderedCandidateDisplay.flag(value,"started")
                    guard (started && RouterVPNOrderedCandidateDisplay.falseFlag(value,"admission_cancelled")) ||
                          (!savedAdmitted && RouterVPNOrderedCandidateDisplay.falseFlag(value,"started") && RouterVPNOrderedCandidateDisplay.flag(value,"admission_cancelled")),
                          value["measurement"] as? String == measurement, RouterVPNOrderedCandidateDisplay.number(value,"prefix_position") == Double(position),
                          ["ok","cancelled","drained"].allSatisfy({ RouterVPNOrderedCandidateDisplay.flag(value,$0) }),
                          ["running","accepted","reviewing","cleanup_pending","active_path_changed"].allSatisfy({ RouterVPNOrderedCandidateDisplay.falseFlag(value,$0) }),
                          let results = value["results"] as? [[String:Any]], results.isEmpty,
                          value["saved_profile_id"] == nil || value["saved_profile_id"] as? String == "" else { throw Self.issue("The original candidate cancellation is still pending.") }
                } else if ["run","poll"].contains(action), value["measurement"] as? String == measurement,
                          RouterVPNOrderedCandidateDisplay.number(value,"prefix_position") == Double(position) {
                    savedAdmitted = true
                }
                if action == "save" {
                    guard value["candidate_id"] as? String == chosenID, let savedAction = value["proposal_action"] as? String,
                          let path = value["proposed_path"] as? [[String:String]],
                          RouterVPNOrderedCandidateDisplay.responseProposal(["id":chosenID,"kind":"router-vpn","proposed_path":path,"proposal_action":savedAction], source:original, position:position),
                          RouterVPNOrderedCandidateDisplay.falseFlag(value,"active_path_changed") else { throw Self.issue("The saved profile differs from the measured final.") }
                }
            }
        }
        if savedPath {try receiveSaved(value,action:action);return}
        if action=="save" {guard RouterVPNOrderedCandidateDisplay.flag(value,"ok"),!RouterVPNOrderedCandidateDisplay.flag(value,"active_path_changed") else{throw Self.issue("Profile save was not confirmed")};receipt=nil;status.stringValue="Saved \(value["profile_name"] as? String ?? "profile"). Disconnect before loading it; the active path is unchanged.";return}
        guard value["request_id"] as? String==requestID else{throw Self.issue("Response belongs to another candidate job")}
        if action=="cancel" {guard RouterVPNOrderedCandidateDisplay.flag(value,"drained") else{throw Self.issue("Original cleanup remains pending")};pendingDrain=false;receipt=nil;status.stringValue="Cancelled; original native work drained.";return}
        if cancelWanted || closeWanted {pendingDrain=true;receipt=nil;receipts=[:];rows=[];table.reloadData();status.stringValue="Waiting for cancellation of this exact completed request.";return}
        guard value["measurement"] as? String == measurement, value["view_token"] as? String==view?["view_token"] as? String,RouterVPNOrderedCandidateDisplay.number(value,"prefix_position")==Double(position) else{throw Self.issue("Candidate receipt changed its original prefix capture")}
        pendingDrain = !RouterVPNOrderedCandidateDisplay.flag(value,"drained");receipt=value;receipts=[:]
        for result in value["results"] as? [[String:Any]] ?? [] {guard RouterVPNOrderedCandidateDisplay.score(result, measurement: measurement) != nil,let id=result["candidate_id"] as? String,choices.filter({$0["id"] as? String==id}).count==1 else{continue};receipts[id]=result}
        rows=choices.filter{receipts[$0["id"] as? String ?? ""] != nil}.sorted{a,b in let x=a["id"] as? String ?? "",y=b["id"] as? String ?? "";let xs=RouterVPNOrderedCandidateDisplay.score(receipts[x]!, measurement: measurement) ?? .infinity,ys=RouterVPNOrderedCandidateDisplay.score(receipts[y]!, measurement: measurement) ?? .infinity;return xs==ys ? x<y:xs<ys};table.reloadData()
        status.stringValue=pendingDrain ? "Cleanup pending; retry Cancel.":!RouterVPNOrderedCandidateDisplay.flag(value,"accepted") ? "Original candidate source or proof changed; retest.":"Results sorted by the 10% trimmed mean of 50 \(RouterVPNOrderedCandidateDisplay.sampleLabel(measurement)). Each expires after 120 seconds. Select one to preview a complete next-connection profile."
    }

    private func receiveSaved(_ value:[String:Any],action:String)throws {
        guard value["request_id"] as? String == requestID else{throw Self.issue("Response belongs to another saved-path job")}
        guard RouterVPNOrderedCandidateDisplay.purpose(value,scope:savedScope),value["scope"] as? String == view?["scope"] as? String,RouterVPNOrderedCandidateDisplay.number(value,"schema")==1,
              value["view_token"] as? String == view?["view_token"] as? String,
              RouterVPNOrderedCandidateDisplay.number(value,"prefix_position")==Double(position),
              value["measurement"] as? String == measurement,RouterVPNOrderedCandidateDisplay.falseFlag(value,"active_path_changed") else{throw Self.issue("Saved-path receipt changed its original purpose or prefix")}
        guard RouterVPNOrderedCandidateDisplay.draftExecution(value,draft:draft,position:position,catalog:false,winner:selectedWinner,epoch:selectedEpoch) else { throw Self.issue("The selected execution changed. Recapture this draft.") }
        if savedScope == "draft-complete-selected", let winner = value["selected_execution"] as? String, let epoch = value["selection_epoch"] as? NSNumber {
            selectedWinner = winner; selectedEpoch = epoch.uint64Value
        }
        // A bound nonce tombstone is not native DOWN. It can retire only this
        // never-admitted request, and cannot replace a previously observed job.
        if RouterVPNOrderedCandidateDisplay.flag(value,"admission_cancelled") {
            guard action=="cancel",!savedAdmitted,savedProfileID.isEmpty,
                  RouterVPNOrderedCandidateDisplay.falseFlag(value,"started"),RouterVPNOrderedCandidateDisplay.flag(value,"drained"),
                  RouterVPNOrderedCandidateDisplay.falseFlag(value,"native_down"),RouterVPNOrderedCandidateDisplay.falseFlag(value,"accepted"),
                  RouterVPNOrderedCandidateDisplay.flag(value,"cancelled"),let results=value["results"] as? [[String:Any]],results.isEmpty else{throw Self.issue("Never-started cancellation cannot retire admitted native work")}
            pendingDrain=false;savedNativeDown=false;receipt=nil;receipts=[:];rows=[];table.reloadData()
            status.stringValue="Cancelled before the temporary path started.";return
        }
        guard !RouterVPNOrderedCandidateDisplay.flag(value,"drained") || RouterVPNOrderedCandidateDisplay.flag(value,"native_down") else{throw Self.issue("Original native DOWN is not confirmed")}
        savedAdmitted=true
        pendingDrain = !RouterVPNOrderedCandidateDisplay.flag(value,"drained")
        savedNativeDown = RouterVPNOrderedCandidateDisplay.flag(value,"native_down")
        if draft != nil, action == "choose" || measurement != "routed-candidate-response" && action == "save" {
            if action == "choose" {
                let matches = choices.filter { $0["id"] as? String == chosenID }
                guard matches.count == 1, let view,
                      let path = RouterVPNOrderedCandidateDisplay.responseDraftPath(matches[0],draft:draft,position:position,view:view),
                      value["draft_action"] as? String == "insert-measured-hop", value["proposed_path"] as? [[String:String]] == path,
                      value["profile_id"] == nil, value["saved"] == nil || RouterVPNOrderedCandidateDisplay.falseFlag(value,"saved"),
                      ["cancelled","running","reviewing","cleanup_pending"].allSatisfy({ RouterVPNOrderedCandidateDisplay.falseFlag(value,$0) }),
                      view["response_executions"] != nil ? selectedWinner == value["selected_execution"] as? String && selectedEpoch > 0 : draft?["execution"] as? String != "auto" || selectedWinner == "local" && selectedEpoch > 0 else {
                    throw Self.issue("The chosen path differs from the measured draft insertion.")
                }
            }
            guard !cancelWanted, !closeWanted, !pendingDrain, savedNativeDown, RouterVPNOrderedCandidateDisplay.flag(value, "chosen"),
                  RouterVPNOrderedCandidateDisplay.falseFlag(value, "accepted"), value["saved_profile_id"] as? String == "",
                  value["candidate_id"] as? String == chosenID, let choose else { throw Self.issue("The original draft choice did not finish cleanup.") }
            receipt=nil;receipts=[:];rows=[];table.reloadData();controls()
            do { try choose(value); closeWanted=true }
            catch { status.stringValue=error.localizedDescription }
            return
        }
        if let id=value["saved_profile_id"] as? String,!id.isEmpty {
            if draft != nil {
                guard let action = value["proposal_action"] as? String, value["candidate_id"] as? String == chosenID,
                      measurement == "routed-candidate-response", !RouterVPNOrderedCandidateDisplay.flag(value, "chosen"),
                      choices.contains(where: { choice in
                          guard choice["id"] as? String == chosenID, choice["proposal_action"] as? String == action,
                                RouterVPNOrderedCandidateDisplay.savesMeasuredFinal(choice, draft: draft, position: position, metric: measurement, view: view ?? [:]) else { return false }
                          if action == "save-intermediate-profile" || view?["response_source_nodes"] != nil {
                              guard let confirmed = value["proposed_path"] as? [[String:String]],
                                    let expected = choice["proposed_path"] as? [[String:String]] else { return false }
                              return confirmed == expected
                          }
                          return true
                      }) else {
                    throw Self.issue("The named profile does not match the measured candidate and original draft.")
                }
            }
            guard id.utf8.count<=128,id.range(of:"^[A-Za-z0-9_-]+$",options:.regularExpression) != nil,
                  RouterVPNOrderedCandidateDisplay.flag(value,"saved"),value["profile_id"] as? String==id,
                  savedProfileID.isEmpty || savedProfileID==id else{throw Self.issue("Committed profile identity changed")}
            savedProfileID=id;savedProfileName=value["profile_name"] as? String ?? id
            receipt=nil;receipts=[:];rows=[];table.reloadData()
            status.stringValue=savedStatus()
            if let failure=value["failure"] as? String,!failure.isEmpty {status.stringValue += " "+failure}
            if let cleanup=value["cleanup_error"] as? String,!cleanup.isEmpty {status.stringValue += " "+cleanup}
            if pendingDrain {cancelWanted=true}
            return
        }
        if !savedProfileID.isEmpty {receipt=nil;receipts=[:];rows=[];status.stringValue=savedStatus();return}
        if action=="save" {throw Self.issue("Profile Save has not been confirmed; observing the original request before another action.")}
        if action=="cancel" {
            receipt=nil;receipts=[:];rows=[];table.reloadData()
            guard !pendingDrain else{throw Self.issue("Original saved-path cleanup remains pending")}
            status.stringValue="Cancelled; the temporary VPN and original observer drained.";return
        }
        if cancelWanted || closeWanted {receipt=nil;receipts=[:];rows=[];table.reloadData();status.stringValue="Waiting for original saved-path cleanup.";return}
        receipt=value;receipts=[:]
        let ready=RouterVPNOrderedCandidateDisplay.review(value,savedPath:true,scope:savedScope)
        if ready {
            for result in value["results"] as? [[String:Any]] ?? [] {guard RouterVPNOrderedCandidateDisplay.score(result, measurement: measurement) != nil,let id=result["candidate_id"] as? String,choices.filter({$0["id"] as? String==id}).count==1 else{continue};receipts[id]=result}
        }
        rows=choices.filter{receipts[$0["id"] as? String ?? ""] != nil}.sorted{a,b in let x=a["id"] as? String ?? "",y=b["id"] as? String ?? "";let xs=RouterVPNOrderedCandidateDisplay.score(receipts[x]!, measurement: measurement) ?? .infinity,ys=RouterVPNOrderedCandidateDisplay.score(receipts[y]!, measurement: measurement) ?? .infinity;return xs==ys ? x<y:xs<ys};table.reloadData()
        if ready, savedScope == "draft-complete-selected" {status.stringValue="Selected execution: \(selectedWinner). Choose a measured hop for this draft."}
        else if ready {status.stringValue="Temporary VPN is DOWN. Review the 50 \(RouterVPNOrderedCandidateDisplay.sampleLabel(measurement)) per candidate and explicitly Save a future profile, or Cancel to retire its retained observer. Scores expire after 120 seconds."}
        else if RouterVPNOrderedCandidateDisplay.flag(value,"running"), draft != nil {status.stringValue="Testing the original draft. Waiting for its temporary route to close."}
        else if RouterVPNOrderedCandidateDisplay.flag(value,"running") {status.stringValue="Testing the saved Local path; choices remain unavailable until original native DOWN."}
        else if pendingDrain {status.stringValue="Original cleanup remains pending; retry Cancel."}
        else {status.stringValue=(value["failure"] as? String).flatMap{$0.isEmpty ? nil:$0} ?? "Original result expired or changed; retest."}
    }
}
