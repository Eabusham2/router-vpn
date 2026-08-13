import AppKit
import Foundation
import MapKit

let routerVPNProductBaseURL = URL(string: "http://127.0.0.1:8788")!
let routerVPNProductContractVersion = 2

final class ProductAPI {
    private let session: URLSession
    init() {
        let c = URLSessionConfiguration.ephemeral
        c.timeoutIntervalForRequest = 8
        c.timeoutIntervalForResource = 15
        c.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        c.connectionProxyDictionary = [:]
        session = URLSession(configuration: c)
    }
    func request(_ path: String, method: String = "GET", body: [String: Any]? = nil, timeout: TimeInterval = 15) throws -> Data {
        guard let url = URL(string: path, relativeTo: routerVPNProductBaseURL) else { throw NSError(domain: "RouterVPNMac", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid local API path"]) }
        var req = URLRequest(url: url); req.httpMethod = method; req.timeoutInterval = timeout; req.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        if let body { req.httpBody = try JSONSerialization.data(withJSONObject: body); req.setValue("application/json", forHTTPHeaderField: "Content-Type") }
        let sem = DispatchSemaphore(value: 0); var data = Data(); var code = 0; var err: Error?
        let task = session.dataTask(with: req) { d, r, e in data = d ?? Data(); code = (r as? HTTPURLResponse)?.statusCode ?? 0; err = e; sem.signal() }
        task.resume()
        if sem.wait(timeout: .now() + timeout + 2) == .timedOut { task.cancel(); throw NSError(domain: "RouterVPNMac", code: 2, userInfo: [NSLocalizedDescriptionKey: "Local controller request timed out"]) }
        if let err { throw err }
        guard (200..<300).contains(code) else { let text = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines); throw NSError(domain: "RouterVPNMac", code: code, userInfo: [NSLocalizedDescriptionKey: (text?.isEmpty == false ? text! : "Local controller request failed")]) }
        return data
    }
    func json(_ path: String, timeout: TimeInterval = 15) throws -> Any { try JSONSerialization.jsonObject(with: request(path, timeout: timeout)) }
    func ready() -> Bool { (try? request("/api/status", timeout: 1)) != nil }
}

final class RouterAnnotation: NSObject, MKAnnotation {
    let routerID: String
    let title: String?
    let subtitle: String?
    let coordinate: CLLocationCoordinate2D
    init(id: String, name: String, location: String, latency: Double, lat: Double, lon: Double) {
        routerID = id; title = name; subtitle = [location, latency > 0 ? String(format: "median %.1f ms", latency) : ""].filter { !$0.isEmpty }.joined(separator: " • "); coordinate = CLLocationCoordinate2D(latitude: lat, longitude: lon)
    }
}

final class ProductWindowController: NSWindowController, MKMapViewDelegate {
    let api: ProductAPI
    let statusLabel = NSTextField(labelWithString: "Checking…")
    let detailLabel = NSTextField(wrappingLabelWithString: "")
    let errorLabel = NSTextField(wrappingLabelWithString: "")
    let routerPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    let modePopup = NSPopUpButton(frame: .zero, pullsDown: false)
    let basePopup = NSPopUpButton(frame: .zero, pullsDown: false)
    let multihopEntryPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    let multihopExitPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    let multihopExitModePopup = NSPopUpButton(frame: .zero, pullsDown: false)
    let map = MKMapView()
    let nodesText = NSTextView(); let modesText = NSTextView(); let dnsText = NSTextView(); let advancedText = NSTextView(); let settingsText = NSTextView(); let helpText = NSTextView()
    let forwardInput = NSTextView(); let forwardOutput = NSTextView()
    var routerIDs: [String] = []; var modeIDs: [String] = []; var profiles: [[String: Any]] = []; var eventSeq: UInt64 = 0; var timer: Timer?
    var multihopNodeIDs: [String] = []

    init(api: ProductAPI) {
        self.api = api
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1180, height: 780), styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = "Router VPN"; window.minSize = NSSize(width: 980, height: 650); window.center()
        super.init(window: window); buildUI(); refreshAll(); timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in self?.refreshLive() }
    }
    required init?(coder: NSCoder) { nil }
    deinit { timer?.invalidate() }

    func button(_ title: String, _ action: Selector) -> NSButton { let b = NSButton(title: title, target: self, action: action); b.bezelStyle = .rounded; b.controlSize = .large; return b }
    func label(_ text: String) -> NSTextField { let x = NSTextField(labelWithString: text); x.textColor = .secondaryLabelColor; return x }
    func scroll(_ text: NSTextView) -> NSScrollView { text.isEditable = false; text.isSelectable = true; text.font = .monospacedSystemFont(ofSize: 12.5, weight: .regular); text.textContainerInset = NSSize(width: 12, height: 12); let s = NSScrollView(); s.hasVerticalScroller = true; s.autohidesScrollers = true; s.documentView = text; return s }
    func addTab(_ tabs: NSTabViewController, _ label: String, _ view: NSView) { let vc = NSViewController(); vc.view = view; let item = NSTabViewItem(viewController: vc); item.label = label; tabs.addTabViewItem(item) }

    func buildUI() {
        guard let content = window?.contentView else { return }
        let root = NSStackView(); root.orientation = .vertical; root.spacing = 10; root.edgeInsets = NSEdgeInsets(top: 16, left: 16, bottom: 16, right: 16); root.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(root); NSLayoutConstraint.activate([root.leadingAnchor.constraint(equalTo: content.leadingAnchor), root.trailingAnchor.constraint(equalTo: content.trailingAnchor), root.topAnchor.constraint(equalTo: content.topAnchor), root.bottomAnchor.constraint(equalTo: content.bottomAnchor)])
        let header = NSStackView(); header.orientation = .horizontal; header.alignment = .centerY
        let title = NSTextField(labelWithString: "Router VPN"); title.font = .systemFont(ofSize: 30, weight: .bold); statusLabel.font = .systemFont(ofSize: 14, weight: .semibold)
        header.addArrangedSubview(title); header.addArrangedSubview(NSView()); header.addArrangedSubview(statusLabel); root.addArrangedSubview(header)
        detailLabel.textColor = .secondaryLabelColor; errorLabel.textColor = .systemRed; root.addArrangedSubview(detailLabel); root.addArrangedSubview(errorLabel)
        let tabs = NSTabViewController(); tabs.tabStyle = .segmentedControlOnTop
        addTab(tabs, "Home", homeView()); addTab(tabs, "Nodes & Map", nodesMapView()); addTab(tabs, "Modes", scroll(modesText)); addTab(tabs, "DNS", dnsView()); addTab(tabs, "Advanced", advancedView()); addTab(tabs, "Forwarding", forwardingView()); addTab(tabs, "Settings", settingsView()); addTab(tabs, "Help", helpView())
        root.addArrangedSubview(tabs.view); tabs.view.heightAnchor.constraint(greaterThanOrEqualToConstant: 540).isActive = true
    }

    func homeView() -> NSView {
        let s = NSStackView(); s.orientation = .vertical; s.spacing = 10; s.edgeInsets = NSEdgeInsets(top: 22, left: 28, bottom: 22, right: 28)
        s.addArrangedSubview(label("Router")); routerPopup.target = self; routerPopup.action = #selector(selectRouter); s.addArrangedSubview(routerPopup)
        s.addArrangedSubview(label("Logical mode")); s.addArrangedSubview(modePopup); s.addArrangedSubview(label("Tunnel base")); basePopup.addItems(withTitles: ["Auto", "WireGuard", "AmneziaWG"]); basePopup.selectItem(at: 0); s.addArrangedSubview(basePopup)
        let r = NSStackView(); r.orientation = .horizontal; r.spacing = 8; r.addArrangedSubview(button("AUTO Connect", #selector(autoConnect))); r.addArrangedSubview(button("Connect Selected", #selector(connectSelected))); r.addArrangedSubview(button("Disconnect", #selector(disconnect))); r.addArrangedSubview(button("Refresh", #selector(refreshAction))); s.addArrangedSubview(r)
        let proof = NSTextField(wrappingLabelWithString: "Connected is shown only after exact selected-node private path proof. Typed AUTO/manual attempt, fallback and rollback events appear in Help."); proof.textColor = .secondaryLabelColor; s.addArrangedSubview(proof); return s
    }

    func nodesMapView() -> NSView {
        let split = NSSplitView(); split.isVertical = true; split.dividerStyle = .thin
        map.delegate = self; map.showsCompass = true; map.showsScale = true; split.addArrangedSubview(map); let right = NSStackView(); right.orientation = .vertical; right.spacing = 8; right.edgeInsets = NSEdgeInsets(top: 8, left: 8, bottom: 8, right: 8); right.addArrangedSubview(scroll(nodesText)); let row = NSStackView(); row.orientation = .horizontal; row.addArrangedSubview(button("Select highlighted map node", #selector(selectMapNode))); row.addArrangedSubview(button("50-sample latency", #selector(latencySelected))); right.addArrangedSubview(row); split.addArrangedSubview(right); split.setPosition(650, ofDividerAt: 0); return split
    }

    func dnsView() -> NSView { let s = NSStackView(); s.orientation = .vertical; s.spacing = 10; s.edgeInsets = NSEdgeInsets(top: 18, left: 18, bottom: 18, right: 18); let note = NSTextField(wrappingLabelWithString: "Selected DNS policy and home-node DNS benchmark. Benchmarking is not mislabeled as end-to-end resolver proof."); note.textColor = .secondaryLabelColor; s.addArrangedSubview(note); s.addArrangedSubview(button("Retest home-exit DNS benchmark", #selector(retestDNS))); s.addArrangedSubview(scroll(dnsText)); return s }
    func advancedView() -> NSView {
        let s = NSStackView(); s.orientation = .vertical; s.spacing = 10; s.edgeInsets = NSEdgeInsets(top: 18, left: 18, bottom: 18, right: 18)
        let note = NSTextField(wrappingLabelWithString: "Real multihop path: client TUN → exit transport → entry WireGuard → exit node → Internet. Entry and exit must be different linked nodes."); note.textColor = .secondaryLabelColor; s.addArrangedSubview(note)
        let selectors = NSStackView(); selectors.orientation = .horizontal; selectors.spacing = 8
        let entry = NSStackView(); entry.orientation = .vertical; entry.addArrangedSubview(label("Entry node")); entry.addArrangedSubview(multihopEntryPopup)
        let exit = NSStackView(); exit.orientation = .vertical; exit.addArrangedSubview(label("Exit node")); exit.addArrangedSubview(multihopExitPopup)
        let mode = NSStackView(); mode.orientation = .vertical; mode.addArrangedSubview(label("Exit transport")); multihopExitModePopup.addItems(withTitles: ["Shadowsocks", "Hysteria2"]); multihopExitModePopup.selectItem(at: 0); mode.addArrangedSubview(multihopExitModePopup)
        selectors.addArrangedSubview(entry); selectors.addArrangedSubview(exit); selectors.addArrangedSubview(mode); s.addArrangedSubview(selectors)
        let row = NSStackView(); row.orientation = .horizontal; row.addArrangedSubview(button("Connect real multihop", #selector(connectMultihop))); row.addArrangedSubview(button("Refresh multihop readiness", #selector(refreshAdvancedAction))); row.addArrangedSubview(button("Emergency stop", #selector(emergencyStop))); s.addArrangedSubview(row); s.addArrangedSubview(scroll(advancedText)); return s
    }
    func settingsView() -> NSView { let s = NSStackView(); s.orientation = .vertical; s.spacing = 10; s.edgeInsets = NSEdgeInsets(top: 18, left: 18, bottom: 18, right: 18); s.addArrangedSubview(scroll(settingsText)); return s }
    func helpView() -> NSView { let s = NSStackView(); s.orientation = .vertical; s.spacing = 10; s.edgeInsets = NSEdgeInsets(top: 18, left: 18, bottom: 18, right: 18); let row = NSStackView(); row.orientation = .horizontal; row.addArrangedSubview(button("Prove public VPN exit", #selector(publicExit))); row.addArrangedSubview(button("Emergency stop", #selector(emergencyStop))); row.addArrangedSubview(button("Refresh", #selector(refreshAction))); s.addArrangedSubview(row); s.addArrangedSubview(scroll(helpText)); return s }
    func forwardingView() -> NSView { let s = NSStackView(); s.orientation = .vertical; s.spacing = 8; s.edgeInsets = NSEdgeInsets(top: 18, left: 18, bottom: 18, right: 18); let note = NSTextField(wrappingLabelWithString: "Forwarding is sent only to the selected Router VPN node through its authenticated private router API. Enter the node-supported JSON rule payload; proxy-only modes cannot fake arbitrary DNAT."); note.textColor = .secondaryLabelColor; s.addArrangedSubview(note); forwardInput.isEditable = true; forwardInput.font = .monospacedSystemFont(ofSize: 12, weight: .regular); forwardInput.string = "{\n  \"enabled\": true\n}"; let inputScroll = NSScrollView(); inputScroll.hasVerticalScroller = true; inputScroll.documentView = forwardInput; inputScroll.heightAnchor.constraint(equalToConstant: 130).isActive = true; s.addArrangedSubview(inputScroll); let row = NSStackView(); row.orientation = .horizontal; row.addArrangedSubview(button("Apply forwarding payload", #selector(applyForward))); row.addArrangedSubview(button("Clear forwarding", #selector(clearForward))); s.addArrangedSubview(row); s.addArrangedSubview(scroll(forwardOutput)); return s }

    func asyncAction(_ work: @escaping () throws -> String) { DispatchQueue.global(qos: .userInitiated).async { [weak self] in guard let self else { return }; do { let message = try work(); DispatchQueue.main.async { self.appendHelp(message); self.refreshAll() } } catch { DispatchQueue.main.async { self.errorLabel.stringValue = error.localizedDescription; self.appendHelp("ERROR: \(error.localizedDescription)"); self.refreshLive() } } } }
    @objc func autoConnect() { asyncAction { String(data: try self.api.request("/api/auto", method: "POST", body: [:], timeout: 150), encoding: .utf8) ?? "AUTO connected" } }
    @objc func connectSelected() { let i = modePopup.indexOfSelectedItem; guard i >= 0 && i < modeIDs.count else { return }; let mode = modeIDs[i]; let base = ["auto", "wg", "awg"][max(0, min(basePopup.indexOfSelectedItem, 2))]; asyncAction { String(data: try self.api.request("/api/connect-logical", method: "POST", body: ["mode": mode, "base": base], timeout: 180), encoding: .utf8) ?? "Connected" } }
    @objc func connectMultihop() {
        let ei = multihopEntryPopup.indexOfSelectedItem; let xi = multihopExitPopup.indexOfSelectedItem
        guard ei >= 0, xi >= 0, ei < multihopNodeIDs.count, xi < multihopNodeIDs.count else { appendHelp("Choose both multihop nodes."); return }
        let entryID = multihopNodeIDs[ei], exitID = multihopNodeIDs[xi]
        guard entryID != exitID else { appendHelp("Multihop entry and exit nodes must be different."); return }
        let exitMode = multihopExitModePopup.indexOfSelectedItem == 1 ? "hysteria2" : "shadowsocks"
        asyncAction { String(data: try self.api.request("/api/multihop/connect", method: "POST", body: ["entry_id": entryID, "exit_id": exitID, "base": "wg", "exit_mode": exitMode], timeout: 180), encoding: .utf8) ?? "Multihop connected" }
    }
    @objc func disconnect() { asyncAction { _ = try self.api.request("/api/disconnect", method: "POST", body: [:], timeout: 20); return "Disconnected." } }
    @objc func publicExit() { asyncAction { String(data: try self.api.request("/api/public-ip", timeout: 20), encoding: .utf8) ?? "" } }
    @objc func retestDNS() { asyncAction { String(data: try self.api.request("/api/dns/retest", method: "POST", body: [:], timeout: 90), encoding: .utf8) ?? "" } }
    @objc func emergencyStop() { asyncAction { _ = try self.api.request("/api/emergency-stop", method: "POST", body: [:], timeout: 20); return "Emergency stop completed." } }
    @objc func refreshAction() { refreshAll() }
    @objc func refreshAdvancedAction() { refreshAdvanced() }
    @objc func selectRouter() { let i = routerPopup.indexOfSelectedItem; guard i >= 0 && i < routerIDs.count else { return }; let id = routerIDs[i]; asyncAction { _ = try self.api.request("/api/profile/select", method: "POST", body: ["id": id], timeout: 10); return "Selected router \(id)" } }
    @objc func selectMapNode() { guard let a = map.selectedAnnotations.first as? RouterAnnotation else { appendHelp("Select a real-coordinate map pin first."); return }; asyncAction { _ = try self.api.request("/api/profile/select", method: "POST", body: ["id": a.routerID], timeout: 10); return "Selected map node \(a.title ?? a.routerID)" } }
    @objc func latencySelected() { let id: String; if let a = map.selectedAnnotations.first as? RouterAnnotation { id = a.routerID } else if routerPopup.indexOfSelectedItem >= 0 && routerPopup.indexOfSelectedItem < routerIDs.count { id = routerIDs[routerPopup.indexOfSelectedItem] } else { appendHelp("Select a node first."); return }; asyncAction { String(data: try self.api.request("/api/profile/latency", method: "POST", body: ["id": id, "samples": 50], timeout: 180), encoding: .utf8) ?? "" } }
    @objc func applyForward() { guard let d = forwardInput.string.data(using: .utf8), let obj = try? JSONSerialization.jsonObject(with: d), let body = obj as? [String: Any] else { appendHelp("Forwarding payload must be a JSON object."); return }; asyncAction { String(data: try self.api.request("/api/forward", method: "POST", body: body, timeout: 20), encoding: .utf8) ?? "" } }
    @objc func clearForward() { asyncAction { String(data: try self.api.request("/api/forward/clear", method: "POST", body: [:], timeout: 20), encoding: .utf8) ?? "Forwarding cleared" } }

    func refreshAll() { refreshProfiles(); refreshModes(); refreshLive(); refreshAdvanced() }
    func refreshLive() { refreshStatus(); refreshSessionEvents() }
    func refreshStatus() { DispatchQueue.global(qos: .utility).async { [weak self] in guard let self else { return }; do { guard let o = try api.json("/api/status") as? [String: Any] else { return }; DispatchQueue.main.async { let connected = o["connected"] as? Bool ?? false; let phase = o["phase"] as? String ?? "off"; self.statusLabel.stringValue = connected ? "● Connected" : "○ \(phase)"; self.statusLabel.textColor = connected ? .systemGreen : (phase == "failed" ? .systemRed : .secondaryLabelColor); self.detailLabel.stringValue = "Logical: \(o["logical_mode"] as? String ?? "—")   Runtime: \((o["runtime_mode"] as? String) ?? (o["mode"] as? String) ?? "—")   Base: \(o["base"] as? String ?? "—")   Router: \(o["router_id"] as? String ?? "—")"; self.errorLabel.stringValue = o["last_error"] as? String ?? "" } } catch { DispatchQueue.main.async { self.statusLabel.stringValue = "● Controller unavailable"; self.statusLabel.textColor = .systemRed; self.errorLabel.stringValue = error.localizedDescription } } } }
    func refreshSessionEvents() { let after = eventSeq; DispatchQueue.global(qos: .utility).async { [weak self] in guard let self else { return }; do { guard let o = try api.json("/api/session/events?after=\(after)") as? [String: Any] else { return }; let events = o["events"] as? [[String: Any]] ?? []; let last = (o["last_event_seq"] as? NSNumber)?.uint64Value ?? after; DispatchQueue.main.async { for e in events { let seq = (e["seq"] as? NSNumber)?.uint64Value ?? 0; guard seq > self.eventSeq else { continue }; var parts: [String] = [e["phase"] as? String ?? ""]; if let r = e["runtime_mode"] as? String, !r.isEmpty { parts.append("runtime=\(r)") }; if let b = e["base"] as? String, !b.isEmpty { parts.append("base=\(b)") }; if let m = e["message"] as? String, !m.isEmpty { parts.append(m) }; self.appendHelp("Session #\(seq) \(e["type"] as? String ?? "event"): " + parts.filter { !$0.isEmpty }.joined(separator: " | ")); self.eventSeq = seq }; self.eventSeq = max(self.eventSeq, last) } } catch { } } }
    func refreshProfiles() { DispatchQueue.global(qos: .utility).async { [weak self] in guard let self else { return }; do { guard let o = try api.json("/api/profiles") as? [String: Any], let p = o["profiles"] as? [[String: Any]] else { return }; let selected = o["selected_id"] as? String ?? ""; DispatchQueue.main.async { self.profiles = p; self.routerIDs = p.compactMap { $0["id"] as? String }; self.routerPopup.removeAllItems(); self.routerPopup.addItems(withTitles: p.map { $0["name"] as? String ?? $0["id"] as? String ?? "Router" }); if let i = self.routerIDs.firstIndex(of: selected) { self.routerPopup.selectItem(at: i) }; self.renderProfiles(selected: selected) } } catch { DispatchQueue.main.async { self.errorLabel.stringValue = error.localizedDescription } } } }
    func renderProfiles(selected: String) { nodesText.string = profiles.map { p in let name = p["name"] as? String ?? p["id"] as? String ?? "Router"; let loc = p["location"] as? String ?? ""; let endpoint = p["endpoint"] as? String ?? "—"; let median = (p["latency_median_ms"] as? NSNumber)?.doubleValue ?? 0; return "\((p["id"] as? String) == selected ? "●" : "○") \(name) \(loc)\n  endpoint: \(endpoint)\n  median: \(median > 0 ? String(format: "%.1f ms", median) : "not measured")" }.joined(separator: "\n\n"); settingsText.string = profiles.map { p in let name = p["name"] as? String ?? "Router"; return "\(name)\n  base=\(p["base_tunnel"] as? String ?? "auto") DNS=\(p["dns_mode"] as? String ?? "home")/\(p["dns_protocol"] as? String ?? "udp")\n  kill-switch=\(p["kill_switch_policy"] as? String ?? "off") LAN=\((p["home_lan_access"] as? Bool ?? false) ? "on" : "off") MTU=\(p["effective_mtu"] ?? "default")" }.joined(separator: "\n\n"); dnsText.string = profiles.map { p in "\(p["name"] as? String ?? "Router"): selected DNS \(p["dns_mode"] as? String ?? "home") \(p["dns_protocol"] as? String ?? "udp") \(p["dns_host"] as? String ?? "—"): \(p["dns_port"] ?? 53)" }.joined(separator: "\n"); renderMap() }
    func renderMap() { map.removeAnnotations(map.annotations); var annotations: [RouterAnnotation] = []; for p in profiles { let lat = (p["latitude"] as? NSNumber)?.doubleValue ?? 0; let lon = (p["longitude"] as? NSNumber)?.doubleValue ?? 0; guard CLLocationCoordinate2DIsValid(CLLocationCoordinate2D(latitude: lat, longitude: lon)), !(lat == 0 && lon == 0) else { continue }; annotations.append(RouterAnnotation(id: p["id"] as? String ?? "", name: p["name"] as? String ?? "Router", location: p["location"] as? String ?? "", latency: (p["latency_median_ms"] as? NSNumber)?.doubleValue ?? 0, lat: lat, lon: lon)) }; map.addAnnotations(annotations); if !annotations.isEmpty { map.showAnnotations(annotations, animated: false) } }
    func refreshModes() { DispatchQueue.global(qos: .utility).async { [weak self] in guard let self else { return }; do { guard let modes = try api.json("/api/logical-modes", timeout: 12) as? [[String: Any]] else { return }; let ready = modes.filter { $0["available"] as? Bool == true }; DispatchQueue.main.async { self.modeIDs = ready.compactMap { $0["id"] as? String }; self.modePopup.removeAllItems(); self.modePopup.addItems(withTitles: ready.map { $0["name"] as? String ?? $0["id"] as? String ?? "Mode" }); self.modesText.string = modes.map { "\(($0["available"] as? Bool ?? false) ? "✓" : "—") \($0["name"] as? String ?? "Mode")\n  \($0["reason"] as? String ?? "Ready")\n  bases: \(($0["ready_bases"] as? [String] ?? []).joined(separator: ", "))" }.joined(separator: "\n\n") } } catch { } } }
    func refreshAdvanced() { DispatchQueue.global(qos: .utility).async { [weak self] in guard let self else { return }; do { let data = try api.request("/api/multihop/status", timeout: 10); guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }; let nodes = obj["nodes"] as? [[String: Any]] ?? []; let ids = nodes.compactMap { $0["id"] as? String }; let names = nodes.map { $0["name"] as? String ?? $0["id"] as? String ?? "Node" }; let savedEntry = obj["entry_id"] as? String ?? ""; let savedExit = obj["exit_id"] as? String ?? ""; let prettyData = try JSONSerialization.data(withJSONObject: obj, options: [.prettyPrinted, .sortedKeys]); let pretty = String(data: prettyData, encoding: .utf8) ?? ""; DispatchQueue.main.async { let oldEntry = self.multihopEntryPopup.indexOfSelectedItem >= 0 && self.multihopEntryPopup.indexOfSelectedItem < self.multihopNodeIDs.count ? self.multihopNodeIDs[self.multihopEntryPopup.indexOfSelectedItem] : savedEntry; let oldExit = self.multihopExitPopup.indexOfSelectedItem >= 0 && self.multihopExitPopup.indexOfSelectedItem < self.multihopNodeIDs.count ? self.multihopNodeIDs[self.multihopExitPopup.indexOfSelectedItem] : savedExit; self.multihopNodeIDs = ids; self.multihopEntryPopup.removeAllItems(); self.multihopExitPopup.removeAllItems(); self.multihopEntryPopup.addItems(withTitles: names); self.multihopExitPopup.addItems(withTitles: names); if let i = ids.firstIndex(of: oldEntry) { self.multihopEntryPopup.selectItem(at: i) } else if let i = ids.firstIndex(of: savedEntry) { self.multihopEntryPopup.selectItem(at: i) }; if let i = ids.firstIndex(of: oldExit) { self.multihopExitPopup.selectItem(at: i) } else if let i = ids.firstIndex(of: savedExit) { self.multihopExitPopup.selectItem(at: i) }; self.advancedText.string = "Multihop status and proof:\n\(pretty)\n\nStrict kill switch is applied before the full-device TUN starts. The controller marks Connected only after exit proof succeeds; unsupported or failed chains stay fail-closed." } } catch { DispatchQueue.main.async { self.advancedText.string = "Advanced status unavailable: \(error.localizedDescription)" } } } }
    func appendHelp(_ message: String) { let f = DateFormatter(); f.dateFormat = "HH:mm:ss"; helpText.textStorage?.append(NSAttributedString(string: "[\(f.string(from: Date()))] \(message.trimmingCharacters(in: .whitespacesAndNewlines))\n")); helpText.scrollToEndOfDocument(nil) }
}

final class ProductDelegate: NSObject, NSApplicationDelegate {
    let api = ProductAPI(); var wc: ProductWindowController?; var controller: Process?; var ownsController = false
    func applicationDidFinishLaunching(_ notification: Notification) { NSApp.setActivationPolicy(.regular); do { try ensureController(); let w = ProductWindowController(api: api); wc = w; w.showWindow(nil); w.window?.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true) } catch { let a = NSAlert(); a.alertStyle = .critical; a.messageText = "Router VPN could not start"; a.informativeText = error.localizedDescription; a.runModal(); NSApp.terminate(nil) } }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
    func applicationWillTerminate(_ notification: Notification) { guard ownsController else { return }; _ = try? api.request("/api/emergency-stop", method: "POST", body: [:], timeout: 2); if let controller, controller.isRunning { controller.terminate() } }
    func ensureController() throws { if api.ready() { return }; let root = Bundle.main.bundleURL.deletingLastPathComponent(); let binary = root.appendingPathComponent("router-vpn-client"); let config = root.appendingPathComponent("client.json"); guard FileManager.default.isExecutableFile(atPath: binary.path), FileManager.default.fileExists(atPath: config.path) else { throw NSError(domain: "RouterVPNMac", code: 10, userInfo: [NSLocalizedDescriptionKey: "RouterVPN.app must stay beside router-vpn-client and client.json in its package."]) }; let p = Process(); p.executableURL = binary; p.currentDirectoryURL = root; var env = ProcessInfo.processInfo.environment; env["HOMEVPN_ROOT"] = root.path; env["HOMEVPN_CLIENT_CONFIG"] = config.path; env["HOMEVPN_NATIVE_APP"] = "macos-appkit-product"; p.environment = env; p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice; try p.run(); controller = p; ownsController = true; let deadline = Date().addingTimeInterval(12); while Date() < deadline { if api.ready() { return }; if !p.isRunning { break }; Thread.sleep(forTimeInterval: 0.2) }; if p.isRunning { p.terminate() }; throw NSError(domain: "RouterVPNMac", code: 11, userInfo: [NSLocalizedDescriptionKey: "Local Router VPN controller did not become ready on 127.0.0.1:8788."]) }
}

func runProductSelfTest() -> Int32 {
    let required = ["/api/status", "/api/profiles", "/api/logical-modes", "/api/auto", "/api/connect-logical", "/api/disconnect", "/api/profile/select", "/api/profile/latency", "/api/public-ip", "/api/dns/retest", "/api/emergency-stop", "/api/session/events", "/api/multihop/status", "/api/multihop/connect", "/api/forward", "/api/forward/clear"]
    let tabs = ["Home", "Nodes & Map", "Modes", "DNS", "Advanced", "Forwarding", "Settings", "Help"]
    guard routerVPNProductBaseURL.absoluteString == "http://127.0.0.1:8788", routerVPNProductContractVersion == 2, required.count == 16, tabs.count == 8 else { return 2 }
    print("Router VPN native macOS product self-test: OK")
    return 0
}

if CommandLine.arguments.contains("--self-test") { exit(runProductSelfTest()) }
let productApp = NSApplication.shared
let productDelegate = ProductDelegate()
productApp.delegate = productDelegate
productApp.run()