import AppKit
import Foundation
import MapKit

let routerVPNProductBaseURL = URL(string: "http://127.0.0.1:8788")!
let routerVPNProductContractVersion = 3

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
        return try perform(req, timeout: timeout)
    }
    func requestRaw(_ path: String, body: Data, timeout: TimeInterval = 15) throws -> Data {
        guard let url = URL(string: path, relativeTo: routerVPNProductBaseURL) else { throw NSError(domain: "RouterVPNMac", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid local API path"]) }
        var req = URLRequest(url: url); req.httpMethod = "POST"; req.timeoutInterval = timeout; req.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData; req.httpBody = body
        req.setValue("application/json", forHTTPHeaderField: "Accept"); req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        return try perform(req, timeout: timeout)
    }
    private func perform(_ req: URLRequest, timeout: TimeInterval) throws -> Data {
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
    let nodePopup = NSPopUpButton(frame: .zero, pullsDown: false)
    let nodeSortPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    let externalEntryPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    let modePopup = NSPopUpButton(frame: .zero, pullsDown: false)
    let basePopup = NSPopUpButton(frame: .zero, pullsDown: false)
    let multihopEntryPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    let multihopExitPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    let multihopExitModePopup = NSPopUpButton(frame: .zero, pullsDown: false)
    let dnsModePopup = NSPopUpButton(frame: .zero, pullsDown: false)
    let dnsProtocolPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    let dnsPresetPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    let dnsHostField = NSTextField(string: "")
    let dnsPortField = NSTextField(string: "53")
    let dnsServerNameField = NSTextField(string: "")
    let dnsPathField = NSTextField(string: "/dns-query")
    let map = MKMapView()
    let nodesText = NSTextView(); let modesText = NSTextView(); let dnsText = NSTextView(); let advancedText = NSTextView(); let settingsText = NSTextView(); let helpText = NSTextView()
    let forwardInput = NSTextView(); let forwardOutput = NSTextView()
    var routerIDs: [String] = []; var modeIDs: [String] = []; var profiles: [[String: Any]] = []; var eventSeq: UInt64 = 0; var timer: Timer?
    var multihopNodeIDs: [String] = []
    let dnsModeIDs = ["home", "fastest", "custom", "dot", "doh", "doh3", "rescue"]
    let dnsProtocolIDs = ["udp", "tcp"]

    init(api: ProductAPI) {
        self.api = api
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1180, height: 780), styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = "Router VPN"; window.minSize = NSSize(width: 980, height: 650); window.center()
        super.init(window: window); buildUI(); refreshAll(); timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in self?.refreshLive() }
        appendHelp("Install once; pair/import Router VPN or validated external node data separately. External protocol credentials remain only in the controller private store.")
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
        map.delegate = self; map.showsCompass = true; map.showsScale = true; split.addArrangedSubview(map)
        let right = NSStackView(); right.orientation = .vertical; right.spacing = 8; right.edgeInsets = NSEdgeInsets(top: 8, left: 8, bottom: 8, right: 8); right.addArrangedSubview(scroll(nodesText))
        right.addArrangedSubview(label("Node order")); nodeSortPopup.addItems(withTitles: ["Current / recent", "Last used", "Lowest latency", "Name"]); nodeSortPopup.target = self; nodeSortPopup.action = #selector(nodeSortChanged); right.addArrangedSubview(nodeSortPopup)
        right.addArrangedSubview(button("Select lowest measured latency", #selector(selectLowestLatency)))
        right.addArrangedSubview(label("Selected node / external exit")); right.addArrangedSubview(nodePopup)
        right.addArrangedSubview(label("Optional external entry (Router VPN or supported external node)")); right.addArrangedSubview(externalEntryPopup)
        let row = NSStackView(); row.orientation = .horizontal; row.spacing = 6
        row.addArrangedSubview(button("Pair", #selector(pairNode))); row.addArrangedSubview(button("Import", #selector(importNode))); row.addArrangedSubview(button("Select", #selector(selectNode))); row.addArrangedSubview(button("External direct", #selector(connectExternalDirect))); row.addArrangedSubview(button("External via entry", #selector(connectExternalViaEntry))); row.addArrangedSubview(button("Remove", #selector(removeNode))); row.addArrangedSubview(button("50-sample latency", #selector(latencySelected)))
        right.addArrangedSubview(row); split.addArrangedSubview(right); split.setPosition(650, ofDividerAt: 0); return split
    }

    func dnsView() -> NSView {
        let s = NSStackView(); s.orientation = .vertical; s.spacing = 9; s.edgeInsets = NSEdgeInsets(top: 18, left: 18, bottom: 18, right: 18)
        let note = NSTextField(wrappingLabelWithString: "Choose Home, Fastest, Custom UDP/TCP, DoT, DoH, DoH3 or Rescue. Common IPv4/IPv6 resolver presets only fill fields. Disconnect before changing policy; reconnect and session DNS proof remain authoritative. Home-node Retest measures real DNS A/AAAA query RTT, not ICMP."); note.textColor = .secondaryLabelColor; s.addArrangedSubview(note)
        dnsModePopup.addItems(withTitles: ["Home AdGuard", "Fastest measured", "Custom UDP/TCP", "DNS-over-TLS", "DNS-over-HTTPS", "DNS-over-HTTP/3", "DNS Rescue"])
        dnsProtocolPopup.addItems(withTitles: ["UDP", "TCP"])
        dnsPresetPopup.addItems(withTitles: ["Manual/current", "Cloudflare IPv4 — 1.1.1.1", "Cloudflare IPv6 — 2606:4700:4700::1111", "Google IPv4 — 8.8.8.8", "Google IPv6 — 2001:4860:4860::8888", "Quad9 IPv4 — 9.9.9.9", "Quad9 IPv6 — 2620:fe::fe"]); dnsPresetPopup.target = self; dnsPresetPopup.action = #selector(dnsPresetChanged)
        dnsHostField.placeholderString = "resolver host / IPv4 / IPv6"; dnsPortField.placeholderString = "port"; dnsServerNameField.placeholderString = "TLS server name"; dnsPathField.placeholderString = "/dns-query"
        let grid = NSGridView(views: [[label("DNS mode"), dnsModePopup], [label("Custom protocol"), dnsProtocolPopup], [label("Common resolver"), dnsPresetPopup], [label("Host"), dnsHostField], [label("Port"), dnsPortField], [label("TLS server name"), dnsServerNameField], [label("HTTPS path"), dnsPathField]])
        grid.rowSpacing = 6; grid.columnSpacing = 10; s.addArrangedSubview(grid)
        let row = NSStackView(); row.orientation = .horizontal; row.spacing = 8; row.addArrangedSubview(button("Save DNS policy", #selector(saveDNS))); row.addArrangedSubview(button("Retest home-node DNS RTT", #selector(retestDNS))); row.addArrangedSubview(button("Refresh DNS", #selector(refreshAction))); s.addArrangedSubview(row)
        s.addArrangedSubview(scroll(dnsText)); return s
    }
    func advancedView() -> NSView {
        let s = NSStackView(); s.orientation = .vertical; s.spacing = 10; s.edgeInsets = NSEdgeInsets(top: 18, left: 18, bottom: 18, right: 18)
        let note = NSTextField(wrappingLabelWithString: "Real Router VPN multihop path: client TUN → exit transport → entry WireGuard → exit node → Internet. External hops use the separate validated external-connect path in Nodes & Map. MTU Retest is only accepted while a single Router VPN node is connected with Auto MTU; it compares bounded private-node loss/RTT/throughput candidates and never claims MTU caused an earlier cellular regression."); note.textColor = .secondaryLabelColor; s.addArrangedSubview(note)
        let selectors = NSStackView(); selectors.orientation = .horizontal; selectors.spacing = 8
        let entry = NSStackView(); entry.orientation = .vertical; entry.addArrangedSubview(label("Entry node")); entry.addArrangedSubview(multihopEntryPopup)
        let exit = NSStackView(); exit.orientation = .vertical; exit.addArrangedSubview(label("Exit node")); exit.addArrangedSubview(multihopExitPopup)
        let mode = NSStackView(); mode.orientation = .vertical; mode.addArrangedSubview(label("Exit transport")); multihopExitModePopup.addItems(withTitles: ["Shadowsocks", "Hysteria2"]); multihopExitModePopup.selectItem(at: 0); mode.addArrangedSubview(multihopExitModePopup)
        selectors.addArrangedSubview(entry); selectors.addArrangedSubview(exit); selectors.addArrangedSubview(mode); s.addArrangedSubview(selectors)
        let row = NSStackView(); row.orientation = .horizontal; row.addArrangedSubview(button("Connect real multihop", #selector(connectMultihop))); row.addArrangedSubview(button("Refresh multihop readiness", #selector(refreshAdvancedAction))); row.addArrangedSubview(button("Retest MTU", #selector(retestMTU))); row.addArrangedSubview(button("Emergency stop", #selector(emergencyStop))); s.addArrangedSubview(row); s.addArrangedSubview(scroll(advancedText)); return s
    }
    func settingsView() -> NSView { let s = NSStackView(); s.orientation = .vertical; s.spacing = 10; s.edgeInsets = NSEdgeInsets(top: 18, left: 18, bottom: 18, right: 18); s.addArrangedSubview(scroll(settingsText)); return s }
    func helpView() -> NSView { let s = NSStackView(); s.orientation = .vertical; s.spacing = 10; s.edgeInsets = NSEdgeInsets(top: 18, left: 18, bottom: 18, right: 18); let row = NSStackView(); row.orientation = .horizontal; row.addArrangedSubview(button("Pair/add node", #selector(pairNode))); row.addArrangedSubview(button("Prove public VPN exit", #selector(publicExit))); row.addArrangedSubview(button("Emergency stop", #selector(emergencyStop))); row.addArrangedSubview(button("Refresh", #selector(refreshAction))); s.addArrangedSubview(row); s.addArrangedSubview(scroll(helpText)); return s }
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
    func selectedNodeID() -> String? {
        if let a = map.selectedAnnotations.first as? RouterAnnotation { return a.routerID }
        let i = nodePopup.indexOfSelectedItem
        guard i >= 0 && i < routerIDs.count else { return nil }
        return routerIDs[i]
    }
    @objc func connectExternalDirect() {
        guard let exitID = selectedNodeID() else { appendHelp("Select an external exit node first."); return }
        asyncAction { String(data: try self.api.request("/api/external-profile/connect", method: "POST", body: ["profile_id": exitID], timeout: 180), encoding: .utf8) ?? "External exit connected" }
    }
    @objc func connectExternalViaEntry() {
        guard let exitID = selectedNodeID() else { appendHelp("Select an external exit node first."); return }
        let i = externalEntryPopup.indexOfSelectedItem
        guard i >= 0 && i < routerIDs.count else { appendHelp("Choose an entry node first."); return }
        let entryID = routerIDs[i]
        guard entryID != exitID else { appendHelp("External entry and exit must be different nodes."); return }
        asyncAction { String(data: try self.api.request("/api/external-profile/connect", method: "POST", body: ["profile_id": exitID, "entry_id": entryID], timeout: 180), encoding: .utf8) ?? "External exit connected through entry" }
    }
    @objc func disconnect() { asyncAction { _ = try self.api.request("/api/disconnect", method: "POST", body: [:], timeout: 20); return "Disconnected." } }
    @objc func publicExit() { asyncAction { String(data: try self.api.request("/api/public-ip", timeout: 20), encoding: .utf8) ?? "" } }
    @objc func retestDNS() { asyncAction { String(data: try self.api.request("/api/dns/retest", method: "POST", body: [:], timeout: 90), encoding: .utf8) ?? "DNS Retest completed" } }
    @objc func saveDNS() {
        let modeIndex = max(0, min(dnsModePopup.indexOfSelectedItem, dnsModeIDs.count - 1)); let protocolIndex = max(0, min(dnsProtocolPopup.indexOfSelectedItem, dnsProtocolIDs.count - 1))
        let body: [String: Any] = ["mode": dnsModeIDs[modeIndex], "protocol": dnsProtocolIDs[protocolIndex], "host": dnsHostField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines), "port": Int(dnsPortField.stringValue) ?? 0, "server_name": dnsServerNameField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines), "path": dnsPathField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)]
        asyncAction { String(data: try self.api.request("/api/dns/policy", method: "POST", body: body, timeout: 10), encoding: .utf8) ?? "DNS policy saved for the next connection" }
    }
    @objc func dnsPresetChanged() {
        let presets: [(String,String)] = [("",""),("1.1.1.1","cloudflare-dns.com"),("2606:4700:4700::1111","cloudflare-dns.com"),("8.8.8.8","dns.google"),("2001:4860:4860::8888","dns.google"),("9.9.9.9","dns.quad9.net"),("2620:fe::fe","dns.quad9.net")]
        let i = max(0, min(dnsPresetPopup.indexOfSelectedItem, presets.count - 1)); guard i > 0 else { return }; dnsHostField.stringValue = presets[i].0; dnsServerNameField.stringValue = presets[i].1
    }
    @objc func retestMTU() { asyncAction { String(data: try self.api.request("/api/mtu/retest", method: "POST", body: [:], timeout: 125), encoding: .utf8) ?? "MTU Retest completed" } }
    @objc func emergencyStop() { asyncAction { _ = try self.api.request("/api/emergency-stop", method: "POST", body: [:], timeout: 20); return "Emergency stop completed." } }
    @objc func refreshAction() { refreshAll() }
    @objc func refreshAdvancedAction() { refreshAdvanced() }
    @objc func nodeSortChanged() { refreshProfiles(order: ["current", "last-used", "latency", "name"][max(0, min(nodeSortPopup.indexOfSelectedItem, 3))]) }
    @objc func selectLowestLatency() {
        asyncAction {
            guard let o = try self.api.json("/api/nodes?sort=latency") as? [String: Any], let p = o["profiles"] as? [[String: Any]] else { return "Lowest-latency node list was unavailable." }
            let measured = p.filter { (($0["latency_samples"] as? NSNumber)?.intValue ?? 0) > 0 && (($0["latency_median_ms"] as? NSNumber)?.doubleValue ?? 0) > 0 }
            guard measured.count >= 2, let id = measured.first?["id"] as? String, !id.isEmpty else { return "Lowest-latency selection requires real 50-sample measurements on at least two usable nodes; current selection was kept." }
            _ = try self.api.request("/api/profile/select", method: "POST", body: ["id": id], timeout: 10)
            DispatchQueue.main.async { self.nodeSortPopup.selectItem(at: 2) }
            return "Selected the lowest measured median-latency node \(id)."
        }
    }
    @objc func selectRouter() { let i = routerPopup.indexOfSelectedItem; guard i >= 0 && i < routerIDs.count else { return }; let id = routerIDs[i]; asyncAction { _ = try self.api.request("/api/profile/select", method: "POST", body: ["id": id], timeout: 10); return "Selected router \(id)" } }
    @objc func selectNode() { guard let id = selectedNodeID() else { appendHelp("Select a linked node first."); return }; asyncAction { _ = try self.api.request("/api/profile/select", method: "POST", body: ["id": id], timeout: 10); return "Selected node \(id)" } }
    @objc func latencySelected() { guard let id = selectedNodeID() else { appendHelp("Select a node first."); return }; asyncAction { String(data: try self.api.request("/api/profile/latency", method: "POST", body: ["id": id, "samples": 50], timeout: 180), encoding: .utf8) ?? "" } }
    @objc func pairNode() {
        let alert = NSAlert(); alert.messageText = "Pair Router VPN home node"; alert.informativeText = "Create a short-lived 6-digit code in the authenticated private Setup Center. Pairing is private-LAN only and the code is one-time."
        alert.addButton(withTitle: "Pair"); alert.addButton(withTitle: "Cancel")
        let stack = NSStackView(); stack.orientation = .vertical; stack.spacing = 8; stack.frame = NSRect(x: 0, y: 0, width: 360, height: 86)
        let host = NSTextField(string: ""); host.placeholderString = "AI Board LAN IP / hostname"
        let code = NSSecureTextField(string: ""); code.placeholderString = "6-digit one-time pairing code"
        stack.addArrangedSubview(host); stack.addArrangedSubview(code); alert.accessoryView = stack
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        let h = host.stringValue.trimmingCharacters(in: .whitespacesAndNewlines), c = code.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard c.count == 6, c.allSatisfy({ $0.isNumber }) else { appendHelp("Pairing code must be exactly 6 digits."); return }
        asyncAction { String(data: try self.api.request("/api/profile/pair", method: "POST", body: ["host": h, "code": c], timeout: 20), encoding: .utf8) ?? "Node paired" }
    }
    @objc func importNode() {
        let panel = NSOpenPanel(); panel.title = "Import Router VPN or external node"; panel.allowedFileTypes = ["json"]; panel.allowsMultipleSelection = false; panel.canChooseDirectories = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let data = try Data(contentsOf: url, options: [.mappedIfSafe])
            guard data.count <= 32 * 1024 * 1024 else { throw NSError(domain: "RouterVPNMac", code: 20, userInfo: [NSLocalizedDescriptionKey: "Node JSON is larger than 32 MiB."]) }
            asyncAction {
                do { return String(data: try self.api.requestRaw("/api/profile/import", body: data, timeout: 25), encoding: .utf8) ?? "Router VPN node imported" }
                catch let routerError {
                    do { return String(data: try self.api.requestRaw("/api/external-profile/import", body: data, timeout: 25), encoding: .utf8) ?? "External node imported" }
                    catch { throw NSError(domain: "RouterVPNMac", code: 21, userInfo: [NSLocalizedDescriptionKey: "Rejected as Router VPN bundle (\(routerError.localizedDescription)) and external schema-v3 node (\(error.localizedDescription))"]) }
                }
            }
        } catch { errorLabel.stringValue = error.localizedDescription; appendHelp("Import failed: \(error.localizedDescription)") }
    }
    @objc func removeNode() {
        guard let id = selectedNodeID() else { appendHelp("Select a node first."); return }
        let alert = NSAlert(); alert.alertStyle = .warning; alert.messageText = "Remove linked node?"; alert.informativeText = "This removes the node from this app; it does not uninstall Router VPN or change the home server."; alert.addButton(withTitle: "Remove"); alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        asyncAction { _ = try self.api.request("/api/profile/delete", method: "POST", body: ["id": id], timeout: 10); return "Removed node \(id)" }
    }
    @objc func applyForward() { guard let d = forwardInput.string.data(using: .utf8), let obj = try? JSONSerialization.jsonObject(with: d), let body = obj as? [String: Any] else { appendHelp("Forwarding payload must be a JSON object."); return }; asyncAction { String(data: try self.api.request("/api/forward", method: "POST", body: body, timeout: 20), encoding: .utf8) ?? "" } }
    @objc func clearForward() { asyncAction { String(data: try self.api.request("/api/forward/clear", method: "POST", body: [:], timeout: 20), encoding: .utf8) ?? "Forwarding cleared" } }

    func refreshAll() { refreshProfiles(); refreshModes(); refreshLive(); refreshAdvanced() }
    func refreshLive() { refreshStatus(); refreshSessionEvents() }
    func refreshStatus() { DispatchQueue.global(qos: .utility).async { [weak self] in guard let self else { return }; do { guard let o = try api.json("/api/status") as? [String: Any] else { return }; DispatchQueue.main.async { let connected = o["connected"] as? Bool ?? false; let phase = o["phase"] as? String ?? "off"; self.statusLabel.stringValue = connected ? "● Connected" : "○ \(phase)"; self.statusLabel.textColor = connected ? .systemGreen : (phase == "failed" ? .systemRed : .secondaryLabelColor); self.detailLabel.stringValue = "Logical: \(o["logical_mode"] as? String ?? "—")   Runtime: \((o["runtime_mode"] as? String) ?? (o["mode"] as? String) ?? "—")   Base: \(o["base"] as? String ?? "—")   Router: \(o["router_id"] as? String ?? "—")"; self.errorLabel.stringValue = o["last_error"] as? String ?? "" } } catch { DispatchQueue.main.async { self.statusLabel.stringValue = "● Controller unavailable"; self.statusLabel.textColor = .systemRed; self.errorLabel.stringValue = error.localizedDescription } } } }
    func refreshSessionEvents() { let after = eventSeq; DispatchQueue.global(qos: .utility).async { [weak self] in guard let self else { return }; do { guard let o = try api.json("/api/session/events?after=\(after)") as? [String: Any] else { return }; let events = o["events"] as? [[String: Any]] ?? []; let last = (o["last_event_seq"] as? NSNumber)?.uint64Value ?? after; DispatchQueue.main.async { for e in events { let seq = (e["seq"] as? NSNumber)?.uint64Value ?? 0; guard seq > self.eventSeq else { continue }; var parts: [String] = [e["phase"] as? String ?? ""]; if let r = e["runtime_mode"] as? String, !r.isEmpty { parts.append("runtime=\(r)") }; if let b = e["base"] as? String, !b.isEmpty { parts.append("base=\(b)") }; if let m = e["message"] as? String, !m.isEmpty { parts.append(m) }; self.appendHelp("Session #\(seq) \(e["type"] as? String ?? "event"): " + parts.filter { !$0.isEmpty }.joined(separator: " | ")); self.eventSeq = seq }; self.eventSeq = max(self.eventSeq, last) } } catch { } } }
    func refreshProfiles() { refreshProfiles(order: ["current", "last-used", "latency", "name"][max(0, min(nodeSortPopup.indexOfSelectedItem, 3))]) }
    func refreshProfiles(order: String) { DispatchQueue.global(qos: .utility).async { [weak self] in guard let self else { return }; do { guard let o = try api.json("/api/nodes?sort=\(order)") as? [String: Any], let p = o["profiles"] as? [[String: Any]] else { return }; let selected = o["selected_id"] as? String ?? ""; DispatchQueue.main.async { let oldIDs = self.routerIDs; let oldNode = self.nodePopup.indexOfSelectedItem >= 0 && self.nodePopup.indexOfSelectedItem < oldIDs.count ? oldIDs[self.nodePopup.indexOfSelectedItem] : selected; let oldEntry = self.externalEntryPopup.indexOfSelectedItem >= 0 && self.externalEntryPopup.indexOfSelectedItem < oldIDs.count ? oldIDs[self.externalEntryPopup.indexOfSelectedItem] : ""; self.profiles = p; self.routerIDs = p.compactMap { $0["id"] as? String }; let names = p.map { $0["name"] as? String ?? $0["id"] as? String ?? "Node" }; self.routerPopup.removeAllItems(); self.nodePopup.removeAllItems(); self.externalEntryPopup.removeAllItems(); self.routerPopup.addItems(withTitles: names); self.nodePopup.addItems(withTitles: names); self.externalEntryPopup.addItems(withTitles: names); if let i = self.routerIDs.firstIndex(of: selected) { self.routerPopup.selectItem(at: i) }; if let i = self.routerIDs.firstIndex(of: oldNode) { self.nodePopup.selectItem(at: i) } else if let i = self.routerIDs.firstIndex(of: selected) { self.nodePopup.selectItem(at: i) }; if let i = self.routerIDs.firstIndex(of: oldEntry) { self.externalEntryPopup.selectItem(at: i) }; self.renderProfiles(selected: selected) } } catch { DispatchQueue.main.async { self.errorLabel.stringValue = error.localizedDescription } } } }
    func renderProfiles(selected: String) {
        nodesText.string = profiles.map { p in let name = p["name"] as? String ?? p["id"] as? String ?? "Router"; let loc = p["location"] as? String ?? ""; let endpoint = p["endpoint"] as? String ?? "—"; let kind = p["node_kind"] as? String ?? "router-vpn"; let median = (p["latency_median_ms"] as? NSNumber)?.doubleValue ?? 0; let lastUsed = p["last_used_at"] as? String ?? ""; return "\((p["id"] as? String) == selected ? "●" : "○") [\(kind)] \(name) \(loc)\n  endpoint: \(endpoint)\n  median: \(median > 0 ? String(format: "%.1f ms", median) : "not measured")\n  last used: \(lastUsed.isEmpty ? "never" : lastUsed)" }.joined(separator: "\n\n")
        settingsText.string = profiles.map { p in let name = p["name"] as? String ?? "Router"; let mtu = (p["effective_mtu"] as? NSNumber)?.intValue ?? 0; let source = p["effective_mtu_source"] as? String ?? "default"; let mbps = (p["effective_mtu_mbps"] as? NSNumber)?.doubleValue ?? 0; let rtt = (p["effective_mtu_median_rtt_ms"] as? NSNumber)?.doubleValue ?? 0; let success = (p["effective_mtu_success_ratio"] as? NSNumber)?.doubleValue ?? 0; let perf = mbps > 0 ? String(format: "  Retest performance=%.1f Mbps median RTT=%.2f ms success=%.1f%%\n", mbps, rtt, success * 100.0) : ""; return "\(name)\n  base=\(p["base_tunnel"] as? String ?? "auto") DNS=\(p["dns_mode"] as? String ?? "home")/\(p["dns_protocol"] as? String ?? "udp")\n  kill-switch=\(p["kill_switch_policy"] as? String ?? "off") LAN=\((p["home_lan_access"] as? Bool ?? false) ? "on" : "off") MTU=\(mtu > 0 ? String(mtu) : "default") source=\(source)\n\(perf)  tested=\(p["effective_mtu_tested_at"] as? String ?? "not retested")" }.joined(separator: "\n\n")
        if let p = profiles.first(where: { ($0["id"] as? String) == selected }) ?? profiles.first {
            let mode = p["dns_mode"] as? String ?? "home"; let proto = p["dns_protocol"] as? String ?? "udp"; if let i = dnsModeIDs.firstIndex(of: mode) { dnsModePopup.selectItem(at: i) }; if let i = dnsProtocolIDs.firstIndex(of: proto) { dnsProtocolPopup.selectItem(at: i) }; dnsPresetPopup.selectItem(at: 0); dnsHostField.stringValue = p["dns_host"] as? String ?? ""; dnsPortField.stringValue = String((p["dns_port"] as? NSNumber)?.intValue ?? 53); dnsServerNameField.stringValue = p["dns_server_name"] as? String ?? ""; dnsPathField.stringValue = p["dns_path"] as? String ?? "/dns-query"
            var lines = ["Selected DNS: \(mode) \(proto) \(dnsHostField.stringValue):\(dnsPortField.stringValue)"]
            let fastestHost = p["fastest_dns_host"] as? String ?? ""; if !fastestHost.isEmpty { lines.append("Fastest measured: \(p["fastest_dns_name"] as? String ?? fastestHost) • \((p["fastest_dns_latency_ms"] as? NSNumber)?.doubleValue ?? 0) ms • \(fastestHost)") }
            let results = (p["dns_results"] as? [[String: Any]] ?? []).sorted { a,b in let aw = a["working"] as? Bool ?? false, bw = b["working"] as? Bool ?? false; if aw != bw { return aw }; return ((a["latency_ms"] as? NSNumber)?.doubleValue ?? Double.greatestFiniteMagnitude) < ((b["latency_ms"] as? NSNumber)?.doubleValue ?? Double.greatestFiniteMagnitude) }
            for r in results { let working = r["working"] as? Bool ?? false; lines.append("\(r["name"] as? String ?? r["address"] as? String ?? "Resolver") • \(r["address"] as? String ?? "") • \(working ? String(format: "%.2f ms", (r["latency_ms"] as? NSNumber)?.doubleValue ?? 0) : "failed")") }
            lines.append("RTT values are home-node DNS A/AAAA query measurements, not ICMP. Saved policy is staged for the next connection; session proof still determines active DNS."); dnsText.string = lines.joined(separator: "\n")
        } else { dnsText.string = "No selected Router VPN node." }
        renderMap()
    }
    func renderMap() { map.removeAnnotations(map.annotations); var annotations: [RouterAnnotation] = []; for p in profiles { let lat = (p["latitude"] as? NSNumber)?.doubleValue ?? 0; let lon = (p["longitude"] as? NSNumber)?.doubleValue ?? 0; guard CLLocationCoordinate2DIsValid(CLLocationCoordinate2D(latitude: lat, longitude: lon)), !(lat == 0 && lon == 0) else { continue }; annotations.append(RouterAnnotation(id: p["id"] as? String ?? "", name: p["name"] as? String ?? "Router", location: p["location"] as? String ?? "", latency: (p["latency_median_ms"] as? NSNumber)?.doubleValue ?? 0, lat: lat, lon: lon)) }; map.addAnnotations(annotations); if !annotations.isEmpty { map.showAnnotations(annotations, animated: false) } }
    func refreshModes() { DispatchQueue.global(qos: .utility).async { [weak self] in guard let self else { return }; do { guard let modes = try api.json("/api/logical-modes", timeout: 12) as? [[String: Any]] else { return }; let ready = modes.filter { $0["available"] as? Bool == true }; DispatchQueue.main.async { self.modeIDs = ready.compactMap { $0["id"] as? String }; self.modePopup.removeAllItems(); self.modePopup.addItems(withTitles: ready.map { $0["name"] as? String ?? $0["id"] as? String ?? "Mode" }); self.modesText.string = modes.map { mode in var layerSet = Set<String>(); if let variants = mode["variants"] as? [String: Any] { for value in variants.values { if let variant = value as? [String: Any], let raw = variant["mode"] as? [String: Any], let layers = raw["layers"] as? [String] { for layer in layers { if !layer.isEmpty { layerSet.insert(layer) } } } } }; let layers = layerSet.sorted().isEmpty ? "—" : layerSet.sorted().joined(separator: " • "); let pingMin=(mode["ping_min_ms"] as? NSNumber)?.doubleValue ?? 0, pingMax=(mode["ping_max_ms"] as? NSNumber)?.doubleValue ?? 0, trafficMin=(mode["traffic_min_pct"] as? NSNumber)?.doubleValue ?? 0, trafficMax=(mode["traffic_max_pct"] as? NSNumber)?.doubleValue ?? 0, speedMin=(mode["speed_loss_min_pct"] as? NSNumber)?.doubleValue ?? 0, speedMax=(mode["speed_loss_max_pct"] as? NSNumber)?.doubleValue ?? 0; let available=mode["available"] as? Bool ?? false; let bases=(mode["ready_bases"] as? [String] ?? []).joined(separator: ", "); let reason=(mode["reason"] as? String ?? "").isEmpty ? (available ? "selected variant is runnable; final Connected still requires selected-path proof" : "no runnable variant") : (mode["reason"] as? String ?? ""); return "\(available ? "✓" : "—") \(mode["name"] as? String ?? "Mode")\n  \(mode["description"] as? String ?? "")\n  layers: \(layers)\n  added latency \(String(format: "%.1f–%.1f ms", pingMin,pingMax)) • traffic \(String(format: "+%.1f–%.1f%%",trafficMin,trafficMax)) • speed loss \(String(format: "%.1f–%.1f%%",speedMin,speedMax))\n  readiness: \(available ? "Ready" : "Unavailable")\(bases.isEmpty ? "" : " • bases: \(bases)")\n  reason: \(reason)" }.joined(separator: "\n\n") } } catch { } } }
    func refreshAdvanced() { DispatchQueue.global(qos: .utility).async { [weak self] in guard let self else { return }; do { let data = try api.request("/api/multihop/status", timeout: 10); guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }; let nodes = obj["nodes"] as? [[String: Any]] ?? []; let ids = nodes.compactMap { $0["id"] as? String }; let names = nodes.map { $0["name"] as? String ?? $0["id"] as? String ?? "Node" }; let savedEntry = obj["entry_id"] as? String ?? ""; let savedExit = obj["exit_id"] as? String ?? ""; let prettyData = try JSONSerialization.data(withJSONObject: obj, options: [.prettyPrinted, .sortedKeys]); let pretty = String(data: prettyData, encoding: .utf8) ?? ""; DispatchQueue.main.async { let oldEntry = self.multihopEntryPopup.indexOfSelectedItem >= 0 && self.multihopEntryPopup.indexOfSelectedItem < self.multihopNodeIDs.count ? self.multihopNodeIDs[self.multihopEntryPopup.indexOfSelectedItem] : savedEntry; let oldExit = self.multihopExitPopup.indexOfSelectedItem >= 0 && self.multihopExitPopup.indexOfSelectedItem < self.multihopNodeIDs.count ? self.multihopNodeIDs[self.multihopExitPopup.indexOfSelectedItem] : savedExit; self.multihopNodeIDs = ids; self.multihopEntryPopup.removeAllItems(); self.multihopExitPopup.removeAllItems(); self.multihopEntryPopup.addItems(withTitles: names); self.multihopExitPopup.addItems(withTitles: names); if let i = ids.firstIndex(of: oldEntry) { self.multihopEntryPopup.selectItem(at: i) } else if let i = ids.firstIndex(of: savedEntry) { self.multihopEntryPopup.selectItem(at: i) }; if let i = ids.firstIndex(of: oldExit) { self.multihopExitPopup.selectItem(at: i) } else if let i = ids.firstIndex(of: savedExit) { self.multihopExitPopup.selectItem(at: i) }; self.advancedText.string = "Multihop status and proof:\n\(pretty)\n\nMTU Retest is available above only for a connected single Router VPN node with Auto MTU. Results are network/path-specific and report effective MTU plus measured private-node throughput/RTT/success. Strict kill switch is applied before the full-device TUN starts. External direct/entry→exit uses the separate validated external profile path and exact expected public-exit proof." } } catch { DispatchQueue.main.async { self.advancedText.string = "Advanced status unavailable: \(error.localizedDescription)" } } } }
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
    let required = ["/api/status", "/api/profiles", "/api/nodes?sort=latency", "/api/logical-modes", "/api/auto", "/api/connect-logical", "/api/disconnect", "/api/profile/select", "/api/profile/latency", "/api/profile/pair", "/api/profile/import", "/api/external-profile/import", "/api/external-profile/connect", "entry_id", "/api/profile/delete", "/api/public-ip", "/api/dns/retest", "/api/dns/policy", "/api/mtu/retest", "/api/emergency-stop", "/api/session/events", "/api/multihop/status", "/api/multihop/connect", "/api/forward", "/api/forward/clear"]
    let tabs = ["Home", "Nodes & Map", "Modes", "DNS", "Advanced", "Forwarding", "Settings", "Help"]
    let parity = ["Added latency", "traffic", "speed loss", "readiness", "Home AdGuard", "Fastest measured", "DNS-over-HTTP/3"]
    guard routerVPNProductBaseURL.absoluteString == "http://127.0.0.1:8788", routerVPNProductContractVersion == 3, required.count == 25, tabs.count == 8, parity.count == 7 else { return 2 }
    print("Router VPN native macOS product self-test: OK")
    return 0
}

if CommandLine.arguments.contains("--self-test") { exit(runProductSelfTest()) }
let productApp = NSApplication.shared
let productDelegate = ProductDelegate()
productApp.delegate = productDelegate
productApp.run()
