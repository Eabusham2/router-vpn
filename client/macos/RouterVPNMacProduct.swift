import AppKit
import Foundation
import CoreFoundation
import MapKit
import Darwin
import CryptoKit

let routerVPNProductBaseURL = URL(string: "http://127.0.0.1:8788")!
let routerVPNProductContractVersion = 3

func productConnectionStatusLabel(connected: Bool, phase: String) -> String {
    if phase.lowercased().hasPrefix("candidate:") { return "○ Testing" }
    return connected ? "● Connected" : "○ \(phase)"
}

enum RouterVPNNodeEntryModes {
    static let choices: [(id: String, title: String)] = [
        ("", "Use saved entry mode / base"),
        ("wg", "WireGuard"),
        ("awg2-fast", "AWG Fast"),
        ("awg2-strong", "AWG Strong"),
        ("wg-pq", "WG + PQ"),
        ("awg2-pq", "AWG + PQ"),
        ("shadowsocks", "Shadowsocks"),
        ("hysteria2", "Hysteria2"),
        ("reality-vision", "REALITY Vision"),
        ("reality-pq-vision", "PQ REALITY Vision"),
        ("reality-xhttp", "REALITY XHTTP"),
        ("naive-h2", "Naive H2"),
        ("naive-h3", "Naive H3"),
        ("ss-v2ray", "SS/V2Ray"),
        ("split", "Split"),
        ("max", "MAX TCP/UDP"),
        ("max-tls-wg", "MAX TLS / WG + PQ"),
        ("max-tls-awg", "MAX TLS / AWG + PQ"),
        ("max-quic-wg", "MAX QUIC / WG + PQ"),
        ("max-quic-awg", "MAX QUIC / AWG + PQ"),
        ("wireguard", "Imported WireGuard · Local only"),
        ("amneziawg", "Imported AmneziaWG · Local only"),
        ("socks5", "Imported SOCKS5 · Local only"),
        ("http-connect", "Imported HTTP CONNECT · Local only"),
        ("https-connect", "Imported HTTPS CONNECT · Local only"),
        ("openvpn", "Imported OpenVPN · Local only"),
    ]
    static func id(at index: Int) -> String? {
        choices.indices.contains(index) ? choices[index].id : nil
    }
    static func index(for id: String) -> Int? { choices.firstIndex { $0.id == id } }
    static func require(index: Int) throws -> String {
        guard let value = id(at: index) else {
            throw NSError(domain: "RouterVPN.Multihop", code: 1, userInfo: [NSLocalizedDescriptionKey: "Select a supported entry mode."])
        }
        return value
    }
}

enum RouterVPNNodeExitModes {
    static let choices: [(id: String, title: String)] = [
        ("shadowsocks", "Shadowsocks"), ("hysteria2", "Hysteria2"),
        ("reality-vision", "REALITY Vision"), ("reality-pq-vision", "PQ REALITY Vision"),
        ("reality-xhttp", "REALITY XHTTP"), ("naive-h2", "Naive H2"), ("naive-h3", "Naive H3"), ("wg", "WireGuard"),
        ("awg2-fast", "AWG Fast"), ("awg2-strong", "AWG Strong"),
        ("ss-v2ray", "SS/V2Ray"), ("split", "Split"), ("max", "MAX"),
        ("wg-pq", "WG + PQ"), ("awg2-pq", "AWG + PQ"),
        ("max-tls-wg", "Complete MAX TLS / WG"),
        ("max-tls-awg", "Complete MAX TLS / AWG"),
        ("max-quic-wg", "Complete MAX QUIC / WG"),
        ("max-quic-awg", "Complete MAX QUIC / AWG"),
    ]
    static func id(at index: Int) -> String? {
        choices.indices.contains(index) ? choices[index].id : nil
    }
    static func index(for id: String) -> Int? { choices.firstIndex { $0.id == id } }
    static func require(index: Int) throws -> String {
        guard let value = id(at: index) else {
            throw NSError(domain: "RouterVPN.Multihop", code: 1, userInfo: [NSLocalizedDescriptionKey: "Select a supported exit transport."])
        }
        return value
    }
}

enum RouterVPNMultihopStartup {
    static func requestTimeout(entryMode: String, exitMode: String, execution: String) -> TimeInterval {
        guard execution == "auto" else { return 180 }
        let initialKeyModes = ["wg-pq", "awg2-pq", "max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"]
        // A blank entry delegates to the saved control profile. Its resolved
        // raw mode may own an initial-key phase; the controller captures it.
        let entry: TimeInterval = entryMode.isEmpty || initialKeyModes.contains(entryMode) ? 30 : 0
        let exit: TimeInterval = initialKeyModes.contains(exitMode) ? 30 : 0
        let alternatives: TimeInterval = exitMode == "auto" ? 2 : 1
        let phases = 4 * (alternatives * entry + exit)
        return phases == 0 ? 180 : 210 + phases
    }
}

func productDNSPolicyBody(captured: [String: Any]?, displayedProfileID: String, fields: [String: Any]) throws -> [String: Any] {
    guard let captured, !displayedProfileID.isEmpty,
          let profileID = captured["profile_id"] as? String, profileID == displayedProfileID,
          let token = captured["profile_token"] as? String, !token.isEmpty else {
        throw NSError(domain: "RouterVPN.DNS", code: 1, userInfo: [NSLocalizedDescriptionKey: "The selected node changed or DNS settings are not loaded. Refresh DNS before saving."])
    }
    guard let port = fields["port"] as? Int, (0...65535).contains(port) else {
        throw NSError(domain: "RouterVPN.DNS", code: 2, userInfo: [NSLocalizedDescriptionKey: "Enter a DNS port from 1 through 65535, or leave it empty for the selected transport default."])
    }
    var body: [String: Any] = ["profile_id": profileID, "profile_token": token]
    for key in ["mode", "protocol", "host", "port", "server_name", "path"] {
        if let value = fields[key] { body[key] = value }
    }
    return body
}

private final class ProductComparisonTransportDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

final class ProductAPI {
    fileprivate let connectionSelfTestRequests: ProductConnectionRequestReadback? =
        CommandLine.arguments.dropFirst().first == "--connection-self-test" ? ProductConnectionRequestReadback() : nil
    private let session: URLSession
    private let allowsRequests: Bool
    init(allowsRequests: Bool = true) {
        self.allowsRequests = allowsRequests
        let c = URLSessionConfiguration.ephemeral
        c.timeoutIntervalForRequest = 8
        // Ordinary transactions retain their shared resource ceiling;
        // each request and perform() still enforce their explicit deadline.
        c.timeoutIntervalForResource = 300
        c.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        c.connectionProxyDictionary = [:]
        session = URLSession(configuration: c, delegate: ProductComparisonTransportDelegate(), delegateQueue: nil)
    }
    func request(_ path: String, method: String = "GET", body: [String: Any]? = nil, timeout: TimeInterval = 15) throws -> Data {
        try validateTimeout(timeout)
        guard let url = URL(string: path, relativeTo: routerVPNProductBaseURL) else { throw NSError(domain: "RouterVPNMac", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid local API path"]) }
        var req = URLRequest(url: url); req.httpMethod = method; req.timeoutInterval = timeout; req.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        if let body { req.httpBody = try JSONSerialization.data(withJSONObject: body); req.setValue("application/json", forHTTPHeaderField: "Content-Type") }
        return try perform(req, timeout: timeout)
    }
    func requestRaw(_ path: String, body: Data, timeout: TimeInterval = 15) throws -> Data {
        try validateTimeout(timeout)
        guard let url = URL(string: path, relativeTo: routerVPNProductBaseURL) else { throw NSError(domain: "RouterVPNMac", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid local API path"]) }
        var req = URLRequest(url: url); req.httpMethod = "POST"; req.timeoutInterval = timeout; req.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData; req.httpBody = body
        req.setValue("application/json", forHTTPHeaderField: "Accept"); req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        return try perform(req, timeout: timeout)
    }
    private func validateTimeout(_ timeout: TimeInterval) throws {
        guard timeout.isFinite, timeout > 0, timeout <= 540 else {
            throw NSError(domain: "RouterVPNMac", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid local request deadline."])
        }
    }
    private func capturedComparisonSession(_ req: URLRequest, timeout: TimeInterval) throws -> URLSession? {
        guard timeout > 300 else { return nil }
        // URLRequest's timeout does not extend the shared 300-second resource
        // ceiling. Only an exact captured comparison owns a longer session.
        guard req.httpMethod == "POST", let bytes = req.httpBody,
              let body = (try? JSONSerialization.jsonObject(with: bytes)) as? [String: Any] else {
            throw NSError(domain: "RouterVPNMac", code: 1, userInfo: [NSLocalizedDescriptionKey: "The extended request deadline requires a captured comparison."])
        }
        if req.url == routerVPNProductBaseURL.appendingPathComponent("api/multihop/connect") {
            guard body["execution"] as? String == "auto",
                  let entryID = body["entry_id"] as? String, !entryID.isEmpty,
                  let exitID = body["exit_id"] as? String, !exitID.isEmpty, entryID != exitID,
                  let entryMode = body["entry_mode"] as? String, RouterVPNNodeEntryModes.index(for: entryMode) != nil,
                  let exitMode = body["exit_mode"] as? String, RouterVPNNodeExitModes.index(for: exitMode) != nil,
                  timeout == RouterVPNMultihopStartup.requestTimeout(entryMode: entryMode, exitMode: exitMode, execution: "auto") else {
                throw NSError(domain: "RouterVPNMac", code: 1, userInfo: [NSLocalizedDescriptionKey: "The multihop deadline does not match its captured graph."])
            }
        } else {
            guard timeout == 540, req.url == routerVPNProductBaseURL.appendingPathComponent("api/external-profile/connect"),
                  body["execution"] as? String == "auto", let id = body["profile_id"] as? String, !id.isEmpty,
                  body["expected_selected_node_id"] is String,
                  let tokens = body["expected_profile_tokens"] as? [String: String], tokens[id] != nil,
                  tokens.allSatisfy({ !$0.key.isEmpty && $0.value.utf8.count == 64 && $0.value.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) }),
                  let requestID = body["comparison_request_id"] as? String, requestID.utf8.count == 32,
                  requestID.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
                throw NSError(domain: "RouterVPNMac", code: 1, userInfo: [NSLocalizedDescriptionKey: "The extended request deadline requires a captured Tor comparison."])
            }
            if let direct = body["direct"] {
                guard let value = direct as? NSNumber, CFGetTypeID(value) == CFBooleanGetTypeID(), !value.boolValue else {
                    throw NSError(domain: "RouterVPNMac", code: 1, userInfo: [NSLocalizedDescriptionKey: "Tor comparison requires a captured Router entry."])
                }
            }
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = timeout
        configuration.timeoutIntervalForResource = timeout
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.connectionProxyDictionary = [:]
        configuration.httpShouldSetCookies = false
        configuration.urlCache = nil
        return URLSession(configuration: configuration, delegate: ProductComparisonTransportDelegate(), delegateQueue: nil)
    }
    private func perform(_ req: URLRequest, timeout: TimeInterval) throws -> Data {
        guard allowsRequests else {
            throw NSError(domain: "RouterVPNMac", code: 1, userInfo: [NSLocalizedDescriptionKey: "The layout self-test does not start a controller or make network requests."])
        }
        guard connectionSelfTestRequests?.permits(req) != false else { throw productConnectionCheckFailure() }
        guard MacProfileLoadTransaction.Store.standard.permitsRequest(req.httpMethod, path: req.url?.path ?? "") else {
            throw MacProfileLoadTransaction.issue("Finish or recover the pending connection profile Load before changing the VPN.")
        }
        var ownedRequest = req
        try RouterVPNMacLocalAuthorization.shared.authorize(&ownedRequest)
        let connectionRequest = connectionSelfTestRequests?.begin(ownedRequest)
        var connectionRequestSucceeded = false
        defer { connectionSelfTestRequests?.end(connectionRequest, succeeded: connectionRequestSucceeded) }
        let comparisonSession = try capturedComparisonSession(ownedRequest, timeout: timeout)
        let activeSession = comparisonSession ?? session
        defer { comparisonSession?.invalidateAndCancel() }
        let sem = DispatchSemaphore(value: 0); var data = Data(); var code = 0; var err: Error?
        let task = activeSession.dataTask(with: ownedRequest) { d, r, e in data = d ?? Data(); code = (r as? HTTPURLResponse)?.statusCode ?? 0; err = e; sem.signal() }
        task.resume()
        if sem.wait(timeout: .now() + timeout + 2) == .timedOut { task.cancel(); throw NSError(domain: "RouterVPNMac", code: 2, userInfo: [NSLocalizedDescriptionKey: "Local controller request timed out"]) }
        if let err { throw err }
        guard (200..<300).contains(code) else { let text = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines); throw NSError(domain: "RouterVPNMac", code: code, userInfo: [NSLocalizedDescriptionKey: (text?.isEmpty == false ? text! : "Local controller request failed")]) }
        connectionRequestSucceeded = true
        return data
    }
    func json(_ path: String, timeout: TimeInterval = 15) throws -> Any { try JSONSerialization.jsonObject(with: request(path, timeout: timeout)) }
    func ready() -> Bool { (try? request("/api/status", timeout: 1)) != nil }
}

final class RouterAnnotation: NSObject, MKAnnotation {
    let routerID: String
    let title: String?
    @objc dynamic var subtitle: String?
    let storedSubtitle: String?
    let coordinate: CLLocationCoordinate2D
    init(id: String, name: String, location: String, latency: Double, lat: Double, lon: Double) {
        routerID = id; title = name; storedSubtitle = [location, latency > 0 ? String(format: "median %.1f ms", latency) : ""].filter { !$0.isEmpty }.joined(separator: " • "); subtitle = storedSubtitle; coordinate = CLLocationCoordinate2D(latitude: lat, longitude: lon)
    }
}

private final class MultihopProgressTransportDelegate: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private static let limit = 32768
    private let lock = NSLock()
    private var active: URLSessionDataTask?
    private var response: URLResponse?
    private var received = Data()
    private var completion: ((Data?, URLResponse?, Error?) -> Void)?

    // Register before resume. One observer has one current task; a delayed
    // delegate callback from an earlier poll cannot clear its replacement.
    func capture(_ task: URLSessionDataTask, completion: @escaping (Data?, URLResponse?, Error?) -> Void) -> Bool {
        let expected = routerVPNProductBaseURL.appendingPathComponent("api/multihop/status")
        guard task.originalRequest?.url == expected, task.originalRequest?.httpMethod == "GET", task.state == .suspended else { return false }
        lock.lock(); defer { lock.unlock() }
        guard active == nil else { return false }
        active = task; response = nil; received.removeAll(keepingCapacity: false); self.completion = completion
        return true
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        lock.lock()
        guard active === dataTask else { lock.unlock(); completionHandler(.cancel); return }
        let expected = routerVPNProductBaseURL.appendingPathComponent("api/multihop/status")
        let valid = self.response == nil && (response as? HTTPURLResponse)?.statusCode == 200 && response.url == expected
        let oversized = response.expectedContentLength > Int64(Self.limit)
        if valid && !oversized { self.response = response }
        lock.unlock()
        completionHandler(valid && !oversized ? .allow : .cancel)
        if !valid || oversized { finish(dataTask, error: Self.rejected(), cancel: true) }
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive bytes: Data) {
        lock.lock()
        guard active === dataTask else { lock.unlock(); return }
        let oversized = bytes.count > Self.limit - received.count
        let valid = response != nil && !oversized
        if valid { received.append(bytes) }
        lock.unlock()
        if !valid { finish(dataTask, error: Self.rejected(), cancel: true) }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        finish(task, error: error, cancel: false)
    }

    func urlSession(_ session: URLSession, didBecomeInvalidWithError error: Error?) {
        lock.lock(); let task = active; lock.unlock()
        if let task { finish(task, error: error ?? URLError(.cancelled), cancel: true) }
    }

    private func finish(_ task: URLSessionTask, error: Error?, cancel: Bool) {
        lock.lock()
        guard let owned = active, owned === task else { lock.unlock(); return }
        let failure = error ?? (response == nil ? Self.rejected() : nil)
        let body = failure == nil ? received : nil
        let reply = response, callback = completion
        active = nil; response = nil; completion = nil; received.removeAll(keepingCapacity: false)
        lock.unlock()
        if cancel { owned.cancel() }
        callback?(body, reply, failure)
    }

    private static func rejected() -> NSError {
        NSError(domain: "RouterVPN.ComparisonProgress", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Local comparison progress exceeded its size or response bounds."])
    }
}

final class ProductWindowController: NSWindowController, MKMapViewDelegate {
    let api: ProductAPI
    var mtuPanel: RouterVPNMacMTUPanel?
    var dnsPanel: RouterVPNMacDNSPanel?
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
    let multihopEntryModePopup = NSPopUpButton(frame: .zero, pullsDown: false)
    let multihopExitPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    let multihopExitModePopup = NSPopUpButton(frame: .zero, pullsDown: false)
    let multihopExecutionPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    var multihopProgressTimer: Timer?
    var multihopProgressTask: URLSessionDataTask?
    var multihopProgressSession: URLSession?
    var multihopProgressGeneration = UUID()
    var multihopProgressDeadline = Date.distantPast
    var multihopProgressLastID = ""
    var multihopProgressOldID = ""
    var multihopProgressExpectedID: String?
    var multihopProgressUpdate: (([String: Any], String) -> Void)?
    let multihopComparisonLabel = NSTextField(wrappingLabelWithString: "Compare: (last-node response time + external-server response time) / 2; either timeout rejects the candidate.")
    let dnsModePopup = NSPopUpButton(frame: .zero, pullsDown: false)
    let dnsProtocolPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let dnsPresets: [(label: String, host: String, serverName: String)] = [
        ("Cloudflare IPv4", "1.1.1.1", "cloudflare-dns.com"),
        ("Cloudflare IPv4 secondary", "1.0.0.1", "cloudflare-dns.com"),
        ("Cloudflare IPv6", "2606:4700:4700::1111", "cloudflare-dns.com"),
        ("Cloudflare IPv6 secondary", "2606:4700:4700::1001", "cloudflare-dns.com"),
        ("Google IPv4", "8.8.8.8", "dns.google"),
        ("Google IPv4 secondary", "8.8.4.4", "dns.google"),
        ("Google IPv6", "2001:4860:4860::8888", "dns.google"),
        ("Google IPv6 secondary", "2001:4860:4860::8844", "dns.google"),
        ("Quad9 IPv4", "9.9.9.9", "dns.quad9.net"),
        ("Quad9 IPv4 secondary", "149.112.112.112", "dns.quad9.net"),
        ("Quad9 IPv6", "2620:fe::fe", "dns.quad9.net"),
        ("Quad9 IPv6 secondary", "2620:fe::9", "dns.quad9.net"),
    ]
    let dnsPresetPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    let dnsHostField = NSTextField(string: "")
    let dnsPortField = NSTextField(string: "53")
    let dnsServerNameField = NSTextField(string: "")
    let dnsPathField = NSTextField(string: "/dns-query")
    var dnsPolicyCapture: [String: Any]?
    var dnsPolicyGeneration = UUID()
    let map = MKMapView()
    var selfTestMapRenderingObserver: ((Bool) -> Void)?
    func mapViewDidFinishRenderingMap(_ mapView: MKMapView, fullyRendered: Bool) {
        guard mapView === map else { return }
        selfTestMapRenderingObserver?(fullyRendered)
    }
    let nodesText = NSTextView(); let modesText = NSTextView(); let dnsText = NSTextView(); let advancedText = NSTextView(); let settingsText = NSTextView(); let helpText = NSTextView()
    let forwardInput = NSTextView(); let forwardOutput = NSTextView()
    var routerIDs: [String] = []; var modeIDs: [String] = []; var profiles: [[String: Any]] = []; var eventSeq: UInt64 = 0; var timer: Timer?
    var multihopNodeIDs: [String] = []
    var multihopNodeTokens: [String: String] = [:]
    var savedConnectionProfileSelection: RouterVPNConnectionProfileSelection? {
        guard let bytes = UserDefaults.standard.data(forKey: MacProfileLoadTransaction.pathKey) else { return nil }
        return try? JSONDecoder().decode(RouterVPNConnectionProfileSelection.self, from: bytes)
    }
    var connectionProfileSelection: RouterVPNConnectionProfileSelection? {
        didSet {
            // A later explicit selection or catalog change supersedes a finished
            // Load. Never use a stale saved path on the next app launch.
            guard !MacProfileLoadTransaction.Store.standard.pending,
                  let saved = savedConnectionProfileSelection,
                  let current = connectionProfileSelection, current != saved else { return }
            UserDefaults.standard.removeObject(forKey: MacProfileLoadTransaction.pathKey)
        }
    }
    var connectionProfileSelectionGeneration = UUID()
    var connectionProfileNodesRequest = UUID()
    var connectionProfileHopsRequest = UUID()
    var connectionProfileCatalogSelectedID = ""
    let dnsModeIDs = ["home", "fastest", "custom", "dot", "doh", "doh3", "rescue"]
    let dnsProtocolIDs = ["udp", "tcp", "tls", "https", "h3"]

    init(api: ProductAPI) {
        self.api = api
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1180, height: 780), styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = "Router VPN"; window.minSize = NSSize(width: 980, height: 650); window.center()
        super.init(window: window); buildUI(); refreshAll(); timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in self?.refreshLive() }
        appendHelp("Install once; pair/import Router VPN or validated external node data separately. External protocol credentials remain only in the controller private store.")
    }
    required init?(coder: NSCoder) { nil }
    deinit { timer?.invalidate(); multihopProgressTimer?.invalidate(); multihopProgressTask?.cancel(); multihopProgressSession?.invalidateAndCancel() }

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
        right.addArrangedSubview(label("Node order")); nodeSortPopup.addItems(withTitles: ["Current / recent", "Last used", "Lowest latency", "Name", "Most used"]); nodeSortPopup.target = self; nodeSortPopup.action = #selector(nodeSortChanged); right.addArrangedSubview(nodeSortPopup)
        right.addArrangedSubview(button("Select lowest measured latency", #selector(selectLowestLatency)))
        right.addArrangedSubview(label("Selected node / external exit")); right.addArrangedSubview(nodePopup)
        right.addArrangedSubview(label("Optional external entry (Router VPN or supported external node)")); right.addArrangedSubview(externalEntryPopup)
        let row = NSStackView(); row.orientation = .horizontal; row.spacing = 6
        row.addArrangedSubview(button("Pair", #selector(pairNode))); row.addArrangedSubview(button("Import", #selector(importNode))); row.addArrangedSubview(button("Select", #selector(selectNode))); row.addArrangedSubview(button("External direct", #selector(connectExternalDirect))); row.addArrangedSubview(button("External via entry", #selector(connectExternalViaEntry))); row.addArrangedSubview(button("Remove", #selector(removeNode))); row.addArrangedSubview(button("50-sample latency", #selector(latencySelected)))
        right.addArrangedSubview(row); split.addArrangedSubview(right); split.setPosition(650, ofDividerAt: 0); return split
    }

    func dnsView() -> NSView {
        let s = NSStackView(); s.orientation = .vertical; s.spacing = 9; s.edgeInsets = NSEdgeInsets(top: 18, left: 18, bottom: 18, right: 18)
        let note = NSTextField(wrappingLabelWithString: "Choose Home, Fastest, Custom UDP/TCP, DoT, DoH, DoH3 or Rescue. Common IPv4/IPv6 resolver presets only fill fields. Disconnect before changing policy; reconnect and session DNS proof remain authoritative. DNS samples describe the path that measured them; saved results do not prove this connection."); note.textColor = .secondaryLabelColor; s.addArrangedSubview(note)
        dnsModePopup.addItems(withTitles: ["Home AdGuard", "Fastest measured", "Custom UDP/TCP", "DNS-over-TLS", "DNS-over-HTTPS", "DNS-over-HTTP/3", "DNS Rescue"])
        dnsProtocolPopup.addItems(withTitles: ["UDP", "TCP", "TLS", "HTTPS", "HTTP/3"])
        dnsPresetPopup.addItems(withTitles: ["Manual/current"] + dnsPresets.map { "\($0.label) — \($0.host)" }); dnsPresetPopup.target = self; dnsPresetPopup.action = #selector(dnsPresetChanged)
        dnsHostField.placeholderString = "resolver host / IPv4 / IPv6"; dnsPortField.placeholderString = "port"; dnsServerNameField.placeholderString = "TLS server name"; dnsPathField.placeholderString = "/dns-query"
        let grid = NSGridView(views: [[label("DNS mode"), dnsModePopup], [label("Home / Custom transport"), dnsProtocolPopup], [label("Common resolver"), dnsPresetPopup], [label("Host"), dnsHostField], [label("Port"), dnsPortField], [label("TLS server name"), dnsServerNameField], [label("HTTPS path"), dnsPathField]])
        grid.rowSpacing = 6; grid.columnSpacing = 10; s.addArrangedSubview(grid)
        let row = NSStackView(); row.orientation = .horizontal; row.spacing = 8; row.addArrangedSubview(button("Save DNS policy", #selector(saveDNS))); row.addArrangedSubview(button("Retest DNS", #selector(retestDNS))); row.addArrangedSubview(button("Refresh DNS", #selector(refreshAction))); s.addArrangedSubview(row)
        s.addArrangedSubview(scroll(dnsText)); return s
    }
    func advancedView() -> NSView {
        let s = NSStackView(); s.orientation = .vertical; s.spacing = 10; s.edgeInsets = NSEdgeInsets(top: 18, left: 18, bottom: 18, right: 18)
        let note = NSTextField(wrappingLabelWithString: "For an imported entry, select the paired final as the main node, choose Local and the entry's original protocol (or Use saved entry mode). Compatible SOCKS5, SS2022, Hysteria2 and HTTP(S) CONNECT entries use the paired final's DNS and identity. Unsupported graphs stay unavailable. MTU progress and cancellation belong to the connected path."); note.textColor = .secondaryLabelColor; s.addArrangedSubview(note)
        let selectors = NSStackView(); selectors.orientation = .horizontal; selectors.spacing = 8
        let entry = NSStackView(); entry.orientation = .vertical; entry.addArrangedSubview(label("Entry node")); entry.addArrangedSubview(multihopEntryPopup)
        let exit = NSStackView(); exit.orientation = .vertical; exit.addArrangedSubview(label("Exit node")); exit.addArrangedSubview(multihopExitPopup)
        let mode = NSStackView(); mode.orientation = .vertical; mode.addArrangedSubview(label("Exit transport")); multihopExitModePopup.addItems(withTitles: RouterVPNNodeExitModes.choices.map { $0.title }); multihopExitModePopup.selectItem(at: 0); mode.addArrangedSubview(multihopExitModePopup)
        selectors.addArrangedSubview(entry); selectors.addArrangedSubview(exit); selectors.addArrangedSubview(mode); s.addArrangedSubview(selectors)
        let entryTransport = NSStackView(); entryTransport.orientation = .horizontal; entryTransport.spacing = 8
        entryTransport.addArrangedSubview(label("Entry mode")); entryTransport.addArrangedSubview(multihopEntryModePopup); s.addArrangedSubview(entryTransport)
        configureMultihopExecution(); s.addArrangedSubview(multihopExecutionPopup); s.addArrangedSubview(multihopComparisonLabel)
        let row = NSStackView(); row.orientation = .horizontal; row.addArrangedSubview(button("Connect real multihop", #selector(connectMultihop))); row.addArrangedSubview(button("Refresh multihop readiness", #selector(refreshAdvancedAction))); row.addArrangedSubview(button("Retest MTU", #selector(retestMTU))); row.addArrangedSubview(button("Emergency stop", #selector(emergencyStop))); s.addArrangedSubview(row); s.addArrangedSubview(scroll(advancedText)); return s
    }
    func settingsView() -> NSView { let s = NSStackView(); s.orientation = .vertical; s.spacing = 10; s.edgeInsets = NSEdgeInsets(top: 18, left: 18, bottom: 18, right: 18); s.addArrangedSubview(scroll(settingsText)); return s }
    func helpView() -> NSView { let s = NSStackView(); s.orientation = .vertical; s.spacing = 10; s.edgeInsets = NSEdgeInsets(top: 18, left: 18, bottom: 18, right: 18); let row = NSStackView(); row.orientation = .horizontal; row.addArrangedSubview(button("Pair/add node", #selector(pairNode))); row.addArrangedSubview(button("Prove public VPN exit", #selector(publicExit))); row.addArrangedSubview(button("Emergency stop", #selector(emergencyStop))); row.addArrangedSubview(button("Refresh", #selector(refreshAction))); s.addArrangedSubview(row); s.addArrangedSubview(scroll(helpText)); return s }
    func forwardingView() -> NSView { let s = NSStackView(); s.orientation = .vertical; s.spacing = 8; s.edgeInsets = NSEdgeInsets(top: 18, left: 18, bottom: 18, right: 18); let note = NSTextField(wrappingLabelWithString: "Forwarding is sent only to the selected Router VPN node through its authenticated private router API. Enter the node-supported JSON rule payload; proxy-only modes cannot fake arbitrary DNAT."); note.textColor = .secondaryLabelColor; s.addArrangedSubview(note); forwardInput.isEditable = true; forwardInput.font = .monospacedSystemFont(ofSize: 12, weight: .regular); forwardInput.string = "{\n  \"enabled\": true\n}"; let inputScroll = NSScrollView(); inputScroll.hasVerticalScroller = true; inputScroll.documentView = forwardInput; inputScroll.heightAnchor.constraint(equalToConstant: 130).isActive = true; s.addArrangedSubview(inputScroll); let row = NSStackView(); row.orientation = .horizontal; row.addArrangedSubview(button("Apply forwarding payload", #selector(applyForward))); row.addArrangedSubview(button("Clear forwarding", #selector(clearForward))); s.addArrangedSubview(row); s.addArrangedSubview(scroll(forwardOutput)); return s }

    func stopMultihopProgress() {
        multihopProgressGeneration = UUID()
        multihopProgressExpectedID = nil; multihopProgressUpdate = nil
        multihopProgressDeadline = .distantPast
        multihopProgressTimer?.invalidate(); multihopProgressTimer = nil
        multihopProgressTask?.cancel(); multihopProgressTask = nil
        multihopProgressSession?.invalidateAndCancel(); multihopProgressSession = nil
    }
    func startMultihopProgress(timeout: TimeInterval = 180) {
        beginMultihopProgress(requestID: nil, timeout: timeout + 15, update: nil)
    }
    func startCapturedComparisonProgress(requestID: String?, timeout: TimeInterval, update: (([String: Any], String) -> Void)? = nil) -> UUID? {
        guard let requestID, requestID.utf8.count == 32,
              requestID.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              timeout.isFinite, timeout > 0, timeout <= 960 else { return nil }
        beginMultihopProgress(requestID: requestID, timeout: timeout, update: update)
        return multihopProgressGeneration
    }
    func stopCapturedComparisonProgress(_ owner: UUID?) {
        guard let owner, multihopProgressGeneration == owner else { return }
        stopMultihopProgress()
    }
    private func beginMultihopProgress(requestID: String?, timeout: TimeInterval, update: (([String: Any], String) -> Void)?) {
        stopMultihopProgress()
        multihopProgressOldID = multihopProgressLastID
        multihopProgressExpectedID = requestID; multihopProgressUpdate = update
        multihopProgressDeadline = Date().addingTimeInterval(timeout)
        let configuration = URLSessionConfiguration.ephemeral
        configuration.connectionProxyDictionary = [:]
        configuration.httpShouldSetCookies = false
        configuration.urlCache = nil
        configuration.timeoutIntervalForRequest = 2
        configuration.timeoutIntervalForResource = 2
        multihopProgressSession = URLSession(configuration: configuration, delegate: MultihopProgressTransportDelegate(), delegateQueue: nil)
        multihopProgressTimer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in self?.pollMultihopProgress() }
        pollMultihopProgress()
    }
    func pollMultihopProgress() {
        guard window?.isVisible == true, Date() < multihopProgressDeadline else { stopMultihopProgress(); return }
        guard multihopProgressTask == nil, let session = multihopProgressSession,
              let transport = session.delegate as? MultihopProgressTransportDelegate else { return }
        let generation = multihopProgressGeneration
        var request = URLRequest(url: routerVPNProductBaseURL.appendingPathComponent("api/multihop/status"))
        request.timeoutInterval = 2
        request.cachePolicy = .reloadIgnoringLocalCacheData
        do { try RouterVPNMacLocalAuthorization.shared.authorize(&request) }
        catch { stopCapturedComparisonProgress(generation); return }
        let task = session.dataTask(with: request)
        let captured = transport.capture(task) { [weak self] data, response, error in
            let status = (response as? HTTPURLResponse)?.statusCode
            let payload: [String: Any]? = error == nil && status == 200 && (data?.count ?? 32769) <= 32768 ?
                data.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] } : nil
            DispatchQueue.main.async {
                guard let self, self.multihopProgressGeneration == generation else { return }
                self.multihopProgressTask = nil
                guard self.window?.isVisible == true, Date() < self.multihopProgressDeadline else { self.stopCapturedComparisonProgress(generation); return }
                guard let payload, let comparison = payload["comparison"] as? [String: Any],
                      let id = comparison["id"] as? String, !id.isEmpty else { return }
                if let requestID = self.multihopProgressExpectedID {
                    guard comparison["request_id"] as? String == requestID,
                          comparison["last_node_measurement"] as? String == "tor-last-relay-http",
                          comparison["external_measurement"] as? String == "same-captured-endpoint-http" else { return }
                } else if id == self.multihopProgressOldID { return }
                let summary = self.multihopComparisonSummary(payload)
                self.multihopComparisonLabel.stringValue = summary
                self.multihopProgressUpdate?(payload, summary)
                if let complete = comparison["complete"] as? NSNumber, CFGetTypeID(complete) == CFBooleanGetTypeID(), complete.boolValue {
                    self.stopCapturedComparisonProgress(generation)
                }
            }
        }
        guard captured else { task.cancel(); return }
        multihopProgressTask = task
        task.resume()
    }
    func configureMultihopExecution() {
        if multihopEntryModePopup.numberOfItems == 0 {
            multihopEntryModePopup.addItems(withTitles: RouterVPNNodeEntryModes.choices.map { $0.title })
            multihopEntryModePopup.selectItem(at: 0)
        }
        multihopEntryModePopup.target = self
        multihopEntryModePopup.action = #selector(connectionProfileHopChanged)
        multihopEntryModePopup.toolTip = "Keep the saved entry mode or choose its complete transport. The entry base supplies the WG/AWG fallback when no mode was saved."
        multihopEntryPopup.target = self
        multihopEntryPopup.action = #selector(connectionProfileEntryChanged)
        multihopExitPopup.target = self
        multihopExitPopup.action = #selector(connectionProfileHopChanged)
        multihopExitModePopup.target = self
        multihopExitModePopup.action = #selector(connectionProfileHopChanged)
        if multihopExecutionPopup.numberOfItems == 0 {
            multihopExecutionPopup.addItems(withTitles: ["Local — exit runs on device", "Server — exit runs on entry node", "Compare both — lowest valid average"])
            let saved = UserDefaults.standard.string(forKey: "routervpn.multihop.execution.v1") ?? "auto"
            multihopExecutionPopup.selectItem(at: ["local", "server", "auto"].firstIndex(of: saved) ?? 2)
            multihopExecutionPopup.target = self
            multihopExecutionPopup.action = #selector(multihopExecutionChanged)
            multihopExecutionPopup.identifier = NSUserInterfaceItemIdentifier("multihop-execution")
        }
        multihopExecutionPopup.toolTip = "Server runs the exit tunnel on the entry node. Compare explicitly tests that trust model against the device-owned local tunnel."
        multihopComparisonLabel.textColor = .secondaryLabelColor
    }
    @objc func multihopExecutionChanged() {
        guard ensureMutationIdle("changing multihop execution") else { restoreOwnedConnectionProfileSelection(); return }
        UserDefaults.standard.set(multihopExecutionChoice(), forKey: "routervpn.multihop.execution.v1")
        recordVisibleConnectionProfileSelection()
    }
    func multihopExecutionChoice() -> String {
        let index = multihopExecutionPopup.indexOfSelectedItem
        return (0..<3).contains(index) ? ["local", "server", "auto"][index] : "local"
    }
    func multihopComparisonSummary(_ status: [String: Any]) -> String {
        multihopProgressLastID = (status["comparison"] as? [String: Any])?["id"] as? String ?? ""
        guard let comparison = status["comparison"] as? [String: Any] else {
            return "Compare: (last-node response time + external-server response time) / 2; either timeout rejects the candidate."
        }
        var lines = ["Execution: \(status["execution"] as? String ?? "none") • \(comparison["stage"] as? String ?? "starting")"]
        if comparison["last_node_measurement"] as? String == "tor-last-relay-http",
           comparison["external_measurement"] as? String == "same-captured-endpoint-http" {
            lines.append("Tor response times: (last-relay HTTP + the same external-server HTTP response) / 2. A timeout or invalid proof excludes that candidate.")
        }
        for item in comparison["measurements"] as? [[String: Any]] ?? [] {
            let candidate = item["candidate"] as? [String: Any] ?? [:]
            let name = "\(candidate["execution"] as? String ?? "") / \(candidate["transport"] as? String ?? "")"
            if item["eligible"] as? Bool == true,
               let last = item["last_node_ms"] as? Double, let external = item["external_ms"] as? Double, let score = item["score_ms"] as? Double, last.isFinite, external.isFinite, score.isFinite, last > 0, external > 0, score > 0 {
                lines.append(String(format: "%@: (%.1f + %.1f) / 2 = %.1f ms", name, last, external, score))
            } else { lines.append("\(name): rejected — \(item["failure"] as? String ?? "probe failed")") }
        }
        if let failure = comparison["failure"] as? String, !failure.isEmpty { lines.append(failure) }
        return lines.joined(separator: "\n")
    }
    func asyncAction(_ work: @escaping () throws -> String) { DispatchQueue.global(qos: .userInitiated).async { [weak self] in guard let self else { return }; do { let message = try work(); DispatchQueue.main.async { self.appendHelp(message); self.refreshAll() } } catch { DispatchQueue.main.async { self.errorLabel.stringValue = error.localizedDescription; self.appendHelp("ERROR: \(error.localizedDescription)"); self.refreshLive() } } } }
    @objc func autoConnect() { asyncAction { String(data: try self.api.request("/api/auto", method: "POST", body: [:], timeout: 150), encoding: .utf8) ?? "AUTO connected" } }
    @objc func connectSelected() { let i = modePopup.indexOfSelectedItem; guard i >= 0 && i < modeIDs.count else { return }; let mode = modeIDs[i]; let base = ["auto", "wg", "awg"][max(0, min(basePopup.indexOfSelectedItem, 2))]; asyncAction { String(data: try self.api.request("/api/connect-logical", method: "POST", body: ["mode": mode, "base": base], timeout: 180), encoding: .utf8) ?? "Connected" } }
    @objc func connectMultihop() {
        do { try requireResolvedConnectionProfileSelection() } catch { appendHelp(error.localizedDescription); return }
        if connectOrderedMultihopIfSelected() { return }
        let ei = multihopEntryPopup.indexOfSelectedItem; let xi = multihopExitPopup.indexOfSelectedItem
        guard ei >= 0, xi >= 0, ei < multihopNodeIDs.count, xi < multihopNodeIDs.count else { appendHelp("Choose both multihop nodes."); return }
        let entryID = multihopNodeIDs[ei], exitID = multihopNodeIDs[xi]
        guard entryID != exitID else { appendHelp("Multihop entry and exit nodes must be different."); return }
        guard let entryMode = RouterVPNNodeEntryModes.id(at: multihopEntryModePopup.indexOfSelectedItem) else { appendHelp("Select a supported entry mode."); return }
        guard let exitMode = RouterVPNNodeExitModes.id(at: multihopExitModePopup.indexOfSelectedItem) else { appendHelp("Select a supported exit transport."); return }
        let execution = multihopExecutionChoice()
        let base = multihopBaseChoice()
        let timeout = RouterVPNMultihopStartup.requestTimeout(entryMode: entryMode, exitMode: exitMode, execution: execution)
        multihopComparisonLabel.stringValue = execution == "auto" ? "Comparing local and server paths; timed-out probes are excluded…" : "Starting \(execution) multihop…"
        startMultihopProgress(timeout: timeout); let progressOwner = multihopProgressGeneration
        asyncAction { defer { DispatchQueue.main.async { self.stopCapturedComparisonProgress(progressOwner) } }; return String(data: try self.api.request("/api/multihop/connect", method: "POST", body: ["entry_id": entryID, "exit_id": exitID, "base": base, "entry_mode": entryMode, "exit_mode": exitMode, "execution": execution], timeout: timeout), encoding: .utf8) ?? "Multihop connected" }
    }
    func multihopBaseChoice() -> String { ["auto", "wg", "awg"][max(0, min(basePopup.indexOfSelectedItem, 2))] }
    func selectedNodeID() -> String? {
        if let a = map.selectedAnnotations.first as? RouterAnnotation { return a.routerID }
        let i = nodePopup.indexOfSelectedItem
        guard i >= 0 && i < routerIDs.count else { return nil }
        return routerIDs[i]
    }
    @objc func connectExternalDirect() {
        guard let exitID = selectedNodeID() else { appendHelp("Select an external exit node first."); return }
        asyncAction { String(data: try self.api.request("/api/external-profile/connect", method: "POST", body: ["profile_id": exitID, "direct": true, "execution": "local"], timeout: 180), encoding: .utf8) ?? "External exit connected" }
    }
    @objc func connectExternalViaEntry() {
        guard let exitID = selectedNodeID() else { appendHelp("Select an external exit node first."); return }
        showExternalPath(profileID: exitID, requireEntry: true)
    }
    @objc func disconnect() { asyncAction { _ = try self.api.request("/api/disconnect", method: "POST", body: [:], timeout: 20); return "Disconnected." } }
    @objc func publicExit() { asyncAction { String(data: try self.api.request("/api/public-ip", timeout: 20), encoding: .utf8) ?? "" } }
    @objc func retestDNS() {
        guard let selected = routerPopup.selectedItem?.representedObject as? String,
              let profile = profiles.first(where: { $0["id"] as? String == selected }) else {
            appendHelp("Select the connected node before DNS Retest."); return
        }
        if (profile["node_kind"] as? String ?? "router-vpn") == "external" {
            showDNSMeasurement(profileID: selected); return
        }
        asyncAction { String(data: try self.api.request("/api/dns/retest", method: "POST", body: [:], timeout: 90), encoding: .utf8) ?? "Home-node DNS query Retest completed" }
    }
    @objc func saveDNS() {
        let displayedID = routerPopup.selectedItem?.representedObject as? String ?? ""
        let captured = dnsPolicyCapture
        let modeIndex = max(0, min(dnsModePopup.indexOfSelectedItem, dnsModeIDs.count - 1))
        let protocolIndex = max(0, min(dnsProtocolPopup.indexOfSelectedItem, dnsProtocolIDs.count - 1))
        let portText = dnsPortField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        do {
            guard let port = portText.isEmpty ? 0 : Int(portText) else {
                throw NSError(domain: "RouterVPN.DNS", code: 2, userInfo: [NSLocalizedDescriptionKey: "Enter a valid numeric DNS port."])
            }
            let fields: [String: Any] = ["mode": dnsModeIDs[modeIndex], "protocol": dnsProtocolIDs[protocolIndex], "host": dnsHostField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines), "port": port, "server_name": dnsServerNameField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines), "path": dnsPathField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)]
            let body = try productDNSPolicyBody(captured: captured, displayedProfileID: displayedID, fields: fields)
            asyncAction { String(data: try self.api.request("/api/dns/policy", method: "POST", body: body, timeout: 10), encoding: .utf8) ?? "DNS policy saved for the next connection" }
        } catch { errorLabel.stringValue = error.localizedDescription; appendHelp("DNS policy failed: \(error.localizedDescription)") }
    }
    @objc func dnsPresetChanged() {
        let index = dnsPresetPopup.indexOfSelectedItem - 1
        guard dnsPresets.indices.contains(index) else { return }
        dnsHostField.stringValue = dnsPresets[index].host
        dnsServerNameField.stringValue = dnsPresets[index].serverName
    }
    @objc func retestMTU() { showMTUPanel(retest: true) }
    @objc func emergencyStop() {
        let mutation = beginLiveHTTPSMutation()
        DispatchQueue.global(qos: .userInitiated).async {
            let message: String
            let confirmed: Bool
            do {
                let data = try self.api.request("/api/emergency-stop", method: "POST", body: [:], timeout: 20)
                let receipt = try JSONSerialization.jsonObject(with: data) as? [String: Any]
                confirmed = receipt?["ok"] as? Bool == true
                message = confirmed ? "Local Router VPN transports stopped." : "The controller did not confirm the stop."
            } catch {
                confirmed = false
                message = error.localizedDescription
            }
            DispatchQueue.main.async {
                self.endLiveHTTPSMutation(mutation)
                self.appendHelp(message)
                self.refreshAll()
                guard let window = self.window else { return }
                let alert = NSAlert()
                alert.alertStyle = confirmed ? .informational : .warning
                alert.messageText = confirmed ? "Emergency Stop completed" : "Emergency Stop was not confirmed"
                alert.informativeText = message
                alert.beginSheetModal(for: window, completionHandler: nil)
            }
        }
    }
    @objc func refreshAction() { refreshAll() }
    @objc func refreshAdvancedAction() { refreshAdvanced() }
    @objc func nodeSortChanged() { refreshProfiles(order: ["current", "last-used", "latency", "name", "most-used"][max(0, min(nodeSortPopup.indexOfSelectedItem, 4))]) }
    @objc func selectLowestLatency() {
        asyncAction {
            guard let result = try JSONSerialization.jsonObject(with: self.api.request("/api/profile/lowest-saved-latency", method: "POST", body: [:], timeout: 10)) as? [String: Any] else {
                return "Saved lowest-latency selection was not confirmed."
            }
            DispatchQueue.main.async { self.nodeSortPopup.selectItem(at: 2) }
            return result["note"] as? String ?? "Selected the lowest saved trimmed mean. Use Fastest to measure current conditions."
        }
    }
    @objc func selectRouter() { let i = routerPopup.indexOfSelectedItem; guard i >= 0 && i < routerIDs.count else { return }; let id = routerIDs[i]; recordConnectionProfileNodeChoice(id); asyncAction { _ = try self.api.request("/api/profile/select", method: "POST", body: ["id": id], timeout: 10); return "Selected router \(id)" } }
    @objc func selectNode() { guard let id = selectedNodeID() else { appendHelp("Select a linked node first."); return }; recordConnectionProfileNodeChoice(id); asyncAction { _ = try self.api.request("/api/profile/select", method: "POST", body: ["id": id], timeout: 10); return "Selected node \(id)" } }
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

    func refreshAll() {
        do { try recoverCoordinatedProfileLoad() }
        catch { errorLabel.stringValue = error.localizedDescription; refreshStatus(); return }
        if connectionProfileSelection == nil, let saved = savedConnectionProfileSelection {
            connectionProfileSelection = saved
            // The next refresh reads the controls to capture its original path.
            restoreOwnedConnectionProfileSelection(persistPreferences: false)
        }
        refreshProfiles(); refreshModes(); refreshLive()
    }
    func refreshLive() { refreshStatus(); refreshSessionEvents() }
    func refreshStatus() { DispatchQueue.global(qos: .utility).async { [weak self] in guard let self else { return }; do { guard let o = try api.json("/api/status") as? [String: Any] else { return }; DispatchQueue.main.async { let connected = o["connected"] as? Bool ?? false; let phase = o["phase"] as? String ?? "off"; self.statusLabel.stringValue = productConnectionStatusLabel(connected: connected, phase: phase); self.statusLabel.textColor = connected ? .systemGreen : (phase == "failed" ? .systemRed : .secondaryLabelColor); self.detailLabel.stringValue = "Logical: \(o["logical_mode"] as? String ?? "—")   Runtime: \((o["runtime_mode"] as? String) ?? (o["mode"] as? String) ?? "—")   Base: \(o["base"] as? String ?? "—")   Router: \(o["router_id"] as? String ?? "—")"; self.errorLabel.stringValue = o["last_error"] as? String ?? "" } } catch { DispatchQueue.main.async { self.statusLabel.stringValue = "● Controller unavailable"; self.statusLabel.textColor = .systemRed; self.errorLabel.stringValue = error.localizedDescription } } } }
    func refreshSessionEvents() { let after = eventSeq; DispatchQueue.global(qos: .utility).async { [weak self] in guard let self else { return }; do { guard let o = try api.json("/api/session/events?after=\(after)") as? [String: Any] else { return }; let events = o["events"] as? [[String: Any]] ?? []; let last = (o["last_event_seq"] as? NSNumber)?.uint64Value ?? after; DispatchQueue.main.async { for e in events { let seq = (e["seq"] as? NSNumber)?.uint64Value ?? 0; guard seq > self.eventSeq else { continue }; var parts: [String] = [e["phase"] as? String ?? ""]; if let r = e["runtime_mode"] as? String, !r.isEmpty { parts.append("runtime=\(r)") }; if let b = e["base"] as? String, !b.isEmpty { parts.append("base=\(b)") }; if let m = e["message"] as? String, !m.isEmpty { parts.append(m) }; self.appendHelp("Session #\(seq) \(e["type"] as? String ?? "event"): " + parts.filter { !$0.isEmpty }.joined(separator: " | ")); self.eventSeq = seq }; self.eventSeq = max(self.eventSeq, last) } } catch { } } }
    func refreshProfiles() { refreshProfiles(order: ["current", "last-used", "latency", "name", "most-used"][max(0, min(nodeSortPopup.indexOfSelectedItem, 4))]) }
    func refreshProfiles(order: String) {
        let capture = beginConnectionProfileRefresh(hops: false)
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            do {
                guard let payload = try self.api.json("/api/nodes?sort=\(order)") as? [String: Any] else { return }
                DispatchQueue.main.async {
                    do {
                        guard try self.applyConnectionProfileNodeCatalog(payload, capture: capture) else { return }
                        // Hop refresh starts only after its selected-node catalog
                        // has been accepted; parallel initial catalogs must not
                        // invalidate one another's empty initial selection.
                        self.refreshAdvanced()
                    } catch {
                        if self.ownsConnectionProfileRefresh(capture, hops: false) { self.errorLabel.stringValue = error.localizedDescription }
                    }
                }
            } catch {
                DispatchQueue.main.async {
                    if self.ownsConnectionProfileRefresh(capture, hops: false) { self.errorLabel.stringValue = error.localizedDescription }
                }
            }
        }
    }
    func renderProfiles(selected: String) {
        nodesText.string = profiles.map { p in let name = p["name"] as? String ?? p["id"] as? String ?? "Router"; let loc = p["location"] as? String ?? ""; let endpoint = p["endpoint"] as? String ?? "—"; let kind = p["node_kind"] as? String ?? "router-vpn"; let median = (p["latency_median_ms"] as? NSNumber)?.doubleValue ?? 0; let lastUsed = p["last_used_at"] as? String ?? ""; return "\((p["id"] as? String) == selected ? "●" : "○") [\(kind)] \(name) \(loc)\n  endpoint: \(endpoint)\n  median: \(median > 0 ? String(format: "%.1f ms", median) : "not measured")\n  last used: \(lastUsed.isEmpty ? "never" : lastUsed)" }.joined(separator: "\n\n")
        settingsText.string = profiles.map { p in let name = p["name"] as? String ?? "Router"; let mtu = (p["effective_mtu"] as? NSNumber)?.intValue ?? 0; let source = p["effective_mtu_source"] as? String ?? "default"; let mbps = (p["effective_mtu_mbps"] as? NSNumber)?.doubleValue ?? 0; let rtt = (p["effective_mtu_median_rtt_ms"] as? NSNumber)?.doubleValue ?? 0; let success = (p["effective_mtu_success_ratio"] as? NSNumber)?.doubleValue ?? 0; let perf = mbps > 0 ? String(format: "  Retest performance=%.1f Mbps median RTT=%.2f ms success=%.1f%%\n", mbps, rtt, success * 100.0) : ""; return "\(name)\n  base=\(p["base_tunnel"] as? String ?? "auto") DNS=\(p["dns_mode"] as? String ?? "home")/\(p["dns_protocol"] as? String ?? "udp")\n  kill-switch=\(p["kill_switch_policy"] as? String ?? "off") LAN=\((p["home_lan_access"] as? Bool ?? false) ? "on" : "off") MTU=\(mtu > 0 ? String(mtu) : "default") source=\(source)\n\(perf)  tested=\(p["effective_mtu_tested_at"] as? String ?? "not retested")" }.joined(separator: "\n\n")
        refreshDNSPolicy(selected: selected)
        renderMap()
    }
    func refreshDNSPolicy(selected: String) {
        let generation = UUID(); dnsPolicyGeneration = generation; dnsPolicyCapture = nil
        dnsHostField.stringValue = ""; dnsPortField.stringValue = ""; dnsServerNameField.stringValue = ""; dnsPathField.stringValue = ""
        guard !selected.isEmpty else { dnsText.string = "Select a node to load DNS settings."; return }
        dnsText.string = "Loading DNS settings for \(selected)…"
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            do {
                guard let policy = try self.api.json("/api/dns/policy") as? [String: Any],
                      policy["profile_id"] as? String == selected,
                      let token = policy["profile_token"] as? String, !token.isEmpty else {
                    throw NSError(domain: "RouterVPN.DNS", code: 1, userInfo: [NSLocalizedDescriptionKey: "The selected node changed while DNS settings loaded. Refresh DNS."])
                }
                DispatchQueue.main.async {
                    guard self.dnsPolicyGeneration == generation,
                          self.routerPopup.selectedItem?.representedObject as? String == selected else { return }
                    let mode = policy["mode"] as? String ?? "home", proto = policy["protocol"] as? String ?? "udp"
                    if let i = self.dnsModeIDs.firstIndex(of: mode) { self.dnsModePopup.selectItem(at: i) }
                    if let i = self.dnsProtocolIDs.firstIndex(of: proto) { self.dnsProtocolPopup.selectItem(at: i) }
                    self.dnsPresetPopup.selectItem(at: 0)
                    self.dnsHostField.stringValue = policy["host"] as? String ?? ""
                    self.dnsPortField.stringValue = String((policy["port"] as? NSNumber)?.intValue ?? 0)
                    self.dnsServerNameField.stringValue = policy["server_name"] as? String ?? ""
                    self.dnsPathField.stringValue = policy["path"] as? String ?? ""
                    var lines = ["Node: \(selected)", "Selected DNS: \(mode) \(proto) \(self.dnsHostField.stringValue):\(self.dnsPortField.stringValue)"]
                    if let fastest = policy["fastest_dns_host"] as? String, !fastest.isEmpty {
                        lines.append("Fastest measured: \(policy["fastest_dns_name"] as? String ?? fastest) • \((policy["fastest_dns_latency_ms"] as? NSNumber)?.doubleValue ?? 0) ms • \(fastest)")
                    }
                    for result in policy["results"] as? [[String: Any]] ?? [] {
                        let working = result["working"] as? Bool ?? false
                        let timing = working ? String(format: "%.2f ms", (result["latency_ms"] as? NSNumber)?.doubleValue ?? 0) : "failed"
                        lines.append("\(result["name"] as? String ?? "Resolver") • \(result["address"] as? String ?? "") • \(timing)")
                    }
                    lines.append(policy["note"] as? String ?? "The next connection must prove the selected DNS policy.")
                    self.dnsText.string = lines.joined(separator: "\n"); self.dnsPolicyCapture = policy
                }
            } catch {
                DispatchQueue.main.async {
                    guard self.dnsPolicyGeneration == generation,
                          self.routerPopup.selectedItem?.representedObject as? String == selected else { return }
                    self.dnsText.string = "DNS policy unavailable: \(error.localizedDescription)"; self.dnsPolicyCapture = nil
                }
            }
        }
    }
    func renderMap() { map.removeAnnotations(map.annotations); var annotations: [RouterAnnotation] = []; for p in profiles { let lat = (p["latitude"] as? NSNumber)?.doubleValue ?? 0; let lon = (p["longitude"] as? NSNumber)?.doubleValue ?? 0; guard CLLocationCoordinate2DIsValid(CLLocationCoordinate2D(latitude: lat, longitude: lon)), !(lat == 0 && lon == 0) else { continue }; annotations.append(RouterAnnotation(id: p["id"] as? String ?? "", name: p["name"] as? String ?? "Router", location: p["location"] as? String ?? "", latency: (p["latency_median_ms"] as? NSNumber)?.doubleValue ?? 0, lat: lat, lon: lon)) }; map.addAnnotations(annotations); if !annotations.isEmpty { map.showAnnotations(annotations, animated: false) } }
    func refreshModes() { DispatchQueue.global(qos: .utility).async { [weak self] in guard let self else { return }; do { guard let modes = try api.json("/api/logical-modes", timeout: 12) as? [[String: Any]] else { return }; let ready = modes.filter { $0["available"] as? Bool == true }; DispatchQueue.main.async { self.modeIDs = ready.compactMap { $0["id"] as? String }; self.modePopup.removeAllItems(); self.modePopup.addItems(withTitles: ready.map { $0["name"] as? String ?? $0["id"] as? String ?? "Mode" }); self.modesText.string = modes.map { mode in var layerSet = Set<String>(); if let variants = mode["variants"] as? [String: Any] { for value in variants.values { if let variant = value as? [String: Any], let raw = variant["mode"] as? [String: Any], let layers = raw["layers"] as? [String] { for layer in layers { if !layer.isEmpty { layerSet.insert(layer) } } } } }; let layers = layerSet.sorted().isEmpty ? "—" : layerSet.sorted().joined(separator: " • "); let pingMin=(mode["ping_min_ms"] as? NSNumber)?.doubleValue ?? 0, pingMax=(mode["ping_max_ms"] as? NSNumber)?.doubleValue ?? 0, trafficMin=(mode["traffic_min_pct"] as? NSNumber)?.doubleValue ?? 0, trafficMax=(mode["traffic_max_pct"] as? NSNumber)?.doubleValue ?? 0, speedMin=(mode["speed_loss_min_pct"] as? NSNumber)?.doubleValue ?? 0, speedMax=(mode["speed_loss_max_pct"] as? NSNumber)?.doubleValue ?? 0; let available=mode["available"] as? Bool ?? false; let bases=(mode["ready_bases"] as? [String] ?? []).joined(separator: ", "); let reason=(mode["reason"] as? String ?? "").isEmpty ? (available ? "selected variant is runnable; final Connected still requires selected-path proof" : "no runnable variant") : (mode["reason"] as? String ?? ""); return "\(available ? "✓" : "—") \(mode["name"] as? String ?? "Mode")\n  \(mode["description"] as? String ?? "")\n  layers: \(layers)\n  added latency \(String(format: "%.1f–%.1f ms", pingMin,pingMax)) • traffic \(String(format: "+%.1f–%.1f%%",trafficMin,trafficMax)) • speed loss \(String(format: "%.1f–%.1f%%",speedMin,speedMax))\n  readiness: \(available ? "Ready" : "Unavailable")\(bases.isEmpty ? "" : " • bases: \(bases)")\n  reason: \(reason)" }.joined(separator: "\n\n") } } catch { } } }
    func refreshAdvanced() {
        let capture = beginConnectionProfileRefresh(hops: true)
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            do {
                let data = try self.api.request("/api/multihop/status", timeout: 10)
                guard let payload = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }
                let prettyData = try JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys])
                let pretty = String(data: prettyData, encoding: .utf8) ?? ""
                DispatchQueue.main.async {
                    do {
                        guard try self.applyConnectionProfileHopCatalog(payload, capture: capture) else { return }
                        self.multihopComparisonLabel.stringValue = self.multihopComparisonSummary(payload)
                        self.advancedText.string = "Multihop status and proof:\n\(pretty)\n\nMTU Retest opens the captured-path progress panel. Auto status, reported candidate measurements, effective MTU and cancellation remain tied to that connection until rollback and the owned request finish. Strict kill switch is applied before the full-device TUN starts. External direct/entry→exit uses the separate validated external profile path and exact expected public-exit proof."
                    } catch {
                        if self.ownsConnectionProfileRefresh(capture, hops: true) { self.advancedText.string = "Advanced status unavailable: \(error.localizedDescription)" }
                    }
                }
            } catch {
                DispatchQueue.main.async {
                    if self.ownsConnectionProfileRefresh(capture, hops: true) { self.advancedText.string = "Advanced status unavailable: \(error.localizedDescription)" }
                }
            }
        }
    }
    func appendHelp(_ message: String) { let f = DateFormatter(); f.dateFormat = "HH:mm:ss"; helpText.textStorage?.append(NSAttributedString(string: "[\(f.string(from: Date()))] \(message.trimmingCharacters(in: .whitespacesAndNewlines))\n")); helpText.scrollToEndOfDocument(nil) }
}

@MainActor final class ProductDelegate: NSObject, NSApplicationDelegate {
    let api = ProductAPI(); var wc: ProductWindowController?; var controller: RouterVPNMacShutdownProcess?; var ownsController = false
    var installedController: RouterVPNMacOwnedProcess?
    var controllerOwnerToken = ""
    var shutdown: RouterVPNMacShutdownController?
    var shutdownPanel: RouterVPNMacShutdownPanel?
    private var terminationReplyPending = false
    func applicationDidFinishLaunching(_ notification: Notification) { NSApp.setActivationPolicy(.regular); do { try ensureController(); let w = ProductWindowController(api: api); wc = w; w.showWindow(nil); w.window?.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true) } catch { let a = NSAlert(); a.alertStyle = .critical; a.messageText = "Router VPN could not start"; a.informativeText = error.localizedDescription; a.runModal(); NSApp.terminate(nil) } }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard ownsController else { return .terminateNow }
        guard let process = controller else { return .terminateCancel }
        installedController?.retireBeforeReady()
        if terminationReplyPending { return .terminateLater }
        let identity = RouterVPNMacShutdownIdentity(processID: process.processIdentifier, token: controllerOwnerToken)
        if let previous = shutdown, previous.process !== process || previous.identity != identity {
            previous.retire(); shutdown = nil
        }
        let flow: RouterVPNMacShutdownController
        if let existing = shutdown { flow = existing }
        else {
            flow = RouterVPNMacShutdownController(baseURL: routerVPNProductBaseURL, identity: identity, process: process,
                isCurrent: { [weak self, weak process] in
                    guard let self, let process else { return false }
                    return self.ownsController && self.controller === process && self.controllerOwnerToken == identity.token
                })
            shutdown = flow
        }
        if shutdownPanel == nil { shutdownPanel = RouterVPNMacShutdownPanel() }
        shutdownPanel?.onRetry = { [weak sender] in sender?.terminate(nil) }
        flow.onUpdate = { [weak self, weak flow] in
            guard let self, let flow, self.shutdown === flow else { return }
            self.shutdownPanel?.present(flow)
        }
        flow.onFinish = { [weak self, weak sender, weak flow] allowed in
            guard let self, let flow, self.shutdown === flow, self.terminationReplyPending else { return }
            self.terminationReplyPending = false
            sender?.reply(toApplicationShouldTerminate: allowed)
        }
        terminationReplyPending = true
        flow.start()
        return .terminateLater
    }
    func applicationWillTerminate(_ notification: Notification) {
        // The terminateLater callback already required the checked receipt and
        // this exact Process exit. No signal or emergency timeout belongs here.
    }
    func ensureController() throws {
        if RouterVPNMacLocalAuthorization.installedBundle() {
            let owned = try RouterVPNMacOwnedProcess.launch()
            installedController = owned; controller = owned; controllerOwnerToken = owned.credentials.ownerToken; ownsController = true
            try RouterVPNMacLocalAuthorization.shared.capture(owned.credentials, processID: owned.processIdentifier,
                live: { [weak owned] in owned?.acceptsRequests == true })
            let deadline = Date().addingTimeInterval(12)
            while Date() < deadline, owned.acceptsRequests {
                do {
                    try RouterVPNMacLocalAuthorization.shared.verifyIdentity()
                    if api.ready() { try owned.markReady(); return }
                } catch { /* Retry only this captured process and fresh challenge. */ }
                Thread.sleep(forTimeInterval: 0.2)
            }
            owned.retireBeforeReady()
            throw RouterVPNMacLocalAuthorization.failure("The captured installed controller did not prove readiness. Router VPN has canceled this launch and will wait for its authenticated cleanup and process join.")
        }
        if api.ready() { return }
        let root = Bundle.main.bundleURL.deletingLastPathComponent()
        let binary = root.appendingPathComponent("router-vpn-client")
        let config = root.appendingPathComponent("client.json")
        guard FileManager.default.isExecutableFile(atPath: binary.path), FileManager.default.fileExists(atPath: config.path) else {
            throw NSError(domain: "RouterVPNMac", code: 10, userInfo: [NSLocalizedDescriptionKey: "RouterVPN.app must stay beside router-vpn-client and client.json in its package."])
        }
        let token = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        let process = Process(); process.executableURL = binary; process.currentDirectoryURL = root
        var environment = ProcessInfo.processInfo.environment
        environment["HOMEVPN_ROOT"] = root.path; environment["HOMEVPN_CLIENT_CONFIG"] = config.path
        environment["HOMEVPN_NATIVE_APP"] = "macos-appkit-product"; environment["HOMEVPN_CONTROLLER_OWNER"] = token
        process.environment = environment
        process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
        try process.run()
        controller = process; controllerOwnerToken = token; ownsController = true
        let deadline = Date().addingTimeInterval(12)
        while Date() < deadline {
            if !process.isRunning { break }
            if api.ready() { return }
            Thread.sleep(forTimeInterval: 0.2)
        }
        // A slow startup may already own native resources. The termination
        // callback uses the same checked shutdown protocol instead of killing it.
        throw NSError(domain: "RouterVPNMac", code: 11, userInfo: [NSLocalizedDescriptionKey: "Local Router VPN controller did not become ready on 127.0.0.1:8788. Router VPN will wait for checked cleanup before closing."])
    }
}

@MainActor func runProductSelfTest() -> Int32 {
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    app.finishLaunching()
    let owner = ProductWindowController(api: ProductAPI(allowsRequests: false))
    guard let window = owner.window, let content = window.contentView else { return 2 }
    defer { owner.timer?.invalidate(); window.close() }
    window.orderFront(nil)
    func writeEvidence(_ size: NSSize, failure: Bool = false) -> Bool {
        guard let directory = ProcessInfo.processInfo.environment["ROUTERVPN_UI_EVIDENCE_DIR"] else { return true }
        do {
            content.layoutSubtreeIfNeeded()
            window.displayIfNeeded()
            let output = URL(fileURLWithPath: directory, isDirectory: true)
            try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
            let number = window.windowNumber, originalFrame = window.frame, originalBounds = content.bounds
            let originalScale = window.backingScaleFactor
            guard number > 0 else { print("macOS compositor capture: original window number unavailable"); return false }
            func windowRecord() -> NSDictionary? {
                guard window.contentView === content, content.window === window, owner.map.window === window,
                      window.isVisible, !window.isMiniaturized, window.windowNumber == number,
                      window.frame == originalFrame, content.bounds == originalBounds,
                      window.backingScaleFactor == originalScale,
                      let rows = CGWindowListCopyWindowInfo(.optionIncludingWindow, CGWindowID(number)) as? [[String: Any]],
                      rows.count == 1, let row = rows.first,
                      (row[kCGWindowNumber as String] as? NSNumber)?.intValue == number,
                      (row[kCGWindowOwnerPID as String] as? NSNumber)?.int32Value == getpid(),
                      (row[kCGWindowIsOnscreen as String] as? NSNumber)?.boolValue == true,
                      let bounds = row[kCGWindowBounds as String] as? NSDictionary else { return nil }
                return bounds
            }
            guard let capturedBounds = windowRecord(),
                  FileManager.default.isExecutableFile(atPath: "/usr/sbin/screencapture") else {
                print("macOS compositor capture: original on-screen window or system capture utility unavailable")
                return false
            }
            let temporary = FileManager.default.temporaryDirectory.appendingPathComponent("routervpn-window-capture-" + UUID().uuidString, isDirectory: true)
            try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            let imageURL = temporary.appendingPathComponent("window.png")
            let errorURL = temporary.appendingPathComponent("capture.stderr")
            var child: pid_t = 0, childStatus: Int32?, waitError: Int32 = 0
            defer {
                // Keep the original files if an exceptional retirement could not prove the child joined.
                if child == 0 || childStatus != nil { try? FileManager.default.removeItem(at: temporary) }
            }
            var actions: posix_spawn_file_actions_t?
            let actionError = posix_spawn_file_actions_init(&actions)
            guard actionError == 0 else { print("macOS compositor capture: file action setup \(actionError)"); return false }
            defer { posix_spawn_file_actions_destroy(&actions) }
            var attributes: posix_spawnattr_t?
            let attributeError = posix_spawnattr_init(&attributes)
            guard attributeError == 0 else { print("macOS compositor capture: spawn attribute setup \(attributeError)"); return false }
            defer { posix_spawnattr_destroy(&attributes) }
            let setup = [
                posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT)),
                posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0),
                posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0),
                posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, errorURL.path, O_WRONLY | O_CREAT | O_EXCL, 0o600)
            ]
            guard setup.allSatisfy({ $0 == 0 }) else { print("macOS compositor capture: child descriptor setup failed"); return false }
            var arguments = ["/usr/sbin/screencapture", "-x", "-o", "-l", String(number), imageURL.path].map { strdup($0) } + [nil]
            var environment = ["PATH=/usr/bin:/bin:/usr/sbin:/sbin"].map { strdup($0) } + [nil]
            defer { arguments.forEach { free($0) }; environment.forEach { free($0) } }
            guard arguments.dropLast().allSatisfy({ $0 != nil }), environment.dropLast().allSatisfy({ $0 != nil }) else {
                print("macOS compositor capture: child argument allocation failed"); return false
            }
            let spawnError = posix_spawn(&child, "/usr/sbin/screencapture", &actions, &attributes, &arguments, &environment)
            guard spawnError == 0 else { child = 0; print("macOS compositor capture: system utility launch \(spawnError)"); return false }
            func joinCapture(until deadline: TimeInterval) -> Bool {
                while childStatus == nil && waitError == 0 {
                    var status: Int32 = 0
                    let result = waitpid(child, &status, WNOHANG)
                    if result == child { childStatus = status; break }
                    if result < 0 && errno != EINTR { waitError = errno; break }
                    let remaining = deadline - ProcessInfo.processInfo.systemUptime
                    if remaining <= 0 { break }
                    _ = RunLoop.main.run(mode: .default, before: Date(timeIntervalSinceNow: min(0.02, remaining)))
                }
                return childStatus != nil
            }
            let completed = joinCapture(until: ProcessInfo.processInfo.systemUptime + 5)
            if !completed && waitError == 0 {
                // The direct child has not been reaped, so this original PID cannot be reused.
                let term = kill(child, SIGTERM)
                if term != 0 && errno != ESRCH { print("macOS compositor capture: original child TERM \(errno)") }
                if !joinCapture(until: ProcessInfo.processInfo.systemUptime + 1) && waitError == 0 {
                    let forced = kill(child, SIGKILL)
                    if forced != 0 && errno != ESRCH { print("macOS compositor capture: original child KILL \(errno)") }
                    _ = joinCapture(until: ProcessInfo.processInfo.systemUptime + 2)
                }
            }
            guard completed, childStatus == 0, waitError == 0 else {
                var detail = ""
                if let handle = try? FileHandle(forReadingFrom: errorURL) {
                    detail = String(data: (try? handle.read(upToCount: 1024)) ?? Data(), encoding: .utf8) ?? ""
                    try? handle.close()
                }
                print("macOS compositor capture failed: completed=\(completed) joined=\(childStatus != nil) status=\(childStatus.map(String.init) ?? "unavailable") waitError=\(waitError) stderr=\(detail)")
                return false
            }
            guard let currentBounds = windowRecord(), currentBounds.isEqual(capturedBounds) else {
                print("macOS compositor capture: original window or frame changed"); return false
            }
            let imageAttributes = try imageURL.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
            guard imageAttributes.isRegularFile == true, let imageBytes = imageAttributes.fileSize, imageBytes > 8, imageBytes <= 32 * 1024 * 1024 else {
                print("macOS compositor capture: invalid bounded image file"); return false
            }
            let png = try Data(contentsOf: imageURL)
            guard png.starts(with: [137, 80, 78, 71, 13, 10, 26, 10]),
                  let bitmap = NSBitmapImageRep(data: png), bitmap.pixelsWide > 0, bitmap.pixelsHigh > 0 else {
                print("macOS compositor capture: system utility omitted a valid PNG"); return false
            }
            print("macOS native capture: method=composited-own-window requested=\(Int(size.width))x\(Int(size.height)) content=\(Int(content.bounds.width))x\(Int(content.bounds.height)) frame=\(NSStringFromRect(originalFrame)) bitmap=\(bitmap.pixelsWide)x\(bitmap.pixelsHigh) joined=true")
            let suffix = failure ? "-failure" : ""
            try png.write(to: output.appendingPathComponent("macos-\(Int(size.width))x\(Int(size.height))\(suffix).png"), options: .atomic)
            return true
        } catch { print("macOS layout image failed: \(error)"); return false }
    }
    func fail(_ message: String, size: NSSize, views: [NSView] = []) -> Int32 {
        print(message)
        for view in views {
            print("macOS layout geometry: \(view.identifier?.rawValue ?? "unknown") bounds=\(NSStringFromRect(view.bounds)) visible=\(NSStringFromRect(view.visibleRect)) content=\(NSStringFromRect(view.convert(view.bounds, to: content))) alignmentInsets=\(view.alignmentRectInsets)")
        }
        _ = writeEvidence(size, failure: true)
        return 2
    }
    func prepareViewport(_ size: NSSize) -> Bool {
        var rendered: Bool?
        owner.selfTestMapRenderingObserver = { rendered = $0 }
        defer { owner.selfTestMapRenderingObserver = nil }
        window.setContentSize(size)
        content.layoutSubtreeIfNeeded()
        let bases = owner.map.overlays.compactMap { $0 as? RouterVPNVectorMapOverlay }
        guard bases.count == 1, let base = bases.first, base.geometry != nil else { return false }
        let deadline = ProcessInfo.processInfo.systemUptime + 5
        var rendererReady = false
        repeat {
            let remaining = max(0, deadline - ProcessInfo.processInfo.systemUptime)
            _ = RunLoop.main.run(mode: .default, before: Date(timeIntervalSinceNow: min(0.02, remaining)))
            content.layoutSubtreeIfNeeded()
            window.displayIfNeeded()
            rendererReady = owner.map.renderer(for: base) is RouterVPNVectorMapRenderer
        } while (!rendererReady || rendered == nil) && ProcessInfo.processInfo.systemUptime < deadline
        // External Apple tile completion is observed, never required for our local vector map.
        let observation = rendered.map { $0 ? "complete" : "partial" } ?? "pending"
        print("macOS native local map: renderer=\(rendererReady) callback=\(observation) viewport=\(Int(owner.map.bounds.width))x\(Int(owner.map.bounds.height))")
        return rendererReady
    }
    let primary = ["unified-connection-profiles", "unified-connect", "unified-kill-switch", "unified-forward-master",
                   "unified-multihop-toggle", "unified-settings", "unified-mode-popup", "unified-dns-popup"]
    for size in [NSSize(width: 720, height: 560), NSSize(width: 1050, height: 720)] {
        guard prepareViewport(size) else {
            return fail("macOS layout self-test: local vector map renderer unavailable", size: size)
        }
        for id in primary {
            guard let control = owner.findUnifiedView(id) as? NSControl,
                  !control.isHidden, control.action != nil, control.target === owner else {
                return fail("macOS layout self-test: missing or unbound \(id)", size: size)
            }
            _ = control.scrollToVisible(control.bounds)
            content.layoutSubtreeIfNeeded()
            let visible = control.bounds.intersection(control.visibleRect)
            guard control.bounds.width >= 20, control.bounds.height >= 16,
                  visible.width >= control.bounds.width - 1,
                  visible.height >= control.bounds.height - 1 else {
                return fail("macOS layout self-test: clipped \(id) at \(Int(size.width))×\(Int(size.height))", size: size, views: [control])
            }
            let shown = control.convert(visible, to: content)
            for otherID in primary where otherID != id {
                guard let other = owner.findUnifiedView(otherID), !other.isHidden else { continue }
                let otherVisible = other.bounds.intersection(other.visibleRect)
                guard !otherVisible.isNull, !otherVisible.isEmpty else { continue }
                let overlap = shown.intersection(other.convert(otherVisible, to: content))
                guard overlap.isNull || overlap.width <= 1 || overlap.height <= 1 else {
                    return fail("macOS layout self-test: overlapping \(id) / \(otherID) at \(Int(size.width))×\(Int(size.height))", size: size, views: [control, other])
                }
            }
        }
        if let connect = owner.findUnifiedView("unified-connect") { _ = connect.scrollToVisible(connect.bounds) }
        guard writeEvidence(size) else { return 2 }
        print("macOS native layout: \(Int(size.width))×\(Int(size.height)), \(primary.count) primary controls reachable")
    }
    return 0
}

// This explicit packaged-app gate uses the existing controls and installed
// controller. It adds no alternative connect, authentication, or cleanup path.
fileprivate final class ProductConnectionRequestReadback: @unchecked Sendable {
    private let lock = NSLock()
    private var expectedMode = ""
    private var started = [String: Int](), finished = [String: Int](), passed = [String: Int]()
    private var invalid = false
    func configure(_ mode: String) { lock.lock(); defer { lock.unlock() }; expectedMode = mode }
    func permits(_ request: URLRequest) -> Bool {
        // The connection gate does not start unrelated public-exit, updater,
        // latency or speed operations from ordinary background UI observers.
        guard let path = request.url?.path else { return false }
        if request.httpMethod == "GET" {
            return ["/api/status", "/api/nodes", "/api/profiles", "/api/logical-modes", "/api/session/events",
                    "/api/multihop/status", "/api/profile/settings", "/api/profile/protection",
                    "/api/dns/policy", "/api/home-summary", "/api/forwarding/master"].contains(path)
        }
        return request.httpMethod == "POST" &&
            ["/api/profile/import", "/api/profile/select", "/api/connect-logical", "/api/disconnect"].contains(path)
    }
    func begin(_ request: URLRequest) -> String? {
        guard request.httpMethod == "POST", let path = request.url?.path,
              ["/api/connect-logical", "/api/disconnect"].contains(path) else { return nil }
        lock.lock(); defer { lock.unlock() }
        started[path, default: 0] += 1
        if path == "/api/connect-logical" {
            let body = request.httpBody.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: String] }
            if body != ["mode": expectedMode, "base": "auto"] || expectedMode.isEmpty { invalid = true }
        }
        return path
    }
    func end(_ path: String?, succeeded: Bool) {
        guard let path else { return }
        lock.lock(); defer { lock.unlock() }
        finished[path, default: 0] += 1
        if succeeded { passed[path, default: 0] += 1 }
    }
    func completed(_ path: String) throws -> Bool {
        lock.lock(); defer { lock.unlock() }
        let count = started[path, default: 0], done = finished[path, default: 0]
        guard !invalid, count <= 1, done <= count,
              done == 0 || passed[path, default: 0] == done else { throw productConnectionCheckFailure() }
        return count == 1 && done == 1
    }
}

private func productConnectionCheckFailure() -> NSError {
    NSError(domain: "RouterVPN.ConnectionSelfTest", code: 1,
            userInfo: [NSLocalizedDescriptionKey: "The original packaged connection check did not complete."])
}
private func productConnectionHex(_ value: String, _ count: Int) -> Bool {
    value.utf8.count == count && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
}
private func productConnectionTrue(_ value: Any?) -> Bool {
    guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else { return false }
    return number.boolValue
}

private final class ProductConnectionFiles: @unchecked Sendable {
    let path: String, name: String
    private var directory: Int32
    private let original: stat
    private var manifestIdentity: stat?
    private(set) var manifest = Data()
    init(_ supplied: String) throws {
        guard getuid() != 0, getuid() == geteuid(), supplied.hasPrefix("/"),
              !supplied.utf8.contains(0), supplied.utf8.count < 4096 else { throw productConnectionCheckFailure() }
        let url = URL(fileURLWithPath: supplied).standardizedFileURL
        guard url.path == supplied, url.resolvingSymlinksInPath().path == supplied else { throw productConnectionCheckFailure() }
        path = url.deletingLastPathComponent().path; name = url.lastPathComponent
        guard !name.isEmpty, !["desktop-connect-connected.json", "desktop-connect-peer-stopped.json",
                             "desktop-connect-cancel.json", "desktop-connect-result.json"].contains(name) else { throw productConnectionCheckFailure() }
        var before = stat()
        guard lstat(path, &before) == 0, before.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
              before.st_uid == getuid(), before.st_mode & 0o777 == 0o700 else { throw productConnectionCheckFailure() }
        try RouterVPNMacPathACL.validate(path)
        let fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw productConnectionCheckFailure() }
        directory = fd; original = before
        do {
            try current()
            guard let captured = try read(name, limit: 1 << 20, marker: false) else { throw productConnectionCheckFailure() }
            manifest = captured.0; manifestIdentity = captured.1
            for sibling in ["desktop-connect-connected.json", "desktop-connect-peer-stopped.json",
                            "desktop-connect-cancel.json", "desktop-connect-result.json"] {
                var info = stat()
                guard fstatat(directory, sibling, &info, AT_SYMLINK_NOFOLLOW) != 0, errno == ENOENT else { throw productConnectionCheckFailure() }
            }
        } catch { directory = -1; close(fd); throw error }
    }
    deinit { if directory >= 0 { close(directory) } }
    private func same(_ a: stat, _ b: stat) -> Bool {
        a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_uid == b.st_uid &&
        a.st_gid == b.st_gid && a.st_mode == b.st_mode && a.st_nlink == b.st_nlink &&
        a.st_size == b.st_size && a.st_mtimespec.tv_sec == b.st_mtimespec.tv_sec &&
        a.st_mtimespec.tv_nsec == b.st_mtimespec.tv_nsec &&
        a.st_ctimespec.tv_sec == b.st_ctimespec.tv_sec && a.st_ctimespec.tv_nsec == b.st_ctimespec.tv_nsec
    }
    func current() throws {
        var held = stat(), named = stat()
        guard fstat(directory, &held) == 0, lstat(path, &named) == 0,
              held.st_dev == original.st_dev, held.st_ino == original.st_ino,
              named.st_dev == original.st_dev, named.st_ino == original.st_ino,
              held.st_mode == original.st_mode, named.st_mode == original.st_mode,
              held.st_uid == original.st_uid, named.st_uid == original.st_uid,
              held.st_gid == original.st_gid, named.st_gid == original.st_gid else { throw productConnectionCheckFailure() }
        try RouterVPNMacPathACL.validate(path)
    }
    private func read(_ leaf: String, limit: Int, marker: Bool) throws -> (Data, stat)? {
        try current()
        let fd = openat(directory, leaf, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        if fd < 0 {
            if marker && errno == ENOENT { return nil }
            throw productConnectionCheckFailure()
        }
        defer { close(fd) }
        var before = stat(), after = stat(), named = stat()
        guard fstat(fd, &before) == 0, before.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              before.st_uid == getuid(), before.st_mode & 0o777 == 0o600,
              before.st_size > 0, before.st_size <= limit else { throw productConnectionCheckFailure() }
        // A hard-link publisher has not finished removing its private temp yet.
        if marker && before.st_nlink == 2 { return nil }
        guard before.st_nlink == 1 else { throw productConnectionCheckFailure() }
        try RouterVPNMacPathACL.validate(path + "/" + leaf)
        var bytes = Data(count: Int(before.st_size))
        var offset = 0
        while offset < bytes.count {
            let amount = bytes.withUnsafeMutableBytes { raw in Darwin.read(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset) }
            if amount < 0 && errno == EINTR { continue }
            guard amount > 0 else { throw productConnectionCheckFailure() }
            offset += amount
        }
        guard fstat(fd, &after) == 0, fstatat(directory, leaf, &named, AT_SYMLINK_NOFOLLOW) == 0,
              same(before, after), same(before, named) else { throw productConnectionCheckFailure() }
        try current()
        return (bytes, after)
    }
    func unchanged() throws {
        guard let original = manifestIdentity, let captured = try read(name, limit: 1 << 20, marker: false),
              captured.0 == manifest, same(original, captured.1) else { throw productConnectionCheckFailure() }
    }
    func marker(_ leaf: String, runID: String, phase: String) throws -> Bool {
        guard ["desktop-connect-peer-stopped.json", "desktop-connect-cancel.json"].contains(leaf) else { throw productConnectionCheckFailure() }
        guard let captured = try read(leaf, limit: 4096, marker: true) else { return false }
        guard let object = try JSONSerialization.jsonObject(with: captured.0) as? [String: Any],
              Set(object.keys) == ["schema", "run_id", "phase"],
              let schema = object["schema"] as? NSNumber, CFGetTypeID(schema) != CFBooleanGetTypeID(),
              schema.stringValue == "1", object["run_id"] as? String == runID,
              object["phase"] as? String == phase else { throw productConnectionCheckFailure() }
        return true
    }
    func write(_ leaf: String, object: [String: Any]) throws {
        guard ["desktop-connect-connected.json", "desktop-connect-result.json"].contains(leaf) else { throw productConnectionCheckFailure() }
        try current()
        let bytes = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        guard !bytes.isEmpty, bytes.count <= 4096 else { throw productConnectionCheckFailure() }
        let temporary = "." + leaf + ".pending"
        let fd = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard fd >= 0 else { throw productConnectionCheckFailure() }
        defer { close(fd) } // Failed writes retain their original private file.
        var identity = stat()
        guard fstat(fd, &identity) == 0, identity.st_uid == getuid(), identity.st_nlink == 1,
              identity.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG), identity.st_mode & 0o777 == 0o600 else { throw productConnectionCheckFailure() }
        var offset = 0
        while offset < bytes.count {
            let amount = bytes.withUnsafeBytes { raw in Darwin.write(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset) }
            if amount < 0 && errno == EINTR { continue }
            guard amount > 0 else { throw productConnectionCheckFailure() }
            offset += amount
        }
        var held = stat(), named = stat()
        guard fsync(fd) == 0, fstat(fd, &held) == 0,
              fstatat(directory, temporary, &named, AT_SYMLINK_NOFOLLOW) == 0,
              held.st_dev == identity.st_dev, held.st_ino == identity.st_ino,
              held.st_uid == identity.st_uid, held.st_gid == identity.st_gid,
              held.st_mode == identity.st_mode, held.st_nlink == 1,
              same(held, named), held.st_size == bytes.count else { throw productConnectionCheckFailure() }
        try current()
        guard renameatx_np(directory, temporary, directory, leaf, UInt32(RENAME_EXCL)) == 0,
              fsync(directory) == 0 else { throw productConnectionCheckFailure() }
    }
}

private struct ProductConnectionFixture {
    let runID: String, profile: [String: Any], mode: String, address: String, digest: String
    let payload: URL, literal: URL
    init(_ bytes: Data) throws {
        guard let object = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
              Set(object.keys) == ["schema", "kind", "run_id", "profile_bundle", "logical_mode", "runtime_mode",
                                   "private_address", "dns_host", "payload_url", "literal_payload_url", "payload_sha256"],
              let schema = object["schema"] as? NSNumber, CFGetTypeID(schema) != CFBooleanGetTypeID(), schema.stringValue == "1",
              object["kind"] as? String == "routervpn-desktop-connect",
              let run = object["run_id"] as? String, productConnectionHex(run, 32),
              let bundle = object["profile_bundle"] as? [String: Any],
              object["logical_mode"] as? String == "base-raw", object["runtime_mode"] as? String == "wg",
              let ip = object["private_address"] as? String,
              let digest = object["payload_sha256"] as? String, productConnectionHex(digest, 64),
              object["dns_host"] as? String == run + ".desktop-smoke.invalid",
              object["payload_url"] as? String == "http://" + run + ".desktop-smoke.invalid:8787/desktop-connect/" + run,
              object["literal_payload_url"] as? String == "http://" + ip + ":8787/desktop-connect/" + run,
              let payload = URL(string: object["payload_url"] as? String ?? ""),
              let literal = URL(string: object["literal_payload_url"] as? String ?? "") else { throw productConnectionCheckFailure() }
        let octets = ip.split(separator: ".", omittingEmptySubsequences: false).compactMap { UInt8($0) }
        var raw = in_addr()
        guard octets.count == 4, octets.map(String.init).joined(separator: ".") == ip,
              inet_pton(AF_INET, ip, &raw) == 1,
              octets[0] == 10 || (octets[0] == 172 && (16...31).contains(octets[1])) || (octets[0] == 192 && octets[1] == 168) else { throw productConnectionCheckFailure() }
        runID = run; profile = bundle; mode = "base-raw"; address = ip; self.digest = digest
        self.payload = payload; self.literal = literal
    }
}

// A fresh ordinary URLSession resolves the nonce hostname through the OS.
// No proxy, custom resolver, URL override, cached response or controller token.
private final class ProductConnectionHTTP: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let done = DispatchSemaphore(value: 0), invalidated = DispatchSemaphore(value: 0), lock = NSLock()
    private var bytes = Data(), failure: Error?, response: HTTPURLResponse?
    private var remote = "", finished = false, overflow = false, sessionRetired = false
    private var originalSession: URLSession?, originalTask: URLSessionDataTask?
    var joined: Bool { lock.lock(); defer { lock.unlock() }; return finished && sessionRetired }
    private static let limit = 65536
    func run(_ url: URL) throws -> (Data, Int, String, Bool) {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.connectionProxyDictionary = [:]; configuration.urlCache = nil
        configuration.httpCookieStorage = nil; configuration.httpShouldSetCookies = false
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.timeoutIntervalForRequest = 12; configuration.timeoutIntervalForResource = 12
        let queue = OperationQueue(); queue.maxConcurrentOperationCount = 1
        let session = URLSession(configuration: configuration, delegate: self, delegateQueue: queue)
        var request = URLRequest(url: url); request.timeoutInterval = 12
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        request.setValue("close", forHTTPHeaderField: "Connection")
        let task = session.dataTask(with: request)
        lock.lock(); originalSession = session; originalTask = task; lock.unlock()
        task.resume()
        let timedOut = done.wait(timeout: .now() + 15) == .timedOut
        var completionJoined = !timedOut
        if timedOut {
            task.cancel()
            completionJoined = done.wait(timeout: .now() + 3) == .success
        }
        if completionJoined { session.finishTasksAndInvalidate() } else { session.invalidateAndCancel() }
        let invalidationJoined = invalidated.wait(timeout: .now() + 3) == .success
        lock.lock(); defer { lock.unlock() }
        // Retain the exact task/session on an unproved join. A canceled request
        // is not an endpoint-denial receipt, even if its late completion arrives.
        if completionJoined && invalidationJoined && finished && sessionRetired {
            originalTask = nil; originalSession = nil
        }
        guard completionJoined, invalidationJoined, finished, sessionRetired,
              !timedOut, !overflow else { throw productConnectionCheckFailure() }
        // Even a partial HTTP response proves the stopped path was reachable.
        if let response { return (bytes, response.statusCode, remote, failure == nil) }
        if let failure { throw failure }
        throw productConnectionCheckFailure()
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        lock.lock(); self.response = response as? HTTPURLResponse
        overflow = response.expectedContentLength > Int64(Self.limit); let reject = overflow; lock.unlock()
        completionHandler(reject ? .cancel : .allow)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        lock.lock(); let reject = bytes.count > Self.limit - data.count
        if reject { overflow = true } else { bytes.append(data) }; lock.unlock()
        if reject { dataTask.cancel() }
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didFinishCollecting metrics: URLSessionTaskMetrics) {
        lock.lock(); defer { lock.unlock() }
        if metrics.transactionMetrics.count == 1, let metric = metrics.transactionMetrics.first,
           !metric.isProxyConnection, metric.resourceFetchType == .networkLoad { remote = metric.remoteAddress ?? "" }
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        lock.lock(); failure = error; finished = true; lock.unlock(); done.signal()
    }
    func urlSession(_ session: URLSession, didBecomeInvalidWithError error: Error?) {
        lock.lock()
        guard session === originalSession else { lock.unlock(); return }
        failure = failure ?? error; sessionRetired = true
        lock.unlock(); invalidated.signal()
    }
}

private final class ProductConnectionLifetime: @unchecked Sendable {
    let deadline = ProcessInfo.processInfo.systemUptime + 180
    private let lock = NSLock(), stop = DispatchSemaphore(value: 0), joined = DispatchSemaphore(value: 0)
    private var expired = false, resultWritten = false, abortCleanup = false, failureNoted = false
    private var stage = "launch", flags = ["connect": false, "traffic": false, "loss": false, "disconnect": false]
    private let files: ProductConnectionFiles, fixture: ProductConnectionFixture
    init(_ files: ProductConnectionFiles, _ fixture: ProductConnectionFixture) { self.files = files; self.fixture = fixture }
    func advance(_ value: String) { lock.lock(); stage = value; lock.unlock() }
    func proved(_ value: String) { lock.lock(); flags[value] = true; lock.unlock() }
    func failed() { lock.lock(); failureNoted = true; lock.unlock() }
    func active() throws {
        lock.lock(); let ended = expired || abortCleanup; lock.unlock()
        guard !ended, ProcessInfo.processInfo.systemUptime < deadline else { throw productConnectionCheckFailure() }
        try files.unchanged()
        guard try !files.marker("desktop-connect-cancel.json", runID: fixture.runID, phase: "cancel") else { throw productConnectionCheckFailure() }
    }
    var timedOut: Bool { lock.lock(); defer { lock.unlock() }; return expired }
    func writeResult(cleanup: Bool) throws -> Bool {
        lock.lock(); defer { lock.unlock() }
        if resultWritten { return false }
        let passed = !expired && stage == "complete" && cleanup && flags.values.allSatisfy { $0 }
        var object: [String: Any] = ["schema": 1, "run_id": fixture.runID, "phase": "complete",
                                    "status": passed ? "passed" : "failed", "cleanup_proved": cleanup,
                                    "failure_stage": passed ? "" : stage]
        for (key, value) in flags { object[key] = value }
        try files.write("desktop-connect-result.json", object: object); resultWritten = true
        return passed
    }
    func arm(api: ProductAPI, owner: RouterVPNMacOwnedProcess, identity: RouterVPNMacShutdownIdentity) {
        DispatchQueue.global(qos: .utility).async { [self, api, owner] in
            defer { joined.signal() }
            while true {
                if stop.wait(timeout: .now() + 0.2) == .success { return }
                do { try active() } catch { break }
            }
            lock.lock()
            if !failureNoted { stage = ProcessInfo.processInfo.systemUptime >= deadline ? "watchdog" : "cancel" }
            expired = true; lock.unlock()
            // Failure cleanup only: retain the same installed capability, without
            // involving a stalled AppKit queue or granting a new connection.
            if owner.acceptsRequests { _ = try? api.request("/api/disconnect", method: "POST", body: [:], timeout: 25) }
            if owner.acceptsRequests {
                let ended = DispatchSemaphore(value: 0)
                do {
                    let request = try RouterVPNMacShutdownTransport(url: routerVPNProductBaseURL.appendingPathComponent("api/controller/shutdown"),
                                                                   identity: identity, timeout: 35) { _ in ended.signal() }
                    request.start()
                    if ended.wait(timeout: .now() + 38) == .timedOut { request.cancel(); _ = ended.wait(timeout: .now() + 3) }
                } catch { /* No replacement capability or forced process retirement. */ }
            }
            let until = ProcessInfo.processInfo.systemUptime + 15
            while owner.isRunning && owner.joinFailure == nil && ProcessInfo.processInfo.systemUptime < until { Thread.sleep(forTimeInterval: 0.05) }
            // Only the normal ShutdownController acknowledgment can prove cleanup.
            _ = try? writeResult(cleanup: false)
        }
    }
    func finishWatchdog(cleanup: Bool) -> Bool {
        if cleanup { stop.signal() }
        else { lock.lock(); abortCleanup = true; failureNoted = true; lock.unlock() }
        return joined.wait(timeout: .now() + 85) == .success
    }
}

@MainActor private func runProductConnectionSelfTest(_ path: String) -> Int32 {
    let files: ProductConnectionFiles, fixture: ProductConnectionFixture
    do {
        files = try ProductConnectionFiles(path); fixture = try ProductConnectionFixture(files.manifest)
        guard RouterVPNMacLocalAuthorization.installedBundle() else { throw productConnectionCheckFailure() }
    } catch { fputs("macOS connection self-test: invalid installed fixture prerequisites\n", stderr); return 2 }
    let app = NSApplication.shared; app.setActivationPolicy(.regular); app.finishLaunching()
    let delegate = ProductDelegate(); app.delegate = delegate
    let lifetime = ProductConnectionLifetime(files, fixture)
    var watchdog = false, cleanup = false, failure = false
    var httpOwners: [ProductConnectionHTTP] = []
    func fetch(_ url: URL) throws -> (Data, Int, String, Bool) {
        let original = ProductConnectionHTTP(); httpOwners.append(original)
        return try original.run(url)
    }
    func pump() { _ = RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.05)) }
    func wait(_ predicate: () throws -> Bool) throws {
        while true { try lifetime.active(); if try predicate() { return }; pump() }
    }
    func click(_ window: ProductWindowController, _ expected: String) throws {
        guard let control = window.findUnifiedView("unified-connect") as? NSButton,
              control.target === window, control.action == #selector(ProductWindowController.connectUnified),
              control.isEnabled, !control.isHiddenOrHasHiddenAncestor, control.title == expected else { throw productConnectionCheckFailure() }
        control.performClick(nil)
    }
    do {
        try delegate.ensureController()
        guard let owner = delegate.installedController, delegate.controller === owner,
              owner.acceptsRequests, let requests = delegate.api.connectionSelfTestRequests else { throw productConnectionCheckFailure() }
        let identity = RouterVPNMacShutdownIdentity(processID: owner.processIdentifier, token: delegate.controllerOwnerToken)
        lifetime.arm(api: delegate.api, owner: owner, identity: identity); watchdog = true
        requests.configure(fixture.mode)
        let window = ProductWindowController(api: delegate.api); delegate.wc = window
        guard RouterVPNVectorMap.geometry != nil,
              window.map.overlays.contains(where: { $0 is RouterVPNVectorMapOverlay }) else { throw productConnectionCheckFailure() }
        window.showWindow(nil); window.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        lifetime.advance("import")
        let imported = try JSONSerialization.jsonObject(with: delegate.api.request("/api/profile/import", method: "POST", body: fixture.profile)) as? [String: Any]
        guard productConnectionTrue(imported?["ok"]), let profile = imported?["profile"] as? [String: Any],
              let profileID = profile["id"] as? String, !profileID.isEmpty, profileID.utf8.count <= 64,
              profileID.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 || $0 == 95 }) else { throw productConnectionCheckFailure() }
        guard profile["base_tunnel"] as? String == "wg", profile["kill_switch_policy"] as? String == "on-connect",
              !productConnectionTrue(profile["home_lan_access"]), profile["ipv6_mode"] as? String == "off",
              profile["dns_mode"] as? String == "home", profile["dns_protocol"] as? String == "udp" else { throw productConnectionCheckFailure() }
        _ = try delegate.api.request("/api/profile/select", method: "POST", body: ["id": profileID])
        guard let catalog = try delegate.api.json("/api/logical-modes") as? [[String: Any]],
              let mode = catalog.first(where: { $0["id"] as? String == fixture.mode }),
              productConnectionTrue(mode["available"]), let variants = mode["variants"] as? [String: Any],
              let wg = variants["wg"] as? [String: Any], productConnectionTrue(wg["available"]),
              wg["runtime_id"] as? String == "wg" else { throw productConnectionCheckFailure() }
        lifetime.advance("controls")
        window.refreshAll(); window.refreshUnifiedModeMenu(preferred: fixture.mode)
        try wait {
            let index = window.routerPopup.indexOfSelectedItem
            return window.routerIDs.indices.contains(index) && window.profiles.indices.contains(index) &&
                window.routerIDs[index] == profileID && window.profiles[index]["id"] as? String == profileID
        }
        guard let popup = window.findUnifiedView("unified-mode-popup") as? NSPopUpButton,
              let toggle = window.findUnifiedView("unified-multihop-toggle") as? NSButton else { throw productConnectionCheckFailure() }
        if toggle.state == .on { toggle.performClick(nil) }
        guard toggle.state == .off else { throw productConnectionCheckFailure() }
        try wait { popup.itemArray.contains { ($0.representedObject as? String) == fixture.mode && $0.isEnabled } }
        guard let item = popup.itemArray.first(where: { ($0.representedObject as? String) == fixture.mode && $0.isEnabled }),
              popup.target === window, popup.action == #selector(ProductWindowController.unifiedModeChanged(_:)) else { throw productConnectionCheckFailure() }
        popup.select(item)
        guard popup.sendAction(popup.action, to: popup.target) else { throw productConnectionCheckFailure() }
        lifetime.advance("connect")
        try wait { (window.findUnifiedView("unified-connect") as? NSButton)?.title == "Connect" }
        try click(window, "Connect")
        try wait { try requests.completed("/api/connect-logical") }
        guard let state = try delegate.api.json("/api/status") as? [String: Any],
              productConnectionTrue(state["connected"]), state["router_id"] as? String == profileID,
              state["runtime_mode"] as? String == "wg", state["base"] as? String == "wg",
              state["logical_mode"] as? String == fixture.mode else { throw productConnectionCheckFailure() }
        try wait { (window.findUnifiedView("unified-connect") as? NSButton)?.title == "Disconnect" }
        lifetime.proved("connect"); lifetime.advance("traffic")
        let (payload, code, address, complete) = try fetch(fixture.payload)
        try lifetime.active()
        guard complete, code == 200, address == fixture.address,
              SHA256.hash(data: payload).map({ String(format: "%02x", $0) }).joined() == fixture.digest else { throw productConnectionCheckFailure() }
        lifetime.proved("traffic")
        try files.write("desktop-connect-connected.json", object: ["schema": 1, "run_id": fixture.runID,
                        "phase": "connected", "profile_id": profileID, "runtime_mode": "wg",
                        "private_address": fixture.address, "payload_sha256": fixture.digest])
        lifetime.advance("peer-stop")
        try wait { try files.marker("desktop-connect-peer-stopped.json", runID: fixture.runID, phase: "peer-stopped") }
        lifetime.advance("loss")
        var denied = false
        do { _ = try fetch(fixture.literal) }
        catch {
            let issue = error as NSError
            denied = issue.domain == NSURLErrorDomain &&
                [NSURLErrorTimedOut, NSURLErrorCannotConnectToHost, NSURLErrorNetworkConnectionLost, NSURLErrorNotConnectedToInternet].contains(issue.code)
        }
        try lifetime.active()
        guard denied else { throw productConnectionCheckFailure() }
        lifetime.proved("loss"); lifetime.advance("disconnect")
        guard let state = try delegate.api.json("/api/status") as? [String: Any], productConnectionTrue(state["connected"]),
              state["router_id"] as? String == profileID, state["runtime_mode"] as? String == "wg" else { throw productConnectionCheckFailure() }
        try click(window, "Disconnect")
        try wait { try requests.completed("/api/disconnect") }
        guard let off = try delegate.api.json("/api/status") as? [String: Any],
              off["connected"] as? Bool == false, off["mode"] as? String == "off",
              (off["runtime_mode"] as? String ?? "").isEmpty,
              (off["phase"] as? String ?? "off") == "off" else { throw productConnectionCheckFailure() }
        try wait { (window.findUnifiedView("unified-connect") as? NSButton)?.title == "Connect" }
        lifetime.proved("disconnect"); lifetime.advance("shutdown")
    } catch { failure = true; lifetime.failed() }
    delegate.wc?.timer?.invalidate()
    if let owner = delegate.installedController, delegate.controller === owner {
        if !watchdog {
            lifetime.arm(api: delegate.api, owner: owner,
                         identity: RouterVPNMacShutdownIdentity(processID: owner.processIdentifier, token: delegate.controllerOwnerToken))
            watchdog = true
        }
        if !lifetime.timedOut {
            let identity = RouterVPNMacShutdownIdentity(processID: owner.processIdentifier, token: delegate.controllerOwnerToken)
            let flow = RouterVPNMacShutdownController(baseURL: routerVPNProductBaseURL, identity: identity, process: owner,
                isCurrent: { delegate.ownsController && delegate.installedController === owner &&
                    delegate.controller === owner && delegate.controllerOwnerToken == identity.token })
            delegate.shutdown = flow
            var finished = false
            flow.onFinish = { allowed in cleanup = allowed && flow.acknowledged && owner.joinedSuccessfully; finished = true }
            flow.start()
            let until = ProcessInfo.processInfo.systemUptime + 55
            while !finished && ProcessInfo.processInfo.systemUptime < until { pump() }
            if !finished { flow.retire() }
        }
        if watchdog && !lifetime.finishWatchdog(cleanup: cleanup) { cleanup = false }
        cleanup = cleanup && !owner.isRunning && owner.joinedSuccessfully
    }
    cleanup = cleanup && httpOwners.allSatisfy { $0.joined }
    if !failure && !lifetime.timedOut && cleanup { lifetime.advance("complete") }
    let passed = (try? lifetime.writeResult(cleanup: cleanup)) == true
    print(passed ? "macOS connection self-test: actual control, private traffic, peer loss and original cleanup passed" :
                   "macOS connection self-test failed; original owner and fixture evidence are retained")
    if let owner = delegate.installedController, !owner.joinedSuccessfully || !httpOwners.allSatisfy({ $0.joined }) {
        // A failed cleanup cannot drop the original controller/HTTP capabilities
        // or remove the installation. Checked Quit remains available.
        withExtendedLifetime((delegate, httpOwners)) { app.run() }
    }
    return passed ? 0 : 2
}

MainActor.assumeIsolated {
    if CommandLine.arguments.contains("--connection-self-test") {
        guard CommandLine.arguments.count == 3, CommandLine.arguments[1] == "--connection-self-test" else {
            fputs("macOS connection self-test: invalid invocation\n", stderr); exit(2)
        }
        exit(runProductConnectionSelfTest(CommandLine.arguments[2]))
    }
    if CommandLine.arguments.contains("--self-test") { exit(runProductSelfTest()) }
    let productApp = NSApplication.shared
    let productDelegate = ProductDelegate()
    productApp.delegate = productDelegate
    withExtendedLifetime(productDelegate) { productApp.run() }
}
