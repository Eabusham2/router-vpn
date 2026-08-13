import AppKit
import Foundation

let routerVPNBaseURL = URL(string: "http://127.0.0.1:8788")!
let nativeAppContractVersion = 1

final class RouterVPNAPI {
    private let session: URLSession

    init() {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 8
        config.timeoutIntervalForResource = 12
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        config.connectionProxyDictionary = [:]
        session = URLSession(configuration: config)
    }

    func request(_ path: String, method: String = "GET", body: [String: Any]? = nil, timeout: TimeInterval = 12) throws -> Data {
        guard let url = URL(string: path, relativeTo: routerVPNBaseURL) else {
            throw NSError(domain: "RouterVPNMac", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid local API path"])
        }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.timeoutInterval = timeout
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let body {
            request.httpBody = try JSONSerialization.data(withJSONObject: body)
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        let semaphore = DispatchSemaphore(value: 0)
        var responseData = Data()
        var responseStatus = 0
        var responseError: Error?
        let task = session.dataTask(with: request) { data, response, error in
            responseData = data ?? Data()
            responseStatus = (response as? HTTPURLResponse)?.statusCode ?? 0
            responseError = error
            semaphore.signal()
        }
        task.resume()
        if semaphore.wait(timeout: .now() + timeout + 2) == .timedOut {
            task.cancel()
            throw NSError(domain: "RouterVPNMac", code: 2, userInfo: [NSLocalizedDescriptionKey: "Local controller request timed out"])
        }
        if let responseError { throw responseError }
        guard (200..<300).contains(responseStatus) else {
            let text = String(data: responseData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
            throw NSError(domain: "RouterVPNMac", code: 3, userInfo: [NSLocalizedDescriptionKey: (text?.isEmpty == false ? text! : "Local controller request failed")])
        }
        return responseData
    }

    func json(_ path: String, timeout: TimeInterval = 12) throws -> Any {
        try JSONSerialization.jsonObject(with: request(path, timeout: timeout))
    }

    func ready() -> Bool { (try? request("/api/status", timeout: 1)) != nil }
}

final class RouterVPNWindowController: NSWindowController {
    let api: RouterVPNAPI
    let statusLabel = NSTextField(labelWithString: "Checking…")
    let detailLabel = NSTextField(wrappingLabelWithString: "")
    let errorLabel = NSTextField(wrappingLabelWithString: "")
    let routerPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    let modePopup = NSPopUpButton(frame: .zero, pullsDown: false)
    let basePopup = NSPopUpButton(frame: .zero, pullsDown: false)
    let nodesText = NSTextView()
    let methodsText = NSTextView()
    let diagnosticsText = NSTextView()
    var routerIDs: [String] = []
    var modeIDs: [String] = []
    var timer: Timer?

    init(api: RouterVPNAPI) {
        self.api = api
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1040, height: 720),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Router VPN"
        window.minSize = NSSize(width: 880, height: 600)
        window.center()
        super.init(window: window)
        buildUI()
        refreshAll()
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in self?.refreshStatus() }
    }

    required init?(coder: NSCoder) { nil }
    deinit { timer?.invalidate() }

    func buildUI() {
        guard let content = window?.contentView else { return }
        let root = NSStackView()
        root.orientation = .vertical
        root.spacing = 12
        root.edgeInsets = NSEdgeInsets(top: 18, left: 18, bottom: 18, right: 18)
        root.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(root)
        NSLayoutConstraint.activate([
            root.leadingAnchor.constraint(equalTo: content.leadingAnchor), root.trailingAnchor.constraint(equalTo: content.trailingAnchor),
            root.topAnchor.constraint(equalTo: content.topAnchor), root.bottomAnchor.constraint(equalTo: content.bottomAnchor)
        ])

        let header = NSStackView()
        header.orientation = .horizontal
        header.alignment = .centerY
        let title = NSTextField(labelWithString: "Router VPN")
        title.font = .systemFont(ofSize: 30, weight: .bold)
        statusLabel.font = .systemFont(ofSize: 14, weight: .semibold)
        header.addArrangedSubview(title)
        header.addArrangedSubview(NSView())
        header.addArrangedSubview(statusLabel)
        root.addArrangedSubview(header)
        detailLabel.textColor = .secondaryLabelColor
        errorLabel.textColor = .systemRed
        root.addArrangedSubview(detailLabel)
        root.addArrangedSubview(errorLabel)

        let tabs = NSTabViewController()
        tabs.tabStyle = .segmentedControlOnTop
        addTab(tabs, label: "Connect", view: connectView())
        addTab(tabs, label: "Nodes", view: textView(nodesText))
        addTab(tabs, label: "Methods", view: textView(methodsText))
        addTab(tabs, label: "Diagnostics", view: diagnosticsView())
        root.addArrangedSubview(tabs.view)
        tabs.view.heightAnchor.constraint(greaterThanOrEqualToConstant: 490).isActive = true
    }

    func addTab(_ tabs: NSTabViewController, label: String, view: NSView) {
        let vc = NSViewController()
        vc.view = view
        let item = NSTabViewItem(viewController: vc)
        item.label = label
        tabs.addTabViewItem(item)
    }

    func connectView() -> NSView {
        let stack = NSStackView()
        stack.orientation = .vertical
        stack.spacing = 10
        stack.edgeInsets = NSEdgeInsets(top: 24, left: 28, bottom: 24, right: 28)
        stack.addArrangedSubview(NSTextField(labelWithString: "Router"))
        routerPopup.target = self
        routerPopup.action = #selector(selectRouter)
        stack.addArrangedSubview(routerPopup)
        stack.addArrangedSubview(NSTextField(labelWithString: "Mode"))
        stack.addArrangedSubview(modePopup)
        stack.addArrangedSubview(NSTextField(labelWithString: "Tunnel base"))
        basePopup.addItems(withTitles: ["Auto", "WireGuard", "AmneziaWG"])
        basePopup.selectItem(at: 0)
        stack.addArrangedSubview(basePopup)
        let row = NSStackView()
        row.orientation = .horizontal
        row.spacing = 8
        row.addArrangedSubview(button("AUTO Connect", #selector(autoConnect)))
        row.addArrangedSubview(button("Connect Selected", #selector(connectSelected)))
        row.addArrangedSubview(button("Disconnect", #selector(disconnect)))
        row.addArrangedSubview(button("Refresh", #selector(refreshAction)))
        stack.addArrangedSubview(row)
        let proof = NSTextField(wrappingLabelWithString: "Connected is shown only after the controller verifies the exact selected Router VPN node on its private proof path.")
        proof.textColor = .secondaryLabelColor
        stack.addArrangedSubview(proof)
        return stack
    }

    func textView(_ text: NSTextView) -> NSView {
        text.isEditable = false
        text.isSelectable = true
        text.font = .monospacedSystemFont(ofSize: 13, weight: .regular)
        text.textContainerInset = NSSize(width: 14, height: 14)
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.documentView = text
        return scroll
    }

    func diagnosticsView() -> NSView {
        let stack = NSStackView()
        stack.orientation = .vertical
        stack.spacing = 10
        stack.edgeInsets = NSEdgeInsets(top: 18, left: 18, bottom: 18, right: 18)
        let row = NSStackView()
        row.orientation = .horizontal
        row.addArrangedSubview(button("Prove public VPN exit", #selector(publicExit)))
        row.addArrangedSubview(button("Retest home-exit DNS", #selector(retestDNS)))
        row.addArrangedSubview(button("Emergency stop", #selector(emergencyStop)))
        stack.addArrangedSubview(row)
        stack.addArrangedSubview(textView(diagnosticsText))
        return stack
    }

    func button(_ title: String, _ action: Selector) -> NSButton {
        let b = NSButton(title: title, target: self, action: action)
        b.bezelStyle = .rounded
        b.controlSize = .large
        return b
    }

    func asyncAction(_ work: @escaping () throws -> String) {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do {
                let message = try work()
                DispatchQueue.main.async { self?.appendDiagnostic(message); self?.refreshAll() }
            } catch {
                DispatchQueue.main.async { self?.errorLabel.stringValue = error.localizedDescription; self?.appendDiagnostic("ERROR: \(error.localizedDescription)"); self?.refreshStatus() }
            }
        }
    }

    @objc func autoConnect() {
        asyncAction { String(data: try self.api.request("/api/auto", method: "POST", body: [:], timeout: 150), encoding: .utf8) ?? "AUTO connected" }
    }

    @objc func connectSelected() {
        let index = modePopup.indexOfSelectedItem
        guard index >= 0, index < modeIDs.count else { return }
        let mode = modeIDs[index]
        let base = ["auto", "wg", "awg"][max(0, min(basePopup.indexOfSelectedItem, 2))]
        asyncAction { String(data: try self.api.request("/api/connect-logical", method: "POST", body: ["mode": mode, "base": base], timeout: 180), encoding: .utf8) ?? "Connected" }
    }

    @objc func disconnect() { asyncAction { _ = try self.api.request("/api/disconnect", method: "POST", body: [:], timeout: 20); return "Disconnected." } }
    @objc func publicExit() { asyncAction { String(data: try self.api.request("/api/public-ip", timeout: 20), encoding: .utf8) ?? "" } }
    @objc func retestDNS() { asyncAction { String(data: try self.api.request("/api/dns/retest", method: "POST", body: [:], timeout: 90), encoding: .utf8) ?? "" } }
    @objc func emergencyStop() { asyncAction { _ = try self.api.request("/api/emergency-stop", method: "POST", body: [:], timeout: 20); return "Emergency stop completed." } }
    @objc func refreshAction() { refreshAll() }

    @objc func selectRouter() {
        let index = routerPopup.indexOfSelectedItem
        guard index >= 0, index < routerIDs.count else { return }
        let id = routerIDs[index]
        asyncAction { _ = try self.api.request("/api/profile/select", method: "POST", body: ["id": id], timeout: 10); return "Selected router \(id)" }
    }

    func refreshAll() { refreshStatus(); refreshProfiles(); refreshModes() }

    func refreshStatus() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            do {
                guard let obj = try api.json("/api/status") as? [String: Any] else { return }
                DispatchQueue.main.async {
                    let connected = obj["connected"] as? Bool ?? false
                    let phase = obj["phase"] as? String ?? "Off"
                    self.statusLabel.stringValue = connected ? "● Connected" : "○ \(phase)"
                    self.statusLabel.textColor = connected ? .systemGreen : .secondaryLabelColor
                    let logical = obj["logical_mode"] as? String ?? "—"
                    let runtime = (obj["runtime_mode"] as? String) ?? (obj["mode"] as? String) ?? "—"
                    let base = obj["base"] as? String ?? "—"
                    let router = obj["router_id"] as? String ?? "—"
                    self.detailLabel.stringValue = "Logical: \(logical)   Runtime: \(runtime)   Base: \(base)   Router: \(router)"
                    self.errorLabel.stringValue = obj["last_error"] as? String ?? ""
                }
            } catch {
                DispatchQueue.main.async { self.statusLabel.stringValue = "● Controller unavailable"; self.statusLabel.textColor = .systemRed; self.errorLabel.stringValue = error.localizedDescription }
            }
        }
    }

    func refreshProfiles() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            do {
                guard let obj = try api.json("/api/profiles") as? [String: Any], let profiles = obj["profiles"] as? [[String: Any]] else { return }
                let selected = obj["selected_id"] as? String ?? ""
                DispatchQueue.main.async {
                    self.routerIDs = profiles.compactMap { $0["id"] as? String }
                    self.routerPopup.removeAllItems()
                    self.routerPopup.addItems(withTitles: profiles.map { ($0["name"] as? String) ?? ($0["id"] as? String) ?? "Router" })
                    if let idx = self.routerIDs.firstIndex(of: selected) { self.routerPopup.selectItem(at: idx) }
                    self.nodesText.string = profiles.map { p in
                        let name = (p["name"] as? String) ?? (p["id"] as? String) ?? "Router"
                        let endpoint = p["endpoint"] as? String ?? "—"
                        let dns = p["dns_host"] as? String ?? "—"
                        let ip = p["public_ip"] as? String ?? "—"
                        return "\(name)\n  endpoint: \(endpoint)\n  DNS: \(dns)\n  public exit: \(ip)"
                    }.joined(separator: "\n\n")
                }
            } catch { DispatchQueue.main.async { self.errorLabel.stringValue = error.localizedDescription } }
        }
    }

    func refreshModes() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            do {
                guard let modes = try api.json("/api/logical-modes", timeout: 12) as? [[String: Any]] else { return }
                let ready = modes.filter { $0["available"] as? Bool == true }
                DispatchQueue.main.async {
                    self.modeIDs = ready.compactMap { $0["id"] as? String }
                    self.modePopup.removeAllItems()
                    self.modePopup.addItems(withTitles: ready.map { $0["name"] as? String ?? $0["id"] as? String ?? "Mode" })
                    if !self.modeIDs.isEmpty { self.modePopup.selectItem(at: 0) }
                    self.methodsText.string = modes.map { m in
                        let ok = m["available"] as? Bool ?? false
                        let name = m["name"] as? String ?? m["id"] as? String ?? "Mode"
                        let reason = m["reason"] as? String ?? "Ready"
                        return "\(ok ? "✓" : "—") \(name)\n  \(reason)"
                    }.joined(separator: "\n\n")
                }
            } catch { DispatchQueue.main.async { self.errorLabel.stringValue = error.localizedDescription } }
        }
    }

    func appendDiagnostic(_ message: String) {
        let f = DateFormatter(); f.dateFormat = "HH:mm:ss"
        diagnosticsText.textStorage?.append(NSAttributedString(string: "[\(f.string(from: Date()))] \(message.trimmingCharacters(in: .whitespacesAndNewlines))\n"))
        diagnosticsText.scrollToEndOfDocument(nil)
    }
}

final class RouterVPNAppDelegate: NSObject, NSApplicationDelegate {
    let api = RouterVPNAPI()
    var windowController: RouterVPNWindowController?
    var controller: Process?
    var ownsController = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        do {
            try ensureController()
            let wc = RouterVPNWindowController(api: api)
            windowController = wc
            wc.showWindow(nil)
            wc.window?.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
        } catch {
            let alert = NSAlert(); alert.alertStyle = .critical; alert.messageText = "Router VPN could not start"; alert.informativeText = error.localizedDescription; alert.runModal(); NSApp.terminate(nil)
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    func applicationWillTerminate(_ notification: Notification) {
        guard ownsController else { return }
        _ = try? api.request("/api/emergency-stop", method: "POST", body: [:], timeout: 2)
        if let controller, controller.isRunning { controller.terminate() }
    }

    func ensureController() throws {
        if api.ready() { return }
        let root = Bundle.main.bundleURL.deletingLastPathComponent()
        let binary = root.appendingPathComponent("router-vpn-client")
        let config = root.appendingPathComponent("client.json")
        guard FileManager.default.isExecutableFile(atPath: binary.path), FileManager.default.fileExists(atPath: config.path) else {
            throw NSError(domain: "RouterVPNMac", code: 10, userInfo: [NSLocalizedDescriptionKey: "RouterVPN.app must stay beside router-vpn-client and client.json in its package."])
        }
        let process = Process()
        process.executableURL = binary
        process.currentDirectoryURL = root
        var env = ProcessInfo.processInfo.environment
        env["HOMEVPN_ROOT"] = root.path
        env["HOMEVPN_CLIENT_CONFIG"] = config.path
        env["HOMEVPN_NATIVE_APP"] = "macos-appkit"
        process.environment = env
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        controller = process
        ownsController = true
        let deadline = Date().addingTimeInterval(12)
        while Date() < deadline {
            if api.ready() { return }
            if !process.isRunning { break }
            Thread.sleep(forTimeInterval: 0.2)
        }
        if process.isRunning { process.terminate() }
        throw NSError(domain: "RouterVPNMac", code: 11, userInfo: [NSLocalizedDescriptionKey: "Local Router VPN controller did not become ready on 127.0.0.1:8788."])
    }
}

func runSelfTest() -> Int32 {
    let requiredPaths = ["/api/status", "/api/profiles", "/api/logical-modes", "/api/auto", "/api/connect-logical", "/api/disconnect", "/api/profile/select", "/api/public-ip", "/api/dns/retest", "/api/emergency-stop"]
    guard routerVPNBaseURL.absoluteString == "http://127.0.0.1:8788", nativeAppContractVersion == 1, requiredPaths.count == 10 else { return 2 }
    print("Router VPN native macOS AppKit self-test: OK")
    return 0
}

if CommandLine.arguments.contains("--self-test") { exit(runSelfTest()) }
let app = NSApplication.shared
let delegate = RouterVPNAppDelegate()
app.delegate = delegate
app.run()
