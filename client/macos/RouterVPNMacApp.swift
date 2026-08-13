import AppKit
import Foundation

private let routerVPNBaseURL = URL(string: "http://127.0.0.1:8788")!
private let nativeAppContractVersion = 1

private struct StatusPayload: Decodable {
    let connected: Bool?
    let mode: String?
    let logical_mode: String?
    let runtime_mode: String?
    let base: String?
    let router_id: String?
    let phase: String?
    let last_error: String?
}

private struct RouterProfile: Decodable {
    let id: String
    let name: String?
    let endpoint: String?
    let dns_host: String?
    let latency_median_ms: Double?
    let public_ip: String?
}

private struct ProfileStore: Decodable {
    let selected_id: String?
    let profiles: [RouterProfile]
}

private struct LogicalMode: Decodable {
    let id: String
    let name: String
    let available: Bool
    let reason: String?
    let ready_bases: [String]?
}

private final class LocalControllerAPI {
    private let session: URLSession

    init() {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 8
        config.timeoutIntervalForResource = 12
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        config.connectionProxyDictionary = [:]
        session = URLSession(configuration: config)
    }

    func request(path: String, method: String = "GET", body: [String: Any]? = nil, timeout: TimeInterval = 12) throws -> Data {
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
        var resultData: Data?
        var resultResponse: URLResponse?
        var resultError: Error?
        let task = session.dataTask(with: request) { data, response, error in
            resultData = data
            resultResponse = response
            resultError = error
            semaphore.signal()
        }
        task.resume()
        if semaphore.wait(timeout: .now() + timeout + 2) == .timedOut {
            task.cancel()
            throw NSError(domain: "RouterVPNMac", code: 2, userInfo: [NSLocalizedDescriptionKey: "Local controller request timed out"])
        }
        if let resultError { throw resultError }
        guard let http = resultResponse as? HTTPURLResponse,
              (200..<300).contains(http.statusCode) else {
            let text = resultData.flatMap { String(data: $0, encoding: .utf8) } ?? ""
            throw NSError(domain: "RouterVPNMac", code: 3, userInfo: [NSLocalizedDescriptionKey: text.isEmpty ? "Local controller request failed" : text.trimmingCharacters(in: .whitespacesAndNewlines)])
        }
        return resultData ?? Data()
    }

    func decode<T: Decodable>(_ type: T.Type, path: String) throws -> T {
        try JSONDecoder().decode(type, from: request(path: path))
    }

    func isReady() -> Bool {
        (try? request(path: "/api/status", timeout: 1)) != nil
    }
}

private final class RouterVPNWindowController: NSWindowController {
    private let api: LocalControllerAPI
    private let statusLabel = NSTextField(labelWithString: "Checking local controller…")
    private let detailLabel = NSTextField(wrappingLabelWithString: "")
    private let errorLabel = NSTextField(wrappingLabelWithString: "")
    private let routerPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let modePopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let basePopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let nodesText = NSTextView()
    private let methodsText = NSTextView()
    private let diagnosticsText = NSTextView()
    private var profiles: [RouterProfile] = []
    private var modes: [LogicalMode] = []
    private var refreshTimer: Timer?

    init(api: LocalControllerAPI) {
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
        refreshTimer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            self?.refreshStatus()
        }
    }

    required init?(coder: NSCoder) { nil }

    deinit { refreshTimer?.invalidate() }

    private func makeButton(_ title: String, action: Selector) -> NSButton {
        let button = NSButton(title: title, target: self, action: action)
        button.bezelStyle = .rounded
        button.controlSize = .large
        return button
    }

    private func buildUI() {
        guard let content = window?.contentView else { return }
        let root = NSStackView()
        root.orientation = .vertical
        root.spacing = 14
        root.edgeInsets = NSEdgeInsets(top: 18, left: 18, bottom: 18, right: 18)
        root.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(root)
        NSLayoutConstraint.activate([
            root.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            root.trailingAnchor.constraint(equalTo: content.trailingAnchor),
            root.topAnchor.constraint(equalTo: content.topAnchor),
            root.bottomAnchor.constraint(equalTo: content.bottomAnchor),
        ])

        let titleRow = NSStackView()
        titleRow.orientation = .horizontal
        titleRow.alignment = .centerY
        let title = NSTextField(labelWithString: "Router VPN")
        title.font = .systemFont(ofSize: 30, weight: .bold)
        statusLabel.font = .systemFont(ofSize: 14, weight: .semibold)
        titleRow.addArrangedSubview(title)
        titleRow.addArrangedSubview(NSView())
        titleRow.addArrangedSubview(statusLabel)
        root.addArrangedSubview(titleRow)

        detailLabel.textColor = .secondaryLabelColor
        errorLabel.textColor = .systemRed
        root.addArrangedSubview(detailLabel)
        root.addArrangedSubview(errorLabel)

        let tabs = NSTabViewController()
        tabs.tabStyle = .segmentedControlOnTop
        tabs.addTabViewItem(NSTabViewItem(viewController: connectController()))
        tabs.tabViewItems[0].label = "Connect"
        tabs.addTabViewItem(NSTabViewItem(viewController: textController(nodesText)))
        tabs.tabViewItems[1].label = "Nodes"
        tabs.addTabViewItem(NSTabViewItem(viewController: textController(methodsText)))
        tabs.tabViewItems[2].label = "Methods"
        tabs.addTabViewItem(NSTabViewItem(viewController: diagnosticsController()))
        tabs.tabViewItems[3].label = "Diagnostics"
        root.addArrangedSubview(tabs.view)
        tabs.view.heightAnchor.constraint(greaterThanOrEqualToConstant: 480).isActive = true
    }

    private func connectController() -> NSViewController {
        let vc = NSViewController()
        let stack = NSStackView()
        stack.orientation = .vertical
        stack.spacing = 12
        stack.edgeInsets = NSEdgeInsets(top: 22, left: 28, bottom: 22, right: 28)
        stack.translatesAutoresizingMaskIntoConstraints = false
        vc.view = NSView()
        vc.view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: vc.view.leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: vc.view.trailingAnchor),
            stack.topAnchor.constraint(equalTo: vc.view.topAnchor),
        ])

        stack.addArrangedSubview(NSTextField(labelWithString: "Router"))
        routerPopup.target = self
        routerPopup.action = #selector(selectRouter)
        stack.addArrangedSubview(routerPopup)
        stack.addArrangedSubview(NSTextField(labelWithString: "Mode"))
        stack.addArrangedSubview(modePopup)
        stack.addArrangedSubview(NSTextField(labelWithString: "Tunnel base"))
        basePopup.addItems(withTitles: ["Auto", "WireGuard", "AmneziaWG"])
        stack.addArrangedSubview(basePopup)

        let buttons = NSStackView()
        buttons.orientation = .horizontal
        buttons.spacing = 10
        buttons.addArrangedSubview(makeButton("AUTO Connect", action: #selector(autoConnect)))
        buttons.addArrangedSubview(makeButton("Connect Selected", action: #selector(connectSelected)))
        buttons.addArrangedSubview(makeButton("Disconnect", action: #selector(disconnect)))
        buttons.addArrangedSubview(makeButton("Refresh", action: #selector(refreshAction)))
        stack.addArrangedSubview(buttons)

        let proof = NSTextField(wrappingLabelWithString: "Connected is shown only after the controller validates the exact selected Router VPN node identity on its private proof path.")
        proof.textColor = .secondaryLabelColor
        stack.addArrangedSubview(proof)
        return vc
    }

    private func textController(_ textView: NSTextView) -> NSViewController {
        let vc = NSViewController()
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        textView.isEditable = false
        textView.isSelectable = true
        textView.font = .monospacedSystemFont(ofSize: 13, weight: .regular)
        textView.textContainerInset = NSSize(width: 14, height: 14)
        scroll.documentView = textView
        vc.view = scroll
        return vc
    }

    private func diagnosticsController() -> NSViewController {
        let vc = NSViewController()
        let stack = NSStackView()
        stack.orientation = .vertical
        stack.spacing = 12
        stack.edgeInsets = NSEdgeInsets(top: 18, left: 18, bottom: 18, right: 18)
        stack.translatesAutoresizingMaskIntoConstraints = false
        vc.view = NSView()
        vc.view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: vc.view.leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: vc.view.trailingAnchor),
            stack.topAnchor.constraint(equalTo: vc.view.topAnchor),
            stack.bottomAnchor.constraint(equalTo: vc.view.bottomAnchor),
        ])
        let row = NSStackView()
        row.orientation = .horizontal
        row.addArrangedSubview(makeButton("Prove public VPN exit", action: #selector(publicExit)))
        row.addArrangedSubview(makeButton("Retest home-exit DNS", action: #selector(retestDNS)))
        row.addArrangedSubview(makeButton("Emergency stop", action: #selector(emergencyStop)))
        stack.addArrangedSubview(row)
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        diagnosticsText.isEditable = false
        diagnosticsText.isSelectable = true
        diagnosticsText.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        scroll.documentView = diagnosticsText
        stack.addArrangedSubview(scroll)
        return vc
    }

    private func runAsync(_ operation: @escaping () throws -> String) {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do {
                let message = try operation()
                DispatchQueue.main.async {
                    self?.appendDiagnostic(message)
                    self?.refreshAll()
                }
            } catch {
                DispatchQueue.main.async {
                    self?.errorLabel.stringValue = error.localizedDescription
                    self?.appendDiagnostic("ERROR: \(error.localizedDescription)")
                    self?.refreshStatus()
                }
            }
        }
    }

    @objc private func refreshAction() { refreshAll() }

    @objc private func autoConnect() {
        runAsync {
            let data = try self.api.request(path: "/api/auto", method: "POST", body: [:], timeout: 150)
            return "AUTO: " + (String(data: data, encoding: .utf8) ?? "connected")
        }
    }

    @objc private func connectSelected() {
        guard let item = modePopup.selectedItem,
              let index = modePopup.indexOfSelectedItem as Int?,
              index >= 0, index < modes.count else { return }
        let mode = modes[index]
        let base = ["auto", "wg", "awg"][max(0, min(basePopup.indexOfSelectedItem, 2))]
        runAsync {
            let data = try self.api.request(path: "/api/connect-logical", method: "POST", body: ["mode": mode.id, "base": base], timeout: 180)
            return "Connect: " + (String(data: data, encoding: .utf8) ?? "ok")
        }
    }

    @objc private func disconnect() {
        runAsync {
            _ = try self.api.request(path: "/api/disconnect", method: "POST", body: [:], timeout: 20)
            return "Disconnected."
        }
    }

    @objc private func selectRouter() {
        let index = routerPopup.indexOfSelectedItem
        guard index >= 0, index < profiles.count else { return }
        let profile = profiles[index]
        runAsync {
            _ = try self.api.request(path: "/api/profile/select", method: "POST", body: ["id": profile.id])
            return "Selected node: \(profile.name ?? profile.id)"
        }
    }

    @objc private func publicExit() {
        runAsync {
            let data = try self.api.request(path: "/api/public-ip", timeout: 20)
            return "Public exit: " + (String(data: data, encoding: .utf8) ?? "")
        }
    }

    @objc private func retestDNS() {
        runAsync {
            let data = try self.api.request(path: "/api/dns/retest", method: "POST", body: [:], timeout: 90)
            return "DNS: " + (String(data: data, encoding: .utf8) ?? "")
        }
    }

    @objc private func emergencyStop() {
        runAsync {
            _ = try self.api.request(path: "/api/emergency-stop", method: "POST", body: [:], timeout: 20)
            return "Emergency stop completed."
        }
    }

    private func refreshAll() {
        refreshStatus()
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            do {
                let store = try api.decode(ProfileStore.self, path: "/api/profiles")
                let modes = try api.decode([LogicalMode].self, path: "/api/logical-modes")
                DispatchQueue.main.async {
                    self.profiles = store.profiles
                    self.modes = modes.filter { $0.available }
                    self.routerPopup.removeAllItems()
                    self.routerPopup.addItems(withTitles: store.profiles.map { $0.name ?? $0.id })
                    if let selected = store.selected_id,
                       let index = store.profiles.firstIndex(where: { $0.id == selected }) {
                        self.routerPopup.selectItem(at: index)
                    }
                    self.modePopup.removeAllItems()
                    self.modePopup.addItems(withTitles: self.modes.map { $0.name })
                    self.nodesText.string = store.profiles.map {
                        "\($0.name ?? $0.id)\n  endpoint: \($0.endpoint ?? "—")\n  DNS: \($0.dns_host ?? "—")\n  median: \($0.latency_median_ms.map { String(format: "%.2f ms", $0) } ?? "—")\n  public exit: \($0.public_ip ?? "—")"
                    }.joined(separator: "\n\n")
                    self.methodsText.string = modes.map {
                        "\($0.available ? "✓" : "—") \($0.name) [\($0.id)]\n  bases: \(($0.ready_bases ?? []).joined(separator: ", "))\n  \($0.reason ?? "Ready")"
                    }.joined(separator: "\n\n")
                }
            } catch {
                DispatchQueue.main.async { self.errorLabel.stringValue = error.localizedDescription }
            }
        }
    }

    private func refreshStatus() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            do {
                let status = try api.decode(StatusPayload.self, path: "/api/status")
                DispatchQueue.main.async {
                    let connected = status.connected ?? false
                    self.statusLabel.stringValue = connected ? "● Connected" : "○ \(status.phase ?? "Off")"
                    self.statusLabel.textColor = connected ? .systemGreen : .secondaryLabelColor
                    self.detailLabel.stringValue = "Logical: \(status.logical_mode ?? "—")   Runtime: \(status.runtime_mode ?? status.mode ?? "—")   Base: \(status.base ?? "—")   Router: \(status.router_id ?? "—")"
                    self.errorLabel.stringValue = status.last_error ?? ""
                }
            } catch {
                DispatchQueue.main.async {
                    self.statusLabel.stringValue = "● Controller unavailable"
                    self.statusLabel.textColor = .systemRed
                    self.errorLabel.stringValue = error.localizedDescription
                }
            }
        }
    }

    private func appendDiagnostic(_ message: String) {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        let line = "[\(formatter.string(from: Date()))] \(message)\n"
        diagnosticsText.textStorage?.append(NSAttributedString(string: line))
        diagnosticsText.scrollToEndOfDocument(nil)
    }
}

private final class RouterVPNAppDelegate: NSObject, NSApplicationDelegate {
    private let api = LocalControllerAPI()
    private var windowController: RouterVPNWindowController?
    private var controllerProcess: Process?
    private var ownsController = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        do {
            try ensureController()
            let controller = RouterVPNWindowController(api: api)
            windowController = controller
            controller.showWindow(nil)
            controller.window?.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
        } catch {
            let alert = NSAlert()
            alert.alertStyle = .critical
            alert.messageText = "Router VPN could not start"
            alert.informativeText = error.localizedDescription
            alert.runModal()
            NSApp.terminate(nil)
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    func applicationWillTerminate(_ notification: Notification) {
        guard ownsController else { return }
        _ = try? api.request(path: "/api/emergency-stop", method: "POST", body: [:], timeout: 2)
        if let process = controllerProcess, process.isRunning {
            process.terminate()
            let deadline = Date().addingTimeInterval(2)
            while process.isRunning && Date() < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.05)) }
            if process.isRunning { process.interrupt() }
        }
    }

    private func ensureController() throws {
        if api.isReady() { return }
        let packageRoot = Bundle.main.bundleURL.deletingLastPathComponent()
        let controllerURL = packageRoot.appendingPathComponent("router-vpn-client")
        let configURL = packageRoot.appendingPathComponent("client.json")
        guard FileManager.default.isExecutableFile(atPath: controllerURL.path),
              FileManager.default.fileExists(atPath: configURL.path) else {
            throw NSError(domain: "RouterVPNMac", code: 10, userInfo: [NSLocalizedDescriptionKey: "This RouterVPN.app must stay beside its generic Router VPN macOS runtime files."])
        }
        let process = Process()
        process.executableURL = controllerURL
        process.currentDirectoryURL = packageRoot
        var environment = ProcessInfo.processInfo.environment
        environment["HOMEVPN_ROOT"] = packageRoot.path
        environment["HOMEVPN_CLIENT_CONFIG"] = configURL.path
        environment["HOMEVPN_NATIVE_APP"] = "macos-appkit"
        process.environment = environment
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        controllerProcess = process
        ownsController = true
        let deadline = Date().addingTimeInterval(12)
        while Date() < deadline {
            if api.isReady() { return }
            if !process.isRunning { break }
            Thread.sleep(forTimeInterval: 0.2)
        }
        if process.isRunning { process.terminate() }
        throw NSError(domain: "RouterVPNMac", code: 11, userInfo: [NSLocalizedDescriptionKey: "Local Router VPN controller did not become ready on 127.0.0.1:8788."])
    }
}

private func runSelfTest() -> Int32 {
    guard routerVPNBaseURL.absoluteString == "http://127.0.0.1:8788" else { return 2 }
    guard nativeAppContractVersion == 1 else { return 3 }
    let requiredPaths = [
        "/api/status", "/api/profiles", "/api/logical-modes", "/api/auto",
        "/api/connect-logical", "/api/disconnect", "/api/profile/select",
        "/api/public-ip", "/api/dns/retest", "/api/emergency-stop",
    ]
    guard requiredPaths.count == 10 else { return 4 }
    print("Router VPN native macOS AppKit self-test: OK")
    return 0
}

if CommandLine.arguments.contains("--self-test") {
    exit(runSelfTest())
}

let app = NSApplication.shared
let delegate = RouterVPNAppDelegate()
app.delegate = delegate
app.run()
