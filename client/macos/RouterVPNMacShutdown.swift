import Foundation
import CoreFoundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(AppKit)
import AppKit
#endif

struct RouterVPNMacShutdownIdentity: Equatable, Sendable {
    let processID: Int32
    let token: String

    var valid: Bool {
        processID > 0 && token.utf8.count == 32 && token.utf8.allSatisfy {
            (48...57).contains($0) || (97...102).contains($0)
        }
    }
    var body: [String: Any] { ["schema": 1, "process_id": Int(processID), "owner_token": token] }

    func accepts(_ data: Data) -> Bool {
        // The controller emits a flat, bounded receipt. Reject escaped/duplicate
        // members as well as foreign or merely truthy identities.
        guard valid, !data.isEmpty, data.count <= 4096,
              let text = String(data: data, encoding: .utf8), !text.contains("\\"),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == ["schema", "process_id", "owner_token", "closed"],
              let schema = object["schema"] as? NSNumber,
              CFGetTypeID(schema) != CFBooleanGetTypeID(), schema.stringValue == "1",
              let pid = object["process_id"] as? NSNumber,
              CFGetTypeID(pid) != CFBooleanGetTypeID(), pid.stringValue == String(processID),
              object["owner_token"] as? String == token,
              let closed = object["closed"] as? NSNumber,
              CFGetTypeID(closed) == CFBooleanGetTypeID(), closed.boolValue else { return false }
        for name in ["schema", "process_id", "owner_token", "closed"] {
            if text.components(separatedBy: "\"" + name + "\"").count != 2 { return false }
        }
        return true
    }
}

struct RouterVPNMacShutdownReply: Sendable { let code: Int; let data: Data }
protocol RouterVPNMacShutdownRequest: AnyObject { func start(); func cancel() }
protocol RouterVPNMacShutdownProcess: AnyObject {
    var processIdentifier: Int32 { get }
    var isRunning: Bool { get }
    var joinedSuccessfully: Bool { get }
    var joinFailure: String? { get }
    var retiredBeforeReady: Bool { get }
}
extension RouterVPNMacShutdownProcess {
    var joinedSuccessfully: Bool { !isRunning }
    var joinFailure: String? { nil }
    var retiredBeforeReady: Bool { false }
}
extension Process: RouterVPNMacShutdownProcess {
    var joinedSuccessfully: Bool { !isRunning && terminationReason == .exit && terminationStatus == 0 }
}

// A separate session owns this one terminal request. Its buffer, task and
// completion are protected by lock; redirect refusal keeps the launch nonce local.
final class RouterVPNMacShutdownTransport: NSObject, RouterVPNMacShutdownRequest, URLSessionDataDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var session: URLSession?
    private var task: URLSessionDataTask?
    private var bytes = Data()
    private var code = 0
    private var failure: Error?
    private var completion: ((Result<RouterVPNMacShutdownReply, Error>) -> Void)?
    private var finished = false
    private static let limit = 4096

    init(url: URL, identity: RouterVPNMacShutdownIdentity, timeout: TimeInterval,
         completion: @escaping (Result<RouterVPNMacShutdownReply, Error>) -> Void) throws {
        guard identity.valid, url.scheme == "http", url.host == "127.0.0.1", url.port != nil,
              url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
              url.path == "/api/controller/shutdown", timeout >= 35, timeout <= 60 else {
            throw NSError(domain: "RouterVPNShutdown", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "Invalid owned controller shutdown request."])
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"; request.timeoutInterval = timeout
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: identity.body)
        try RouterVPNMacLocalAuthorization.shared.authorize(&request)
        self.completion = completion
        super.init()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.connectionProxyDictionary = [:]; configuration.urlCache = nil
        configuration.httpCookieStorage = nil; configuration.httpShouldSetCookies = false
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.timeoutIntervalForRequest = timeout; configuration.timeoutIntervalForResource = timeout
        let queue = OperationQueue(); queue.maxConcurrentOperationCount = 1
        let owned = URLSession(configuration: configuration, delegate: self, delegateQueue: queue)
        session = owned; task = owned.dataTask(with: request)
    }
    func start() { lock.lock(); let owned = finished ? nil : task; lock.unlock(); owned?.resume() }
    func cancel() { lock.lock(); let owned = finished ? nil : task; lock.unlock(); owned?.cancel() }
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        lock.lock()
        guard !finished else { lock.unlock(); completionHandler(.cancel); return }
        code = (response as? HTTPURLResponse)?.statusCode ?? 0
        let oversized = response.expectedContentLength > Int64(Self.limit)
        if oversized { failure = Self.sizeError() }
        lock.unlock(); completionHandler(oversized ? .cancel : .allow)
        if oversized { finish(nil, cancelOwned: true) }
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        let oversized = bytes.count > Self.limit - data.count
        if oversized { failure = Self.sizeError() } else { bytes.append(data) }
        lock.unlock()
        if oversized { finish(nil, cancelOwned: true) }
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        finish(error, cancelOwned: false)
    }
    private static func sizeError() -> NSError {
        NSError(domain: "RouterVPNShutdown", code: 2,
                userInfo: [NSLocalizedDescriptionKey: "Controller shutdown response exceeded its size limit."])
    }
    private func finish(_ error: Error?, cancelOwned: Bool) {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        finished = true
        let callback = completion; completion = nil
        let reply = RouterVPNMacShutdownReply(code: code, data: bytes); bytes.removeAll()
        let resultError = failure ?? error
        let ownedTask = task, ownedSession = session; task = nil; session = nil
        lock.unlock()
        if cancelOwned { ownedTask?.cancel(); ownedSession?.invalidateAndCancel() }
        else { ownedSession?.finishTasksAndInvalidate() }
        if let resultError { callback?(.failure(resultError)) } else { callback?(.success(reply)) }
    }
}

@MainActor final class RouterVPNMacShutdownController {
    typealias Factory = (URL, RouterVPNMacShutdownIdentity, TimeInterval,
                         @escaping (Result<RouterVPNMacShutdownReply, Error>) -> Void) throws -> RouterVPNMacShutdownRequest
    enum Phase { case idle, requesting, waitingForProcess, failed, complete }
    let identity: RouterVPNMacShutdownIdentity
    let process: RouterVPNMacShutdownProcess
    private let baseURL: URL
    private let factory: Factory
    private let isCurrent: () -> Bool
    private let pollInterval: TimeInterval
    private let exitTimeout: TimeInterval
    private var request: RouterVPNMacShutdownRequest?
    private var timer: Timer?
    private var generation = UUID()
    private var replyPending = false
    private var launchCanceled = false
    private var exitDeadline = Date.distantPast
    private(set) var acknowledged = false
    private(set) var phase = Phase.idle
    private(set) var message = ""
    var onUpdate: (() -> Void)?
    var onFinish: ((Bool) -> Void)?

    init(baseURL: URL, identity: RouterVPNMacShutdownIdentity, process: RouterVPNMacShutdownProcess,
         pollInterval: TimeInterval = 0.1, exitTimeout: TimeInterval = 15,
         isCurrent: @escaping () -> Bool,
         factory: @escaping Factory = { try RouterVPNMacShutdownTransport(url: $0, identity: $1, timeout: $2, completion: $3) }) {
        self.baseURL = baseURL; self.identity = identity; self.process = process; self.isCurrent = isCurrent
        self.factory = factory; self.pollInterval = pollInterval; self.exitTimeout = exitTimeout
    }
    var pending: Bool { replyPending }
    func start() {
        guard !replyPending else { onUpdate?(); return }
        replyPending = true; generation = UUID()
        let captured = generation
        // AppKit must receive terminateLater before we ever send its reply.
        DispatchQueue.main.async { [weak self] in self?.begin(captured) }
    }
    private func owned() -> Bool { identity.valid && process.processIdentifier == identity.processID && isCurrent() }
    private func begin(_ captured: UUID) {
        guard generation == captured, replyPending else { return }
        guard owned() else { fail("The controller owner changed. Router VPN remains open."); return }
        if let failure = process.joinFailure { fail(failure); return }
        // A startup that never proved HTTP ownership closes only its captured
        // lifetime write half. Its independent root supervisor must still
        // authenticate a successful actual process join before Quit succeeds.
        if process.retiredBeforeReady { launchCanceled = true; waitForExit(); return }
        if acknowledged || launchCanceled { waitForExit(); return }
        guard process.isRunning else { fail("The controller exited before confirming cleanup. Router VPN remains open."); return }
        phase = .requesting; message = "Stopping the owned connection and waiting for cleanup…"; onUpdate?()
        do {
            let url = baseURL.appendingPathComponent("api/controller/shutdown")
            request = try factory(url, identity, 35) { [weak self] result in
                DispatchQueue.main.async { self?.received(result, captured: captured) }
            }
            request?.start()
        } catch { fail("The controller shutdown request could not start. Retry to check cleanup.") }
    }
    private func received(_ result: Result<RouterVPNMacShutdownReply, Error>, captured: UUID) {
        guard generation == captured, replyPending, phase == .requesting else { return }
        request = nil
        guard owned() else { fail("The controller owner changed. Router VPN remains open."); return }
        switch result {
        case .success(let reply) where reply.code == 200 && identity.accepts(reply.data):
            acknowledged = true; waitForExit()
        case .success(let reply) where reply.code == 503:
            fail("Cleanup is still pending. Retry to wait for the same controller; it has retained the connection owner.")
        case .success:
            fail("The controller did not confirm cleanup for this app. Router VPN remains open; retry to check again.")
        case .failure:
            fail("The shutdown request ended without a cleanup confirmation. Router VPN remains open; retry to check again.")
        }
    }
    private func waitForExit() {
        guard owned(), acknowledged || launchCanceled else { fail("The controller owner changed. Router VPN remains open."); return }
        if let failure = process.joinFailure { fail(failure); return }
        if !process.isRunning && !process.joinedSuccessfully { fail("The controller exited without proving successful cleanup. Router VPN remains open."); return }
        if !process.isRunning { finish(); return }
        phase = .waitingForProcess
        message = launchCanceled ? "Startup was canceled. Waiting for the privileged supervisor to confirm the captured controller drained and joined…" : "Connection cleanup is confirmed. Waiting for the owned controller to exit…"
        exitDeadline = Date().addingTimeInterval(exitTimeout); onUpdate?()
        timer?.invalidate()
        let timer = Timer(timeInterval: pollInterval, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.poll() }
        }
        self.timer = timer
        RunLoop.main.add(timer, forMode: .common)
        #if canImport(AppKit)
        RunLoop.main.add(timer, forMode: .modalPanel)
        #endif
    }
    private func poll() {
        guard replyPending, phase == .waitingForProcess else { return }
        guard owned() else { fail("The controller owner changed. Router VPN remains open."); return }
        if let failure = process.joinFailure { fail(failure) }
        else if !process.isRunning && !process.joinedSuccessfully { fail("The controller exited without proving successful cleanup. Router VPN remains open.") }
        else if !process.isRunning { finish() }
        else if Date() >= exitDeadline { fail("Cleanup was confirmed, but the controller is still exiting. Retry to wait; it has not been terminated.") }
    }
    private func finish() {
        timer?.invalidate(); timer = nil
        guard replyPending, acknowledged || launchCanceled, owned(), !process.isRunning, process.joinedSuccessfully else { return }
        phase = .complete; message = "Owned controller cleanup and exit confirmed."
        replyPending = false; onUpdate?(); onFinish?(true)
    }
    private func fail(_ text: String) {
        timer?.invalidate(); timer = nil; request?.cancel(); request = nil
        phase = .failed; message = text
        let notify = replyPending; replyPending = false; onUpdate?()
        if notify { onFinish?(false) }
    }
    func retire() {
        generation = UUID(); timer?.invalidate(); timer = nil; request?.cancel(); request = nil
        let notify = replyPending; replyPending = false; phase = .failed
        message = "This shutdown attempt no longer owns the controller."
        onUpdate?(); if notify { onFinish?(false) }
    }
}

#if canImport(AppKit)
@MainActor final class RouterVPNMacShutdownPanel: NSWindowController {
    let detail = NSTextField(wrappingLabelWithString: "Stopping the owned connection…")
    let progress = NSProgressIndicator()
    let retry = NSButton(title: "Retry shutdown", target: nil, action: nil)
    var onRetry: (() -> Void)?
    init() {
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 510, height: 190),
                            styleMask: [.titled], backing: .buffered, defer: false)
        panel.title = "Closing Router VPN"; panel.isReleasedWhenClosed = false; panel.center()
        super.init(window: panel)
        let title = NSTextField(labelWithString: "Waiting for connection cleanup")
        title.font = .boldSystemFont(ofSize: 15)
        detail.maximumNumberOfLines = 4
        progress.style = .spinning; progress.controlSize = .small
        retry.target = self; retry.action = #selector(retryShutdown)
        let row = NSStackView(views: [progress, retry]); row.orientation = .horizontal; row.spacing = 12
        let stack = NSStackView(views: [title, detail, row]); stack.orientation = .vertical; stack.alignment = .leading; stack.spacing = 16
        stack.translatesAutoresizingMaskIntoConstraints = false
        panel.contentView?.addSubview(stack)
        if let content = panel.contentView { NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            stack.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -20),
            stack.topAnchor.constraint(equalTo: content.topAnchor, constant: 20),
            stack.bottomAnchor.constraint(lessThanOrEqualTo: content.bottomAnchor, constant: -20)]) }
    }
    required init?(coder: NSCoder) { nil }
    func present(_ controller: RouterVPNMacShutdownController) {
        detail.stringValue = controller.message
        retry.isEnabled = !controller.pending
        retry.isHidden = controller.phase == .complete
        if controller.pending { progress.startAnimation(nil) } else { progress.stopAnimation(nil) }
        showWindow(nil); window?.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
    }
    @objc func retryShutdown() { onRetry?() }
}
#endif
