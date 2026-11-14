import Foundation

private func orderedLatencyIssue(_ message: String) -> NSError {
    NSError(domain: "RouterVPNOrderedLatency", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
}

struct RouterVPNOrderedCapture: Codable, Equatable {
    let session_id, profile_id, profile_token, source_sha256, config_sha256, generation_sha256: String
    static func hex(_ value: String, count: Int = 64) -> Bool {
        value.utf8.count == count && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    static func text(_ value: String, maximum: Int = 128) -> Bool {
        !value.isEmpty && value.utf8.count <= maximum && !value.unicodeScalars.contains { $0.value < 32 || $0.value == 127 }
    }
    static func session(_ value: String) -> Bool {
        value.utf8.count <= 64 && value.range(of: "^session-[0-9]+-[0-9]+$", options: .regularExpression) != nil
    }
    func validate() throws {
        guard Self.session(session_id), Self.text(profile_id),
              [profile_token, source_sha256, config_sha256, generation_sha256].allSatisfy({ Self.hex($0) }) else {
            throw orderedLatencyIssue("The connected route has no complete measurement identity.")
        }
    }
    var body: [String: Any] {
        ["session_id": session_id, "profile_id": profile_id, "profile_token": profile_token,
         "source_sha256": source_sha256, "config_sha256": config_sha256, "generation_sha256": generation_sha256]
    }
}

struct RouterVPNOrderedLatencyNode: Decodable, Equatable {
    let node_id, kind, role, label, measurement: String
    let position: Int
    var timingLabel: String { kind == "private-node" ? "HTTP response including connection" : "HTTPS response after TLS" }
    func receiptLabel(count: Int) -> String { kind == "public-path" ? "Cumulative path through custom node 2 of 3 → Cloudflare edge" : "Cumulative path through node \(position + 1) of \(count)" }
    func validate(count: Int = 3) throws {
        let expectedRole = position == 0 ? "entry" : position == count - 1 ? "exit" : "intermediate"
        let isPublic = kind == "public-path"
        guard RouterVPNOrderedCapture.text(node_id), RouterVPNOrderedCapture.text(label, maximum: 256),
              (2...8).contains(count), position >= 0, position < count, role == expectedRole,
              kind == "private-node" || isPublic && count == 3 && position == 1,
              measurement == (isPublic ? "routed-https-response-after-tls" : "routed-private-response-including-connection") else {
            throw orderedLatencyIssue("A measured hop changed its original position or timing method.")
        }
    }
}

struct RouterVPNOrderedLatencyReceipt: Decodable {
    struct Distribution: Decodable {
        let samples: Int
        let min_ms, median_ms, average_ms, p90_ms, max_ms, jitter_ms: Double
    }
    struct Benchmark: Decodable {
        let schema, attempts, failed: Int
        let measurement: String
        let endpoint: String?
        let trimmed_mean_ms: Double
        let distribution: Distribution
    }
    struct Result: Decodable {
        let node_id, role, kind, label: String
        let ready: Bool
        let failure: String?
        let benchmark: Benchmark
        enum CodingKeys: String, CodingKey { case node_id, role, kind, label, ready, failure, benchmark, idle, download, upload, response }
        init(from decoder: Decoder) throws {
            let values = try decoder.container(keyedBy: CodingKeys.self)
            for key in [CodingKeys.idle, .download, .upload, .response] {
                if values.contains(key), try !values.decodeNil(forKey: key) {
                    throw orderedLatencyIssue("A response-time receipt contains a different measurement.")
                }
            }
            node_id = try values.decode(String.self, forKey: .node_id); role = try values.decode(String.self, forKey: .role)
            kind = try values.decode(String.self, forKey: .kind); label = try values.decode(String.self, forKey: .label)
            ready = try values.decode(Bool.self, forKey: .ready); failure = try values.decodeIfPresent(String.self, forKey: .failure)
            benchmark = try values.decode(Benchmark.self, forKey: .benchmark)
        }
    }
    let schema, position: Int
    let source_sha256, config_sha256, generation_sha256, node_id, request_id: String
    let measured_at: Int64
    let result: Result
    func validate(capture: RouterVPNOrderedCapture, node: RouterVPNOrderedLatencyNode,
                  count: Int = 3, current: Bool, now: Date = Date()) throws {
        try node.validate(count: count)
        let b = result.benchmark, d = b.distribution, maximum = node.kind == "public-path" ? 5000.0 : 2000.0
        guard schema == 1, source_sha256 == capture.source_sha256, config_sha256 == capture.config_sha256,
              RouterVPNOrderedCapture.hex(generation_sha256), !current || generation_sha256 == capture.generation_sha256,
              position == node.position, node_id == node.node_id, RouterVPNOrderedCapture.hex(request_id, count: 32),
              measured_at > 0, measured_at <= Int64(now.timeIntervalSince1970 * 1000) + 1000,
              result.node_id == node_id, result.kind == node.kind, result.role == node.role, result.label == node.receiptLabel(count: count),
              result.ready, (result.failure ?? "").isEmpty,
              b.schema == 1, b.measurement == node.measurement, b.attempts == 50, b.failed == 0, d.samples == 50,
              [d.min_ms, d.median_ms, d.average_ms, d.p90_ms, d.max_ms, b.trimmed_mean_ms].allSatisfy({ $0.isFinite && $0 > 0 && $0 <= maximum }),
              d.jitter_ms.isFinite, d.jitter_ms >= 0, d.jitter_ms <= d.max_ms - d.min_ms + 1e-9,
              d.min_ms <= d.median_ms, d.median_ms <= d.p90_ms, d.p90_ms <= d.max_ms,
              (d.min_ms...d.max_ms).contains(d.average_ms), (d.min_ms...d.max_ms).contains(b.trimmed_mean_ms),
              node.kind == "private-node" ? (b.endpoint ?? "").isEmpty : b.endpoint == "https://speed.cloudflare.com/__down?bytes=1" else {
            throw orderedLatencyIssue("The result does not contain 50 valid responses from this captured hop.")
        }
    }
    var display: String {
        let b = result.benchmark, d = b.distribution
        let date = Date(timeIntervalSince1970: Double(measured_at) / 1000)
        return String(format: "Saved %@\n50 responses · median %.2f ms · trimmed mean %.2f ms\nMin %.2f · average %.2f · p90 %.2f · max %.2f · jitter %.2f ms",
                      DateFormatter.localizedString(from: date, dateStyle: .medium, timeStyle: .medium),
                      d.median_ms, b.trimmed_mean_ms, d.min_ms, d.average_ms, d.p90_ms, d.max_ms, d.jitter_ms)
    }
}

struct RouterVPNOrderedLatencyReply: Decodable {
    struct Status: Decodable {
        let request_id, stage: String
        let complete, drained: Bool
        let failure: String?
    }
    let schema: Int
    let capture: RouterVPNOrderedCapture
    let nodes: [RouterVPNOrderedLatencyNode]?
    let history: [RouterVPNOrderedLatencyReceipt]?
    let node_id, request_id: String?
    let position: Int?
    let status: Status
    let receipt: RouterVPNOrderedLatencyReceipt?
    static func decode(_ data: Data) throws -> Self {
        guard data.count <= 1 << 20 else { throw orderedLatencyIssue("Measurement response is too large.") }
        let reply = try JSONDecoder().decode(Self.self, from: data)
        try reply.capture.validate()
        guard reply.schema == 1, !reply.status.drained || reply.status.complete,
              RouterVPNOrderedCapture.text(reply.status.stage, maximum: 128),
              (reply.status.failure ?? "").utf8.count <= 512 else { throw orderedLatencyIssue("Invalid measurement status.") }
        return reply
    }
}

protocol RouterVPNOrderedLatencyTask: AnyObject { func start(); func cancel() }
extension RouterVPNMacSpeedLabTransport: RouterVPNOrderedLatencyTask {}

// Loopback completion never proves native drain. One controller retains its
// exact capture through queued start, cancellation, late status and durable save.
final class RouterVPNMacOrderedLatencyController {
    typealias Factory = (URL, [String: Any]?, TimeInterval, @escaping (Result<Data, Error>) -> Void) throws -> RouterVPNOrderedLatencyTask
    var changed: (() -> Void)?
    private(set) var capture: RouterVPNOrderedCapture?
    private(set) var nodes: [RouterVPNOrderedLatencyNode] = []
    private(set) var history: [RouterVPNOrderedLatencyReceipt] = []
    private(set) var message = "Reading the connected ordered route…"
    private(set) var requestID = ""
    private(set) var selected: RouterVPNOrderedLatencyNode?
    private(set) var drained = true
    private(set) var cancelling = false
    private(set) var closing = false
    private(set) var invalid = false
    private var closed = false
    private var generation = UUID()
    private var tasks: [String: (UUID, RouterVPNOrderedLatencyTask)] = [:]
    private var timer: Timer?
    private var nextPoll = Date.distantPast, nextCancel = Date.distantPast
    private var deadline = Date.distantFuture
    private let profileID: String
    private let base: URL
    private let factory: Factory
    private let clock: () -> Date
    private let selectionCurrent: () -> Bool
    init(base: URL, profileID: String, clock: @escaping () -> Date = Date.init,
         selectionCurrent: @escaping () -> Bool = { true }, factory: Factory? = nil) {
        self.base = base; self.profileID = profileID; self.clock = clock; self.selectionCurrent = selectionCurrent
        self.factory = factory ?? { url, body, timeout, reply in
            try RouterVPNMacSpeedLabTransport(url: url, body: body, timeout: timeout, completion: reply)
        }
    }
    deinit { timer?.invalidate(); for (_, task) in tasks.values { task.cancel() } }
    var canRetest: Bool { capture != nil && drained && tasks.isEmpty && !closing && !closed && !invalid }
    var closeReady: Bool { drained && tasks.isEmpty }
    func open() {
        precondition(Thread.isMainThread)
        guard !closed, !closing, capture == nil, tasks.isEmpty else { return }
        send("capture", body: nil)
        timer = Timer.scheduledTimer(withTimeInterval: 0.25, repeats: true) { [weak self] _ in self?.tick() }
    }
    private func body() -> [String: Any]? {
        guard let capture, let selected, !requestID.isEmpty else { return nil }
        return ["capture": capture.body, "node_id": selected.node_id, "position": selected.position, "request_id": requestID]
    }
    private func checkSelection() {
        guard !invalid, !selectionCurrent() else { return }
        invalid = true
        if !drained { cancelling = true }
        message = "The selected profile changed. Waiting for the original test to finish."
    }
    func retest(position: Int) {
        precondition(Thread.isMainThread)
        checkSelection()
        guard canRetest, let node = nodes.first(where: { $0.position == position }) else { return }
        selected = node; requestID = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        drained = false; cancelling = false; nextPoll = .distantPast; deadline = clock().addingTimeInterval(100)
        message = "Measuring 50 responses through hop \(position + 1)…"
        send("start", body: body()); changed?()
    }
    func cancel() {
        precondition(Thread.isMainThread)
        guard !closed, !drained, !requestID.isEmpty else { return }
        cancelling = true; message = "Cancelling the test. Waiting for it to finish…"
        if tasks["cancel"] == nil && clock() >= nextCancel {
            nextCancel = clock().addingTimeInterval(1)
            send("cancel", body: body())
        }
        changed?()
    }
    func requestClose() -> Bool {
        closing = true
        if !drained { cancel() }
        else { for (_, task) in tasks.values { task.cancel() } }
        if closeReady { return true }
        changed?(); return false
    }
    func stop() {
        guard closeReady else { return }
        closed = true; generation = UUID(); timer?.invalidate(); timer = nil; changed = nil
    }
    func tick() {
        guard !closed else { return }
        checkSelection()
        if !drained {
            if clock() >= deadline { cancelling = true }
            if cancelling || closing || invalid { cancel() }
            if tasks["poll"] == nil && clock() >= nextPoll {
                nextPoll = clock().addingTimeInterval(0.7); send("poll", body: nil)
            }
        }
        changed?()
    }
    private func send(_ kind: String, body: [String: Any]?) {
        guard !closed, tasks[kind] == nil else { return }
        let path = "/api/speed-lab/ordered-latency" + (kind == "cancel" ? "/cancel" : kind == "poll" ? "?request_id=" + requestID : "")
        guard let url = URL(string: path, relativeTo: base)?.absoluteURL else { return }
        let job = UUID(), owner = generation, capturedRequest = requestID
        do {
            let task = try factory(url, body, 6) { [weak self] result in
                DispatchQueue.main.async { [weak self] in
                    guard let self, !self.closed, self.generation == owner,
                          self.tasks[kind]?.0 == job else { return }
                    self.tasks.removeValue(forKey: kind)
                    guard capturedRequest == self.requestID else { self.changed?(); return }
                    do { try self.receive(RouterVPNOrderedLatencyReply.decode(result.get()), kind: kind) }
                    catch {
                        if kind == "capture" { self.invalid = true; self.message = error.localizedDescription }
                        else {
                            self.cancelling = true
                            self.message = "The result was not confirmed. Cancelling this test and waiting for completion."
                        }
                    }
                    self.tick()
                }
            }
            tasks[kind] = (job, task); task.start()
        } catch {
            if kind == "capture" { invalid = true }
            else if kind == "start" { drained = true; cancelling = false }
            else { cancelling = true }
            message = error.localizedDescription; changed?()
        }
    }
    func receive(_ reply: RouterVPNOrderedLatencyReply, kind: String) throws {
        checkSelection()
        if kind == "capture" {
            guard !invalid else { throw orderedLatencyIssue("The selected profile changed. Reopen hop measurements.") }
            guard capture == nil, reply.capture.profile_id == profileID, (reply.request_id ?? "").isEmpty,
                  reply.status.request_id.isEmpty, reply.status.stage == "idle", reply.status.complete, reply.status.drained,
                  let rows = reply.nodes, (2...8).contains(rows.count), Set(rows.map { $0.node_id }).count == rows.count,
                  rows.map({ $0.position }) == Array(rows.indices), (reply.history ?? []).count <= 128 else {
                throw orderedLatencyIssue("Connect the selected ordered route, then reopen hop measurements.")
            }
            for row in rows { try row.validate(count: rows.count) }
            for record in reply.history ?? [] {
                guard let node = rows.first(where: { $0.node_id == record.node_id && $0.position == record.position }) else {
                    throw orderedLatencyIssue("Saved history belongs to another hop.")
                }
                try record.validate(capture: reply.capture, node: node, count: rows.count, current: false, now: clock())
            }
            capture = reply.capture; nodes = rows; history = reply.history ?? []
            message = "Choose a hop. Saved results show when that route was measured."
            return
        }
        guard let capture, let selected, reply.capture == capture, reply.request_id == requestID,
              reply.status.request_id == requestID, reply.node_id == selected.node_id, reply.position == selected.position else {
            throw orderedLatencyIssue("The response belongs to a different measurement.")
        }
        // A late start acknowledgement cannot undo an earlier terminal cancel.
        if drained { return }
        let finished = reply.status.complete && reply.status.drained
        if let record = reply.receipt {
            guard finished, reply.status.stage == "complete",
                  (reply.status.failure ?? "").isEmpty, record.request_id == requestID else {
                throw orderedLatencyIssue("An unfinished test cannot replace saved history.")
            }
            try record.validate(capture: capture, node: selected, count: nodes.count, current: true, now: clock())
            if invalid {
                message = "The original test finished and saved its result for the previous profile. Reopen hop measurements for the selected profile."
            } else {
                history.removeAll { $0.node_id == selected.node_id && $0.position == selected.position }
                history.append(record)
                message = cancelling ? "The test finished before cancellation; its 50 responses were saved." : "Saved 50 responses for hop \(selected.position + 1)."
            }
        } else if finished {
            guard reply.status.stage != "complete" || !(reply.status.failure ?? "").isEmpty else {
                throw orderedLatencyIssue("The completed measurement did not confirm its saved result.")
            }
            message = cancelling || closing ? "Test cancelled. Previous saved results remain available." : (reply.status.failure ?? "Measurement failed.")
        } else if !cancelling && !closing {
            message = "Measuring 50 responses through hop \(selected.position + 1)…"
        }
        if finished {
            drained = true
            if ["invalidated", "retired"].contains(reply.status.stage) { invalid = true }
        }
    }
}

#if canImport(AppKit)
import AppKit
import ObjectiveC

private var orderedLatencyPanelKey: UInt8 = 0
private final class RouterVPNMacOrderedLatencyPanel: NSWindowController, NSWindowDelegate {
    let controller: RouterVPNMacOrderedLatencyController
    private let node = NSPopUpButton(frame: .zero, pullsDown: false)
    private let status = NSTextField(wrappingLabelWithString: "Reading the connected route…")
    private let detail = NSTextField(wrappingLabelWithString: "No saved result selected.")
    private let retestButton = NSButton(title: "Retest 50 responses", target: nil, action: nil)
    private let cancelButton = NSButton(title: "Cancel test", target: nil, action: nil)
    private let onClosed: () -> Void
    private var populated = false
    init(profileID: String, selectionCurrent: @escaping () -> Bool, onClosed: @escaping () -> Void) {
        self.onClosed = onClosed; controller = RouterVPNMacOrderedLatencyController(base: routerVPNProductBaseURL, profileID: profileID, selectionCurrent: selectionCurrent)
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 720, height: 440), styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        super.init(window: panel); panel.delegate = self; panel.title = "Router VPN hop response times"; panel.minSize = NSSize(width: 580, height: 400)
        let stack = NSStackView(); stack.orientation = .vertical; stack.alignment = .leading; stack.spacing = 14
        stack.edgeInsets = NSEdgeInsets(top: 20, left: 20, bottom: 20, right: 20)
        let title = NSTextField(labelWithString: "50 responses through each hop"); title.font = .systemFont(ofSize: 23, weight: .bold); stack.addArrangedSubview(title)
        let explanation = NSTextField(wrappingLabelWithString: "Select a hop on the connected route. Private-node HTTP timing includes connection setup; the public middle is timed after TLS. Saved results are historical and keep their measurement date.")
        explanation.textColor = .secondaryLabelColor; stack.addArrangedSubview(explanation)
        node.target = self; node.action = #selector(selectionChanged); node.setAccessibilityLabel("Measured hop"); stack.addArrangedSubview(node)
        status.setAccessibilityLabel("Measurement progress"); stack.addArrangedSubview(status)
        detail.isSelectable = true; detail.font = .monospacedSystemFont(ofSize: 13, weight: .regular); stack.addArrangedSubview(detail)
        let row = NSStackView(); row.orientation = .horizontal; row.spacing = 10
        retestButton.target = self; retestButton.action = #selector(retest); cancelButton.target = self; cancelButton.action = #selector(cancel)
        row.addArrangedSubview(retestButton); row.addArrangedSubview(cancelButton); row.addArrangedSubview(NSButton(title: "Close", target: self, action: #selector(closeRequested))); stack.addArrangedSubview(row)
        panel.contentView = stack
        controller.changed = { [weak self] in self?.render() }; render(); controller.open()
    }
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    private func render() {
        if !populated && !controller.nodes.isEmpty {
            for row in controller.nodes { node.addItem(withTitle: "\(row.position + 1). \(row.label) · \(row.role)"); node.lastItem?.representedObject = row.position }
            populated = true
        }
        status.stringValue = controller.message; retestButton.isEnabled = controller.canRetest && node.indexOfSelectedItem >= 0
        node.isEnabled = controller.canRetest; cancelButton.isEnabled = !controller.drained && !controller.cancelling
        selectionChanged()
        if controller.closing && controller.closeReady { window?.performClose(nil) }
    }
    @objc private func selectionChanged() {
        guard let position = node.selectedItem?.representedObject as? Int,
              let row = controller.nodes.first(where: { $0.position == position }) else { return }
        let record = controller.history.filter { $0.node_id == row.node_id && $0.position == position }.max { $0.measured_at < $1.measured_at }
        detail.stringValue = row.timingLabel + "\n\n" + (record?.display ?? "No saved 50-response result for this route.")
    }
    @objc private func retest() { if let position = node.selectedItem?.representedObject as? Int { controller.retest(position: position) } }
    @objc private func cancel() { controller.cancel() }
    @objc private func closeRequested() { window?.performClose(nil) }
    func windowShouldClose(_ sender: NSWindow) -> Bool { controller.requestClose() }
    func windowWillClose(_ notification: Notification) { controller.stop(); onClosed() }
}

extension ProductWindowController {
    func orderedLatencyPresented() -> Bool {
        (objc_getAssociatedObject(self, &orderedLatencyPanelKey) as? RouterVPNMacOrderedLatencyPanel)?.window?.isVisible == true
    }
    @objc func showOrderedLatency() {
        if let panel = objc_getAssociatedObject(self, &orderedLatencyPanelKey) as? RouterVPNMacOrderedLatencyPanel { panel.window?.makeKeyAndOrderFront(nil); return }
        guard let id = selectedNodeID(), !id.isEmpty else { appendHelp("Select the connected ordered route first."); return }
        let panel = RouterVPNMacOrderedLatencyPanel(profileID: id, selectionCurrent: { [weak self] in self?.selectedNodeID() == id }) { [weak self] in
            guard let self else { return }; objc_setAssociatedObject(self, &orderedLatencyPanelKey, nil, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)
        }
        objc_setAssociatedObject(self, &orderedLatencyPanelKey, panel, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)
        panel.showWindow(nil); panel.window?.center(); panel.window?.makeKeyAndOrderFront(nil)
    }
}
#endif
