import Foundation

private func dnsIssue(_ text: String) -> NSError {
    NSError(domain: "RouterVPNDNS", code: 3, userInfo: [NSLocalizedDescriptionKey: text])
}

struct RouterVPNMacDNSResult: Decodable, Equatable {
    let id: String
    let name: String
    let kind: String
    let address: String
    let port: Int
    let transport: String
    let server_name: String?
    let path: String?
    let route: String
    let route_label: String
    let samples: Int
    let failed: Int
    let ready: Bool
    let median_ms: Double?
    let failure: String?

    var selectable: Bool { kind == "public" && ready && samples == 3 && failed == 0 && median_ms != nil && (failure ?? "").isEmpty }
    var measurement: String {
        if ready, let value = median_ms { return String(format: "%.2f ms", value) }
        return (failure ?? "").isEmpty ? "Pending" : "Failed"
    }
}

struct RouterVPNMacDNSSnapshot: Decodable {
    struct Status: Decodable {
        let schema: Int
        let node_id: String
        let session_id: String
        let request_id: String
        let public_transport: String
        let stage: String
        let complete: Bool
        let drained: Bool
        let results: [RouterVPNMacDNSResult]
        let failure: String?
    }
    let profile_id: String
    let profile_token: String
    let session_id: String
    let request_id: String
    let expires_in_ms: Int64
    let status: Status

    var completed: Bool { status.complete && status.drained }
    var usable: Bool { completed && status.stage == "complete" && (status.failure ?? "").isEmpty && expires_in_ms > 0 }

    static func decode(_ data: Data) throws -> Self {
        let value = try JSONDecoder().decode(Self.self, from: data)
        guard RouterVPNMacDNSTransport.validIdentity(value.profile_id), RouterVPNMacDNSTransport.validToken(value.profile_token),
              RouterVPNMacDNSTransport.validRequestID(value.session_id),
              value.request_id.isEmpty || RouterVPNMacDNSTransport.validRequestID(value.request_id),
              value.status.schema == 1, value.status.node_id == value.profile_id,
              value.status.session_id == value.session_id, value.status.request_id == value.request_id,
              (0...120_000).contains(value.expires_in_ms),
              ["idle", "preparing", "starting", "measuring", "verifying", "complete", "cancelled", "invalidated", "failed", "draining"].contains(value.status.stage),
              !value.status.drained || value.status.complete,
              value.status.results.count <= 13,
              Set(value.status.results.map { $0.id }).count == value.status.results.count else {
            throw dnsIssue("DNS status has an invalid captured identity or lifecycle.")
        }
        if value.request_id.isEmpty {
            guard value.status.stage == "idle", value.completed, value.status.results.isEmpty,
                  value.status.public_transport.isEmpty else { throw dnsIssue("DNS capture is not an idle connection receipt.") }
        } else {
            guard ["tcp", "tls", "https"].contains(value.status.public_transport) ||
                    value.status.public_transport.isEmpty && value.status.stage == "cancelled" && value.completed else {
                throw dnsIssue("DNS status changed its comparison transport.")
            }
        }
        for row in value.status.results {
            guard RouterVPNMacDNSTransport.validIdentity(row.id), ["selected", "public"].contains(row.kind),
                  !row.name.isEmpty, row.name.utf8.count <= 160, !row.address.isEmpty, row.address.utf8.count <= 253,
                  (1...65535).contains(row.port), ["udp", "tcp", "tls", "https", "h3"].contains(row.transport),
                  !row.route.isEmpty, !row.route_label.isEmpty, row.route_label.utf8.count <= 160,
                  (0...3).contains(row.samples), (0...3).contains(row.failed), row.samples + row.failed <= 3,
                  value.status.stage != "complete" || row.samples + row.failed == 3,
                  row.kind != "public" || row.transport == value.status.public_transport,
                  row.kind != "selected" || row.id == "selected",
                  !row.ready || row.samples == 3 && row.failed == 0 && row.median_ms != nil && (row.failure ?? "").isEmpty,
                  row.median_ms == nil || row.ready && row.median_ms!.isFinite && row.median_ms! > 0 else {
                throw dnsIssue("DNS row has an invalid measurement or route.")
            }
        }
        return value
    }
}

struct RouterVPNMacDNSDraft: Decodable, Equatable {
    let profile_id: String
    let profile_token: String
    let mode: String
    let `protocol`: String
    let host: String
    let port: Int
    let server_name: String?
    let path: String?
    let measurement_id: String
    let result_id: String

    func validate() throws {
        guard RouterVPNMacDNSTransport.validIdentity(profile_id), RouterVPNMacDNSTransport.validToken(profile_token),
              RouterVPNMacDNSTransport.validRequestID(measurement_id), RouterVPNMacDNSTransport.validIdentity(result_id),
              ["tcp", "tls", "https"].contains(`protocol`),
              mode == (`protocol` == "tcp" ? "custom" : `protocol` == "tls" ? "dot" : "doh"),
              !host.isEmpty, host.utf8.count <= 253, (1...65535).contains(port),
              (server_name ?? "").utf8.count <= 253, (path ?? "").utf8.count <= 2048 else {
            throw dnsIssue("The measured DNS draft is invalid.")
        }
    }
    var body: [String: Any] {
        ["profile_id": profile_id, "profile_token": profile_token, "mode": mode, "protocol": `protocol`,
         "host": host, "port": port, "server_name": server_name ?? "", "path": path ?? "",
         "measurement_id": measurement_id, "result_id": result_id]
    }
    func matches(_ row: RouterVPNMacDNSResult) -> Bool {
        row.selectable && result_id == row.id && host == row.address && port == row.port && `protocol` == row.transport &&
            (server_name ?? "") == (row.server_name ?? "") && (path ?? "") == (row.path ?? "")
    }
}

struct RouterVPNMacDNSViewState {
    var title = "Reading the connected DNS path…"
    var detail = ""
    var owner = ""
    var rows: [RouterVPNMacDNSResult] = []
    var draft = "No measured resolver selected."
    var busy = true
    var canRetest = false
    var canCancel = false
    var canSelect = false
    var canSave = false
    var closeReady = false
}

// Every transition runs on the main thread. The panel retains this owner until
// its queued Start and captured native workers have both actually drained.
final class RouterVPNMacDNSController {
    typealias Factory = (URL, [String: Any]?, TimeInterval, @escaping (Result<RouterVPNMacDNSReply, Error>) -> Void) throws -> RouterVPNMacDNSRequest
    var onChange: ((RouterVPNMacDNSViewState) -> Void)?
    var onSaved: (() -> Void)?
    private(set) var view = RouterVPNMacDNSViewState()
    private(set) var requestID = ""
    private(set) var stagedDraft: RouterVPNMacDNSDraft?
    private var capture: RouterVPNMacDNSSnapshot?
    private var snapshot: RouterVPNMacDNSSnapshot?
    private var generation = UUID()
    private var tasks: [String: RouterVPNMacDNSRequest] = [:]
    private var taskIDs: [String: UUID] = [:]
    private var timer: Timer?
    private var expiry = Date.distantPast
    private var nextCancel = Date.distantPast
    private var terminal = true
    private var cancelling = false
    private var closing = false
    private var closed = false
    private var saving = false
    private var idleVerified = false
    private var transport = "tcp"
    private var notice = ""
    private let baseURL: URL
    private let displayedProfileID: String
    private let interval: TimeInterval
    private let clock: () -> Date
    private let factory: Factory

    init(baseURL: URL, profileID: String, pollInterval: TimeInterval = 0.7,
         clock: @escaping () -> Date = Date.init, factory: Factory? = nil) {
        self.baseURL = baseURL; displayedProfileID = profileID; interval = pollInterval; self.clock = clock
        self.factory = factory ?? { url, body, timeout, completion in
            try RouterVPNMacDNSTransport(url: url, body: body, timeout: timeout, completion: completion)
        }
    }
    deinit { timer?.invalidate(); for task in tasks.values { task.cancel() } }

    func open(retest: Bool = false, publicTransport: String = "tcp") {
        precondition(Thread.isMainThread)
        guard !closed, !closing, terminal, !saving, tasks["start"] == nil, tasks["cancel"] == nil,
              ["tcp", "tls", "https"].contains(publicTransport) else { return }
        retireTasks(); generation = UUID(); transport = publicTransport
        capture = nil; snapshot = nil; requestID = ""; stagedDraft = nil; expiry = .distantPast
        terminal = true; cancelling = false; idleVerified = false; notice = "Capturing the selected connected node."
        send("capture", "/api/dns/measurement") { [weak self] result in
            guard let self else { return }
            do {
                let value = try RouterVPNMacDNSSnapshot.decode(self.success(result))
                guard value.profile_id == self.displayedProfileID, value.request_id.isEmpty else {
                    throw dnsIssue("The selected node changed. Reopen DNS for the connected node.")
                }
                self.capture = value
                self.notice = "Ready to compare actual DNS queries through this connection."
                if retest { self.begin() }
            } catch { self.notice = error.localizedDescription }
            self.render()
        }
        render()
    }

    func retest(publicTransport: String) {
        precondition(Thread.isMainThread)
        guard view.canRetest else { return }
        open(retest: true, publicTransport: publicTransport)
    }

    private var ownerBody: [String: Any] {
        guard let capture else { return [:] }
        return ["profile_id": capture.profile_id, "profile_token": capture.profile_token,
                "session_id": capture.session_id, "request_id": requestID]
    }

    private func begin() {
        guard capture != nil, requestID.isEmpty else { return }
        requestID = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        terminal = false; cancelling = false; stagedDraft = nil; idleVerified = false
        var body = ownerBody; body["public_transport"] = transport
        notice = "Starting the captured DNS test…"
        send("start", "/api/dns/measurement", body: body) { [weak self] result in
            guard let self else { return }
            do { try self.adopt(RouterVPNMacDNSSnapshot.decode(self.success(result)), fromPoll: false) }
            catch { self.notice = "Start was not confirmed: " + error.localizedDescription; self.cancelling = true }
            // A poll issued before Start finished cannot establish its drain.
            self.abort("poll")
            if self.cancelling { self.sendCancel() }
            self.render(); self.schedule(immediate: true)
        }
        schedule(immediate: true); render()
    }

    func cancel() {
        precondition(Thread.isMainThread)
        guard !closed, !requestID.isEmpty, !terminal else { return }
        cancelling = true; stagedDraft = nil; idleVerified = false
        // Retain the Start callback until its actual HTTP task finishes. The
        // server tombstone rejects a queued Start even if no worker exists yet.
        tasks["start"]?.cancel()
        notice = "Cancellation requested. Waiting for this captured test to drain."
        sendCancel(); render(); schedule(immediate: true)
    }

    private func sendCancel() {
        guard cancelling, !terminal, tasks["cancel"] == nil, !requestID.isEmpty else { return }
        nextCancel = clock().addingTimeInterval(1)
        send("cancel", "/api/dns/measurement/cancel", body: ownerBody) { [weak self] result in
            guard let self else { return }
            do { try self.adopt(RouterVPNMacDNSSnapshot.decode(self.success(result)), fromPoll: false) }
            catch { self.notice = "Cancellation is unconfirmed: " + error.localizedDescription }
            self.abort("poll")
            self.render(); self.schedule(immediate: true)
        }
    }

    private func adopt(_ value: RouterVPNMacDNSSnapshot, fromPoll: Bool) throws {
        guard let capture, value.profile_id == capture.profile_id, value.profile_token == capture.profile_token,
              value.session_id == capture.session_id, value.request_id == requestID,
              value.status.public_transport == transport || value.status.public_transport.isEmpty && value.status.stage == "cancelled" else {
            throw dnsIssue("DNS response belongs to another source, connection or request.")
        }
        snapshot = value
        if fromPoll && tasks["start"] == nil && tasks["cancel"] == nil && value.completed {
            if !terminal {
                notice = cancelling ? "DNS test cancelled and its native workers have drained."
                    : value.usable ? "Current-path DNS queries are complete. Failed resolvers have no score."
                    : "DNS test finished without a usable current-path comparison."
            }
            terminal = true
        } else if !cancelling && !terminal {
            notice = "Measuring DNS queries through the captured connection."
        }
        if value.usable && !cancelling {
            let deadline = clock().addingTimeInterval(Double(value.expires_in_ms) / 1000)
            expiry = expiry == .distantPast ? deadline : min(expiry, deadline)
        } else if terminal {
            stagedDraft = nil; idleVerified = false; expiry = .distantPast
        }
    }

    private func poll() {
        guard !closed, !requestID.isEmpty, tasks["poll"] == nil else { return }
        send("poll", "/api/dns/measurement?request_id=" + requestID) { [weak self] result in
            guard let self else { return }
            do { try self.adopt(RouterVPNMacDNSSnapshot.decode(self.success(result)), fromPoll: true) }
            catch {
                self.notice = "DNS status is unconfirmed: " + error.localizedDescription
                self.stagedDraft = nil; self.snapshot = nil; self.expiry = .distantPast; self.idleVerified = false
            }
            if self.cancelling && !self.terminal && self.clock() >= self.nextCancel { self.sendCancel() }
            if self.stagedDraft != nil && !self.saving { self.refreshIdle() }
            self.render(); self.schedule()
        }
    }

    func choose(_ resultID: String) {
        precondition(Thread.isMainThread)
        guard view.canSelect, let capture, let snapshot else { return }
        let eligible = snapshot.status.results.filter { $0.selectable }
        let expected = resultID == "fastest"
            ? eligible.sorted { $0.median_ms! == $1.median_ms! ? $0.id < $1.id : $0.median_ms! < $1.median_ms! }.first
            : eligible.first { $0.id == resultID }
        guard let expected else { notice = "Choose a public resolver with three successful samples."; render(); return }
        var body = ownerBody; body["result_id"] = resultID
        stagedDraft = nil; idleVerified = false; notice = "Requesting the measured resolver draft…"
        send("select", "/api/dns/measurement/select", body: body) { [weak self] result in
            guard let self else { return }
            struct Selection: Decodable { let draft: RouterVPNMacDNSDraft; let expires_in_ms: Int64; let session_id: String; let request_id: String }
            do {
                let value = try JSONDecoder().decode(Selection.self, from: self.success(result))
                try value.draft.validate()
                guard self.clock() < self.expiry, value.session_id == capture.session_id, value.request_id == self.requestID,
                      value.draft.profile_id == capture.profile_id, value.draft.profile_token == capture.profile_token,
                      value.draft.measurement_id == self.requestID, value.draft.matches(expected),
                      (1...120_000).contains(value.expires_in_ms) else { throw dnsIssue("The measured resolver or its capture changed.") }
                self.expiry = min(self.expiry, self.clock().addingTimeInterval(Double(value.expires_in_ms) / 1000))
                self.stagedDraft = value.draft
                self.notice = "Measured draft selected. Disconnect in the main window, then explicitly Save here."
                self.refreshIdle()
            } catch { self.stagedDraft = nil; self.notice = error.localizedDescription }
            self.render(); self.schedule()
        }
        render()
    }

    private static func disconnected(_ data: Data) throws -> Bool {
        struct State: Decodable { let connected: Bool; let phase: String? }
        let state = try JSONDecoder().decode(State.self, from: data)
        let phase = (state.phase ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return !state.connected && ["", "off", "failed"].contains(phase)
    }

    private func refreshIdle() {
        guard tasks["idle"] == nil, stagedDraft != nil, !saving else { return }
        send("idle", "/api/status") { [weak self] result in
            guard let self else { return }
            self.idleVerified = (try? Self.disconnected(self.success(result))) == true
            self.render()
        }
    }

    func save() {
        precondition(Thread.isMainThread)
        guard view.canSave, let draft = stagedDraft, clock() < expiry else { return }
        saving = true; idleVerified = false; abort("idle")
        notice = "Checking that the selected connection is disconnected…"
        send("save-idle", "/api/status") { [weak self] result in
            guard let self else { return }
            do {
                guard try Self.disconnected(self.success(result)), self.clock() < self.expiry, self.stagedDraft == draft else {
                    throw dnsIssue("Disconnect and keep the same measured draft before saving DNS.")
                }
                self.commit(draft)
            } catch { self.saving = false; self.notice = error.localizedDescription; self.render(); self.schedule() }
        }
        render()
    }

    private func commit(_ draft: RouterVPNMacDNSDraft) {
        // The exact server-issued six policy fields and both measurement IDs
        // remain immutable. The server rechecks idle/source/entry/expiry itself.
        send("save", "/api/dns/policy", body: draft.body) { [weak self] result in
            guard let self else { return }
            self.saving = false
            do {
                let data = try self.success(result)
                struct Saved: Decodable {
                    let profile_id: String; let mode: String; let `protocol`: String; let host: String; let port: Int
                    let server_name: String?; let path: String?
                }
                let value = try JSONDecoder().decode(Saved.self, from: data)
                guard value.profile_id == draft.profile_id, value.mode == draft.mode, value.protocol == draft.protocol,
                      value.host == draft.host, value.port == draft.port,
                      (value.server_name ?? "") == (draft.server_name ?? ""), (value.path ?? "") == (draft.path ?? "") else {
                    throw dnsIssue("DNS save returned a different policy. Refresh the saved node settings.")
                }
                self.stagedDraft = nil; self.snapshot = nil; self.expiry = .distantPast
                self.abort("poll"); self.abort("idle")
                self.notice = "Measured DNS policy saved. The next connection must prove it again."
                self.onSaved?()
            } catch { self.notice = "DNS save was not confirmed: " + error.localizedDescription }
            self.render(); self.schedule()
        }
    }

    func requestClose() -> Bool {
        precondition(Thread.isMainThread)
        closing = true
        if !terminal || tasks["start"] != nil || tasks["cancel"] != nil {
            cancel(); render(); return false
        }
        if saving { render(); return false }
        stop(); return true
    }

    func stop() {
        precondition(Thread.isMainThread)
        guard terminal, tasks["start"] == nil, tasks["cancel"] == nil, !saving else { return }
        closed = true; generation = UUID(); retireTasks(); onChange = nil; onSaved = nil
    }

    private func render() {
        guard !closed else { return }
        let current = clock()
        if current >= expiry { stagedDraft = nil; idleVerified = false }
        let capturing = tasks["capture"] != nil
        let active = !terminal || tasks["start"] != nil || tasks["cancel"] != nil
        let selectable = terminal && !active && !cancelling && snapshot?.usable == true && current < expiry
        view.busy = capturing || active || saving || tasks["select"] != nil
        view.canRetest = !closing && !view.busy && capture != nil
        view.canCancel = active && !requestID.isEmpty
        view.canSelect = !closing && selectable && !saving && tasks["select"] == nil
        view.canSave = !closing && selectable && stagedDraft != nil && idleVerified && !saving
        view.closeReady = closing && !active && !saving
        view.owner = capture.map { "Node: " + $0.profile_id + " • captured connected path" } ?? "Node: " + displayedProfileID
        view.rows = !cancelling ? (snapshot?.status.results ?? []) : []
        view.rows.sort {
            if $0.kind != $1.kind { return $0.kind == "selected" }
            if $0.ready != $1.ready { return $0.ready }
            if let a = $0.median_ms, let b = $1.median_ms, a != b { return a < b }
            return $0.name == $1.name ? $0.id < $1.id : $0.name < $1.name
        }
        if capturing { view.title = "Reading the connected DNS path…" }
        else if active { view.title = cancelling ? "Cancelling DNS test — waiting for drain" : "DNS test: " + (snapshot?.status.stage ?? "preparing") }
        else if saving { view.title = "Saving measured DNS policy…" }
        else if selectable { view.title = "DNS queries measured through the captured path" }
        else { view.title = "DNS measurement" }
        view.detail = notice
        if let failure = snapshot?.status.failure, !failure.isEmpty { view.detail = failure + "\n" + notice }
        if let draft = stagedDraft {
            let seconds = max(0, Int(expiry.timeIntervalSince(current)))
            view.draft = "Selected: \(draft.host):\(draft.port) • \(draft.protocol.uppercased()) • expires in \(seconds)s. " + (idleVerified ? "Ready for explicit Save." : "Disconnect in the main window to save.")
        } else if terminal && snapshot != nil && current >= expiry {
            view.draft = "Results are historical or expired. Retest before selecting a resolver."
        } else { view.draft = "Choose a successful public row or Fastest measured. Selection alone does not change DNS." }
        onChange?(view)
    }

    private func schedule(immediate: Bool = false) {
        timer?.invalidate(); timer = nil
        guard !closed, !requestID.isEmpty, !view.closeReady,
              !terminal || tasks["start"] != nil || tasks["cancel"] != nil || clock() < expiry else { return }
        timer = Timer.scheduledTimer(withTimeInterval: immediate ? 0.001 : interval, repeats: false) { [weak self] _ in
            guard let self else { return }
            self.timer = nil; self.render(); self.poll()
        }
    }

    private func success(_ result: Result<RouterVPNMacDNSReply, Error>) throws -> Data {
        let reply = try result.get()
        guard (200..<300).contains(reply.code) else {
            let text = String(data: reply.data.prefix(2048), encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            throw dnsIssue(text.isEmpty ? "The local DNS controller rejected the request." : text)
        }
        return reply.data
    }

    private func abort(_ channel: String) {
        taskIDs[channel] = UUID(); tasks.removeValue(forKey: channel)?.cancel()
    }
    private func retireTasks() {
        timer?.invalidate(); timer = nil
        taskIDs.removeAll()
        let owned = tasks; tasks.removeAll()
        for task in owned.values { task.cancel() }
    }
    private func send(_ channel: String, _ path: String, body: [String: Any]? = nil,
                      completion: @escaping (Result<RouterVPNMacDNSReply, Error>) -> Void) {
        let owner = generation, taskID = UUID(); taskIDs[channel] = taskID
        let callback: (Result<RouterVPNMacDNSReply, Error>) -> Void = { [weak self] result in
            DispatchQueue.main.async {
                guard let self, !self.closed, self.generation == owner, self.taskIDs[channel] == taskID else { return }
                self.taskIDs[channel] = nil
                self.tasks[channel] = nil
                completion(result)
            }
        }
        do {
            guard let url = URL(string: path, relativeTo: baseURL)?.absoluteURL else { throw dnsIssue("Invalid local DNS path.") }
            let task = try factory(url, body, 10, callback)
            tasks[channel] = task; task.start()
        } catch { callback(.failure(error)) }
    }
}
