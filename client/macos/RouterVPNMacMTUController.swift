import Foundation

struct RouterVPNMacMTUSnapshot: Decodable {
    struct Transfer: Decodable {
        let bytes: Int64
        let seconds: Double
        let mbps: Double
    }
    struct Candidate: Decodable {
        let mtu: Int
        let working: Bool
        let packets_sent: Int
        let packets_received: Int
        let datagram_bytes: Int?
        let median_rtt_ms: Double
        let latency_kind: String?
        let download: Transfer?
        let upload: Transfer?
        let failure: String?
    }
    struct Status: Decodable {
        let request_id: String
        let phase: String
        let running: Bool
        let complete: Bool
        let measured: Bool
        let restored: Bool
        let original_mtu: Int
        let effective_mtu: Int
        let source: String
        let failure: String?
        let candidates: [Candidate]?
    }
    let session_id: String
    let profile_id: String
    let requested: Bool
    let waiting_commit: Bool
    let status: Status

    static func decode(_ data: Data) throws -> RouterVPNMacMTUSnapshot {
        let value = try JSONDecoder().decode(Self.self, from: data)
        guard !value.session_id.isEmpty, value.session_id.utf8.count <= 128,
              !value.profile_id.isEmpty, value.profile_id.utf8.count <= 128,
              value.status.request_id.isEmpty || RouterVPNMacMTUTransport.validRequestID(value.status.request_id),
              !(value.status.running && value.status.complete),
              (!value.status.running && !value.status.complete) || !value.status.request_id.isEmpty,
              (0...9000).contains(value.status.original_mtu), (0...9000).contains(value.status.effective_mtu),
              (value.status.candidates?.count ?? 0) <= 256 else {
            throw NSError(domain: "RouterVPNMTU", code: 3, userInfo: [NSLocalizedDescriptionKey: "Invalid MTU status identity or measurements."])
        }
        for candidate in value.status.candidates ?? [] {
            guard (576...9000).contains(candidate.mtu), candidate.packets_sent >= 0,
                  (0...candidate.packets_sent).contains(candidate.packets_received), candidate.median_rtt_ms.isFinite,
                  candidate.median_rtt_ms >= 0, (0...9000).contains(candidate.datagram_bytes ?? 0) else {
                throw NSError(domain: "RouterVPNMTU", code: 3, userInfo: [NSLocalizedDescriptionKey: "Invalid MTU candidate measurement."])
            }
            for transfer in [candidate.download, candidate.upload].compactMap({ $0 }) {
                guard transfer.bytes >= 0, transfer.seconds.isFinite, transfer.seconds >= 0,
                      transfer.mbps.isFinite, transfer.mbps >= 0 else {
                    throw NSError(domain: "RouterVPNMTU", code: 3, userInfo: [NSLocalizedDescriptionKey: "Invalid MTU throughput measurement."])
                }
            }
        }
        return value
    }
}

struct RouterVPNMacMTUViewState {
    var title = "Reading current MTU status…"
    var detail = "Capturing the connected path."
    var owner = ""
    var measurements = "Candidate measurements will appear as the controller reports them."
    var busy = true
    var canRetest = false
    var canCancel = false
    var closeReady = false
}

// All transitions and view callbacks run on the main thread. A callback must
// match both this view generation and its particular HTTP task before it can
// publish a result or schedule the next poll.
final class RouterVPNMacMTUController {
    typealias Factory = (URL, [String: Any]?, TimeInterval, @escaping (Result<RouterVPNMacMTUReply, Error>) -> Void) throws -> RouterVPNMacMTURequest
    var onChange: ((RouterVPNMacMTUViewState) -> Void)?
    private(set) var view = RouterVPNMacMTUViewState()
    private(set) var sessionID = ""
    private(set) var profileID = ""
    private(set) var requestID = ""
    private(set) var seenRequest = false
    private(set) var manualPostPending = false
    private(set) var manual = false
    private var generation = UUID()
    private var pollID = UUID()
    private var postID = UUID()
    private var cancelID = UUID()
    private var pollTask: RouterVPNMacMTURequest?
    private var postTask: RouterVPNMacMTURequest?
    private var cancelTask: RouterVPNMacMTURequest?
    private var timer: Timer?
    private var closed = false
    private var retired = false
    private var opening = false
    private var startAfterCapture = false
    private var cancelling = false
    private var closeAfterDrain = false
    private var completionEpoch: UInt64 = 0
    private var awaitingFinalStatus = false
    private var snapshot: RouterVPNMacMTUSnapshot?
    private var notice = ""
    private let baseURL: URL
    private let pollInterval: TimeInterval
    private let factory: Factory

    init(baseURL: URL, pollInterval: TimeInterval = 0.7, factory: Factory? = nil) {
        self.baseURL = baseURL
        self.pollInterval = pollInterval
        self.factory = factory ?? { url, body, timeout, completion in
            try RouterVPNMacMTUTransport(url: url, body: body, timeout: timeout, completion: completion)
        }
    }
    deinit { timer?.invalidate(); pollTask?.cancel(); postTask?.cancel(); cancelTask?.cancel() }

    func open(retest: Bool = false) {
        precondition(Thread.isMainThread)
        guard !closed, !manualPostPending, cancelTask == nil, !view.canCancel else { return }
        generation = UUID(); timer?.invalidate(); timer = nil; pollTask?.cancel(); pollTask = nil
        sessionID = ""; profileID = ""; requestID = ""; seenRequest = false
        snapshot = nil; retired = false; manual = false; cancelling = false; closeAfterDrain = false
        completionEpoch = 0; awaitingFinalStatus = false
        opening = true; startAfterCapture = retest; notice = ""
        render(); poll()
    }

    func retest() {
        precondition(Thread.isMainThread)
        guard view.canRetest else { return }
        // Recapture the connection before each new operation. A previous
        // terminal receipt cannot authorize a Retest on a replacement path.
        open(retest: true)
    }

    func cancel() {
        precondition(Thread.isMainThread)
        guard !closed, !retired, !requestID.isEmpty, view.canCancel else { return }
        cancelling = true
        // The POST may still be waiting to register. Abort only this task so
        // it cannot register a new operation after an early cancellation.
        if manualPostPending { postTask?.cancel() }
        notice = "Cancellation requested. Waiting for this operation's rollback and request to finish."
        render()
        guard cancelTask == nil else { return }
        let owner = generation, taskOwner = UUID(); cancelID = taskOwner
        let body = ["request_id": requestID, "session_id": sessionID]
        do {
            let task = try make("/api/mtu/cancel", body: body, timeout: 10) { [weak self] result in
                DispatchQueue.main.async {
                    guard let self, !self.closed, self.generation == owner, self.cancelID == taskOwner else { return }
                    self.cancelTask = nil
                    self.completionEpoch &+= 1; self.awaitingFinalStatus = true
                    switch result {
                    case .success(let reply):
                        if (200..<300).contains(reply.code) {
                            let object = (try? JSONSerialization.jsonObject(with: reply.data)) as? [String: Any]
                            guard object?["request_id"] as? String == self.requestID,
                                  object?["phase"] as? String == "canceling",
                                  object?["session_id"] == nil || object?["session_id"] as? String == self.sessionID else {
                                self.notice = "Cancellation acknowledgement did not match this operation. Completion is unconfirmed."
                                self.render(); self.schedulePoll(); return
                            }
                            // An acknowledgement is never a completed rollback.
                            self.notice = "Cancelling this MTU test. Waiting for confirmed rollback."
                        } else if reply.code != 404 {
                            self.notice = "Cancellation response: " + self.message(reply)
                        }
                    case .failure(let error):
                        self.notice = "Cancellation status is unconfirmed: " + error.localizedDescription
                    }
                    self.render(); self.schedulePoll()
                }
            }
            cancelTask = task; task.start()
        } catch { notice = error.localizedDescription; render(); schedulePoll() }
    }

    // A manual test's Close acts as Cancel and waits for the same rollback.
    // Observing Auto does not transfer ownership of that automatic operation.
    func requestClose() -> Bool {
        precondition(Thread.isMainThread)
        if (manual || cancelling) && view.busy && !retired {
            closeAfterDrain = true
            if !cancelling { cancel() } else { render() }
            return false
        }
        stop()
        return true
    }

    func stop() {
        precondition(Thread.isMainThread)
        guard !closed else { return }
        closed = true; generation = UUID(); timer?.invalidate(); timer = nil
        pollTask?.cancel(); pollTask = nil
        postTask?.cancel(); postTask = nil
        cancelTask?.cancel(); cancelTask = nil
        onChange = nil
    }

    private func make(_ path: String, body: [String: Any]?, timeout: TimeInterval,
                      completion: @escaping (Result<RouterVPNMacMTUReply, Error>) -> Void) throws -> RouterVPNMacMTURequest {
        guard let url = URL(string: path, relativeTo: baseURL)?.absoluteURL else {
            throw NSError(domain: "RouterVPNMTU", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid MTU endpoint."])
        }
        return try factory(url, body, timeout, completion)
    }

    private func startManual() {
        guard !closed, !retired, !sessionID.isEmpty, !profileID.isEmpty,
              !manualPostPending, cancelTask == nil else { return }
        requestID = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        seenRequest = false; manual = true; manualPostPending = true
        snapshot = nil; notice = "Starting MTU Retest on the captured connection."
        let owner = generation, taskOwner = UUID(); postID = taskOwner
        let body = ["request_id": requestID, "session_id": sessionID, "profile_id": profileID]
        do {
            let task = try make("/api/mtu/retest", body: body, timeout: 130) { [weak self] result in
                DispatchQueue.main.async {
                    guard let self, !self.closed, self.generation == owner, self.postID == taskOwner else { return }
                    self.postTask = nil; self.manualPostPending = false
                    self.completionEpoch &+= 1; self.awaitingFinalStatus = true
                    switch result {
                    case .success(let reply):
                        if !(200..<300).contains(reply.code) { self.notice = "Retest response: " + self.message(reply) }
                    case .failure(let error):
                        if !self.cancelling { self.notice = "Retest request ended: " + error.localizedDescription }
                    }
                    // The POST result is not the status/rollback receipt.
                    self.render(); self.schedulePoll()
                }
            }
            postTask = task; task.start(); render(); schedulePoll()
        } catch {
            manualPostPending = false
            retire("MTU Retest could not start: " + error.localizedDescription)
        }
    }

    private func poll() {
        guard !closed, !retired, pollTask == nil else { return }
        timer?.invalidate(); timer = nil
        let owner = generation, taskOwner = UUID(); pollID = taskOwner
        let readEpoch = completionEpoch
        var path = "/api/mtu/status"
        if !sessionID.isEmpty {
            var components = URLComponents(); components.path = path
            components.queryItems = [URLQueryItem(name: "session_id", value: sessionID)]
            if !requestID.isEmpty { components.queryItems?.append(URLQueryItem(name: "request_id", value: requestID)) }
            path = components.string!
        }
        do {
            let task = try make(path, body: nil, timeout: 8) { [weak self] result in
                DispatchQueue.main.async {
                    guard let self, !self.closed, self.generation == owner, self.pollID == taskOwner else { return }
                    self.pollTask = nil
                    switch result {
                    case .failure(let error):
                        self.opening = false
                        self.notice = "MTU status unavailable; completion is unconfirmed. " + error.localizedDescription
                        self.render()
                        if !self.sessionID.isEmpty { self.schedulePoll() }
                    case .success(let reply): self.receive(reply, readEpoch: readEpoch)
                    }
                }
            }
            pollTask = task; task.start()
        } catch { opening = false; retire(error.localizedDescription) }
    }

    private func receive(_ reply: RouterVPNMacMTUReply, readEpoch: UInt64) {
        if reply.code == 409 { retire("The connection or MTU operation changed. This view has stopped."); return }
        if reply.code == 404 {
            if readEpoch != completionEpoch { render(); schedulePoll(); return }
            // Only an unobserved request whose own POST is still pending can
            // legitimately appear after this response. Never follow a new ID.
            if !seenRequest && manualPostPending { render(); schedulePoll(); return }
            let reason = cancelling ? "Cancellation requested; this operation is no longer registered. No rollback result is claimed." : "The captured MTU operation is no longer available."
            let response = !cancelling && notice.hasPrefix("Retest response:") ? "\n" + notice : ""
            retire(reason + response)
            return
        }
        guard (200..<300).contains(reply.code) else {
            opening = false; notice = message(reply); render()
            if !sessionID.isEmpty { schedulePoll() }
            return
        }
        do {
            let value = try RouterVPNMacMTUSnapshot.decode(reply.data)
            if sessionID.isEmpty {
                sessionID = value.session_id; profileID = value.profile_id
            } else if value.session_id != sessionID || value.profile_id != profileID {
                retire("The connected path changed. This view will not adopt its MTU result."); return
            }
            if !requestID.isEmpty {
                guard value.status.request_id == requestID else { retire("A different MTU operation replaced this request. This view has stopped."); return }
                seenRequest = true
            } else if !value.status.request_id.isEmpty {
                requestID = value.status.request_id; seenRequest = true
            }
            snapshot = value; opening = false
            // A status request started before POST/Cancel ended cannot attest
            // to their final rollback/commit, even if its body says complete.
            if readEpoch == completionEpoch { awaitingFinalStatus = false }
            if startAfterCapture {
                startAfterCapture = false
                if value.status.running || value.waiting_commit {
                    notice = "An MTU operation is already active. Observing its captured request."
                } else {
                    startManual(); return
                }
            } else if !cancelling { notice = "" }
            render()
            if needsPoll { schedulePoll() }
        } catch { retire("MTU status rejected: " + error.localizedDescription) }
    }

    private var operationPending: Bool {
        guard !closed, !retired else { return false }
        return manualPostPending || cancelTask != nil || awaitingFinalStatus || snapshot?.waiting_commit == true || snapshot?.status.running == true ||
            (!requestID.isEmpty && snapshot?.status.complete != true)
    }

    private var needsPoll: Bool {
        guard !closed, !retired else { return false }
        // Auto can register just after the initial idle snapshot. Keep this
        // visible observer bound to its session until its first ID appears.
        return operationPending || (!manual && snapshot != nil && requestID.isEmpty)
    }

    private func schedulePoll() {
        guard !closed, !retired, timer == nil else { return }
        let owner = generation
        let next = Timer(timeInterval: pollInterval, repeats: false) { [weak self] _ in
            guard let self, !self.closed, self.generation == owner else { return }
            self.timer = nil; self.poll()
        }
        timer = next; RunLoop.main.add(next, forMode: .common)
    }

    private func retire(_ reason: String) {
        retired = true; opening = false; notice = reason; startAfterCapture = false
        generation = UUID(); timer?.invalidate(); timer = nil
        pollTask?.cancel(); pollTask = nil; postTask?.cancel(); postTask = nil; manualPostPending = false
        cancelTask?.cancel(); cancelTask = nil
        render()
    }

    private func message(_ reply: RouterVPNMacMTUReply) -> String {
        let text = String(decoding: reply.data.prefix(2048), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        return text.isEmpty ? "Local controller returned HTTP \(reply.code)." : text
    }

    private func render() {
        var next = RouterVPNMacMTUViewState()
        let status = snapshot?.status
        next.busy = !retired && (opening || operationPending)
        next.canRetest = !closed && !retired && !opening && !next.busy && snapshot != nil
        next.canCancel = !closed && !retired && !requestID.isEmpty && next.busy
        next.closeReady = closeAfterDrain && !next.busy
        next.owner = sessionID.isEmpty ? "" : "Profile: \(profileID)\nConnection: \(sessionID)" + (requestID.isEmpty ? "" : "\nMTU request: \(requestID)")
        if retired { next.title = "MTU observation ended" }
        else if opening { next.title = "Reading current MTU status…" }
        else if cancelling && next.busy { next.title = "Cancelling — waiting for rollback…" }
        else if snapshot?.waiting_commit == true { next.title = "Waiting for the captured connection to finish committing…" }
        else if status?.complete == true && (manualPostPending || awaitingFinalStatus) { next.title = "MTU result ready — confirming the final owned status…" }
        else if status?.complete == true {
            next.title = (status?.failure?.isEmpty == false) ? "MTU test finished with a reported failure" : (cancelling ? "MTU cancellation finished" : "MTU test finished")
        } else if next.busy { next.title = "MTU test: " + (status?.phase.isEmpty == false ? status!.phase.replacingOccurrences(of: "-", with: " ") : "starting") }
        else { next.title = "Current MTU configuration" }
        var detail: [String] = []
        if let status {
            let mtuLabel = status.source.hasPrefix("saved-") ? "Saved MTU (historical)" : "Effective interface MTU"
            detail.append(status.effective_mtu > 0 ? "\(mtuLabel): \(status.effective_mtu) bytes" : "\(mtuLabel): not reported")
            if status.original_mtu > 0 { detail.append("Original MTU: \(status.original_mtu) bytes") }
            detail.append("Source: " + status.source)
            detail.append(status.measured ? "Measured on this captured path." : "No fresh measurement is reported for this value.")
            if status.restored { detail.append("The controller reports that the original MTU was restored.") }
            if let failure = status.failure, !failure.isEmpty { detail.append("Reported failure: " + failure) }
            let candidates = status.candidates ?? []
            next.measurements = candidates.isEmpty ? "No candidate measurements have been reported." : candidates.map { candidate in
                var line = "MTU \(candidate.mtu): " + (candidate.working ? "working" : "not proved")
                if candidate.packets_sent > 0 { line += " · authenticated replies \(candidate.packets_received)/\(candidate.packets_sent)" }
                if let bytes = candidate.datagram_bytes, bytes > 0 { line += " · \(bytes)-byte UDP payload" }
                if candidate.median_rtt_ms > 0 {
                    let kind = candidate.latency_kind == "https-response" ? "HTTPS response" :
                        ((candidate.datagram_bytes ?? 0) > 0 ? "authenticated UDP round trip" : (candidate.latency_kind ?? "reported response time"))
                    line += String(format: " · %.2f ms", candidate.median_rtt_ms) + " (\(kind))"
                }
                for (label, transfer) in [("download", candidate.download), ("upload", candidate.upload)] {
                    if let transfer, transfer.bytes > 0, transfer.seconds > 0 {
                        line += String(format: "\n  %@ %.2f Mbps · %lld bytes in %.3f s", label, transfer.mbps, transfer.bytes, transfer.seconds)
                    }
                }
                if let failure = candidate.failure, !failure.isEmpty { line += "\n  " + failure }
                return line
            }.joined(separator: "\n\n")
        }
        if !notice.isEmpty { detail.append(notice) }
        if detail.isEmpty { detail.append("Capturing the connected path.") }
        next.detail = detail.joined(separator: "\n")
        view = next; onChange?(next)
    }
}
