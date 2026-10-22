import Foundation

/// One proved Router node and one active bounded request. Retired requests keep
/// their native owner until real socket/callback drain and receipt persistence.
final class RouterVPNTelemetryChannel: @unchecked Sendable {
    typealias Endpoint = RouterVPNForwardingPolicy.Endpoint
    typealias Factory = @Sendable (Endpoint) -> RouterVPNTelemetryConnection?
    private let queue = DispatchQueue(label: "routervpn.private-telemetry")
    private let queueKey = DispatchSpecificKey<Bool>()
    private let endpoint: Endpoint
    private let factory: Factory
    private let requireStorage: @Sendable () throws -> Void
    private let persist: @Sendable (Data) throws -> Void
    private var epoch = UUID().uuidString
    private var proofSession = UUID().uuidString
    private var retired = false
    private var reserved: Set<String> = []
    private var replies: [String: Data] = [:]
    private var pendingWrites: [String: Data] = [:]
    private var retry: DispatchSourceTimer?
    private var active: Job?

    private final class Job: @unchecked Sendable {
        let id: String, kind: String
        var cancelled = false
        var probe: RouterVPNTelemetryTransport?
        var responseMS: [Double] = []
        var down: RouterVPNTelemetryTransport.Response?
        var up: RouterVPNTelemetryTransport.Response?
        var serverMS: Double?
        init(id: String, kind: String) { self.id = id; self.kind = kind }
    }
    init(profile: [String: Any], proofID: String, factory: @escaping Factory,
         requireStorage: @escaping @Sendable () throws -> Void = { try IOSDNSRetirementReceipts.shared.requireAvailable() },
         persist: @escaping @Sendable (Data) throws -> Void = { try IOSDNSRetirementReceipts.shared.storeDrained($0) }) throws {
        endpoint = try Endpoint(profile: profile, proofID: proofID)
        self.factory = factory; self.requireStorage = requireStorage; self.persist = persist
        queue.setSpecific(key: queueKey, value: true)
    }
    func handle(_ data: Data) -> Data? {
        guard let command = try? IOSTelemetryProtocol.command(data) else { return nil }
        return serial {
            guard command.node_id == endpoint.nodeID else { return nil }
            if command.operation == "telemetry-info" {
                // All completed owners already have durable cleanup evidence.
                // Rotate both epochs before recycling a bounded nonce table.
                if !retired, active == nil, reserved.count == 128,
                   replies.count == reserved.count, pendingWrites.isEmpty {
                    epoch = UUID().uuidString; proofSession = UUID().uuidString
                    reserved.removeAll(); replies.removeAll()
                }
                guard !retired, active == nil, reserved.count < 128,
                      !reserved.contains(command.request_id) else { return nil }
                do { try requireStorage() } catch { return nil }
                reserved.insert(command.request_id)
                return status(command.request_id, stage: "ready", complete: false, drained: true)
            }
            guard command.session_id == epoch, command.native_session_id == proofSession,
                  reserved.contains(command.request_id) else { return nil }
            if command.operation == "telemetry-cancel" {
                if let job = active, job.id == command.request_id {
                    job.cancelled = true
                    job.probe?.cancel()
                    return status(job.id, stage: "draining", complete: true, drained: false,
                        failure: "Cancelling the captured private-node measurement.")
                }
                if let reply = replies[command.request_id] { return reply }
                return complete(command.request_id, failure: "The reserved measurement was cancelled before starting.")
            }
            if command.operation == "telemetry-status" {
                if let job = active, job.id == command.request_id {
                    return status(job.id, stage: job.cancelled ? "draining" : "measuring", complete: job.cancelled,
                        drained: false, failure: job.cancelled ? "Waiting for the captured sockets to drain." : nil)
                }
                return replies[command.request_id]
            }
            guard command.operation == "telemetry-start", !retired, active == nil,
                  replies[command.request_id] == nil else { return nil }
            let job = Job(id: command.request_id, kind: command.kind)
            active = job
            // Enqueue so the immediate reply is small; native work owns the
            // same job even when the app loses that initial acknowledgement.
            queue.async { [self] in prove(job, final: false) }
            return status(job.id, stage: "proving", complete: false, drained: false)
        }
    }
    func close() {
        serial {
            retired = true
            if let active { active.cancelled = true; active.probe?.cancel() }
            for id in reserved where id != active?.id && replies[id] == nil {
                _ = complete(id, failure: "The proved VPN retired before this reserved measurement started.")
            }
            retryWrites()
        }
    }
    private func prove(_ job: Job, final: Bool) {
        guard current(job) else { finishCancelled(job); return }
        let bytes = RouterVPNForwardingPolicy.request(endpoint: endpoint, proof: true)
        exchange(job, headers: bytes, limit: 16 << 10, timeout: job.kind == "rtt" ? 1.8 : 6) { [self] result in
            do {
                let response = try result.get()
                try RouterVPNForwardingPolicy.verifyProof(RouterVPNForwardingPolicy.response(response.wire), endpoint: endpoint)
                guard current(job) else { finishCancelled(job); return }
                job.responseMS.append(response.seconds * 1000)
                if final { succeed(job) }
                else if job.kind == "rtt" { prove(job, final: true) }
                else { download(job) }
            } catch { fail(job) }
        }
    }
    private func headers(method: String, path: String, upload: Bool = false) -> Data {
        var head = "\(method) \(path) HTTP/1.1\r\nHost: \(endpoint.authority)\r\nConnection: close\r\nAuthorization: Bearer \(endpoint.token)\r\nAccept-Encoding: identity\r\nCache-Control: no-store\r\n"
        if upload { head += "Content-Type: application/octet-stream\r\nContent-Length: \(IOSTelemetryProtocol.bytes)\r\n" }
        return Data((head + "\r\n").utf8)
    }
    private func download(_ job: Job) {
        guard current(job), job.responseMS.count == 1 else { finishCancelled(job); return }
        exchange(job, headers: headers(method: "GET", path: "/api/benchmark/download?bytes=\(IOSTelemetryProtocol.bytes)"),
            limit: IOSTelemetryProtocol.bytes, expected: IOSTelemetryProtocol.bytes, keep: false, timeout: 30) { [self] result in
            do {
                job.down = try result.get()
                guard current(job) else { finishCancelled(job); return }
                upload(job)
            } catch { fail(job) }
        }
    }
    private func upload(_ job: Job) {
        guard current(job), job.responseMS.count == 1, job.down != nil else { finishCancelled(job); return }
        exchange(job, headers: headers(method: "POST", path: "/api/benchmark/upload", upload: true),
            upload: IOSTelemetryProtocol.bytes, limit: 64 << 10, timeout: 30) { [self] result in
            do {
                let response = try result.get()
                let object = try RouterVPNForwardingPolicy.response(response.wire)
                struct Receipt: Decodable { let bytes: Int; let server_receive_ms: Double? }
                let receipt = try JSONDecoder().decode(Receipt.self, from: JSONSerialization.data(withJSONObject: object))
                guard receipt.bytes == IOSTelemetryProtocol.bytes,
                      receipt.server_receive_ms.map({ $0.isFinite && $0 >= 0 && $0 <= 90_000 }) ?? true else { throw CancellationError() }
                job.up = response; job.serverMS = receipt.server_receive_ms
                guard current(job) else { finishCancelled(job); return }
                prove(job, final: true)
            } catch { fail(job) }
        }
    }
    private func exchange(_ job: Job, headers: Data, upload: Int = 0, limit: Int,
                          expected: Int? = nil, keep: Bool = true, timeout: Double,
                          completion: @escaping @Sendable (Result<RouterVPNTelemetryTransport.Response, Error>) -> Void) {
        guard current(job), let connection = factory(endpoint) else { fail(job); return }
        let probe = RouterVPNTelemetryTransport(queue: queue, connection: connection, headers: headers,
            uploadBytes: upload, bodyLimit: limit, expectedBytes: expected, keepBody: keep, timeout: timeout) { [self] result in
            guard active === job else { return }
            job.probe = nil
            // Transport completion joins native cancellation and every late
            // read/write callback. Only now may another operation or ack run.
            completion(result)
        }
        job.probe = probe; probe.start()
    }
    private func current(_ job: Job) -> Bool { active === job && !retired && !job.cancelled }
    private func fail(_ job: Job) {
        guard active === job else { return }
        if job.cancelled || retired { finishCancelled(job); return }
        active = nil
        _ = complete(job.id, failure: "The captured private node or bounded transfer could not be verified; no measurement was accepted.")
    }
    private func finishCancelled(_ job: Job) {
        guard active === job, job.probe == nil else { job.probe?.cancel(); return }
        active = nil
        _ = complete(job.id, failure: "The captured private-node measurement was cancelled and drained.")
    }
    private func succeed(_ job: Job) {
        guard current(job), job.probe == nil else { finishCancelled(job); return }
        let value = IOSTelemetryProtocol.Result(kind: job.kind, response_ms: job.responseMS,
            download_bytes: job.down == nil ? nil : IOSTelemetryProtocol.bytes,
            upload_bytes: job.up == nil ? nil : IOSTelemetryProtocol.bytes,
            download_seconds: job.down?.seconds, upload_seconds: job.up?.seconds, server_receive_ms: job.serverMS)
        do { try value.validate(kind: job.kind) } catch { fail(job); return }
        active = nil
        _ = complete(job.id, result: value)
    }
    @discardableResult private func complete(_ id: String, result: IOSTelemetryProtocol.Result? = nil, failure: String? = nil) -> Data? {
        guard let data = status(id, stage: result == nil ? "cancelled" : "complete", complete: true, drained: true,
            results: result.map { [$0] } ?? [], failure: failure) else { return nil }
        replies[id] = data; pendingWrites[id] = data; retryWrites()
        return data
    }
    private func status(_ id: String, stage: String, complete: Bool, drained: Bool,
                        results: [IOSTelemetryProtocol.Result] = [], failure: String? = nil) -> Data? {
        try? IOSTelemetryProtocol.Status(schema: 1, request_id: id, ack_id: id, session_id: epoch,
            native_session_id: proofSession, node_id: endpoint.nodeID, stage: stage,
            complete: complete, drained: drained, results: results, failure: failure).data()
    }
    private func retryWrites() {
        for (id, data) in pendingWrites {
            do { try persist(data); pendingWrites.removeValue(forKey: id) } catch { }
        }
        if pendingWrites.isEmpty { retry?.cancel(); retry = nil; return }
        guard retry == nil else { return }
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 2, repeating: 2)
        // Retain this exact stopped owner through transient disk failures.
        timer.setEventHandler { [self] in retryWrites() }
        retry = timer; timer.resume()
    }
    private func serial<T>(_ operation: () -> T) -> T {
        DispatchQueue.getSpecific(key: queueKey) == true ? operation() : queue.sync(execute: operation)
    }
}
