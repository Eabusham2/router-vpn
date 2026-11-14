import Foundation
import Libbox

struct RouterVPNOrderedLatencyRequest: Sendable {
    let operation: String, request: String, session: String, owner: String, lease: String, source: String, config: String, node: String
    var key: String { session + ":" + request }
    static func parse(_ data: Data) -> Self? {
        guard data.count <= 1536, let raw = String(data: data, encoding: .utf8) else { return nil }
        var failure: NSError?
        guard LibboxRouterValidatePrivateNodeJSON(raw, &failure), failure == nil else { return nil }
        guard data.count <= 1536, let v = try? JSONSerialization.jsonObject(with: data) as? [String: String],
              Set(v.keys) == Set(["operation", "request_id", "session_id", "owner", "lease", "source_sha256", "config_sha256", "node_id"]),
              let op = v["operation"], ["ordered-latency-info", "ordered-latency-open", "ordered-latency-start", "ordered-latency-status", "ordered-latency-cancel", "ordered-latency-close"].contains(op),
              let id = v["request_id"], valid(id, 32), let owner = v["owner"], valid(owner, 32),
              let session = v["session_id"], let lease = v["lease"], let source = v["source_sha256"], let config = v["config_sha256"], let node = v["node_id"] else { return nil }
        if op == "ordered-latency-info" {
            guard session.isEmpty, lease.isEmpty, source.isEmpty, config.isEmpty, node.isEmpty else { return nil }
        } else {
            guard UUID(uuidString: session) != nil, valid(lease, 32), valid(source, 64), valid(config, 64),
                  node.range(of: "\\A[A-Za-z0-9_-]{1,64}\\z", options: .regularExpression) != nil else { return nil }
        }
        return Self(operation: op, request: id, session: session, owner: owner, lease: lease, source: source, config: config, node: node)
    }
    static func valid(_ text: String, _ count: Int) -> Bool { text.utf8.count == count && text.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }
    func matches(_ other: Self) -> Bool { request == other.request && session == other.session && owner == other.owner && lease == other.lease && source == other.source && config == other.config && node == other.node }
    func reply(_ values: [String: Any]) -> Data? {
        var v = values; v["request_id"] = request; v["session_id"] = session; v["owner"] = owner
        guard let data = try? JSONSerialization.data(withJSONObject: v, options: [.sortedKeys]), data.count <= 32768 else { return nil }; return data
    }
}

/// Retained before factory entry. The exact object, not a reusable request
/// string, owns late factory results and cleanup. Only this facade is closed.
final class RouterVPNOrderedLatencyOwner: @unchecked Sendable {
    let request: RouterVPNOrderedLatencyRequest
    private let lock = NSLock(), calls = NSLock()
    private var native: LibboxRouterOrderedLatency?
    private var cancelled = false, attempted = false, closed = false, started = false
    private let current: () throws -> Void
    init(_ request: RouterVPNOrderedLatencyRequest, current: @escaping () throws -> Void) { self.request = request; self.current = current }
    private func require() throws {
        lock.lock(); let allowed = !cancelled && !closed; lock.unlock()
        guard allowed else { throw CancellationError() }; try current()
    }
    func open(_ factory: (_ retain: (LibboxRouterOrderedLatency) -> Void) throws -> Void) throws {
        calls.lock(); defer { calls.unlock() }
        lock.lock(); let entered = attempted; attempted = true; lock.unlock()
        guard !entered else { try require(); return }
        try require()
        try factory { returned in
            lock.lock(); native = returned; lock.unlock() // before any post-factory checks
        }
        lock.lock(); let attached = native != nil; lock.unlock()
        guard attached else { throw CancellationError() }
        try require()
    }
    func cancel() {
        lock.lock(); cancelled = true; let captured = native; lock.unlock()
        captured?.cancel(request.request)
    }
    func response(start: Bool) throws -> Data? {
        calls.lock(); defer { calls.unlock() }
        try require()
        lock.lock(); let captured = native, alreadyStarted = started; lock.unlock()
        guard let captured else { throw CancellationError() }
        if start && !alreadyStarted {
            // A throwing Start can still own work: Close always retains it.
            lock.lock(); started = true; lock.unlock()
            try captured.start(request.request, nodeID: request.node)
        }
        try require()
        let status = captured.statusJSON()
        guard status.utf8.count <= 16384 else { throw CancellationError() }
        let body = try JSONSerialization.jsonObject(with: Data(status.utf8)) as? [String: Any]
        var saved = ""
        if body?["complete"] as? Bool == true {
            try captured.drain(request.request)
            try require()
            saved = captured.savedJSON(request.node)
        }
        let joinedStatus = captured.statusJSON()
        guard joinedStatus.utf8.count <= 16384, saved.utf8.count <= 8192 else { throw CancellationError() }
        try require()
        return request.reply(["status": joinedStatus, "saved": saved, "closed": false])
    }
    func close() throws {
        // Cancel marks entry before waiting for a still-entered factory.
        cancel()
        guard calls.try() else { throw CancellationError() }; defer { calls.unlock() }
        lock.lock(); let done = closed, captured = native; lock.unlock()
        if done { return }
        try captured?.close()
        lock.lock(); closed = true; native = nil; lock.unlock()
    }
    func isClosed() -> Bool { lock.lock(); defer { lock.unlock() }; return closed }
}

/// Survives engine replacement and replies only for the retained original
/// session/request/opaque-owner tuple. Closed tombstones prevent replay.
final class RouterVPNOrderedLatencyRegistry: @unchecked Sendable {
    static let shared = RouterVPNOrderedLatencyRegistry()
    private let lock = NSLock()
    private var owners: [String: RouterVPNOrderedLatencyOwner] = [:]
    private var tombstones: [String: RouterVPNOrderedLatencyRequest] = [:]
    func retain(_ owner: RouterVPNOrderedLatencyOwner) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard owners[owner.request.key] == nil, tombstones[owner.request.key] == nil, owners.count + tombstones.count < 256 else { return false }
        owners[owner.request.key] = owner; return true
    }
    func find(_ request: RouterVPNOrderedLatencyRequest) -> RouterVPNOrderedLatencyOwner? {
        lock.lock(); defer { lock.unlock() }; guard let value = owners[request.key], value.request.matches(request) else { return nil }; return value
    }
    func cleanup(_ request: RouterVPNOrderedLatencyRequest) -> Data? {
        guard ["ordered-latency-cancel", "ordered-latency-close"].contains(request.operation) else { return nil }
        lock.lock()
        if let old = tombstones[request.key] { lock.unlock(); return old.matches(request) ? request.reply(["closed": true]) : nil }
        guard let captured = owners[request.key] else {
            // Cancellation can beat open on the provider worker queue. A
            // tombstone bars that late open before any factory is entered.
            guard owners.count + tombstones.count < 256 else { lock.unlock(); return nil }
            tombstones[request.key] = request; lock.unlock(); return request.reply(["closed": true])
        }
        lock.unlock()
        guard captured.request.matches(request) else { return nil }
        captured.cancel()
        do { try captured.close() } catch { return request.reply(["closed": false]) }
        lock.lock()
        if owners[request.key] === captured { owners.removeValue(forKey: request.key); tombstones[request.key] = captured.request }
        lock.unlock()
        return request.reply(["closed": true])
    }
}
