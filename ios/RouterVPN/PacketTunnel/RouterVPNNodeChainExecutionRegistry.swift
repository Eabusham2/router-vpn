import Foundation

/// Process-owned temporary restoration. The IPC token is only a reference to
/// an original native capsule; it cannot reconstruct one after process exit.
final class RouterVPNNodeChainExecutionRegistry: @unchecked Sendable {
    static let shared = RouterVPNNodeChainExecutionRegistry()
    static let restoreKey = "routervpn_node_chain_execution_restore"
    static let restoreOwnerKey = "routervpn_node_chain_execution_restore_owner"
    static let lastKey = "routervpn_node_chain_execution_last"
    static let temporaryOwnerKey = "routervpn_speed_lab_owner"

    struct Request: Sendable {
        let operation: String, request: String, session: String, owner: String, token: String
        static func parse(_ data: Data) -> Request? {
            guard !data.isEmpty, data.count <= 1024,
                  let body = try? JSONSerialization.jsonObject(with: data) as? [String: String],
                  Set(body.keys) == Set(["operation", "request_id", "session_id", "owner_id", "token"]),
                  let operation = body["operation"], ["ordered-execution-capture", "ordered-execution-verify", "ordered-execution-release", "ordered-execution-last"].contains(operation),
                  let request = body["request_id"], validToken(request),
                  let session = body["session_id"], session.isEmpty || UUID(uuidString: session)?.uuidString == session,
                  let owner = body["owner_id"], let token = body["token"] else { return nil }
            if operation == "ordered-execution-last" {
                guard owner.isEmpty, token.isEmpty else { return nil }
            } else {
                guard UUID(uuidString: owner)?.uuidString == owner else { return nil }
                if operation == "ordered-execution-capture" { guard token.isEmpty else { return nil } }
                else { guard !session.isEmpty, validToken(token) else { return nil } }
            }
            return Request(operation: operation, request: request, session: session, owner: owner, token: token)
        }
    }

    // Immutable reference; only this registry may claim its entry under lock.
    struct Admission: @unchecked Sendable {
        fileprivate let epoch: UUID
        fileprivate let entry: Entry?
    }

    /// Only consume() can construct this typed temporary launch. Its retained
    /// capsule has proved both shared cleanup and the actual original Close.
    final class Restored {
        let capture: IOSNodeChainExecutionCapture
        let originalToken: String
        fileprivate init(capture: IOSNodeChainExecutionCapture, original: Entry) {
            self.capture = capture; originalToken = original.token
        }
        func require(_ capture: IOSNodeChainExecutionCapture) throws {
            guard self.capture === capture else { throw issue() }
            try capture.requireCurrent()
        }
    }

    fileprivate final class Entry {
        let host: RouterVPNNodeChainExecutionHost
        let capsule: IOSNodeChainExecutionCapture.Restoration
        let observation: UUID
        let session: String, owner: String, token: String, execution: String, request: String
        let source: String, configuration: String
        var claiming = false
        init(host: RouterVPNNodeChainExecutionHost, capsule: IOSNodeChainExecutionCapture.Restoration,
             observation: UUID, session: String, owner: String, request: String) {
            self.host = host; self.capsule = capsule; self.observation = observation
            self.session = session; self.owner = owner; self.request = request
            token = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
            execution = capsule.selected; source = host.capture.sourceSHA256; configuration = host.capture.configSHA256
        }
        func reply(_ request: String) -> Data? {
            encode(["schema": 1, "kind": "routervpn-ordered-execution-restore", "request_id": request,
                    "session_id": session, "owner_id": owner, "token": token, "execution": execution,
                    "source_sha256": source, "preparation_config_sha256": configuration])
        }
    }

    private let lock = NSLock()
    private var generation = UUID()
    private var entry: Entry?

    func epoch() -> UUID { lock.lock(); defer { lock.unlock() }; return generation }

    struct Start {
        let admission: Admission
        let lastRecord: String?
        let restoring: Bool
    }

    /// Only these bounded launch values cross the process boundary. Presence
    /// and type are checked separately so malformed options cannot disappear.
    func beginProviderStart(temporaryOwner: Any?, restoreValue: Any?, restoreOwnerValue: Any?,
                            lastValue: Any?, executionSourcePresent: Bool) throws -> Start {
        let temporary = temporaryOwner as? String, token = restoreValue as? String
        let owner = restoreOwnerValue as? String, last = lastValue as? String
        guard (temporaryOwner == nil) == (temporary == nil), (restoreValue == nil) == (token == nil),
              (restoreOwnerValue == nil) == (owner == nil), (lastValue == nil) == (last == nil),
              last == nil || !(last?.isEmpty ?? true) && (last?.utf8.count ?? 0) <= 16 * 1024,
              last == nil || token == nil && owner == nil,
              token == nil && owner == nil && last == nil || executionSourcePresent else { throw issue() }
        return Start(admission: try beginStart(temporaryOwner: temporary, restoreToken: token, restoreOwner: owner),
                     lastRecord: last, restoring: token != nil)
    }

    /// Every actual start invalidates late capture publication. A captured
    /// Speed Lab original survives only trials carrying that same owner UUID.
    /// Any other start discards it, even if labels or source hashes match.
    func beginStart(temporaryOwner: String?, restoreToken: String?, restoreOwner: String?) throws -> Admission {
        if let temporaryOwner, UUID(uuidString: temporaryOwner)?.uuidString != temporaryOwner { throw issue() }
        lock.lock(); defer { lock.unlock() }
        generation = UUID()
        if restoreToken != nil || restoreOwner != nil {
            guard let restoreToken, validToken(restoreToken), let restoreOwner,
                  UUID(uuidString: restoreOwner)?.uuidString == restoreOwner,
                  temporaryOwner == nil || temporaryOwner == restoreOwner,
                  let entry, entry.owner == restoreOwner, entry.token == restoreToken, !entry.claiming else {
                self.entry = nil; throw issue()
            }
            return Admission(epoch: generation, entry: entry)
        }
        if entry?.owner != temporaryOwner { entry = nil }
        return Admission(epoch: generation, entry: nil)
    }

    func capture(host: RouterVPNNodeChainExecutionHost, session: String, request: Request, epoch: UUID) throws -> Data {
        guard request.operation == "ordered-execution-capture", request.session.isEmpty || request.session == session else { throw issue() }
        let (capsule, observation) = try host.captureRestoration()
        let next = Entry(host: host, capsule: capsule, observation: observation, session: session, owner: request.owner, request: request.request)
        lock.lock()
        guard generation == epoch, entry == nil || entry?.owner == request.owner && entry?.host === host else { lock.unlock(); throw issue() }
        entry = next
        lock.unlock()
        do { try host.validateRestoration(observation, execution: capsule.selected) }
        catch { discard(next); throw error }
        lock.lock(); let current = generation == epoch && entry === next; lock.unlock()
        guard current, let data = next.reply(request.request) else { throw issue() }
        return data
    }

    func verify(host: RouterVPNNodeChainExecutionHost, session: String, request: Request) throws -> Data {
        lock.lock(); let original = entry, epoch = generation, claiming = entry?.claiming ?? false; lock.unlock()
        guard let original, original.host === host, original.session == session, matches(original, request), !claiming else { throw issue() }
        try host.validateRestoration(original.observation, execution: original.execution)
        lock.lock(); let current = generation == epoch && entry === original && !original.claiming; lock.unlock()
        guard current, let data = original.reply(request.request) else { throw issue() }
        return data
    }

    func release(_ request: Request) -> Data? {
        lock.lock(); defer { lock.unlock() }
        guard request.operation == "ordered-execution-release", let entry, matches(entry, request), !entry.claiming else { return nil }
        self.entry = nil
        return encode(["schema": 1, "kind": "routervpn-ordered-execution-release", "request_id": request.request,
                       "session_id": request.session, "owner_id": request.owner, "token": request.token, "released": true])
    }

    func consume(_ admission: Admission, original: IOSNodeChainExecutionCapture) throws -> Restored {
        lock.lock()
        guard generation == admission.epoch, let captured = admission.entry, entry === captured, !captured.claiming else { lock.unlock(); throw issue() }
        captured.claiming = true
        lock.unlock()
        defer { lock.lock(); captured.claiming = false; lock.unlock() }
        let replacement = try captured.capsule.makeCapture(ordinaryInput: original.ordinaryLaunchInput, selectedProfile: original.finalProfile)
        lock.lock(); let current = generation == admission.epoch && entry === captured; if current { entry = nil }; lock.unlock()
        guard current else { try replacement.close(); throw issue() }
        return Restored(capture: replacement, original: captured)
    }

    func discardReply(host: RouterVPNNodeChainExecutionHost, request: Request) {
        lock.lock(); defer { lock.unlock() }
        if entry?.host === host, entry?.owner == request.owner, entry?.request == request.request, !((entry?.claiming) ?? false) { entry = nil }
    }
    private func discard(_ captured: Entry) { lock.lock(); if entry === captured { entry = nil }; lock.unlock() }
    private func matches(_ entry: Entry, _ request: Request) -> Bool {
        entry.session == request.session && entry.owner == request.owner && entry.token == request.token
    }
}

private func issue() -> NSError { NSError(domain: "RouterVPN.OrderedRestoration", code: 1) }
private func validToken(_ value: String) -> Bool {
    value.utf8.count == 32 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
}
private func encode(_ fields: [String: Any]) -> Data? {
    guard let data = try? JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys]), data.count <= 20 * 1024 else { return nil }
    return data
}
