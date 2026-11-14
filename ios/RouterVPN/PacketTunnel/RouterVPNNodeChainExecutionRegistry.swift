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
        let operation: String, request: String, session: String, owner: String, token: String, captureRequest: String
        let process: String?, registryGeneration: UInt64?
        static func parse(_ data: Data) -> Request? {
            guard !data.isEmpty, data.count <= 1024,
                  let body = try? JSONSerialization.jsonObject(with: data) as? [String: String],
                  let operation = body["operation"], ["ordered-execution-capture", "ordered-execution-verify", "ordered-execution-release", "ordered-execution-capture-release", "ordered-execution-last", "ordered-execution-owner"].contains(operation),
                  let request = body["request_id"], validToken(request),
                  let session = body["session_id"], session.isEmpty || UUID(uuidString: session)?.uuidString == session,
                  let owner = body["owner_id"] else { return nil }
            if operation == "ordered-execution-capture-release" {
                guard Set(body.keys) == Set(["operation", "request_id", "session_id", "owner_id", "capture_request_id", "process_id", "registry_generation"]),
                      !session.isEmpty, UUID(uuidString: owner)?.uuidString == owner,
                      let capture = body["capture_request_id"], validToken(capture),
                      let process = body["process_id"], UUID(uuidString: process)?.uuidString == process,
                      let raw = body["registry_generation"], let generation = UInt64(raw), String(generation) == raw else { return nil }
                return Request(operation: operation, request: request, session: session, owner: owner, token: "", captureRequest: capture,
                    process: process, registryGeneration: generation)
            }
            let scoped = operation == "ordered-execution-capture" && body["process_id"] != nil
            let fields: Set<String> = scoped ? ["operation", "request_id", "session_id", "owner_id", "token", "process_id", "registry_generation"] :
                ["operation", "request_id", "session_id", "owner_id", "token"]
            guard Set(body.keys) == fields,
                  let token = body["token"] else { return nil }
            var process: String?, generation: UInt64?
            if scoped {
                guard let value = body["process_id"], UUID(uuidString: value)?.uuidString == value,
                      let raw = body["registry_generation"], let number = UInt64(raw), String(number) == raw else { return nil }
                process = value; generation = number
            }
            if operation == "ordered-execution-last" || operation == "ordered-execution-owner" {
                guard owner.isEmpty, token.isEmpty else { return nil }
            } else {
                guard UUID(uuidString: owner)?.uuidString == owner else { return nil }
                if operation == "ordered-execution-capture" { guard token.isEmpty else { return nil } }
                else { guard !session.isEmpty, validToken(token) else { return nil } }
            }
            return Request(operation: operation, request: request, session: session, owner: owner, token: token, captureRequest: "",
                process: process, registryGeneration: generation)
        }
        func lastObservation() -> Request {
            Request(operation: "ordered-execution-last", request: request, session: session, owner: "", token: "", captureRequest: "",
                process: nil, registryGeneration: nil)
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
        let registryGeneration: UInt64
        let source: String, configuration: String
        var claiming = false
        init(host: RouterVPNNodeChainExecutionHost, capsule: IOSNodeChainExecutionCapture.Restoration,
             observation: UUID, session: String, owner: String, request: String, registryGeneration: UInt64) {
            self.host = host; self.capsule = capsule; self.observation = observation
            self.session = session; self.owner = owner; self.request = request
            self.registryGeneration = registryGeneration
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
    private let process = UUID().uuidString
    private var generation = UUID()
    private var generationNumber: UInt64 = 0
    private var entry: Entry?
    private struct CaptureRequest: Hashable {
        let session: String, owner: String, request: String
    }
    // A timeout may precede the original worker's publication. Keep each
    // retired nonce for this whole generation; never evict a live fence to
    // admit another cleanup. A new start already fences every older worker.
    private var retiredCaptures = Set<CaptureRequest>()
    private static let maximumRetiredCaptures = 64

    func epoch() -> UUID { lock.lock(); defer { lock.unlock() }; return generation }

    /// Add registry identity only to an actual proved Last response retained
    /// by the provider's original engine/proof callback. A different process
    /// cannot acknowledge the absence of an older process's native capsule.
    func observe(_ data: Data?, request: Request, epoch: UUID) -> Data? {
        guard request.operation == "ordered-execution-owner", let data, data.count <= 20 * 1024,
              var fields = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(fields.keys) == Set(["schema", "kind", "request_id", "session_id", "source_sha256", "preparation_config_sha256", "last"]),
              fields["kind"] as? String == "routervpn-ordered-execution-last", fields["request_id"] as? String == request.request else { return nil }
        lock.lock(); defer { lock.unlock() }
        guard generation == epoch else { return nil }
        fields["kind"] = "routervpn-ordered-execution-owner"
        fields["process_id"] = process; fields["registry_generation"] = String(generationNumber)
        return encode(fields)
    }

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
        guard generationNumber < UInt64.max else { throw issue() }
        generationNumber += 1
        generation = UUID()
        retiredCaptures.removeAll(keepingCapacity: true)
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
        let key = CaptureRequest(session: session, owner: request.owner, request: request.request)
        lock.lock()
        let scoped = request.process == nil || request.process == process && request.registryGeneration == generationNumber
        let capturedGeneration = generationNumber
        let available = generation == epoch && scoped && !retiredCaptures.contains(key)
        lock.unlock()
        guard available else { throw issue() }
        let (capsule, observation) = try host.captureRestoration()
        let next = Entry(host: host, capsule: capsule, observation: observation, session: session, owner: request.owner, request: request.request,
            registryGeneration: capturedGeneration)
        lock.lock()
        guard generation == epoch, !retiredCaptures.contains(key), entry == nil || entry?.owner == request.owner && entry?.host === host else { lock.unlock(); throw issue() }
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

    /// Retire exactly one capture request, even when its original reply was
    /// lost or its worker has not published yet. This is independent of the
    /// opaque native restoration token, and never stops or consumes a host.
    func releaseCapture(_ request: Request) -> Data? {
        guard request.operation == "ordered-execution-capture-release" else { return nil }
        let key = CaptureRequest(session: request.session, owner: request.owner, request: request.captureRequest)
        lock.lock(); defer { lock.unlock() }
        guard request.process == process, let requestedGeneration = request.registryGeneration,
              requestedGeneration <= generationNumber else { return nil }
        let matches = entry?.session == request.session && entry?.owner == request.owner && entry?.request == request.captureRequest &&
            entry?.registryGeneration == requestedGeneration
        guard !matches || entry?.claiming == false,
              requestedGeneration < generationNumber || retiredCaptures.contains(key) || retiredCaptures.count < Self.maximumRetiredCaptures else { return nil }
        // Every older worker has already been fenced by beginStart. Only a
        // current-generation retirement needs a non-evictable pending marker.
        if requestedGeneration == generationNumber { retiredCaptures.insert(key) }
        if matches { entry = nil }
        return encode(["schema": 1, "kind": "routervpn-ordered-execution-capture-release", "request_id": request.request,
            "session_id": request.session, "owner_id": request.owner, "capture_request_id": request.captureRequest, "released": true,
            "process_id": process, "registry_generation": String(requestedGeneration)])
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
