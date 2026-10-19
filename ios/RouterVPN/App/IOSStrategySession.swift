import Foundation
import CoreFoundation

struct IOSStrategyCandidate: Codable, Equatable, Sendable {
    let raw: String
    let logical: String

    static func validID(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 96 && value.utf8.allSatisfy {
            (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || [45, 46, 95].contains($0)
        } && !value.contains("..")
    }
}

struct IOSStrategyPlan: Codable, Sendable {
    enum Kind: String, Codable, Sendable { case automatic = "auto", smart, custom, manual, logical }
    let version: Int
    let requestID: String
    let kind: Kind
    let candidates: [IOSStrategyCandidate]
    let preferredRaw: String?

    enum CodingKeys: String, CodingKey {
        case version, kind, candidates
        case requestID = "request_id", preferredRaw = "preferred_raw"
    }

    init(kind: Kind, candidates: [IOSStrategyCandidate], preferredRaw: String? = nil) throws {
        guard !candidates.isEmpty, candidates.count <= 32,
              Set(candidates.map(\.raw)).count == candidates.count,
              candidates.allSatisfy({ IOSStrategyCandidate.validID($0.raw) && IOSStrategyCandidate.validID($0.logical) }),
              kind != .manual || candidates.count == 1,
              kind != .logical || Set(candidates.map(\.logical)).count == 1,
              preferredRaw == nil || (kind == .smart && candidates.contains(where: { $0.raw == preferredRaw })) else {
            throw IOSStrategyWire.failure("The captured strategy has invalid or ambiguous candidates.")
        }
        version = 1; requestID = UUID().uuidString
        self.kind = kind; self.candidates = candidates; self.preferredRaw = preferredRaw
    }

    func object() throws -> [String: Any] {
        try JSONSerialization.jsonObject(with: JSONEncoder().encode(self)) as! [String: Any]
    }
}

struct IOSStrategyStatus: Decodable, Equatable, Sendable {
    enum Phase: String, Decodable, Sendable {
        case starting, trying, proving, restoring, connected, blocked, cancelled, stopped
    }
    enum Outcome: String, Decodable, Sendable { case pending, success, restored, cancelled, blocked }
    let version: Int
    let providerSession: String
    let runtimeEpoch: String
    let requestID: String
    let bundleDigest: String
    let kind: IOSStrategyPlan.Kind
    let phase: Phase
    let outcome: Outcome
    let nodeProven: Bool
    let dnsProven: Bool
    let currentRaw: String
    let currentLogical: String
    let provenRaw: String
    let provenLogical: String
    let engine: String
    let attempt: Int
    let candidateCount: Int
    let message: String

    enum CodingKeys: String, CodingKey {
        case version, kind, phase, outcome, engine, attempt, message
        case nodeProven = "node_proven", dnsProven = "dns_proven"
        case providerSession = "provider_session", runtimeEpoch = "runtime_epoch", requestID = "request_id"
        case bundleDigest = "bundle_digest", currentRaw = "current_raw", currentLogical = "current_logical"
        case provenRaw = "proven_raw", provenLogical = "proven_logical", candidateCount = "candidate_count"
    }

    var isProven: Bool { nodeProven && dnsProven && [.connected, .cancelled].contains(phase) }
    var isRunning: Bool { [.starting, .trying, .proving, .restoring].contains(phase) }
}

enum IOSStrategyWire {
    static func failure(_ message: String) -> NSError {
        NSError(domain: "RouterVPN.Strategy", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }

    static func catalog(_ configuration: [String: Any]) throws -> [IOSStrategyCandidate] {
        guard let value = configuration["strategy_catalog"] as? [String: Any],
              Set(value.keys) == Set(["version", "candidates"]),
              let version = value["version"] as? NSNumber, CFGetTypeID(version) != CFBooleanGetTypeID(), version == NSNumber(value: 1),
              let values = value["candidates"] as? [[String: Any]], !values.isEmpty, values.count <= 32 else {
            throw failure("This VPN has no frozen strategy catalog; reconnect to use owned mode switching.")
        }
        let candidates = try values.map { value -> IOSStrategyCandidate in
            guard Set(value.keys) == Set(["raw", "logical"]), let raw = value["raw"] as? String,
                  let logical = value["logical"] as? String, IOSStrategyCandidate.validID(raw),
                  IOSStrategyCandidate.validID(logical) else { throw failure("The frozen strategy catalog is malformed.") }
            return IOSStrategyCandidate(raw: raw, logical: logical)
        }
        guard Set(candidates.map(\.raw)).count == candidates.count else { throw failure("The frozen strategy catalog repeats a runtime.") }
        return candidates
    }

    static func status(_ data: Data, bundleDigest: String, catalog: [IOSStrategyCandidate],
                       requestID: String? = nil, providerSession: String? = nil) throws -> IOSStrategyStatus {
        guard !data.isEmpty, data.count <= 8192,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == Set(["version", "provider_session", "runtime_epoch", "request_id", "bundle_digest",
                                      "kind", "phase", "outcome", "node_proven", "dns_proven", "current_raw", "current_logical", "proven_raw", "proven_logical",
                                      "engine", "attempt", "candidate_count", "message"]) else {
            throw failure("The owned VPN returned an invalid strategy status.")
        }
        let value = try JSONDecoder().decode(IOSStrategyStatus.self, from: data)
        guard value.version == 1, UUID(uuidString: value.providerSession) != nil,
              UUID(uuidString: value.requestID) != nil,
              value.runtimeEpoch.isEmpty || UUID(uuidString: value.runtimeEpoch) != nil,
              bundleDigest.utf8.count == 64, bundleDigest.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              value.bundleDigest == bundleDigest, requestID == nil || value.requestID == requestID,
              providerSession == nil || value.providerSession == providerSession,
              value.engine == "libbox", (1...32).contains(value.candidateCount),
              value.candidateCount <= catalog.count, (0...128).contains(value.attempt),
              value.message.utf8.count <= 512, !value.message.contains("\u{0}") else {
            throw failure("The strategy reply belongs to another configuration, request, or runtime.")
        }
        func contains(_ raw: String, _ logical: String) -> Bool {
            catalog.contains(IOSStrategyCandidate(raw: raw, logical: logical))
        }
        guard (value.currentRaw.isEmpty && value.currentLogical.isEmpty) || contains(value.currentRaw, value.currentLogical) else {
            throw failure("Strategy status named a runtime outside the frozen catalog.")
        }
        if value.isProven {
            guard !value.runtimeEpoch.isEmpty, value.attempt > 0,
                  value.provenRaw == value.currentRaw, value.provenLogical == value.currentLogical,
                  contains(value.provenRaw, value.provenLogical) else {
                throw failure("Connected strategy status did not prove its current runtime.")
            }
        } else if !value.provenRaw.isEmpty || !value.provenLogical.isEmpty || value.phase == .connected || value.nodeProven || value.dnsProven {
            throw failure("An unfinished strategy cannot publish a proven runtime.")
        }
        if value.isRunning && value.outcome != .pending { throw failure("An active strategy cannot report a final outcome.") }
        if value.outcome == .success && value.phase != .connected { throw failure("A successful strategy must prove its current connection.") }
        if value.outcome == .restored && !value.isProven { throw failure("A restored strategy must re-prove its protected runtime.") }
        return value
    }
}

final class IOSStrategyReply: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data, Error>?
    private var completed = false
    func install(_ value: CheckedContinuation<Data, Error>) -> Bool {
        lock.lock()
        if completed { lock.unlock(); value.resume(throwing: CancellationError()); return false }
        continuation = value; lock.unlock(); return true
    }
    func finish(_ data: Data?, cancelled: Bool = false) {
        lock.lock()
        guard !completed else { lock.unlock(); return }
        completed = true; let pending = continuation; continuation = nil; lock.unlock()
        guard let pending else { return }
        if cancelled { pending.resume(throwing: CancellationError()) }
        else if let data, !data.isEmpty, data.count <= 8192 { pending.resume(returning: data) }
        else { pending.resume(throwing: IOSStrategyWire.failure("The owned VPN did not answer the strategy request.")) }
    }
}

#if canImport(NetworkExtension)
@preconcurrency import NetworkExtension

@MainActor enum IOSStrategyTransport {
    static func send(_ connection: NETunnelProviderSession, request: [String: Any]) async throws -> Data {
        try Task.checkCancellation()
        let data = try JSONSerialization.data(withJSONObject: request)
        guard data.count <= 8192 else { throw IOSStrategyWire.failure("The strategy request exceeds its bound.") }
        let reply = IOSStrategyReply()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                guard reply.install(continuation) else { return }
                DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 3) { reply.finish(nil) }
                do { try connection.sendProviderMessage(data) { reply.finish($0) } }
                catch { reply.finish(nil) }
            }
        } onCancel: { reply.finish(nil, cancelled: true) }
    }
}
#endif
