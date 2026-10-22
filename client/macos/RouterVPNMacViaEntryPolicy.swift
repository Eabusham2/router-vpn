import Foundation

/// One modal candidate transaction reserves native editing until the controller
/// acknowledges retirement of the exact nonce, including cancel-before-start.
final class MacViaEntryCandidateReservation: @unchecked Sendable {
    static let shared = MacViaEntryCandidateReservation()
    private let lock = NSLock()
    private var token: UUID?

    var active: Bool { lock.lock(); defer { lock.unlock() }; return token != nil }
    func acquire() -> UUID? {
        lock.lock(); defer { lock.unlock() }
        guard token == nil else { return nil }
        let value = UUID(); token = value; return value
    }
    func release(_ owner: UUID) {
        lock.lock(); defer { lock.unlock() }
        if token == owner { token = nil }
    }
}

struct MacViaEntryCandidateReceipt {
    struct Row {
        let id: String
        let medianMS: Double?
        let samples: Int
        let reason: String?
    }
    let requestID: String
    let entryID: String
    let measuredAt: Date
    let expiresAt: Date
    let rows: [Row]
    let fastestID: String?

    private struct Payload: Decodable {
        let schema: Int, request_id: String, entry_id: String, entry_mode: String, entry_base: String, drained: Bool
        let measured_at: String, expires_at: String
        let results: [Measurement]?, errors: [Failure]?, fastest_id: String
    }
    private struct Measurement: Decodable {
        let id: String, node_kind: String
        let samples: Int, failed: Int, median_ms: Double
    }
    private struct Failure: Decodable { let id: String, error: String }

    init(data: Data, requestID: String, entryID: String, candidates: [String], now: Date = Date()) throws {
        guard data.count <= 256 * 1024 else { throw Self.issue("Candidate response is too large.") }
        let value = try JSONDecoder().decode(Payload.self, from: data)
        guard value.schema == 1, value.request_id == requestID, value.entry_id == entryID,
              value.entry_mode == "wg", value.entry_base == "wg", value.drained,
              let measured = Self.date(value.measured_at), let expires = Self.date(value.expires_at),
              measured <= now.addingTimeInterval(5), expires > now, expires > measured,
              expires.timeIntervalSince(measured) <= 150,
              !candidates.isEmpty, candidates.count <= 64, Set(candidates).count == candidates.count,
              !candidates.contains(entryID) else { throw Self.issue("Candidate result is stale or does not match the captured WireGuard entry.") }
        let requested = Set(candidates)
        var seen = Set<String>(), rows: [Row] = []
        for result in value.results ?? [] {
            guard requested.contains(result.id), seen.insert(result.id).inserted, result.node_kind == "router-vpn",
                  (0...5).contains(result.samples), (0...5).contains(result.failed), result.samples + result.failed <= 5,
                  result.median_ms.isFinite else { throw Self.issue("Candidate response contains an invalid or unrelated measurement.") }
            let eligible = result.samples >= 3 && result.failed == 0 && result.median_ms > 0
            rows.append(Row(id: result.id, medianMS: eligible ? result.median_ms : nil, samples: result.samples,
                            reason: eligible ? nil : "Unavailable: routed response samples were incomplete."))
        }
        for failure in value.errors ?? [] {
            guard requested.contains(failure.id), seen.insert(failure.id).inserted else { throw Self.issue("Candidate response contains duplicate or unrelated rows.") }
            rows.append(Row(id: failure.id, medianMS: nil, samples: 0, reason: "Unavailable through this entry."))
        }
        guard seen == requested else { throw Self.issue("Candidate response is incomplete; Retest before selecting a measured exit.") }
        let eligible = rows.filter { $0.medianMS != nil }
        if value.fastest_id.isEmpty {
            guard eligible.isEmpty else { throw Self.issue("Candidate result has no valid Fastest decision.") }
        } else {
            guard let fastest = eligible.first(where: { $0.id == value.fastest_id }),
                  let minimum = eligible.compactMap(\.medianMS).min(), fastest.medianMS == minimum else {
                throw Self.issue("Fastest does not identify the lowest valid routed response.")
            }
        }
        self.requestID = requestID; self.entryID = entryID; measuredAt = measured; expiresAt = expires
        self.rows = rows.sorted {
            if let a = $0.medianMS, let b = $1.medianMS { return a == b ? $0.id < $1.id : a < b }
            if ($0.medianMS != nil) != ($1.medianMS != nil) { return $0.medianMS != nil }
            return $0.id < $1.id
        }
        fastestID = value.fastest_id.isEmpty ? nil : value.fastest_id
    }

    func eligible(_ id: String, now: Date = Date()) -> Bool {
        now < expiresAt && rows.contains { $0.id == id && $0.medianMS != nil }
    }
    static func issue(_ message: String) -> NSError {
        NSError(domain: "RouterVPN.ViaEntryCandidates", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
    private static func date(_ value: String) -> Date? {
        let parser = ISO8601DateFormatter()
        parser.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = parser.date(from: value) { return date }
        parser.formatOptions = [.withInternetDateTime]
        return parser.date(from: value)
    }
}

/// UI callbacks use tickets so queued replies cannot adopt a superseded entry,
/// release another transaction or restart before old native cleanup is proved.
final class MacViaEntryCandidateSession {
    enum Phase { case idle, measuring, ready, validating, draining, cleanupFailed, closed }
    enum AfterDrain { case stay, retest, close }
    struct Ticket: Equatable {
        let requestID: String
        let entryID: String
        let candidates: [String]
    }
    private(set) var phase = Phase.idle
    private(set) var ticket: Ticket?
    private(set) var receipt: MacViaEntryCandidateReceipt?
    private var afterDrain = AfterDrain.stay
    private var validatingExit: String?
    private var usedNonces = Set<String>()

    func begin(entryID: String, candidates: [String], nonce: String = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()) throws -> Ticket {
        guard phase == .idle, ticket == nil, !entryID.isEmpty, !candidates.isEmpty, candidates.count <= 64,
              Set(candidates).count == candidates.count, !candidates.contains(entryID), candidates.allSatisfy({ !$0.isEmpty }),
              nonce.count == 32, nonce.allSatisfy({ "0123456789abcdef".contains($0) }), !usedNonces.contains(nonce) else {
            throw MacViaEntryCandidateReceipt.issue("Candidate test cannot start until its previous transaction has drained.")
        }
        let next = Ticket(requestID: nonce, entryID: entryID, candidates: candidates)
        usedNonces.insert(nonce); ticket = next; receipt = nil; phase = .measuring; return next
    }

    @discardableResult func accept(_ data: Data, for captured: Ticket, now: Date = Date()) throws -> Bool {
        guard ticket == captured, phase == .measuring else { return false }
        receipt = try MacViaEntryCandidateReceipt(data: data, requestID: captured.requestID, entryID: captured.entryID, candidates: captured.candidates, now: now)
        phase = .ready; return true
    }

    func beginValidation(exitID: String, now: Date = Date()) throws -> Ticket {
        guard phase == .ready, let ticket, receipt?.eligible(exitID, now: now) == true else {
            throw MacViaEntryCandidateReceipt.issue("This exit has no current routed measurement. Retest before selecting it here.")
        }
        validatingExit = exitID; phase = .validating; return ticket
    }

    @discardableResult func acceptValidation(_ data: Data, for captured: Ticket, exitID: String, now: Date = Date()) throws -> Bool {
        guard ticket == captured, phase == .validating, validatingExit == exitID else { return false }
        guard data.count <= 8192 else { throw MacViaEntryCandidateReceipt.issue("Candidate validation response is too large.") }
        struct Reply: Decodable { let ok: Bool, request_id: String, entry_id: String, exit_id: String, entry_base: String, entry_mode: String, measured: Bool }
        let value = try JSONDecoder().decode(Reply.self, from: data)
        guard value.ok, value.request_id == captured.requestID, value.entry_id == captured.entryID,
              value.exit_id == exitID, value.entry_base == "wg", value.entry_mode == "wg", value.measured,
              receipt?.eligible(exitID, now: now) == true else {
            throw MacViaEntryCandidateReceipt.issue("The source, network or measured selection changed. Retest before adopting an exit.")
        }
        validatingExit = nil; phase = .ready; return true
    }

    func beginDrain(_ action: AfterDrain) -> Ticket? {
        guard phase != .closed else { return nil }
        if afterDrain != .close { afterDrain = action }
        receipt = nil; validatingExit = nil
        guard let ticket, phase != .draining else { return nil }
        phase = .draining; return ticket
    }

    func acceptDrain(_ data: Data, for captured: Ticket) throws -> AfterDrain? {
        guard ticket == captured, phase == .draining else { return nil }
        guard data.count <= 8192 else { throw MacViaEntryCandidateReceipt.issue("Candidate cleanup response is too large.") }
        struct Reply: Decodable { let ok: Bool, request_id: String, drained: Bool }
        let value = try JSONDecoder().decode(Reply.self, from: data)
        guard value.ok, value.request_id == captured.requestID, value.drained else {
            throw MacViaEntryCandidateReceipt.issue("The controller has not confirmed cleanup of this candidate transaction.")
        }
        ticket = nil; receipt = nil; phase = .idle
        let action = afterDrain; afterDrain = .stay; return action
    }

    func failedDrain(_ captured: Ticket) {
        if ticket == captured, phase == .draining { phase = .cleanupFailed }
    }

    func closeIdle() throws {
        guard ticket == nil, phase == .idle else { throw MacViaEntryCandidateReceipt.issue("Candidate cleanup is still pending.") }
        phase = .closed
    }
}
