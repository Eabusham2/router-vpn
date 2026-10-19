import Foundation

struct RouterVPNStrategyAttempt: Sendable, Equatable {
    let epoch: String
    let candidate: RouterVPNStrategyCandidate
    let restoring: Bool
}

struct RouterVPNStrategyProof: Sendable {
    let nodeID: String
    let dns: Bool
}

/// The native driver serializes close/start operations. Every callback carries
/// the immutable epoch that owned it; no callback may adopt a newer runtime.
protocol RouterVPNStrategyDriver: AnyObject, Sendable {
    func replace(_ attempt: RouterVPNStrategyAttempt,
                 proving: @escaping @Sendable () -> Void,
                 completion: @escaping @Sendable (Result<RouterVPNStrategyProof, Error>) -> Void)
    func activate(_ attempt: RouterVPNStrategyAttempt, completion: @escaping @Sendable (Error?) -> Void)
    func protect(epoch: String)
}

/// Foundation-only lifetime owner, executed by the same tests on Linux and
/// Apple. The lock protects state only: native close/start and callbacks always
/// run outside it, so a closing Go runtime cannot deadlock the strategy owner.
final class RouterVPNProviderStrategy: @unchecked Sendable {
    private enum Purpose { case initial, reduction, restoration, recovery, cancellation, previous }
    private enum Action { case replace(RouterVPNStrategyAttempt), activate(RouterVPNStrategyAttempt), protect(String) }
    private let lock = NSRecursiveLock()
    private let policy: RouterVPNStrategyPolicy
    private let driver: any RouterVPNStrategyDriver
    let providerSession = UUID().uuidString
    let bundleDigest: String
    private let nodeID: String
    private var plan: RouterVPNStrategyPlan
    private var epoch = UUID().uuidString
    private var phase = "starting"
    private var outcome = "pending"
    private var message = "Preparing a protected native strategy session."
    private var current: RouterVPNStrategyCandidate?
    private var proven: RouterVPNStrategyCandidate?
    private var lastGood: RouterVPNStrategyCandidate?
    private var previousGood: RouterVPNStrategyCandidate?
    private var purpose: Purpose = .initial
    private var remaining: [RouterVPNStrategyCandidate] = []
    private var visited = Set<String>()
    private var seenRequests = Set<String>()
    private var attempts = 0
    private var recoveries = 0
    private var cancelling = false
    private var activating = false

    init(policy: RouterVPNStrategyPolicy, plan: RouterVPNStrategyPlan, bundleDigest: String,
         nodeID: String, driver: any RouterVPNStrategyDriver) throws {
        guard bundleDigest.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
              nodeID.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else {
            throw RouterVPNStrategyPolicy.error("Strategy ownership requires exact bundle and node identities.")
        }
        self.policy = policy; self.plan = plan; self.bundleDigest = bundleDigest
        self.nodeID = nodeID; self.driver = driver
        seenRequests.insert(plan.requestID)
    }

    func start() {
        lock.lock()
        guard phase == "starting" else { lock.unlock(); return }
        preparePlanLocked()
        let action = nextInitialLocked()
        lock.unlock()
        perform(action)
    }

    func isCurrent(_ candidateEpoch: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return epoch == candidateEpoch && phase != "stopped"
    }

    /// Short provider property/owner transactions only. Do not perform native
    /// operations or wait for NetworkExtension callbacks inside this body.
    @discardableResult
    func withCurrentEpoch(_ candidateEpoch: String, _ body: () -> Void) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard epoch == candidateEpoch, phase != "stopped" else { return false }
        body(); return true
    }

    var currentEpoch: String {
        lock.lock(); defer { lock.unlock() }; return epoch
    }

    private var busyLocked: Bool { ["starting", "trying", "proving", "restoring"].contains(phase) }

    func handle(_ data: Data) -> Data? {
        guard !data.isEmpty, data.count <= 8192,
              let request = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let operation = request["operation"] as? String else { return nil }
        if operation == "strategy-status" {
            lock.lock(); defer { lock.unlock() }
            let keys = Set(request.keys)
            if keys == ["operation", "bundle_digest"] {
                guard request["bundle_digest"] as? String == bundleDigest else { return nil }
            } else {
                guard keys == ["operation", "request_id"] || keys == ["operation", "request_id", "provider_session"],
                      request["request_id"] as? String == plan.requestID,
                      request["provider_session"] == nil || request["provider_session"] as? String == providerSession else { return nil }
            }
            return statusLocked()
        }
        if operation == "strategy-cancel" {
            lock.lock()
            guard Set(request.keys) == ["operation", "request_id", "provider_session"],
                  request["request_id"] as? String == plan.requestID,
                  request["provider_session"] as? String == providerSession, phase != "stopped" else { lock.unlock(); return nil }
            let action = cancelLocked()
            let response = statusLocked()
            lock.unlock()
            perform(action)
            return response
        }
        if operation == "strategy-run" {
            guard Set(request.keys) == ["operation", "provider_session", "request_id", "strategy"],
                  let value = request["strategy"] as? [String: Any],
                  let next = try? policy.plan(value, initial: false) else { return nil }
            lock.lock()
            guard request["provider_session"] as? String == providerSession,
                  request["request_id"] as? String == plan.requestID,
                  !busyLocked, phase != "stopped", seenRequests.count < 128,
                  seenRequests.insert(next.requestID).inserted else { lock.unlock(); return nil }
            previousGood = proven ?? lastGood
            lastGood = previousGood
            plan = next; attempts = 0; recoveries = 0; cancelling = false
            preparePlanLocked()
            let action = nextInitialLocked()
            let response = statusLocked()
            lock.unlock()
            perform(action)
            return response
        }
        return nil
    }

    /// A path/MTU/padding lifetime boundary invalidates proof immediately. A
    /// fresh generation may re-prove the immutable last good configuration.
    func invalidate(epoch captured: String) {
        lock.lock()
        guard epoch == captured, phase != "stopped", phase != "blocked" else { lock.unlock(); return }
        let action: Action?
        if busyLocked {
            action = failedLocked()
        } else if let saved = lastGood, recoveries < 2 {
            recoveries += 1
            action = attemptLocked(saved, purpose: .recovery)
        } else {
            action = blockLocked("The native path lost proof; traffic remains protected until a new strategy succeeds.")
        }
        lock.unlock()
        perform(action)
    }

    func stop() {
        lock.lock()
        epoch = UUID().uuidString; phase = "stopped"; outcome = "blocked"
        proven = nil; current = nil; lastGood = nil; previousGood = nil
        remaining = []; activating = false
        message = "The provider session has stopped."
        lock.unlock()
    }

    func teardownFailed(epoch captured: String) {
        lock.lock()
        guard epoch == captured, phase != "stopped" else { lock.unlock(); return }
        let action = blockLocked("Native teardown could not be verified. Traffic remains protected; no replacement runtime was started.")
        lock.unlock()
        perform(action)
    }

    private func preparePlanLocked() {
        remaining = plan.candidates
        if plan.kind == .smart, let preferred = plan.preferredRaw,
           let index = remaining.firstIndex(where: { $0.raw == preferred }) {
            let first = remaining.remove(at: index); remaining.insert(first, at: 0)
        }
        visited = []; proven = nil; outcome = "pending"; activating = false
    }

    private func nextInitialLocked() -> Action? {
        guard !remaining.isEmpty else {
            if let saved = previousGood { return attemptLocked(saved, purpose: .previous) }
            return blockLocked("No captured candidate passed selected-node and DNS proof. Traffic remains protected.")
        }
        let candidate = remaining.removeFirst()
        visited.insert(candidate.raw)
        return attemptLocked(candidate, purpose: .initial)
    }

    private func attemptLocked(_ candidate: RouterVPNStrategyCandidate, purpose: Purpose) -> Action {
        guard attempts < 96 else { return blockLocked("The bounded strategy attempt budget was exhausted. Traffic remains protected.") }
        attempts += 1; epoch = UUID().uuidString; current = candidate; proven = nil
        self.purpose = purpose; activating = false
        let restoring = [.restoration, .recovery, .cancellation, .previous].contains(purpose)
        phase = restoring ? "restoring" : "trying"; outcome = "pending"
        message = restoring ? "Restoring and re-proving the captured last good runtime." : "Trying a captured native runtime while route protection remains active."
        return .replace(RouterVPNStrategyAttempt(epoch: epoch, candidate: candidate, restoring: restoring))
    }

    private func blockLocked(_ text: String) -> Action {
        epoch = UUID().uuidString; phase = "blocked"; outcome = "blocked"
        current = nil; proven = nil; activating = false; message = text
        return .protect(epoch)
    }

    private func cancelLocked() -> Action? {
        if cancelling, phase == "restoring" { return nil }
        cancelling = true; remaining = []
        if let proven, !busyLocked {
            lastGood = proven; phase = "cancelled"; outcome = "cancelled"
            message = "Strategy cancelled; the proven native runtime remains protected."
            return nil
        }
        if let saved = lastGood { return attemptLocked(saved, purpose: .cancellation) }
        let action = blockLocked("Strategy cancelled before a candidate was proved. Traffic remains protected.")
        phase = "cancelled"; outcome = "cancelled"
        return action
    }

    private func nextReductionLocked() -> Action? {
        guard let best = lastGood else { return blockLocked("SMART lost its captured last good runtime. Traffic remains protected.") }
        for raw in RouterVPNStrategyPolicy.simplify[best.raw] ?? [] where !visited.contains(raw) {
            visited.insert(raw)
            guard let candidate = plan.candidates.first(where: { $0.raw == raw }) else { continue }
            return attemptLocked(candidate, purpose: .reduction)
        }
        return activationLocked(best)
    }

    private func activationLocked(_ candidate: RouterVPNStrategyCandidate) -> Action {
        current = candidate; phase = "proving"; activating = true
        message = "Activating only the proved runtime's MTU and forwarding owners."
        return .activate(RouterVPNStrategyAttempt(epoch: epoch, candidate: candidate,
            restoring: [.restoration, .recovery, .cancellation, .previous].contains(purpose)))
    }

    private func failedLocked() -> Action? {
        activating = false; proven = nil
        switch purpose {
        case .initial: return nextInitialLocked()
        case .reduction:
            guard let saved = lastGood else { return blockLocked("SMART's candidate failed without a restorable proven runtime.") }
            return attemptLocked(saved, purpose: .restoration)
        case .restoration, .recovery, .cancellation, .previous:
            return blockLocked("The captured last good runtime could not be re-proved. Traffic remains protected.")
        }
    }

    private func proved(_ attempt: RouterVPNStrategyAttempt, _ result: Result<RouterVPNStrategyProof, Error>) {
        lock.lock()
        guard epoch == attempt.epoch, current == attempt.candidate, busyLocked, !activating else { lock.unlock(); return }
        let action: Action?
        switch result {
        case .failure: action = failedLocked()
        case .success(let proof):
            if proof.nodeID != nodeID || !proof.dns {
                action = failedLocked()
            } else {
                lastGood = attempt.candidate
                if cancelling || [.recovery, .cancellation, .previous].contains(purpose) {
                    action = activationLocked(attempt.candidate)
                } else if plan.kind == .smart {
                    action = nextReductionLocked()
                } else {
                    action = activationLocked(attempt.candidate)
                }
            }
        }
        lock.unlock()
        perform(action)
    }

    private func activated(_ attempt: RouterVPNStrategyAttempt, error: Error?) {
        lock.lock()
        guard epoch == attempt.epoch, current == attempt.candidate, activating else { lock.unlock(); return }
        let action: Action?
        if error != nil {
            action = failedLocked()
        } else {
            activating = false; proven = attempt.candidate; lastGood = attempt.candidate
            phase = cancelling ? "cancelled" : "connected"
            outcome = cancelling ? "cancelled" : (purpose == .previous ? "restored" : "success")
            message = cancelling ? "Strategy cancelled; the captured last good runtime passed fresh node and DNS proof."
                : (purpose == .previous ? "The requested candidates failed; the previous runtime passed fresh node and DNS proof."
                    : "The selected native runtime passed exact node and DNS proof.")
            action = nil
        }
        lock.unlock()
        perform(action)
    }

    private func perform(_ action: Action?) {
        switch action {
        case .replace(let attempt):
            driver.replace(attempt, proving: { [weak self] in
                guard let self else { return }
                self.lock.lock(); defer { self.lock.unlock() }
                guard self.epoch == attempt.epoch, self.current == attempt.candidate, self.busyLocked, !self.activating else { return }
                if !attempt.restoring { self.phase = "proving" }
                self.message = "Proving the exact selected node and captured DNS policy through this native runtime."
            }, completion: { [weak self] result in self?.proved(attempt, result) })
        case .activate(let attempt): driver.activate(attempt) { [weak self] error in self?.activated(attempt, error: error) }
        case .protect(let epoch): driver.protect(epoch: epoch)
        case nil: break
        }
    }

    private func statusLocked() -> Data? {
        let status: [String: Any] = [
            "version": 1, "provider_session": providerSession, "runtime_epoch": epoch,
            "request_id": plan.requestID, "bundle_digest": bundleDigest, "kind": plan.kind.rawValue,
            "phase": phase, "outcome": outcome, "current_raw": current?.raw ?? "", "current_logical": current?.logical ?? "",
            "proven_raw": proven?.raw ?? "", "proven_logical": proven?.logical ?? "", "engine": "libbox",
            "node_proven": proven != nil, "dns_proven": proven != nil,
            "attempt": attempts, "candidate_count": plan.candidates.count, "message": String(message.prefix(512))
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: status, options: [.sortedKeys]), data.count <= 4096 else { return nil }
        return data
    }
}
