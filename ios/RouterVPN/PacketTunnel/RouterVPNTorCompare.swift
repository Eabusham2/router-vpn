import Foundation
import CoreFoundation
import Libbox

/// One comparison inside an existing PacketTunnel. The native coordinator owns
/// the random endpoint, both response probes, scoring and final repetition.
/// This host owns the concrete engines and their single physical-path epoch.
final class RouterVPNTorCompare: NSObject, LibboxRouterTorCompareHostProtocol, @unchecked Sendable {
    let epoch = UUID().uuidString
    let source: IOSMultihopExecution.Source
    private let profile: Data
    private let entryProfile: Data
    private let entryFiles: [String: Data]
    private let strict: Bool
    private let mtuHold: String
    private let captureSHA256: String
    private let makeEngine: (String) throws -> RouterVPNLibboxEngine
    private let available: (RouterVPNTorCompare) -> Bool
    private let ownsEngine: (RouterVPNTorCompare, RouterVPNLibboxEngine) -> Bool
    private let install: (RouterVPNTorCompare, RouterVPNLibboxEngine) throws -> Void
    private let release: (RouterVPNTorCompare, RouterVPNLibboxEngine) -> Void
    private let activate: (RouterVPNTorCompare, RouterVPNLibboxEngine) throws -> Void
    private let lock = NSLock()
    private let queue = DispatchQueue(label: "com.eabusham.routervpn.tor-compare", qos: .userInitiated)
    private var round: LibboxRouterTorCompare?
    private var candidate: Candidate?
    private var callback: ((RouterVPNTorCompare, Error?) -> Void)?
    private var cancelled = false
    private var transferred = false
    private var started = false
    private var drained = false
    private var stage = "pending"
    private var execution = ""
    private var target = ""
    private var result: [String: Any]?

    init(source: IOSMultihopExecution.Source, profile: Data, entryProfile: Data,
         entryFiles: [String: Data], strict: Bool, mtuHold: String, captureSHA256: String,
         makeEngine: @escaping (String) throws -> RouterVPNLibboxEngine,
         available: @escaping (RouterVPNTorCompare) -> Bool,
         ownsEngine: @escaping (RouterVPNTorCompare, RouterVPNLibboxEngine) -> Bool,
         install: @escaping (RouterVPNTorCompare, RouterVPNLibboxEngine) throws -> Void,
         release: @escaping (RouterVPNTorCompare, RouterVPNLibboxEngine) -> Void,
         activate: @escaping (RouterVPNTorCompare, RouterVPNLibboxEngine) throws -> Void,
         completion: @escaping (RouterVPNTorCompare, Error?) -> Void) throws {
        guard source.valid, source.requested == "auto", ["tor", "tor-bridge"].contains(source.exitMode),
              let selected = try JSONSerialization.jsonObject(with: profile) as? [String: Any],
              let entry = try JSONSerialization.jsonObject(with: entryProfile) as? [String: Any],
              selected["multihop_execution"] as? String == "auto", selected["multihop_enabled"] as? Bool == true,
              selected["id"] as? String == source.exitID, entry["id"] as? String == source.entryID,
              selected["multihop_entry_id"] as? String == source.entryID,
              selected["multihop_exit_id"] as? String == source.exitID,
              selected["multihop_entry_mode"] as? String == source.entryMode,
              selected["multihop_exit_mode"] as? String == source.exitMode,
              entry["node_kind"] as? String == "router-vpn",
              captureSHA256.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
              mtuHold.isEmpty || mtuHold.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil else { throw Self.issue() }
        self.source = source; self.profile = profile; self.entryProfile = entryProfile; self.entryFiles = entryFiles
        self.strict = strict; self.mtuHold = mtuHold; self.captureSHA256 = captureSHA256
        self.makeEngine = makeEngine; self.available = available; self.ownsEngine = ownsEngine; self.install = install
        self.release = release; self.activate = activate; self.callback = completion
        super.init()

    }

    var isDrained: Bool { lock.lock(); defer { lock.unlock() }; return drained }

    func ownsSettingsEpoch(_ epoch: String) -> Bool {
        lock.lock(); let captured = candidate; lock.unlock()
        return captured?.engine.settingsEpoch == epoch && captured?.current() == true
    }

    func current() -> Bool {
        lock.lock(); let valid = !cancelled && !drained; lock.unlock()
        return valid && available(self)
    }

    func newCandidate(_ execution: String?, target: String?) -> (any LibboxRouterTorCompareCandidateProtocol)? {
        guard let execution, ["local", "server"].contains(execution), let target,
              Self.targets.contains(target), current(),
              let selected = try? JSONSerialization.jsonObject(with: profile) as? [String: Any],
              let entry = try? JSONSerialization.jsonObject(with: entryProfile) as? [String: Any],
              let runtime = try? RouterVPNExternalExitBuilder.build(profile: selected, predecessorFiles: entryFiles,
                predecessorProfile: entry, restoredExecution: execution), runtime.torExecution == execution else { return nil }
        lock.lock()
        guard !cancelled, !transferred, !drained, candidate == nil,
              self.target.isEmpty || self.target == target else { lock.unlock(); return nil }
        // The physical-path guard belongs to the whole round. Native settings
        // tokens belong to one engine: old OS callbacks cannot be relabeled as
        // the next trial merely because the system VPN itself is unchanged.
        guard let engine = try? makeEngine(UUID().uuidString) else { lock.unlock(); return nil }
        self.target = target
        let next = Candidate(host: self, engine: engine, runtime: runtime, execution: execution,
                             strict: strict, mtuHold: mtuHold)
        candidate = next
        lock.unlock()
        // Go retains this exact partial owner before it calls blocking Start.
        // Construction above creates no native service, peer or socket.
        return next
    }

    func progress(_ stage: String?, execution: String?) {
        guard let stage, !stage.isEmpty, stage.utf8.count <= 96,
              let execution, ["", "local", "server"].contains(execution) else { return }
        lock.lock(); defer { lock.unlock() }
        guard !cancelled, !drained, !transferred else { return }
        self.stage = stage; self.execution = execution
    }

    func progressData() -> Data? {
        lock.lock()
        var value = result ?? [:]
        value["stage"] = stage; value["execution"] = execution
        value["complete"] = transferred
        value["last_node_measurement"] = "tor-relay-http-response-time"
        value["external_measurement"] = "https-response-time"
        lock.unlock()
        guard let encoded = try? JSONSerialization.data(withJSONObject: value), encoded.count <= 16384 else { return nil }
        return encoded
    }

    func start() {
        lock.lock()
        guard !started, !cancelled, !drained else { lock.unlock(); finish(Self.issue()); return }
        started = true
        lock.unlock()
        queue.async { [self] in run() }
    }

    private func run() {
        do {
            guard current() else { throw Self.issue() }
            var failure: NSError?
            let created = LibboxRouterTorNewCompare(self, source.entryID, source.exitID, source.exitMode, captureSHA256, &failure)
            guard let created, failure == nil else { throw failure ?? Self.issue() }
            lock.lock(); round = created; let stopped = cancelled; lock.unlock()
            if stopped { created.cancel(); throw Self.issue() }
            try created.run()
            guard current() else { throw Self.issue() }
            let choice = created.execution()
            let verified = try validateResult(created.resultJSON(), execution: choice)
            lock.lock(); let selected = candidate; lock.unlock()
            guard let selected, selected.execution == choice, selected.current(), current() else { throw Self.issue() }
            // The native Keep revalidates and drains measurement ownership.
            // It cannot transfer a partial comparison or fabricate a proof.
            try created.keep()
            guard current(), created.execution() == choice, selected.current() else { throw Self.issue() }
            lock.lock()
            guard !cancelled, !drained, candidate === selected else { lock.unlock(); throw Self.issue() }
            guard selected.transfer() else { lock.unlock(); throw Self.issue() }
            transferred = true; round = nil; result = verified; stage = "selected"; execution = choice
            lock.unlock()
            // Keep drained native measurement ownership. Release our bridge
            // reference now: the Go coordinator retains this callback host,
            // while the provider alone retains the adopted VPN from here.
            do {
                // MTU, hop/DNS measurement and the restoration receipt are
                // published only for the exact adopted final native owner.
                try activate(self, selected.engine)
                guard available(self), selected.adoptedCurrent() else { throw Self.issue() }
            } catch {
                // Keep already transferred the engine. Explicit activation
                // failure cleanup belongs to this exact engine, not the old
                // round (whose Close must remain harmless after Keep).
                selected.engine.invalidateMultihop()
                do { try selected.engine.stopCheckedForStrategy(); release(self, selected.engine) }
                catch { finish(error); return }
                // Keep transferred measurement ownership, but activation
                // never completed. Only this acknowledged native teardown
                // makes the failed start safe to release and retry.
                lock.lock(); drained = true; candidate = nil; lock.unlock()
                finish(error); return
            }
            try created.close()
            finish(nil)
        } catch {
            cancel()
            let original = error
            do { try closeOwned(); finish(original) }
            catch { finish(error) }
        }
    }

    func cancel() {
        lock.lock()
        guard !transferred else { lock.unlock(); return }
        cancelled = true
        let captured = round, path = candidate
        lock.unlock()
        captured?.cancel(); path?.cancel()
    }

    /// A whole-provider stop may call this while Start, proof or Keep is
    /// pending. Failed drain retains every owner and can be retried later.
    func cancelAndDrain(_ completion: @escaping (Error?) -> Void) {
        cancel()
        let delivery = Drain(completion)
        queue.async { [self] in
            do { try closeOwned(); delivery.complete(nil) }
            catch { delivery.complete(error) }
        }
    }

    private func closeOwned() throws {
        lock.lock()
        let kept = transferred, captured = round, path = candidate
        lock.unlock()
        if kept { return }
        var first: Error?
        do { try captured?.close() } catch { first = error }
        // A cancellation can race native Keep before the Swift transfer.
        // Even if Go no longer owns that path, this unadopted Swift candidate
        // must finish its real engine teardown before the round is drained.
        do { try path?.close() } catch { if first == nil { first = error } }
        if let first { throw first }
        lock.lock(); drained = true; round = nil; lock.unlock()
    }

    func nativeFailure(_ engine: RouterVPNLibboxEngine) -> Bool {
        lock.lock(); let path = candidate, kept = transferred; lock.unlock()
        guard !kept, let path, path.engine === engine else { return false }
        path.cancel()
        return true
    }

    private func owns(_ path: Candidate) -> Bool {
        lock.lock(); let valid = candidate === path && !cancelled && !drained; lock.unlock()
        return valid && available(self)
    }

    private func install(_ path: Candidate) throws {
        guard owns(path) else { throw Self.issue() }
        try install(self, path.engine)
        guard owns(path) else { throw Self.issue() }
    }

    private func closed(_ path: Candidate) {
        // The caller has already joined Start and the exact native service.
        // Releasing a stale candidate cannot clear a replacement engine.
        release(self, path.engine)
        lock.lock(); if candidate === path { candidate = nil }; lock.unlock()
    }

    private func finish(_ error: Error?) {
        lock.lock(); let callback = self.callback; self.callback = nil
        if error != nil { stage = "failed" }
        lock.unlock()
        callback?(self, error)
    }

    private func validateResult(_ text: String, execution: String) throws -> [String: Any] {
        lock.lock(); let capturedTarget = target; lock.unlock()
        guard ["local", "server"].contains(execution), !text.isEmpty, text.utf8.count <= 16384,
              let value = try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any],
              Set(value.keys) == Set(["target", "measurements", "winner", "final"]),
              let target = value["target"] as? String, Self.targets.contains(target), target == capturedTarget,
              let measurements = value["measurements"] as? [[String: Any]], measurements.count == 2,
              let winner = value["winner"] as? [String: Any], matches(winner, execution: execution),
              let final = value["final"] as? [String: Any], try measurement(final, execution: execution) else { throw Self.issue() }
        var seen = Set<String>()
        var winnerScore: Double?, lowestScore = Double.greatestFiniteMagnitude
        for item in measurements {
            guard let path = item["candidate"] as? [String: Any], let leaf = path["execution"] as? String,
                  ["local", "server"].contains(leaf), seen.insert(leaf).inserted else { throw Self.issue() }
            if try measurement(item, execution: leaf) {
                let score = (item["score_ms"] as! NSNumber).doubleValue
                lowestScore = min(lowestScore, score)
                if leaf == execution { winnerScore = score }
            }
        }
        guard let winnerScore, winnerScore <= lowestScore + 0.000001 else { throw Self.issue() }
        return value
    }

    private func matches(_ candidate: [String: Any], execution: String) -> Bool {
        Set(candidate.keys) == Set(["execution", "transport", "entry_id", "exit_id"]) &&
            candidate["execution"] as? String == execution && candidate["transport"] as? String == source.exitMode &&
            candidate["entry_id"] as? String == source.entryID && candidate["exit_id"] as? String == source.exitID
    }

    private func measurement(_ value: [String: Any], execution: String) throws -> Bool {
        guard let path = value["candidate"] as? [String: Any], matches(path, execution: execution),
              let eligible = value["eligible"] as? NSNumber, CFGetTypeID(eligible) == CFBooleanGetTypeID() else { throw Self.issue() }
        if !eligible.boolValue {
            guard value["score_ms"] == nil, let failure = value["failure"] as? String, !failure.isEmpty,
                  failure.utf8.count <= 4096 else { throw Self.issue() }
            return false
        }
        guard value["failure"] == nil,
              let last = value["last_node_ms"] as? NSNumber, CFGetTypeID(last) != CFBooleanGetTypeID(),
              let external = value["external_ms"] as? NSNumber, CFGetTypeID(external) != CFBooleanGetTypeID(),
              let score = value["score_ms"] as? NSNumber, CFGetTypeID(score) != CFBooleanGetTypeID(),
              last.doubleValue.isFinite, external.doubleValue.isFinite, score.doubleValue.isFinite,
              last.doubleValue > 0, external.doubleValue > 0, last.doubleValue <= 12000, external.doubleValue <= 12000,
              abs(score.doubleValue - (last.doubleValue / 2 + external.doubleValue / 2)) <= 0.000001 else { throw Self.issue() }
        return true
    }

    private static let targets: Set<String> = ["https://1.1.1.1/cdn-cgi/trace", "https://1.0.0.1/cdn-cgi/trace"]
    private static func issue() -> NSError {
        NSError(domain: "RouterVPN.TorCompare", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Tor comparison lost its captured path, final proof, or verified native teardown."])
    }
    private final class Drain: @unchecked Sendable {
        let complete: (Error?) -> Void
        init(_ complete: @escaping (Error?) -> Void) { self.complete = complete }
    }

    /// The protocol object retained by Go before native startup. No callback
    /// ever obtains its engine by reading the provider's later selection.
    private final class Candidate: NSObject, LibboxRouterTorCompareCandidateProtocol, @unchecked Sendable {
        private weak var host: RouterVPNTorCompare?
        let engine: RouterVPNLibboxEngine
        let runtime: RouterVPNExternalExitRuntime
        let execution: String
        private let strict: Bool
        private let mtuHold: String
        private let condition = NSCondition()
        private var starting = false
        private var started = false
        private var installed = false
        private var cancelled = false
        private var closed = false
        private var adopted = false
        private var closing: CloseAttempt?

        init(host: RouterVPNTorCompare, engine: RouterVPNLibboxEngine, runtime: RouterVPNExternalExitRuntime,
             execution: String, strict: Bool, mtuHold: String) {
            self.host = host; self.engine = engine; self.runtime = runtime; self.execution = execution
            self.strict = strict; self.mtuHold = mtuHold
        }

        func current() -> Bool {
            condition.lock(); let valid = !cancelled && !closed, installed = self.installed; condition.unlock()
            guard valid, let host, host.owns(self) else { return false }
            return !installed || host.ownsEngine(host, engine)
        }
        func adoptedCurrent() -> Bool {
            condition.lock(); let valid = adopted && !cancelled && !closed; condition.unlock()
            return valid && current() && engine.torComparisonNative() != nil
        }
        func start() throws {
            condition.lock()
            guard !started, !cancelled, !closed, !adopted else { condition.unlock(); throw RouterVPNTorCompare.issue() }
            started = true; starting = true
            condition.unlock()
            defer { condition.lock(); starting = false; condition.broadcast(); condition.unlock() }
            guard current(), let host, let session = runtime.torSessionID, let profile = runtime.torProfileJSON,
                  let original = runtime.torSourceProfileJSON, let entry = runtime.torPredecessorProfile,
                  IOSMultihopExecution.torLeafMatches(source: original, leaf: profile, execution: execution) else { throw RouterVPNTorCompare.issue() }
            try host.install(self)
            condition.lock(); installed = true; condition.unlock()
            guard current() else { throw RouterVPNTorCompare.issue() }
            try engine.prepareMTUHold(mtuHold)
            try engine.start(files: runtime.files, strict: strict)
            guard current() else { throw RouterVPNTorCompare.issue() }
            let proof = RouterVPNSettingsResult()
            engine.proveTor(sessionID: session, profile: profile, predecessorProfile: entry, sourceProfile: original) { proof.finish($0) }
            guard proof.completed.wait(timeout: .now() + 125) != .timedOut else { cancel(); throw RouterVPNTorCompare.issue() }
            if let error = proof.error { throw error }
            guard current(), engine.torComparisonNative() != nil else { throw RouterVPNTorCompare.issue() }
        }
        func server() -> LibboxCommandServer? { current() ? engine.torComparisonNative()?.0 : nil }
        func proof() -> LibboxRouterTorProofRequest? { current() ? engine.torComparisonNative()?.1 : nil }
        func cancel() {
            condition.lock()
            guard !adopted else { condition.unlock(); return }
            cancelled = true
            condition.unlock()
            engine.invalidateMultihop()
        }
        func transfer() -> Bool {
            condition.lock(); defer { condition.unlock() }
            guard started, !starting, !cancelled, !closed, closing == nil else { return false }
            adopted = true
            return true
        }
        func close() throws {
            cancel()
            condition.lock()
            if adopted || closed { condition.unlock(); return }
            let attempt: CloseAttempt
            if let existing = closing { attempt = existing }
            else {
                attempt = CloseAttempt(); closing = attempt
                DispatchQueue.global(qos: .userInitiated).async { [self, attempt] in
                    var failure: Error?
                    do { try engine.stopCheckedForStrategy() } catch { failure = error }
                    condition.lock(); attempt.error = failure; attempt.finished = true; condition.broadcast(); condition.unlock()
                }
            }
            let deadline = Date().addingTimeInterval(10)
            while !attempt.finished || starting {
                if !condition.wait(until: deadline) { condition.unlock(); throw RouterVPNTorCompare.issue() }
            }
            if let error = attempt.error { closing = nil; condition.unlock(); throw error }
            closed = true; closing = nil
            condition.unlock()
            host?.closed(self)
        }
        private final class CloseAttempt: @unchecked Sendable {
            var finished = false
            var error: Error?
        }
    }
}
