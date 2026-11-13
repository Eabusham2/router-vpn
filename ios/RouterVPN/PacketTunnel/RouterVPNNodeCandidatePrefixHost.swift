import Foundation
import Libbox

/// Retains one original temporary Box and its closed-ingress prefix service.
/// Prepared is deliberately not ordinary connection, DNS, Last or MTU proof.
final class RouterVPNNodeCandidatePrefixHost: NSObject, LibboxRouterNodeChainCandidateCatalogProtocol, @unchecked Sendable {
    let input: IOSNodeCandidatePrefixProviderCapture
    private let platform: RouterVPNLibboxPlatform
    private let current: () -> Bool
    private let failure: (Error) -> Void
    private let state = NSLock(), operation = NSLock(), closing = NSLock()
    private var server: LibboxCommandServer?
    private var directory: URL?
    private var constructing = true, bound = false, attempted = false, started = false
    private var factoryAttempted = false, factoryEntered = false, factoryJoined = false
    private var stopped = false, running = false, runEntered = false, observers = 0
    private var candidatesClosed = false, boxClosed = false, resourcesClosed = false, complete = false
    private var request = "", candidate = ""
    private struct Readback: Equatable {
        let session: String, path: String, interface: String, mtu: Int32
        init(_ value: LibboxRouterMTUState) {
            session = value.session; path = value.path; interface = value.interface; mtu = value.mtu
        }
    }
    private var readback: Readback?
    private var health: DispatchSourceTimer?
    private var callback: ((Error?) -> Void)?
    private static let retirement = Retirement()

    init(input: IOSNodeCandidatePrefixProviderCapture, platform: RouterVPNLibboxPlatform,
         current: @escaping () -> Bool, failure: @escaping (Error) -> Void) {
        self.input = input; self.platform = platform; self.current = current; self.failure = failure
    }
    private static func issue() -> NSError { IOSNodeCandidatePrefixCapture.issue() }
    static func requireAvailable() throws { try retirement.requireAvailable() }
    func retainForRetirement() { Self.retirement.retain(self) }
    func releaseRetirement() { Self.retirement.release(self) }

    func retainDirectory(_ value: URL) throws {
        state.lock()
        guard constructing, directory == nil else { state.unlock(); throw Self.issue() }
        directory = value; state.unlock()
        try requireCurrent()
    }
    func beginFactory() throws {
        try requireCurrent()
        state.lock(); defer { state.unlock() }
        guard constructing, !stopped, !factoryAttempted else { throw Self.issue() }
        factoryAttempted = true; factoryEntered = true
    }
    /// The original synchronous factory reports even nil/error completion.
    /// Every nonnil return is retained before native binding or cancellation.
    func finishFactory(_ value: LibboxCommandServer?) throws {
        state.lock()
        guard factoryEntered, server == nil else { state.unlock(); throw Self.issue() }
        server = value; factoryEntered = false; factoryJoined = true; state.unlock()
        if let value {
            try input.capture.native.bindNative(value)
            state.lock(); bound = true; state.unlock()
        }
        try requireCurrent()
    }
    func startNative() throws {
        try requireCurrent()
        state.lock(); let original = server; let allowed = constructing && bound && !stopped && !attempted; state.unlock()
        guard allowed, let original else { throw Self.issue() }
        try original.start()
        try requireCurrent()
        state.lock()
        guard !stopped, constructing, server === original, !attempted else { state.unlock(); throw Self.issue() }
        attempted = true; state.unlock()
        var error: NSError?
        guard LibboxRouterStrategyStartService(original, input.capture.config, &error), error == nil else { throw error ?? Self.issue() }
        try requireCurrent()
        state.lock(); started = true; state.unlock()
    }
    func finishConstruction() { state.lock(); constructing = false; state.unlock() }
    private func requireCurrent() throws {
        state.lock(); let allowed = !stopped && !complete; state.unlock()
        guard allowed, current() else { throw Self.issue() }
        try input.requireCurrent()
        guard current() else { throw Self.issue() }
    }
    private func requireReadback() throws {
        state.lock(); let expected = readback; state.unlock()
        guard let expected, let actual = platform.mtu.captureMTU(), Readback(actual) == expected,
              actual.mtu == Int32(input.capture.metadata.mtu.original), !platform.mtu.isChanging else { throw Self.issue() }
    }
    func currentInventorySHA256() -> String {
        state.lock(); let allowed = !stopped && !candidatesClosed; state.unlock()
        guard allowed, (try? requireCurrent()) != nil, (try? requireReadback()) != nil else { return "" }
        return input.source.inventorySHA256
    }
    func run(completion: @escaping (Error?) -> Void) {
        state.lock()
        guard !stopped, !constructing, started, !running, server != nil else {
            state.unlock(); completion(Self.issue()); return
        }
        running = true; runEntered = true; callback = completion; state.unlock()
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            var error: Error?
            do {
                try requireCurrent()
                state.lock(); let capturedServer = server; state.unlock()
                guard let original = capturedServer else { throw Self.issue() }
                guard let actual = platform.mtu.captureMTU(), actual.mtu == Int32(input.capture.metadata.mtu.original),
                      !actual.session.isEmpty, !actual.path.isEmpty, !actual.interface.isEmpty,
                      !platform.mtu.isChanging else { throw Self.issue() }
                state.lock(); readback = Readback(actual); state.unlock()
                try input.capture.native.run(original, catalog: self)
                try requirePrepared()
                installHealth()
            } catch let caught { error = caught }
            state.lock(); runEntered = false; let cancelled = stopped, completion = callback; callback = nil; state.unlock()
            completion?(error ?? (cancelled ? Self.issue() : nil))
        }
    }
    private func requirePrepared() throws {
        try requireCurrent(); try requireReadback()
        guard input.capture.native.healthy(),
              let progress = try JSONSerialization.jsonObject(with: Data(input.capture.native.progressJSON().utf8)) as? [String: Any],
              progress["stage"] as? String == "prefix-prepared", progress["prepared"] as? Bool == true,
              progress["application_open"] as? Bool == false, progress["dns_open"] as? Bool == false else { throw Self.issue() }
        try requireCurrent(); try requireReadback()
    }
    private func installHealth() {
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now() + .milliseconds(250), repeating: .milliseconds(250))
        timer.setEventHandler { [self] in
            state.lock(); let allowed = !stopped && !complete; if allowed { observers += 1 }; state.unlock()
            guard allowed else { return }
            var error: Error?
            do { try requirePrepared() } catch let caught { error = caught }
            state.lock(); observers -= 1; let active = !stopped; state.unlock()
            if let error, active, current() { cancel(); failure(error) }
        }
        state.lock(); let allowed = !stopped; if allowed { health = timer }; timer.resume(); state.unlock()
        if !allowed { timer.cancel() }
    }
    func cancel() {
        state.lock(); stopped = true; let timer = health; health = nil; state.unlock()
        timer?.cancel(); input.capture.native.networkChanged()
    }

    /// Only the original request/epoch can obtain prefix-only IPC receipts.
    /// Candidate-close joins this native service; PacketTunnel Stop separately
    /// joins the original Box/TUN before the app may expose saved choices.
    func reply(operation name: String, request: String, epoch: String, owner: String,
               prefix: String, candidate: String) -> Data? {
        guard epoch == input.epoch, owner == input.source.request,
              IOSCandidateCatalogPublication.validRequest(request) else { return nil }
        if name == "prefix-candidate-close" {
            guard request == owner, prefix.isEmpty, candidate.isEmpty else { return nil }
            do { try closeCandidates() } catch { return nil }
            return envelope(request: request, values: ["closed": true])
        }
        guard operation.try() else { return nil }; defer { operation.unlock() }
        state.lock(); let allowed = !stopped && !runEntered && running && !candidatesClosed
        if allowed { observers += 1 }; state.unlock()
        guard allowed else { return nil }
        defer { state.lock(); observers -= 1; state.unlock() }
        do {
            try requirePrepared()
            switch name {
            case "prefix-candidate-open":
                guard request == owner, prefix == String(input.capture.metadata.prefix_position), candidate.isEmpty else { throw Self.issue() }
                return envelope(request: request, values: ["metadata": input.capture.native.metadata()])
            case "prefix-candidate-start":
                guard prefix.isEmpty, !candidate.isEmpty, candidate.utf8.count <= 128 else { throw Self.issue() }
                if self.request != request {
                    try input.capture.native.start(request, candidateID: candidate)
                    self.request = request; self.candidate = candidate
                }
                guard self.candidate == candidate else { throw Self.issue() }
            case "prefix-candidate-status":
                guard prefix.isEmpty, candidate.isEmpty, self.request == request else { throw Self.issue() }
            default: throw Self.issue()
            }
            let status = input.capture.native.statusJSON()
            try requirePrepared()
            return envelope(request: request, values: ["status": status])
        } catch { return nil }
    }
    private func envelope(request: String, values: [String: Any]) -> Data? {
        var body = values
        body["session_id"] = input.epoch; body["owner_request"] = input.source.request; body["request_id"] = request
        guard let data = try? JSONSerialization.data(withJSONObject: body), data.count <= 131072 else { return nil }
        if values["closed"] as? Bool != true, (try? requirePrepared()) == nil { return nil }
        return data
    }
    func closeCandidates() throws {
        cancel()
        guard closing.try() else { throw Self.issue() }; defer { closing.unlock() }
        try joinCandidates()
    }
    private func joinCandidates() throws {
        state.lock(); let done = candidatesClosed; state.unlock()
        if done { try input.storeCandidatesClosed(); return }
        try input.capture.native.close()
        state.lock(); let pending = constructing || factoryEntered || runEntered || observers != 0; state.unlock()
        guard !pending else { throw Self.issue() }
        try input.storeCandidatesClosed()
        state.lock(); candidatesClosed = true; state.unlock()
    }
    func close() throws {
        cancel()
        guard closing.try() else { throw Self.issue() }; defer { closing.unlock() }
        state.lock(); let done = complete; state.unlock()
        if done { return }
        try joinCandidates()
        state.lock()
        let original = server, serviceAttempted = attempted, path = directory
        let noAcquisition = !constructing && !factoryEntered && (!factoryAttempted || factoryJoined) && server == nil && !attempted
        state.unlock()
        if let original, !boxClosed {
            if !serviceAttempted {
                // A cancelled bind may have returned before sealing its slot.
                // Rebind only this original unstarted server for cleanup.
                if !input.capture.native.nativeClosed() {
                    try? input.capture.native.bindNative(original)
                    try input.capture.native.close()
                }
            } else {
                var error: NSError?
                guard LibboxRouterStrategyCloseService(original, &error), error == nil else { throw error ?? Self.issue() }
            }
            // A nil daemon service on retry is not the original Instance.Close
            // receipt. Failed native close retains this host and its MTU hold.
            guard input.capture.native.nativeClosed() else { throw Self.issue() }
            boxClosed = true
        }
        if original == nil { guard noAcquisition else { throw Self.issue() } }
        // Keep the original MTU hold and physical observer until native Close
        // joins; a cancelled candidate callback is not a TUN shutdown receipt.
        try platform.mtu.stopChecked()
        if !resourcesClosed { original?.close(); platform.reset(); resourcesClosed = true }
        if let path, FileManager.default.fileExists(atPath: path.path) { try FileManager.default.removeItem(at: path) }
        state.lock(); complete = true; state.unlock()
    }
    private final class Retirement: @unchecked Sendable {
        private let lock = NSLock(); private var owners: [RouterVPNNodeCandidatePrefixHost] = []
        func retain(_ owner: RouterVPNNodeCandidatePrefixHost) {
            lock.lock(); defer { lock.unlock() }; if !owners.contains(where: { $0 === owner }) { owners.append(owner) }
        }
        func release(_ owner: RouterVPNNodeCandidatePrefixHost) {
            lock.lock(); owners.removeAll { $0 === owner }; lock.unlock()
        }
        func requireAvailable() throws {
            lock.lock(); let captured = owners; lock.unlock()
            for owner in captured { try owner.close(); release(owner) }
        }
    }
}
