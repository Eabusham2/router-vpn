import Foundation
import Libbox

/// One captured Server/Compare native construction and its joined retirement.
/// The original platform, command server and files survive every failed close.
/// Local ordered chains keep their separate owner and teardown contract.
final class RouterVPNNodeChainExecutionHost: @unchecked Sendable {
    let capture: IOSNodeChainExecutionCapture
    private let platform: RouterVPNLibboxPlatform
    private let isCurrent: () -> Bool
    private let onFailure: (Error) -> Void
    private let lock = NSLock()
    private let closeLock = NSLock()
    private var server: LibboxCommandServer?
    private var directory: URL?
    private var constructing = true
    private var bound = false, serviceAttempted = false, started = false
    private var cancelled = false, runStarted = false, runEntered = false
    private var observations = 0
    private var measurement: LibboxRouterHopMeasurement?
    private var health: DispatchSourceTimer?
    private var callback: ((Error?) -> Void)?
    private var measurementAdoption: ((LibboxRouterHopMeasurement?, LibboxRouterHopMeasurement) -> Bool)?
    private var measurementEpoch: UUID?
    private var remoteJoined = false, nativeCloseSucceeded = false, nativeClosed = false
    private var resourcesClosed = false, complete = false
    private static let retirement = Retirement()

    init(capture: IOSNodeChainExecutionCapture, platform: RouterVPNLibboxPlatform,
         isCurrent: @escaping () -> Bool, onFailure: @escaping (Error) -> Void) {
        self.capture = capture; self.platform = platform
        self.isCurrent = isCurrent; self.onFailure = onFailure
    }

    static func requireAvailable() throws { try retirement.requireAvailable() }
    func retainForRetirement() { Self.retirement.retain(self) }
    func releaseRetirement() { Self.retirement.release(self) }

    private static func issue(_ text: String) -> NSError {
        NSError(domain: "RouterVPN.NodeChainExecutionHost", code: 1,
                userInfo: [NSLocalizedDescriptionKey: text])
    }

    func retainDirectory(_ value: URL) throws {
        lock.lock()
        guard constructing, directory == nil || directory == value else {
            lock.unlock(); throw Self.issue("The original private execution directory changed.")
        }
        directory = value
        lock.unlock()
        try requireCurrent()
    }

    /// Retain even a late-created server and reserve its first construction
    /// before checking cancellation. Native Bind seals a cleanup-only empty
    /// slot when cancellation won; no replacement server can satisfy it.
    func bindNative(_ value: LibboxCommandServer) throws {
        lock.lock()
        guard constructing, server == nil else {
            lock.unlock(); throw Self.issue("The original native construction slot was already used.")
        }
        server = value
        lock.unlock()
        try capture.bindNative(value)
        lock.lock(); bound = true; lock.unlock()
        try requireCurrent()
    }

    func startNative() throws {
        lock.lock()
        let original = server
        let available = constructing && bound && !cancelled && !started && !serviceAttempted
        lock.unlock()
        guard available, let original else { throw Self.issue("The ordered native service has no original bound slot.") }
        try requireCurrent()
        try original.start()
        try requireCurrent()
        lock.lock()
        guard !cancelled, constructing, server === original else {
            lock.unlock(); throw Self.issue("Ordered startup was cancelled before native construction.")
        }
        serviceAttempted = true
        lock.unlock()
        var failure: NSError?
        let opened = LibboxRouterStrategyStartService(original, capture.config, &failure)
        guard opened, failure == nil else { throw failure ?? Self.issue("The original ordered native Box did not start.") }
        try requireCurrent()
        lock.lock(); started = true; lock.unlock()
    }

    /// Called by the outer startup defer only after all original file/factory
    /// work has returned. A Stop cannot acknowledge a still-entered factory.
    func finishConstruction() { lock.lock(); constructing = false; lock.unlock() }

    private func requireCurrent() throws {
        lock.lock(); let available = !cancelled && !complete; lock.unlock()
        guard available, isCurrent() else { throw Self.issue("The ordered native owner has retired.") }
        try capture.requireCurrent()
        guard isCurrent() else { throw Self.issue("The ordered native generation changed.") }
    }

    private func beginObservation() -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard !cancelled, !complete, started, !constructing else { return false }
        observations += 1
        return true
    }
    private func endObservation() { lock.lock(); observations -= 1; lock.unlock() }

    func run(adoptMeasurement: @escaping (LibboxRouterHopMeasurement?, LibboxRouterHopMeasurement) -> Bool,
             completion: @escaping (Error?) -> Void) {
        lock.lock()
        guard !cancelled, !constructing, started, !runStarted, server != nil else {
            lock.unlock(); completion(Self.issue("The ordered proof has no original started service.")); return
        }
        runStarted = true; runEntered = true; callback = completion; measurementAdoption = adoptMeasurement
        lock.unlock()
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            var failure: Error?
            do {
                try requireCurrent()
                lock.lock(); let capturedServer = server; lock.unlock()
                guard let original = capturedServer else { throw Self.issue("The original ordered native server was lost.") }
                try capture.run(original)
                try requireCurrent()
                guard capture.healthy() else { throw Self.issue("The complete ordered native proof did not remain healthy.") }
                _ = try capture.execution()
                try requireCurrent()
                guard let token = platform.mtu.proofObservationToken,
                      try platform.mtu.observeNodeChainExecutionMeasurement(token, { try replaceMeasurement(token, original: original) }) else {
                    throw Self.issue("The original ordered measurement was not admitted while its optimizer was idle.")
                }
                installHealthWatch()
            } catch { failure = error }
            // No native operation follows this join point. The completion may
            // synchronously request Stop on this same original host.
            lock.lock(); runEntered = false; lock.unlock()
            finish(failure)
        }
    }

    private func finish(_ failure: Error?) {
        lock.lock()
        let completion = callback; callback = nil
        let result = cancelled ? (failure ?? Self.issue("The ordered proof was cancelled.")) : failure
        lock.unlock()
        completion?(result)
    }

    func cancel() {
        lock.lock(); cancelled = true
        let timer = health, probe = measurement; health = nil
        lock.unlock()
        timer?.cancel()
        capture.networkChanged(); probe?.networkChanged()
        finish(Self.issue("The ordered execution owner was cancelled."))
    }

    private func installHealthWatch() {
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now() + 1, repeating: 1)
        timer.setEventHandler { [self] in checkHealth() }
        lock.lock()
        let accepted = !cancelled && !complete
        if accepted { health = timer }
        timer.resume()
        lock.unlock()
        if !accepted { timer.cancel() }
    }

    private func checkHealth() {
        guard let token = platform.mtu.proofObservationToken, beginObservation() else { return }
        var failure: Error?
        do {
            try requireCurrent()
            guard capture.healthy() else { throw Self.issue("An ordered node, selected resolver or native execution proof expired.") }
            lock.lock(); let original = server, epoch = measurementEpoch; lock.unlock()
            if epoch != token, let original {
                _ = try platform.mtu.observeNodeChainExecutionMeasurement(token) { try replaceMeasurement(token, original: original) }
            }
        } catch { failure = error }
        let current = isCurrent() && platform.mtu.proofObservationToken == token
        endObservation()
        if let failure, current { onFailure(failure) }
    }

    /// An authorized MTU transaction retires the old runtime's service. Its
    /// replacement is bound only after selected reproof and the full optimizer
    /// joins, using the original execution/server and exact old probe pointer.
    private func replaceMeasurement(_ token: UUID, original: LibboxCommandServer) throws {
        lock.lock(); let previous = measurement, epoch = measurementEpoch, adopt = measurementAdoption; lock.unlock()
        if epoch == token { return }
        try previous?.close()
        try requireCurrent()
        guard platform.mtu.proofObservationToken == token, capture.healthy() else { throw Self.issue("The ordered measurement lost its proved MTU generation.") }
        var createError: NSError?
        let returned = LibboxRouterNodeChainExecutionNewHopMeasurement(capture.plan, original, &createError)
        // A returned original owner remains reachable even with an error.
        if let returned { lock.lock(); measurement = returned; lock.unlock() }
        guard let returned, createError == nil else { throw createError ?? Self.issue("The proved ordered path has no owned measurement service.") }
        try requireCurrent()
        guard platform.mtu.proofObservationToken == token, capture.healthy(),
              adopt?(previous, returned) == true else { throw Self.issue("The ordered measurement belongs to a retired host or runtime.") }
        try requireCurrent()
        lock.lock(); measurementEpoch = token; lock.unlock()
    }

    /// Keep an entered native observation in the original retirement inventory.
    /// Callers deliver callbacks only after this method has released the hold.
    func observe(_ operation: () throws -> Void) throws {
        guard beginObservation() else { throw Self.issue("The ordered native observation belongs to a retired owner.") }
        defer { endObservation() }
        try requireCurrent()
        try operation()
        try requireCurrent()
    }

    func activateMTU() throws {
        guard beginObservation() else { throw Self.issue("The ordered MTU owner retired before attachment.") }
        defer { endObservation() }
        try requireCurrent()
        lock.lock(); let original = server; lock.unlock()
        guard let original, capture.healthy() else { throw Self.issue("The ordered MTU owner lost its current native proof.") }
        try platform.mtu.activateNodeChainExecution(server: original, plan: capture.plan) { [self] message in
            if isCurrent() { onFailure(Self.issue(message)) }
        }
        try requireCurrent()
        guard platform.mtu.isChanging || capture.healthy() else { throw Self.issue("The ordered MTU attachment changed its original native owner.") }
    }

    func progress() -> Data? {
        guard beginObservation() else { return nil }
        defer { endObservation() }
        guard (try? requireCurrent()) != nil else { return nil }
        let result = Data(capture.plan.progressJSON().utf8)
        guard !result.isEmpty, result.count <= 65536, (try? requireCurrent()) != nil else { return nil }
        return result
    }

    /// The platform monitor and exact original Box remain available while a
    /// sealed remote DELETE or original activity still needs them. Native close
    /// starts only after those joins and all host callbacks have returned.
    func close() throws {
        cancel()
        closeLock.lock(); defer { closeLock.unlock() }
        lock.lock(); let alreadyComplete = complete; lock.unlock()
        if alreadyComplete { return }
        if !remoteJoined {
            var failure: Error?
            do { try platform.mtu.drainForNodeChainExecutionCleanup() } catch { failure = error }
            lock.lock(); let probe = measurement; lock.unlock()
            do { try probe?.close() } catch { if failure == nil { failure = error } }
            do { try capture.close() } catch { if failure == nil { failure = error } }
            if let failure { throw failure }
            lock.lock(); let pending = constructing || runEntered || observations != 0; lock.unlock()
            guard !pending else { throw Self.issue("The original ordered construction or observation has not joined.") }
            remoteJoined = true
        }
        lock.lock(); let original = server, attempted = serviceAttempted, path = directory; lock.unlock()
        if let original, !nativeClosed {
            if !attempted {
                // An interrupted Bind may have returned before reserving the
                // slot. Retry only that exact unstarted server, then seal it.
                if !capture.nativeClosed() {
                    try? capture.bindNative(original)
                    try capture.close()
                }
            } else if !nativeCloseSucceeded {
                var failure: NSError?
                let stopped = LibboxRouterStrategyCloseService(original, &failure)
                guard stopped, failure == nil else { throw failure ?? Self.issue("The original ordered native Box has not joined its close.") }
                nativeCloseSucceeded = true
            }
            guard capture.nativeClosed() else { throw Self.issue("The original native Instance.Close receipt is missing.") }
            nativeClosed = true
        }
        if !resourcesClosed {
            original?.close()
            platform.reset()
            resourcesClosed = true
        }
        if let path, FileManager.default.fileExists(atPath: path.path) { try FileManager.default.removeItem(at: path) }
        lock.lock(); complete = true; measurementAdoption = nil; lock.unlock()
    }

    private final class Retirement: @unchecked Sendable {
        private let lock = NSLock()
        private var owners: [RouterVPNNodeChainExecutionHost] = []
        func retain(_ owner: RouterVPNNodeChainExecutionHost) {
            lock.lock(); defer { lock.unlock() }
            if !owners.contains(where: { $0 === owner }) { owners.append(owner) }
        }
        func release(_ owner: RouterVPNNodeChainExecutionHost) {
            lock.lock(); owners.removeAll { $0 === owner }; lock.unlock()
        }
        func requireAvailable() throws {
            lock.lock(); let captured = owners; lock.unlock()
            for owner in captured { try owner.close(); release(owner) }
        }
    }
}
