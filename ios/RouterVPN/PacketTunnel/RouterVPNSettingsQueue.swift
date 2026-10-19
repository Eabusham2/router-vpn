import Foundation

/// Serialize non-nil settings across native generations. NetworkExtension
/// callbacks cannot be cancelled, so the next generation is not submitted until
/// the preceding OS application has completed. A late result is never adopted.
final class RouterVPNSettingsQueue<Settings: AnyObject>: @unchecked Sendable {
    private final class Operation {
        let id = UUID()
        let epoch: String
        let settings: Settings
        let completion: (Error?) -> Void
        init(epoch: String, settings: Settings, completion: @escaping (Error?) -> Void) {
            self.epoch = epoch; self.settings = settings; self.completion = completion
        }
    }
    private let lock = NSLock()
    private let apply: (Settings, @escaping (Error?) -> Void) -> Void
    private var epoch: String?
    private var pending: [Operation] = []
    private var running: Operation?

    init(apply: @escaping (Settings, @escaping (Error?) -> Void) -> Void) { self.apply = apply }

    func begin(epoch: String) {
        lock.lock()
        self.epoch = epoch
        let discarded = pending; pending = []
        lock.unlock()
        discarded.forEach { $0.completion(Self.stale()) }
    }

    func current(_ expected: String) -> Bool {
        lock.lock(); defer { lock.unlock() }; return epoch == expected
    }

    func retire(epoch expected: String) {
        lock.lock()
        guard epoch == expected else { lock.unlock(); return }
        epoch = nil
        let discarded = pending; pending = []
        lock.unlock()
        discarded.forEach { $0.completion(Self.stale()) }
    }

    func submit(_ settings: Settings, epoch expected: String, completion: @escaping (Error?) -> Void) {
        let operation = Operation(epoch: expected, settings: settings, completion: completion)
        lock.lock()
        guard epoch == expected, pending.count < 8 else { lock.unlock(); completion(Self.stale()); return }
        pending.append(operation)
        let next = nextLocked()
        lock.unlock()
        perform(next)
    }

    private func nextLocked() -> Operation? {
        guard running == nil, !pending.isEmpty else { return nil }
        let next = pending.removeFirst(); running = next; return next
    }

    private func perform(_ operation: Operation?) {
        guard let operation else { return }
        apply(operation.settings) { [weak self] error in self?.finished(operation, error: error) }
    }

    private func finished(_ operation: Operation, error: Error?) {
        lock.lock()
        guard running === operation else { lock.unlock(); return }
        let result = epoch == operation.epoch ? error : Self.stale()
        running = nil
        let next = nextLocked()
        lock.unlock()
        operation.completion(result)
        perform(next)
    }

    private static func stale() -> NSError {
        NSError(domain: "RouterVPN.NetworkSettings", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Network settings belong to a retired native runtime."])
    }
}

final class RouterVPNSettingsResult: @unchecked Sendable {
    private let lock = NSLock()
    private var result: Error?
    let completed = DispatchSemaphore(value: 0)
    func finish(_ error: Error?) { lock.lock(); result = error; lock.unlock(); completed.signal() }
    var error: Error? { lock.lock(); defer { lock.unlock() }; return result }
}
