import Foundation

/// Keeps the original PacketTunnel stop callback pending until its captured
/// engine has joined proof, MTU and native service retirement. The engine's
/// existing retirement gate owns the native resources; this object owns only
/// delivery and never searches for a current or replacement service.
final class RouterVPNNodeChainStop: @unchecked Sendable {
    private let lock = NSLock()
    private let owner: RouterVPNLibboxEngine
    private var callbacks: [() -> Void] = []
    private var started = false, complete = false
    private var drained: (() -> Void)?

    init(owner: RouterVPNLibboxEngine, drained: @escaping () -> Void) {
        self.owner = owner; self.drained = drained
    }
    func owns(_ engine: RouterVPNLibboxEngine) -> Bool { owner === engine }
    func start(completion: @escaping () -> Void) {
        lock.lock()
        if complete { lock.unlock(); completion(); return }
        callbacks.append(completion)
        let run = !started; started = true
        lock.unlock()
        if run { DispatchQueue.global(qos: .userInitiated).async { [self] in attempt() } }
    }
    private func attempt() {
        do { try owner.stopCheckedForStrategy() }
        catch {
            // Stop remains pending. A later retry joins only this original
            // owner; the provider's admission block stays installed throughout.
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + .milliseconds(250)) { [self] in attempt() }
            return
        }
        lock.lock()
        guard !complete else { lock.unlock(); return }
        let notify = drained
        drained = nil
        lock.unlock()
        notify?()
        lock.lock()
        let waiting = callbacks; callbacks = []; complete = true
        lock.unlock()
        for completion in waiting { completion() }
    }
}
