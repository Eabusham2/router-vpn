import Foundation

/// A task-local lease distinguishes Speed Lab's own connection changes from
/// a newer user action, including Disconnect while the test is between paths.
enum IOSSpeedLabContext {
    static let ownerKey = "routervpn_speed_lab_owner"
    @TaskLocal static var owner: UUID?
    @TaskLocal static var restoringSelection = false
    static func mark(_ configuration: inout [String: Any]) {
        if let owner { configuration[ownerKey] = owner.uuidString }
    }
}

@MainActor final class IOSSpeedLabOwnership {
    enum Action { case connection, disconnect, profile }
    private var owner: UUID?
    private var superseded: Action?
    private var invalidate: (() -> Void)?
    private var userRevision = UUID()

    var active: Bool { owner != nil }

    func begin(owner token: UUID = UUID(), onSuperseded: @escaping () -> Void) throws -> UUID {
        guard owner == nil else { throw issue("Another temporary Speed Lab transaction is still draining.") }
        owner = token; superseded = nil; invalidate = onSuperseded
        return token
    }

    func current(_ token: UUID) -> Bool { owner == token && superseded == nil }
    func owns(_ token: UUID) -> Bool { owner == token }
    func userDisconnected(_ token: UUID) -> Bool { owner == token && superseded == .disconnect }

    func mayRestoreSelection(_ token: UUID) -> Bool {
        owner == token && (superseded == nil || superseded == .disconnect)
    }

    func require(_ token: UUID) throws {
        guard current(token) else { throw CancellationError() }
    }

    /// Late work from a superseded test cannot start a tunnel or write a
    /// profile. A user Disconnect preserves only the right to restore saved
    /// selection while idle; it never grants permission to reconnect.
    func admit(_ action: Action) -> Bool {
        if let captured = IOSSpeedLabContext.owner {
            if current(captured) { return true }
            return action == .profile && IOSSpeedLabContext.restoringSelection && mayRestoreSelection(captured)
        }
        guard owner != nil else { return true }
        userRevision = UUID()
        if superseded == nil || action != .disconnect { superseded = action }
        let callback = invalidate
        callback?()
        return true
    }

    /// A newer Home connection waits for the captured temporary worker to
    /// retire. It never races a save/stop of the same system VPN preferences.
    /// A later Disconnect/profile action revokes this waiting connection too.
    func admitConnection() async -> Bool {
        if IOSSpeedLabContext.owner != nil { return admit(.connection) }
        guard owner != nil else { return true }
        _ = admit(.connection)
        let revision = userRevision
        while owner != nil {
            guard userRevision == revision, !Task.isCancelled else { return false }
            do { try await Task.sleep(for: .milliseconds(50)) }
            catch { return false }
        }
        return userRevision == revision && !Task.isCancelled
    }

    func finish(_ token: UUID) {
        guard owner == token else { return }
        owner = nil; superseded = nil; invalidate = nil
    }

    private func issue(_ text: String) -> NSError {
        NSError(domain: "RouterVPN.SpeedLab", code: 60,
                userInfo: [NSLocalizedDescriptionKey: text])
    }
}
