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

    func begin(onSuperseded: @escaping () -> Void) throws -> UUID {
        guard owner == nil else { throw issue("Another temporary Speed Lab transaction is still draining.") }
        let token = UUID()
        owner = token; superseded = nil; invalidate = onSuperseded
        return token
    }

    func current(_ token: UUID) -> Bool { owner == token && superseded == nil }

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
        if superseded == nil || action != .disconnect { superseded = action }
        let callback = invalidate
        callback?()
        return true
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
