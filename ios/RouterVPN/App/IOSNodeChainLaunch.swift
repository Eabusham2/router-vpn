import Foundation

@MainActor
extension RouterVPNModel {
    /// Every selected record is read independently in its saved order. The
    /// caller closes this socket-free plan after staging its canonical input.
    func captureIOSNodeChain(_ selected: ClientBundle) throws -> IOSNodeChainCapture {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let sources = try iosNodeChainBundles(for: selected).map { try encoder.encode($0) }
        return try IOSNodeChainCapture.compile(bundles: sources)
    }

    /// Preference save/load can suspend while a middle node is edited or
    /// relinked. Compare the full compiled source again before native startup.
    func requireCurrentIOSNodeChain(_ input: String, selected: ClientBundle) throws {
        let current = try captureIOSNodeChain(selected)
        defer { try? current.plan.close() }
        guard current.launchInput == input else { throw CancellationError() }
    }
}
