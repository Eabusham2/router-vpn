import Foundation

/// One decision per app model, shared by every window/view using that model.
/// This controls an explicit cold app launch; it does not install an iOS
/// on-demand rule or claim execution after device boot or in the background.
@MainActor final class IOSStartupPolicy {
    private var claimed = false

    func claim() -> Bool {
        guard !claimed else { return false }
        claimed = true
        return true
    }

    static func mode(_ value: String?) throws -> String {
        let normalized = (value ?? "smart-auto").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let mode = normalized.isEmpty ? "smart-auto" : normalized
        guard ["smart-auto", "auto", "last", "manual"].contains(mode) else {
            throw issue("The saved startup behavior is invalid. Choose a startup setting before connecting.")
        }
        return mode
    }

    static func applying(mode: String, enabled: Bool, to source: RouterProfile) throws -> RouterProfile {
        guard ["router-vpn", "external"].contains(source.normalizedNodeKind) else {
            throw issue("This node has no supported startup policy.")
        }
        let mode = try self.mode(mode)
        var profile = source
        profile.startupMode = mode
        profile.autoConnect = enabled && mode != "manual"
        return profile
    }

    nonisolated static func issue(_ text: String) -> NSError {
        NSError(domain: "RouterVPN.Startup", code: 1, userInfo: [NSLocalizedDescriptionKey: text])
    }
}

/// Private bytes exist only for this in-memory admission. They are neither a
/// second credential store nor permission to overwrite the selected node.
struct IOSStartupCapture: Equatable {
    let source: Data
    let entry: Data?
    let generation: UUID

    init(bundle: ClientBundle, entry: Data?, generation: UUID) throws {
        guard !bundle.selectedRouterID.isEmpty,
              bundle.routerProfiles.filter({ $0.id == bundle.selectedRouterID }).count == 1 else {
            throw IOSStartupPolicy.issue("Startup requires one exact selected node.")
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let source = try encoder.encode(bundle)
        guard source.count <= 32 * 1024 * 1024, (entry?.count ?? 0) <= 32 * 1024 * 1024 else {
            throw IOSStartupPolicy.issue("The saved startup path exceeds its private bundle limit.")
        }
        self.source = source
        self.entry = entry
        self.generation = generation
    }
}

/// Only the launch's own runtime claim may advance its expected generation.
/// The private source and entry remain the exact initial in-memory snapshot.
@MainActor final class IOSStartupIntent {
    let captured: IOSStartupCapture
    var generation: UUID
    init(_ captured: IOSStartupCapture) {
        self.captured = captured; generation = captured.generation
    }
    func matches(_ current: IOSStartupCapture) -> Bool {
        current.source == captured.source && current.entry == captured.entry && current.generation == generation
    }
}
