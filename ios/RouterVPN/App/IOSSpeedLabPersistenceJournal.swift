import Foundation

@MainActor
enum IOSSpeedLabPersistenceJournal {
    private struct Journal: Codable {
        let schema: Int
        let createdAt: Date
        let originalBundle: Data?
        let originalLastRuntime: Data?
    }

    private static let journalKey = "router-vpn.speed-lab-journal-v1"
    private static let bundleKey = "router-vpn.bundle"
    private static let lastRuntimeKey = "router-vpn.ios.last-runtime-v1"

    static var active: Bool { UserDefaults.standard.data(forKey: journalKey) != nil }

    static func begin() throws {
        let defaults = UserDefaults.standard
        guard defaults.data(forKey: journalKey) == nil else {
            throw NSError(domain: "RouterVPN.SpeedLab", code: 40, userInfo: [NSLocalizedDescriptionKey: "A previous iOS Speed Lab transaction still requires recovery."])
        }
        let journal = Journal(
            schema: 1,
            createdAt: Date(),
            originalBundle: defaults.data(forKey: bundleKey),
            originalLastRuntime: defaults.data(forKey: lastRuntimeKey)
        )
        let body = try JSONEncoder().encode(journal)
        defaults.set(body, forKey: journalKey)
        guard defaults.synchronize(), defaults.data(forKey: journalKey) == body else {
            defaults.removeObject(forKey: journalKey)
            throw NSError(domain: "RouterVPN.SpeedLab", code: 41, userInfo: [NSLocalizedDescriptionKey: "Could not durably record the original iOS Speed Lab state."])
        }
    }

    /// Reassert the original UserDefaults bytes without touching the model's
    /// in-memory temporary bundle. Call this after any normal model operation
    /// that may save the temporary node/mode while the journal remains active.
    static func reassertOriginalPersistentState() throws {
        let journal = try load()
        let defaults = UserDefaults.standard
        restore(journal.originalBundle, key: bundleKey, defaults: defaults)
        restore(journal.originalLastRuntime, key: lastRuntimeKey, defaults: defaults)
        guard defaults.synchronize() else {
            throw NSError(domain: "RouterVPN.SpeedLab", code: 42, userInfo: [NSLocalizedDescriptionKey: "iOS could not flush the original Speed Lab state back to preferences."])
        }
        try verify(journal, defaults: defaults)
    }

    static func finish() throws {
        let journal = try load()
        let defaults = UserDefaults.standard
        restore(journal.originalBundle, key: bundleKey, defaults: defaults)
        restore(journal.originalLastRuntime, key: lastRuntimeKey, defaults: defaults)
        guard defaults.synchronize() else {
            throw NSError(domain: "RouterVPN.SpeedLab", code: 43, userInfo: [NSLocalizedDescriptionKey: "iOS could not flush Speed Lab cleanup to preferences."])
        }
        try verify(journal, defaults: defaults)
        defaults.removeObject(forKey: journalKey)
        guard defaults.synchronize(), defaults.data(forKey: journalKey) == nil else {
            throw NSError(domain: "RouterVPN.SpeedLab", code: 44, userInfo: [NSLocalizedDescriptionKey: "Speed Lab cleanup completed but its recovery journal could not be cleared."])
        }
    }

    static func recoverIfNeeded(model: RouterVPNModel) async {
        guard let journal = try? load() else { return }
        await model.refreshTunnelStatus()
        if model.connected || model.tunnelTransitioning {
            if !model.tunnelTransitioning { model.disconnect() }
            for _ in 0..<50 {
                await model.refreshTunnelStatus()
                if !model.connected && !model.tunnelTransitioning { break }
                try? await Task.sleep(for: .milliseconds(150))
            }
            await model.refreshTunnelStatus()
            guard !model.connected, !model.tunnelTransitioning else {
                model.message = "Speed Lab recovery is waiting for the temporary VPN tunnel to stop before restoring your saved node."
                return
            }
        }

        do {
            let defaults = UserDefaults.standard
            restore(journal.originalBundle, key: bundleKey, defaults: defaults)
            restore(journal.originalLastRuntime, key: lastRuntimeKey, defaults: defaults)
            guard defaults.synchronize() else {
                throw NSError(domain: "RouterVPN.SpeedLab", code: 45, userInfo: [NSLocalizedDescriptionKey: "Could not flush recovered Speed Lab preferences."])
            }
            try verify(journal, defaults: defaults)
            if let bundle = journal.originalBundle {
                try model.importBundle(bundle)
            }
            defaults.removeObject(forKey: journalKey)
            guard defaults.synchronize(), defaults.data(forKey: journalKey) == nil else {
                throw NSError(domain: "RouterVPN.SpeedLab", code: 46, userInfo: [NSLocalizedDescriptionKey: "Recovered state is safe but the Speed Lab journal could not be cleared."])
            }
            model.message = "Recovered your original Router VPN state after an interrupted Speed Lab test."
        } catch {
            model.message = "Speed Lab recovery failed closed: \(error.localizedDescription)"
        }
    }

    private static func load() throws -> Journal {
        let defaults = UserDefaults.standard
        guard let body = defaults.data(forKey: journalKey) else {
            throw NSError(domain: "RouterVPN.SpeedLab", code: 47, userInfo: [NSLocalizedDescriptionKey: "No active iOS Speed Lab recovery journal."])
        }
        let journal = try JSONDecoder().decode(Journal.self, from: body)
        guard journal.schema == 1 else {
            throw NSError(domain: "RouterVPN.SpeedLab", code: 48, userInfo: [NSLocalizedDescriptionKey: "Unsupported iOS Speed Lab recovery journal schema."])
        }
        return journal
    }

    private static func restore(_ data: Data?, key: String, defaults: UserDefaults) {
        if let data { defaults.set(data, forKey: key) }
        else { defaults.removeObject(forKey: key) }
    }

    private static func verify(_ journal: Journal, defaults: UserDefaults) throws {
        guard defaults.data(forKey: bundleKey) == journal.originalBundle,
              defaults.data(forKey: lastRuntimeKey) == journal.originalLastRuntime else {
            throw NSError(domain: "RouterVPN.SpeedLab", code: 49, userInfo: [NSLocalizedDescriptionKey: "Original iOS Speed Lab persistence state did not verify after restore."])
        }
    }
}
