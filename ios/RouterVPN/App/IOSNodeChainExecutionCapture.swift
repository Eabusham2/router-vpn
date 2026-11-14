import Foundation
import CryptoKit
import Libbox

/// Complete private Server/Compare preparation. Its source-only Local plan
/// retains the original node bytes; only the execution plan owns forwarding.
final class IOSNodeChainExecutionCapture {
    let local: IOSNodeChainCapture
    let plan: LibboxRouterNodeChainExecution
    let requested: String
    let source: String
    let launchInput: String
    /// Durable Last always reopens the original ordinary envelope. A temporary
    /// restore may honestly have another private effective-MTU ConfigSHA.
    let ordinaryLaunchInput: String
    private let expectedExecution: String?
    private let lastRecord: String?
    let config: String
    let sourceSHA256: String
    let configSHA256: String
    private let lock = NSLock()
    private var closed = false

    var members: [IOSNodeChainCapture.Member] { local.members }
    var strict: Bool { local.strict }
    var homeLANAccess: Bool { local.homeLANAccess }
    var finalProfile: [String: Any] { local.finalProfile }
    var startupTimeout: TimeInterval { 120 }

    static func compile(bundles: [Data], requested: String) throws -> IOSNodeChainExecutionCapture {
        let local = try IOSNodeChainCapture.compileOriginalForExecution(bundles: bundles, requested: requested)
        do {
            var failure: NSError?
            guard let plan = LibboxRouterNodeChainExecutionFromLaunch(local.launchInput, requested, &failure), failure == nil else {
                throw failure ?? issue("The complete ordered execution could not be prepared.")
            }
            return try adopt(local: local, requested: requested, plan: plan)
        } catch { try? local.plan.close(); throw error }
    }

    static func reopen(_ input: String, selectedProfile: [String: Any]) throws -> IOSNodeChainExecutionCapture {
        let launch = try object(input, limit: IOSNodeChainCapture.maximumInputBytes)
        guard launch["schema"] as? Int == 1, launch["last"] == nil else { throw issue("Ordinary execution cannot replace an explicit saved Last choice.") }
        guard let source = launch["source"] as? String else { throw issue("The private execution launch has no original source.") }
        let preparation = try object(source, limit: IOSNodeChainCapture.maximumInputBytes)
        guard let original = preparation["local_source"] as? String, let requested = preparation["execution"] as? String,
              ["server", "auto"].contains(requested) else { throw issue("The original execution selection is missing.") }
        var failure: NSError?
        guard let localPlan = LibboxNewRouterNodeChain(original, &failure), failure == nil else {
            throw failure ?? issue("The original complete Local source could not be reproduced.")
        }
        let local: IOSNodeChainCapture
        do { local = try IOSNodeChainCapture(plan: localPlan, selectionExecution: requested) }
        catch { try? localPlan.close(); throw error }
        do {
            guard try canonical(IOSNodeChainCapture.executionProfile(selectedProfile)) == canonical(local.finalProfile) else {
                throw issue("The selected final node changed its private execution source.")
            }
            failure = nil
            guard let plan = LibboxNewRouterNodeChainExecutionLaunch(input, &failure), failure == nil else {
                throw failure ?? issue("The private execution source could not be reproduced.")
            }
            let result = try adopt(local: local, requested: requested, plan: plan)
            guard result.launchInput == input else {
                try result.close()
                throw issue("The execution launch is not its exact original canonical source.")
            }
            return result
        } catch { try? local.plan.close(); throw error }
    }

    private static func adopt(local: IOSNodeChainCapture, requested: String, plan: LibboxRouterNodeChainExecution, ordinaryInput: String? = nil, expected: String? = nil, lastRecord: String? = nil) throws -> IOSNodeChainExecutionCapture {
        do { return try IOSNodeChainExecutionCapture(local: local, requested: requested, plan: plan, ordinaryInput: ordinaryInput, expected: expected, lastRecord: lastRecord) }
        catch { try? plan.close(); throw error }
    }

    private init(local: IOSNodeChainCapture, requested: String, plan: LibboxRouterNodeChainExecution, ordinaryInput: String?, expected: String?, lastRecord: String?) throws {
        guard requested == "server" || requested == "auto", local.selectionExecution == requested else { throw Self.issue("The requested execution changed.") }
        guard expected == nil || expected == "server" || requested == "auto" && expected == "local" else { throw Self.issue("The retained concrete execution is invalid.") }
        self.local = local; self.requested = requested; self.plan = plan; self.expectedExecution = expected; self.lastRecord = lastRecord
        source = try Self.bounded(plan.source(), limit: IOSNodeChainCapture.maximumInputBytes)
        var failure: NSError?
        let input: String? = plan.launchInput(&failure)
        guard failure == nil, let input else { throw failure ?? Self.issue("The native execution returned no private source.") }
        launchInput = try Self.bounded(input, limit: IOSNodeChainCapture.maximumInputBytes)
        ordinaryLaunchInput = try Self.bounded(ordinaryInput ?? input, limit: IOSNodeChainCapture.maximumInputBytes)
        config = try Self.bounded(plan.config(), limit: 4 * 1024 * 1024)
        sourceSHA256 = plan.sourceSHA256(); configSHA256 = plan.configSHA256()
        let preparation = try Self.object(source, limit: IOSNodeChainCapture.maximumInputBytes)
        let launch = try Self.object(launchInput, limit: IOSNodeChainCapture.maximumInputBytes)
        guard Set(preparation.keys) == Set(["schema", "execution", "local_source"]), preparation["schema"] as? Int == 1,
              preparation["execution"] as? String == requested, plan.requestedExecution() == requested,
              plan.localSourceSHA256() == local.sourceSHA256, Self.hex(sourceSHA256),
              configSHA256 == SHA256.hash(data: Data(config.utf8)).map({ String(format: "%02x", $0) }).joined(),
              Self.launchFields(launch, lastRecord: lastRecord),
              launch["kind"] as? String == "routervpn-node-chain-execution-preparation-input",
              launch["source"] as? String == source, launch["source_sha256"] as? String == sourceSHA256,
              launch["config_sha256"] as? String == configSHA256,
              let localSource = preparation["local_source"] as? String else {
            throw Self.issue("The execution compiler changed its captured node source or native configuration.")
        }
        let returned = try Self.object(localSource, limit: IOSNodeChainCapture.maximumInputBytes)
        let original = try Self.object(local.launchInput, limit: IOSNodeChainCapture.maximumInputBytes)
        // Embedded Local schema two identifies the imported SS member. It is
        // independent of the ordinary execution and saved Last launch schemas.
        guard Set(returned.keys) == Set(["schema", "execution", "nodes", "identity_sources"]),
              let schema = original["schema"] as? Int, schema == 1 || schema == 2,
              returned["schema"] as? Int == schema, returned["execution"] as? String == "local",
              let nodes = returned["nodes"] as? [String], let identities = returned["identity_sources"] as? [String],
              nodes == original["nodes"] as? [String], identities == original["identity_sources"] as? [String] else {
            throw Self.issue("Server execution requires the exact complete member order and independent private identities.")
        }
    }

    func requireCurrent() throws {
        lock.lock(); let retired = closed; lock.unlock()
        guard !retired else { throw Self.issue("The original execution capture has retired.") }
    }
    // Bind the fresh native construction slot even when cancellation already
    // retired this wrapper. The native plan then seals a cleanup-only receipt;
    // skipping that reservation would leave native teardown unprovable.
    func bindNative(_ server: LibboxCommandServer) throws { try plan.bindNative(server); try requireCurrent() }
    func run(_ server: LibboxCommandServer) throws { try requireCurrent(); try plan.run(server); try requireCurrent() }
    func healthy() -> Bool { (try? requireCurrent()) != nil && plan.healthy() && (try? requireCurrent()) != nil }
    func execution() throws -> String {
        try requireCurrent()
        let value = plan.execution()
        guard ["local", "server"].contains(value), requested == "auto" || value == requested,
              expectedExecution == nil || value == expectedExecution else { throw Self.issue("The ordered execution has no proved selected path.") }
        try requireCurrent(); return value
    }
    func networkChanged() { plan.networkChanged() }
    func nativeClosed() -> Bool { plan.nativeClosed() }
    func retainsServerCleanup(_ server: LibboxCommandServer) -> Bool {
        lock.lock(); let retired = closed; lock.unlock()
        return !retired && plan.retainsServerCleanup(server)
    }
    func close() throws {
        try plan.close()
        lock.lock(); closed = true; lock.unlock()
        try local.plan.close()
    }

    /// This value is private-storage content, never a live or cleanup receipt.
    /// Native validation covers every source/DNS/descriptor binding; a fresh
    /// source-only Last factory confirms the canonical record independently.
    func captureLastRecord() throws -> String {
        try requireCurrent()
        guard healthy() else { throw Self.issue("Last requires this exact healthy native execution.") }
        let selected = try execution()
        var failure: NSError?
        let returned: String? = plan.captureLastJSON(&failure)
        guard failure == nil, let returned else { throw failure ?? Self.issue("The current native execution returned no Last record.") }
        let raw = try Self.bounded(returned, limit: 16 * 1024)
        let record = try Self.object(raw, limit: 16 * 1024)
        guard record["execution"] as? String == selected else { throw Self.issue("Last changed the proved concrete execution.") }
        failure = nil
        let validation = LibboxRouterNodeChainExecutionFromLast(local.launchInput, requested, raw, &failure)
        defer { try? validation?.close() }
        guard failure == nil, let validation, validation.source() == source,
              validation.requestedExecution() == requested, healthy(), try execution() == selected else {
            throw failure ?? Self.issue("The Last record lost the original source or current proof.")
        }
        try requireCurrent()
        return raw
    }

    static func reopenLast(_ input: String, selectedProfile: [String: Any], record: String) throws -> IOSNodeChainExecutionCapture {
        let original = try reopen(input, selectedProfile: selectedProfile)
        defer { try? original.close() }
        let raw = try bounded(record, limit: 16 * 1024)
        let value = try object(raw, limit: 16 * 1024)
        guard let selected = value["execution"] as? String, ["local", "server"].contains(selected) else { throw issue("Last has no original concrete execution.") }
        var failure: NSError?
        let returned = LibboxRouterNodeChainExecutionFromLast(original.local.launchInput, original.requested, raw, &failure)
        guard let plan = returned, failure == nil else {
            try? returned?.close()
            throw failure ?? issue("The saved Last record no longer matches every original node.")
        }
        let local: IOSNodeChainCapture
        do { local = try original.freshLocalSource() } catch { try? plan.close(); throw error }
        do {
            let result = try adopt(local: local, requested: original.requested, plan: plan, ordinaryInput: input, expected: selected, lastRecord: raw)
            guard result.source == original.source, result.config == original.config else {
                try result.close(); throw issue("Last changed the original ordinary preparation.")
            }
            return result
        } catch { try? local.plan.close(); throw error }
    }

    /// Schema two is a separate dispatch. Native canonical parsing must keep
    /// the exact saved record; an ordinary schema-one replay is never a Last.
    static func reopenLastLaunch(_ input: String, selectedProfile: [String: Any]) throws -> IOSNodeChainExecutionCapture {
        let launch = try object(input, limit: IOSNodeChainCapture.maximumInputBytes)
        guard let raw = launch["last"] as? String, launchFields(launch, lastRecord: raw),
              let source = launch["source"] as? String else { throw issue("The saved Last launch is incomplete.") }
        let preparation = try object(source, limit: IOSNodeChainCapture.maximumInputBytes)
        guard let original = preparation["local_source"] as? String,
              let requested = preparation["execution"] as? String else { throw issue("The original Last selection is missing.") }
        var failure: NSError?
        let localReturned = LibboxNewRouterNodeChain(original, &failure)
        guard let localPlan = localReturned, failure == nil else {
            try? localReturned?.close(); throw failure ?? issue("The original Last members could not be reproduced.")
        }
        let local: IOSNodeChainCapture
        do { local = try IOSNodeChainCapture(plan: localPlan, selectionExecution: requested) }
        catch { try? localPlan.close(); throw error }
        defer { try? local.plan.close() }
        guard try canonical(IOSNodeChainCapture.executionProfile(selectedProfile)) == canonical(local.finalProfile) else { throw issue("The selected final node changed before Last.") }
        failure = nil
        let ordinary = LibboxRouterNodeChainExecutionFromLaunch(local.launchInput, requested, &failure)
        defer { try? ordinary?.close() }
        guard failure == nil, let ordinary else { throw failure ?? issue("The original ordinary source could not be reproduced.") }
        failure = nil
        let ordinaryInput: String? = ordinary.launchInput(&failure)
        guard failure == nil, let ordinaryInput else { throw failure ?? issue("The original ordinary launch is unavailable.") }
        let result = try reopenLast(ordinaryInput, selectedProfile: selectedProfile, record: raw)
        guard result.launchInput == input else {
            try result.close(); throw issue("The saved Last launch changed its exact canonical source.")
        }
        return result
    }

    /// Capture while the current host's observation hold is entered. The
    /// native capsule binds the actual issued reader and exact controller; it
    /// cannot be serialized or replaced by a source hash or a caller MTU.
    func captureRestoration() throws -> Restoration {
        try requireCurrent()
        guard healthy() else { throw Self.issue("Temporary restore requires the original healthy owner.") }
        let selected = try execution()
        let returned: LibboxRouterNodeChainExecutionRestoreCapture? = try plan.captureRestore()
        guard let returned, healthy(), try execution() == selected else { throw Self.issue("The original restore observation changed during capture.") }
        try requireCurrent()
        return Restoration(original: self, native: returned, selected: selected)
    }

    private func freshLocalSource() throws -> IOSNodeChainCapture {
        let preparation = try Self.object(source, limit: IOSNodeChainCapture.maximumInputBytes)
        guard let input = preparation["local_source"] as? String else { throw Self.issue("The complete original Local source is missing.") }
        var failure: NSError?
        let returned = LibboxNewRouterNodeChain(input, &failure)
        guard let plan = returned, failure == nil else {
            try? returned?.close(); throw failure ?? Self.issue("The original member source could not be reproduced.")
        }
        do { return try IOSNodeChainCapture(plan: plan, selectionExecution: requested) }
        catch { try? plan.close(); throw error }
    }

    final class Restoration {
        private let original: IOSNodeChainExecutionCapture
        private let native: LibboxRouterNodeChainExecutionRestoreCapture
        let selected: String
        private let lock = NSLock()
        private var constructing = false, claimed = false

        fileprivate init(original: IOSNodeChainExecutionCapture, native: LibboxRouterNodeChainExecutionRestoreCapture, selected: String) {
            self.original = original; self.native = native; self.selected = selected
        }

        func makeCapture(ordinaryInput: String, selectedProfile: [String: Any]) throws -> IOSNodeChainExecutionCapture {
            guard ordinaryInput == original.ordinaryLaunchInput,
                  try IOSNodeChainExecutionCapture.canonical(IOSNodeChainCapture.executionProfile(selectedProfile)) == IOSNodeChainExecutionCapture.canonical(original.finalProfile) else {
                throw IOSNodeChainExecutionCapture.issue("The original ordered source changed before temporary restore.")
            }
            original.lock.lock(); let closed = original.closed; original.lock.unlock()
            guard closed, original.nativeClosed() else { throw IOSNodeChainExecutionCapture.issue("The original shared and native Instance.Close owners have not joined.") }
            lock.lock()
            guard !constructing, !claimed else { lock.unlock(); throw IOSNodeChainExecutionCapture.issue("This original restore capsule is already claimed.") }
            constructing = true; lock.unlock()
            defer { lock.lock(); constructing = false; lock.unlock() }
            var failure: NSError?
            let returned = LibboxNewRouterNodeChainExecutionRestore(native, &failure)
            if returned != nil { lock.lock(); claimed = true; lock.unlock() }
            guard let plan = returned, failure == nil else {
                try? returned?.close(); throw failure ?? IOSNodeChainExecutionCapture.issue("The original native restore could not be constructed.")
            }
            do { try plan.requireRestore(native) } catch { try? plan.close(); throw error }
            let local: IOSNodeChainCapture
            do { local = try original.freshLocalSource() } catch { try? plan.close(); throw error }
            do {
                let result = try IOSNodeChainExecutionCapture.adopt(local: local, requested: original.requested, plan: plan,
                    ordinaryInput: original.ordinaryLaunchInput, expected: selected)
                guard result.source == original.source, result.sourceSHA256 == original.sourceSHA256,
                      result.plan.localSourceSHA256() == original.local.sourceSHA256 else {
                    try result.close(); throw IOSNodeChainExecutionCapture.issue("Typed restore changed the original complete node identity.")
                }
                // Require the exact returned plan/preparation/capsule relation
                // again after every source/config read before host adoption.
                try plan.requireRestore(native)
                return result
            } catch { try? local.plan.close(); try? plan.close(); throw error }
        }
    }

    private static func launchFields(_ launch: [String: Any], lastRecord: String?) -> Bool {
        let ordinary = Set(["kind", "schema", "source", "source_sha256", "config_sha256"])
        if let lastRecord {
            return !lastRecord.isEmpty && lastRecord.utf8.count <= 16 * 1024 &&
                Set(launch.keys) == ordinary.union(["last"]) && launch["schema"] as? Int == 2 &&
                launch["last"] as? String == lastRecord
        }
        return Set(launch.keys) == ordinary && launch["schema"] as? Int == 1
    }

    private static func bounded(_ raw: String, limit: Int) throws -> String {
        guard !raw.isEmpty, raw.utf8.count <= limit else { throw issue("The complete private execution source exceeds its bound.") }
        return raw
    }
    private static func object(_ raw: String, limit: Int) throws -> [String: Any] {
        let input = try bounded(raw, limit: limit)
        guard let value = try JSONSerialization.jsonObject(with: Data(input.utf8)) as? [String: Any] else { throw issue("The private execution source is malformed.") }
        return value
    }
    private static func canonical(_ object: [String: Any]) throws -> Data { try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) }
    private static func hex(_ value: String) -> Bool { value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }
    private static func issue(_ text: String) -> NSError { NSError(domain: "RouterVPN.NodeChainExecution", code: 1, userInfo: [NSLocalizedDescriptionKey: text]) }
}
