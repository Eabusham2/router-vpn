import Foundation
import CryptoKit
import Libbox

/// Closed source union. Each typed proxy keeps its original parser and native
/// factory; none of the source-only plans owns PacketTunnel forwarding.
enum IOSNodeChainExecutionLocalSource {
    case ordinary(IOSNodeChainCapture)
    case connect(IOSNodeChainCONNECTCapture)
    case socks(IOSNodeChainSOCKSCapture)

    var isCONNECT: Bool { if case .connect = self { return true }; return false }
    var isSOCKS: Bool { if case .socks = self { return true }; return false }
    var members: [IOSNodeChainCapture.Member] { switch self { case .ordinary(let v): return v.members; case .connect(let v): return v.members; case .socks(let v): return v.members } }
    var strict: Bool { switch self { case .ordinary(let v): return v.strict; case .connect(let v): return v.strict; case .socks(let v): return v.strict } }
    var homeLANAccess: Bool { switch self { case .ordinary(let v): return v.homeLANAccess; case .connect(let v): return v.homeLANAccess; case .socks(let v): return v.homeLANAccess } }
    var finalProfile: [String: Any] { switch self { case .ordinary(let v): return v.finalProfile; case .connect(let v): return v.finalProfile; case .socks(let v): return v.finalProfile } }
    var selectionExecution: String { switch self { case .ordinary(let v): return v.selectionExecution; case .connect(let v): return v.selectionExecution; case .socks(let v): return v.selectionExecution } }
    var launchInput: String { switch self { case .ordinary(let v): return v.launchInput; case .connect(let v): return v.source; case .socks(let v): return v.source } }
    var sourceSHA256: String { switch self { case .ordinary(let v): return v.sourceSHA256; case .connect(let v): return v.sourceSHA256; case .socks(let v): return v.sourceSHA256 } }
    func close() throws { switch self { case .ordinary(let v): try v.plan.close(); case .connect(let v): try v.plan.close(); case .socks(let v): try v.plan.close() } }

    static func compile(bundles: [Data], requested: String) throws -> Self {
        guard let last = bundles.last, let root = try JSONSerialization.jsonObject(with: last) as? [String: Any],
              let id = root["selectedRouterID"] as? String, let profiles = root["routerProfiles"] as? [[String: Any]],
              profiles.filter({ $0["id"] as? String == id }).count == 1,
              let final = profiles.first(where: { $0["id"] as? String == id }),
              let nodes = final["multihop_nodes"] as? [[String: Any]] else { throw IOSNodeChainCONNECTCapture.issue() }
        if nodes.contains(where: { ["http-connect", "https-connect"].contains($0["mode"] as? String ?? "") }) {
            return .connect(try IOSNodeChainCONNECTCapture.compileOriginalForExecution(bundles: bundles, requested: requested))
        }
        if nodes.contains(where: { $0["mode"] as? String == "socks5" }) {
            return .socks(try IOSNodeChainSOCKSCapture.compileOriginalForExecution(bundles: bundles, requested: requested))
        }
        return .ordinary(try IOSNodeChainCapture.compileOriginalForExecution(bundles: bundles, requested: requested))
    }

    static func open(_ original: String, requested: String) throws -> Self {
        guard let root = try JSONSerialization.jsonObject(with: Data(original.utf8)) as? [String: Any] else { throw IOSNodeChainCONNECTCapture.issue() }
        if root["schema"] as? Int == 4 {
            return .connect(try IOSNodeChainCONNECTCapture.open(original, selectionExecution: requested))
        }
        if root["schema"] as? Int == 3 {
            return .socks(try IOSNodeChainSOCKSCapture.open(original, selectionExecution: requested))
        }
        var failure: NSError?
        let returned = LibboxNewRouterNodeChain(original, &failure)
        guard let plan = returned, failure == nil else { try? returned?.close(); throw failure ?? IOSNodeChainCONNECTCapture.issue() }
        do { return .ordinary(try IOSNodeChainCapture(plan: plan, selectionExecution: requested)) }
        catch { try? plan.close(); throw error }
    }

    func newExecution(_ requested: String, _ failure: UnsafeMutablePointer<NSError?>?) -> LibboxRouterNodeChainExecution? {
        isSOCKS ? LibboxNewRouterNodeChainSOCKSExecution(launchInput, requested, failure) : isCONNECT ? LibboxNewRouterNodeChainCONNECTExecution(launchInput, requested, failure) : LibboxRouterNodeChainExecutionFromLaunch(launchInput, requested, failure)
    }
    func fromLast(_ requested: String, _ record: String, _ failure: UnsafeMutablePointer<NSError?>?) -> LibboxRouterNodeChainExecution? {
        isSOCKS ? LibboxRouterNodeChainSOCKSExecutionFromLast(launchInput, requested, record, failure) : isCONNECT ? LibboxRouterNodeChainCONNECTExecutionFromLast(launchInput, requested, record, failure) : LibboxRouterNodeChainExecutionFromLast(launchInput, requested, record, failure)
    }
}

/// Complete private Server/Compare preparation. Its source-only Local plan
/// retains the original node bytes; only the execution plan owns forwarding.
final class IOSNodeChainExecutionCapture {
    let local: IOSNodeChainExecutionLocalSource
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
    var isCONNECT: Bool { local.isCONNECT }
    var isSOCKS: Bool { local.isSOCKS }

    static func compile(bundles: [Data], requested: String) throws -> IOSNodeChainExecutionCapture {
        let local = try IOSNodeChainExecutionLocalSource.compile(bundles: bundles, requested: requested)
        do {
            var failure: NSError?
            guard let plan = local.newExecution(requested, &failure), failure == nil else {
                throw failure ?? issue("The complete ordered execution could not be prepared.")
            }
            return try adopt(local: local, requested: requested, plan: plan)
        } catch { try? local.close(); throw error }
    }

    static func reopen(_ input: String, selectedProfile: [String: Any]) throws -> IOSNodeChainExecutionCapture {
        let launch = try object(input, limit: IOSNodeChainCapture.maximumInputBytes)
        guard launch["schema"] as? Int == 1, launch["last"] == nil else { throw issue("Ordinary execution cannot replace an explicit saved Last choice.") }
        guard let source = launch["source"] as? String else { throw issue("The private execution launch has no original source.") }
        let preparation = try object(source, limit: IOSNodeChainCapture.maximumInputBytes)
        guard let original = preparation["local_source"] as? String, let requested = preparation["execution"] as? String,
              ["server", "auto"].contains(requested) else { throw issue("The original execution selection is missing.") }
        var failure: NSError?
        let local = try IOSNodeChainExecutionLocalSource.open(original, requested: requested)
        do {
            guard try canonical(IOSNodeChainCapture.executionProfile(selectedProfile)) == canonical(local.finalProfile) else {
                throw issue("The selected final node changed its private execution source.")
            }
            failure = nil
            let returned = local.isSOCKS ? LibboxNewRouterNodeChainSOCKSExecutionLaunch(input, &failure) : local.isCONNECT ? LibboxNewRouterNodeChainCONNECTExecutionLaunch(input, &failure) : LibboxNewRouterNodeChainExecutionLaunch(input, &failure)
            guard let plan = returned, failure == nil else {
                throw failure ?? issue("The private execution source could not be reproduced.")
            }
            let result = try adopt(local: local, requested: requested, plan: plan)
            guard result.launchInput == input else {
                try result.close()
                throw issue("The execution launch is not its exact original canonical source.")
            }
            return result
        } catch { try? local.close(); throw error }
    }

    private static func adopt(local: IOSNodeChainExecutionLocalSource, requested: String, plan: LibboxRouterNodeChainExecution, ordinaryInput: String? = nil, expected: String? = nil, lastRecord: String? = nil) throws -> IOSNodeChainExecutionCapture {
        do { return try IOSNodeChainExecutionCapture(local: local, requested: requested, plan: plan, ordinaryInput: ordinaryInput, expected: expected, lastRecord: lastRecord) }
        catch { try? plan.close(); throw error }
    }

    private init(local: IOSNodeChainExecutionLocalSource, requested: String, plan: LibboxRouterNodeChainExecution, ordinaryInput: String?, expected: String?, lastRecord: String?) throws {
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
        guard Set(preparation.keys) == Set(["schema", "execution", "local_source"]), preparation["schema"] as? Int == (local.isSOCKS ? 3 : local.isCONNECT ? 4 : 1),
              preparation["execution"] as? String == requested, plan.requestedExecution() == requested,
              plan.localSourceSHA256() == local.sourceSHA256, Self.hex(sourceSHA256),
              configSHA256 == SHA256.hash(data: Data(config.utf8)).map({ String(format: "%02x", $0) }).joined(),
              Self.launchFields(launch, lastRecord: lastRecord),
              launch["kind"] as? String == (local.isSOCKS ? "routervpn-node-chain-socks-execution-preparation-input" : local.isCONNECT ? "routervpn-node-chain-connect-execution-preparation-input" : "routervpn-node-chain-execution-preparation-input"),
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
              let schema = original["schema"] as? Int, local.isSOCKS ? schema == 3 : local.isCONNECT ? schema == 4 : (schema == 1 || schema == 2),
              returned["schema"] as? Int == schema, returned["execution"] as? String == "local",
              let nodes = returned["nodes"] as? [String], schema != 3 || nodes.count == 3,
              schema != 4 || (3...IOSMultihopNodeSelection.maximumNodes).contains(nodes.count),
              let identities = returned["identity_sources"] as? [String],
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
        try local.close()
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
        let validation = local.fromLast(requested, raw, &failure)
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
        let returned = original.local.fromLast(original.requested, raw, &failure)
        guard let plan = returned, failure == nil else {
            try? returned?.close()
            throw failure ?? issue("The saved Last record no longer matches every original node.")
        }
        let local: IOSNodeChainExecutionLocalSource
        do { local = try original.freshLocalSource() } catch { try? plan.close(); throw error }
        do {
            let result = try adopt(local: local, requested: original.requested, plan: plan, ordinaryInput: input, expected: selected, lastRecord: raw)
            guard result.source == original.source, result.config == original.config else {
                try result.close(); throw issue("Last changed the original ordinary preparation.")
            }
            return result
        } catch { try? local.close(); throw error }
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
        let local = try IOSNodeChainExecutionLocalSource.open(original, requested: requested)
        defer { try? local.close() }
        guard try canonical(IOSNodeChainCapture.executionProfile(selectedProfile)) == canonical(local.finalProfile) else { throw issue("The selected final node changed before Last.") }
        failure = nil
        let ordinary = local.newExecution(requested, &failure)
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

    private func freshLocalSource() throws -> IOSNodeChainExecutionLocalSource {
        let preparation = try Self.object(source, limit: IOSNodeChainCapture.maximumInputBytes)
        guard let input = preparation["local_source"] as? String else { throw Self.issue("The complete original Local source is missing.") }
        return try IOSNodeChainExecutionLocalSource.open(input, requested: requested)
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
            let local: IOSNodeChainExecutionLocalSource
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
            } catch { try? local.close(); try? plan.close(); throw error }
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
