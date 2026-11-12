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
            guard try canonical(selectedProfile) == canonical(local.finalProfile) else {
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

    private static func adopt(local: IOSNodeChainCapture, requested: String, plan: LibboxRouterNodeChainExecution) throws -> IOSNodeChainExecutionCapture {
        do { return try IOSNodeChainExecutionCapture(local: local, requested: requested, plan: plan) }
        catch { try? plan.close(); throw error }
    }

    private init(local: IOSNodeChainCapture, requested: String, plan: LibboxRouterNodeChainExecution) throws {
        guard requested == "server" || requested == "auto", local.selectionExecution == requested else { throw Self.issue("The requested execution changed.") }
        self.local = local; self.requested = requested; self.plan = plan
        source = try Self.bounded(plan.source(), limit: IOSNodeChainCapture.maximumInputBytes)
        var failure: NSError?
        let input: String? = plan.launchInput(&failure)
        guard failure == nil, let input else { throw failure ?? Self.issue("The native execution returned no private source.") }
        launchInput = try Self.bounded(input, limit: IOSNodeChainCapture.maximumInputBytes)
        config = try Self.bounded(plan.config(), limit: 4 * 1024 * 1024)
        sourceSHA256 = plan.sourceSHA256(); configSHA256 = plan.configSHA256()
        let preparation = try Self.object(source, limit: IOSNodeChainCapture.maximumInputBytes)
        let launch = try Self.object(launchInput, limit: IOSNodeChainCapture.maximumInputBytes)
        guard Set(preparation.keys) == Set(["schema", "execution", "local_source"]), preparation["schema"] as? Int == 1,
              preparation["execution"] as? String == requested, plan.requestedExecution() == requested,
              plan.localSourceSHA256() == local.sourceSHA256, Self.hex(sourceSHA256),
              configSHA256 == SHA256.hash(data: Data(config.utf8)).map({ String(format: "%02x", $0) }).joined(),
              Set(launch.keys) == Set(["kind", "schema", "source", "source_sha256", "config_sha256"]),
              launch["kind"] as? String == "routervpn-node-chain-execution-preparation-input", launch["schema"] as? Int == 1,
              launch["source"] as? String == source, launch["source_sha256"] as? String == sourceSHA256,
              launch["config_sha256"] as? String == configSHA256,
              let localSource = preparation["local_source"] as? String else {
            throw Self.issue("The execution compiler changed its captured node source or native configuration.")
        }
        let returned = try Self.object(localSource, limit: IOSNodeChainCapture.maximumInputBytes)
        let original = try Self.object(local.launchInput, limit: IOSNodeChainCapture.maximumInputBytes)
        guard Set(returned.keys) == Set(["schema", "execution", "nodes", "identity_sources"]),
              returned["schema"] as? Int == 1, original["schema"] as? Int == 1, returned["execution"] as? String == "local",
              let nodes = returned["nodes"] as? [String], let identities = returned["identity_sources"] as? [String],
              nodes == original["nodes"] as? [String], identities == original["identity_sources"] as? [String] else {
            throw Self.issue("Server execution requires the exact complete paired-node order and independent private identities.")
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
        guard ["local", "server"].contains(value), requested == "auto" || value == requested else { throw Self.issue("The ordered execution has no proved selected path.") }
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
