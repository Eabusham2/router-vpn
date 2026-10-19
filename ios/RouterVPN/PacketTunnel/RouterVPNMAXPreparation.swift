import Foundation
import Libbox
@preconcurrency import Network

/// Private launch copies for one pending native attempt. Construction checks
/// every complete source and its app handoff digest before creating a resolver.
/// Run/Close are serialized; Cancel never waits for a foreign DNS callback.
final class RouterVPNMAXPreparation: @unchecked Sendable {
    let sourceHashes: [String: String]
    let requiresResolution: Bool
    private let providerData: Data
    private let sources: [IOSMAXSourceSelection.Source]
    private let lock = NSLock()
    private let operation = NSLock()
    private var canceled = false
    private var started = false
    private var succeeded = false
    private var requests: [LibboxRouterMAXProfileRequest] = []
    private var resolvers: [RouterVPNMAXDNSOwner] = []

    init(provider: [String: Any]) throws {
        providerData = try PropertyListSerialization.data(fromPropertyList: provider, format: .binary, options: 0)
        guard providerData.count <= 80 * 1024 * 1024,
              let original = try PropertyListSerialization.propertyList(from: providerData, options: [], format: nil) as? [String: Any] else { throw Self.issue() }
        sources = try IOSMAXSourceSelection.sources(provider: original)
        sourceHashes = try IOSMAXSourceSelection.sourceHashes(provider: original, checker: Self.check)
        requiresResolution = sources.contains { Self.hostname($0.input.endpoint) }
        // Literal profiles saved by an older app keep their existing compiler
        // path. A hostname requires a new exact app-to-extension source stamp.
        if let handoff = original["max_source_sha256"] {
            guard let hashes = handoff as? [String: String], hashes == sourceHashes else { throw Self.issue() }
        } else if requiresResolution { throw Self.issue() }
    }

    private static func check(_ mode: String, _ files: String, _ metadata: String) throws -> String {
        var failure: NSError?
        let value: String? = LibboxRouterCheckMAXProfile(mode, files, metadata, &failure)
        guard failure == nil, let value else { throw issue() }
        return value
    }

    private static func hostname(_ value: String) -> Bool { IPv4Address(value) == nil && IPv6Address(value) == nil }

    func run() throws -> [String: Any] {
        operation.lock(); defer { operation.unlock() }
        lock.lock()
        guard !canceled, !started else { lock.unlock(); throw Self.issue() }
        started = true; lock.unlock()
        guard var launch = try PropertyListSerialization.propertyList(from: providerData, options: [], format: nil) as? [String: Any] else { throw Self.issue() }
        for source in sources where Self.hostname(source.input.endpoint) {
            guard active else { throw Self.issue() }
            let resolver = RouterVPNMAXDNSOwner()
            lock.lock()
            let accepted = !canceled
            if accepted { resolvers.append(resolver) }
            lock.unlock()
            guard accepted else { resolver.cancel(); throw Self.issue() }
            try resolver.capture()
            guard active, resolver.current(), let digest = sourceHashes[source.key] else { throw Self.issue() }
            var failure: NSError?
            let request = LibboxRouterCreateMAXProfileRequest(source.input.mode, source.input.filesJSON, source.input.metadataJSON, resolver, &failure)
            // A returned native handle stays owned even if a foreign binding
            // simultaneously reports an error. Never abandon it on this path.
            if let request {
                lock.lock(); requests.append(request); let retired = canceled; lock.unlock()
                if retired { request.cancel() }
            }
            guard failure == nil, let request, active, request.sourceSHA256() == digest else { throw Self.issue() }
            let result = try request.run()
            guard active, request.healthy(), resolver.current(), request.sourceSHA256() == digest else { throw Self.issue() }
            let bytes = try Self.launchBundle(source: source, digest: digest, ownerID: resolver.ownerID(), envelope: result)
            guard active, request.healthy() else { throw Self.issue() }
            launch[source.slot] = bytes
        }
        lock.lock(); succeeded = !canceled; let valid = succeeded; lock.unlock()
        guard valid, healthy() else { throw Self.issue() }
        return launch
    }

    private var active: Bool { lock.lock(); defer { lock.unlock() }; return !canceled }

    func healthy() -> Bool {
        lock.lock(); let live = !canceled && succeeded; let captured = requests; let dns = resolvers; lock.unlock()
        return live && captured.allSatisfy { $0.healthy() } && dns.allSatisfy { $0.current() }
    }

    func cancel() {
        lock.lock(); canceled = true; let captured = requests; let dns = resolvers; lock.unlock()
        for request in captured { request.cancel() }
        for resolver in dns { resolver.beginCancel() }
    }

    /// Close joins the actual Run worker, native cancellation and DNS-SD
    /// deallocation. The caller retains this owner until Close returns.
    func close() {
        cancel()
        operation.lock(); defer { operation.unlock() }
        lock.lock(); let captured = requests; let dns = resolvers; lock.unlock()
        for request in captured { request.close() }
        for resolver in dns { resolver.cancel() }
        lock.lock(); requests.removeAll(); resolvers.removeAll(); lock.unlock()
    }

    private static func launchBundle(source: IOSMAXSourceSelection.Source, digest: String, ownerID: String,
                                     envelope: String) throws -> Data {
        guard !envelope.isEmpty, envelope.utf8.count <= 24 * 1024 * 1024,
              let body = try JSONSerialization.jsonObject(with: Data(envelope.utf8)) as? [String: Any],
              Set(body.keys) == ["schema", "owner_id", "source_sha256", "hostname", "endpoint", "config_json", "files_json", "metadata_json"],
              body["schema"] as? Int == 1, body["source_sha256"] as? String == digest,
              body["owner_id"] as? String == ownerID, body["hostname"] as? String == source.input.endpoint,
              let endpoint = body["endpoint"] as? String, !hostname(endpoint),
              let filesJSON = body["files_json"] as? String, filesJSON.utf8.count <= 16 * 1024 * 1024,
              let metadataJSON = body["metadata_json"] as? String, metadataJSON.utf8.count <= 16384,
              let config = body["config_json"] as? String, !config.isEmpty, config.utf8.count <= IOSNativeMAXProfile.maxGraphBytes,
              let encoded = try JSONSerialization.jsonObject(with: Data(filesJSON.utf8)) as? [String: String],
              var expectedMetadata = try JSONSerialization.jsonObject(with: Data(source.input.metadataJSON.utf8)) as? [String: Any],
              let metadata = try JSONSerialization.jsonObject(with: Data(metadataJSON.utf8)) as? [String: Any] else { throw issue() }
        expectedMetadata["endpoint"] = endpoint
        guard try equal(metadata, expectedMetadata) else { throw issue() }
        let assets = try IOSNativeMAXProfile.decode(mode: source.input.mode, encoded: encoded)
        guard Set(assets.keys) == Set(source.input.assets.keys) else { throw issue() }
        let outer = source.input.mode.hasPrefix("max-tls-") ? "outer-xray.json" : "middle-sing-box.json"
        for (name, data) in source.input.assets where name != outer {
            guard assets[name] == data else { throw issue() }
        }
        guard let oldOuter = source.input.assets[outer], let newOuter = assets[outer],
              var expected = try JSONSerialization.jsonObject(with: oldOuter) as? [String: Any],
              var outputs = expected["outbounds"] as? [[String: Any]],
              let actual = try JSONSerialization.jsonObject(with: newOuter) as? [String: Any] else { throw issue() }
        var changed = 0
        for index in outputs.indices {
            if source.input.mode.hasPrefix("max-tls-") {
                guard var settings = outputs[index]["settings"] as? [String: Any],
                      var remotes = settings["vnext"] as? [[String: Any]], remotes.count == 1,
                      remotes[0]["address"] as? String == source.input.endpoint else { throw issue() }
                remotes[0]["address"] = endpoint; settings["vnext"] = remotes; outputs[index]["settings"] = settings; changed += 1
            } else if outputs[index]["tag"] as? String == "outer" {
                guard outputs[index]["server"] as? String == source.input.endpoint,
                      outputs[index]["type"] as? String == "hysteria2", var tls = outputs[index]["tls"] as? [String: Any] else { throw issue() }
                if tls["server_name"] == nil || tls["server_name"] as? String == "" { tls["server_name"] = source.input.endpoint }
                outputs[index]["tls"] = tls; outputs[index]["server"] = endpoint; changed += 1
            }
        }
        expected["outbounds"] = outputs
        guard changed == 1, try equal(expected, actual) else { throw issue() }
        var root = try IOSMAXSourceSelection.object(source.bundle)
        var profile = try IOSMAXSourceSelection.profile(root)
        guard profile["id"] as? String == source.selectedID, profile["endpoint"] as? String == source.input.endpoint,
              var profiles = root["profiles"] as? [String: Any], var nodes = root["routerProfiles"] as? [[String: Any]],
              let selected = nodes.firstIndex(where: { $0["id"] as? String == source.selectedID }) else { throw issue() }
        profile["endpoint"] = endpoint
        var compilationProfile = profile; compilationProfile["node_proof_id"] = source.input.nodeID
        let compiled = try IOSNativeMAXProfile.compile(mode: source.input.mode, encoded: encoded, nodeID: source.input.nodeID,
            profile: compilationProfile, startLayer: source.input.startLayer) { mode, files, metadata in
                var failure: NSError?
                let value: String? = LibboxRouterCompileMAXProfile(mode, files, metadata, &failure)
                guard failure == nil, let value else { throw issue() }; return value
            }
        guard compiled["sing-box.json"] == Data(config.utf8) else { throw issue() }
        profiles[source.input.mode] = encoded; root["profiles"] = profiles
        nodes[selected] = profile; root["routerProfiles"] = nodes
        let bytes = try JSONSerialization.data(withJSONObject: root, options: [.sortedKeys])
        guard bytes.count <= 32 * 1024 * 1024 else { throw issue() }
        return bytes
    }

    private static func equal(_ left: Any, _ right: Any) throws -> Bool {
        try JSONSerialization.data(withJSONObject: left, options: [.sortedKeys]) == JSONSerialization.data(withJSONObject: right, options: [.sortedKeys])
    }

    static func issue() -> NSError {
        NSError(domain: "RouterVPN.MAXPreparation", code: 1, userInfo: [NSLocalizedDescriptionKey:
            "MAX preparation failed its captured source, resolver or pending session check."])
    }
}

/// Serializes prestart adoption with Stop. Native proof may finish while the
/// adoption closure is still running; completion waits for DNS/Run retirement.
final class RouterVPNMAXStart: @unchecked Sendable {
    private let preparation: RouterVPNMAXPreparation
    private let queue = DispatchQueue(label: "routervpn.max.prestart", qos: .userInitiated)
    private let lock = NSLock()
    private var canceled = false
    private var drained = false
    private var received = false
    private var pendingError: Error?
    private var completion: ((RouterVPNMAXStart, Error?) -> Void)?
    private var launched = false
    init(preparation: RouterVPNMAXPreparation, completion: @escaping (RouterVPNMAXStart, Error?) -> Void) {
        self.preparation = preparation; self.completion = completion
    }
    var current: Bool { lock.lock(); defer { lock.unlock() }; return !canceled }

    private final class Work: @unchecked Sendable {
        let adopt: ([String: Any], RouterVPNMAXPreparation, @escaping (Error?) -> Void) throws -> Void
        init(_ adopt: @escaping ([String: Any], RouterVPNMAXPreparation, @escaping (Error?) -> Void) throws -> Void) { self.adopt = adopt }
    }
    func start(adopt: @escaping ([String: Any], RouterVPNMAXPreparation, @escaping (Error?) -> Void) throws -> Void) {
        let work = Work(adopt)
        lock.lock()
        guard !launched, !canceled else { lock.unlock(); receive(RouterVPNMAXPreparation.issue()); return }
        launched = true
        // Queue admission and cancellation share the lock. A Stop that wins
        // before this point cannot be followed by a newly admitted Run worker.
        queue.async { [self] in
            do {
                let launch = try preparation.run()
                guard current, preparation.healthy() else { throw RouterVPNMAXPreparation.issue() }
                try work.adopt(launch, preparation, { [self] error in receive(error) })
                guard current, preparation.healthy() else { throw RouterVPNMAXPreparation.issue() }
            } catch { receive(RouterVPNMAXPreparation.issue()) }
            preparation.close()
            lock.lock(); drained = true; lock.unlock()
            publishIfReady()
        }
        lock.unlock()
    }
    private func receive(_ error: Error?) {
        lock.lock()
        // A preparation failure overrides an early successful proof until the
        // adoption worker has joined; after publication the callback is gone.
        if !received || error != nil { received = true; pendingError = error }
        lock.unlock(); publishIfReady()
    }
    private func publishIfReady() {
        lock.lock()
        guard drained, received, let callback = completion else { lock.unlock(); return }
        completion = nil
        let failure = canceled ? RouterVPNMAXPreparation.issue() : pendingError
        lock.unlock(); callback(self, failure)
    }
    func cancel() {
        lock.lock(); canceled = true; lock.unlock()
        preparation.cancel(); receive(RouterVPNMAXPreparation.issue())
    }
    private final class Drain: @unchecked Sendable {
        let action: () -> Void
        init(_ action: @escaping () -> Void) { self.action = action }
    }
    func cancelAndDrain(_ completion: @escaping () -> Void) {
        cancel()
        let delivery = Drain(completion)
        lock.lock()
        queue.async { [self] in
            preparation.close()
            lock.lock(); drained = true; lock.unlock()
            publishIfReady(); delivery.action()
        }
        lock.unlock()
    }
}
