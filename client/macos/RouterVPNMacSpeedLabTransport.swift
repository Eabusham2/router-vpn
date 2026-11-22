import Foundation
import CoreFoundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

// Both the display model and transport must recognize the same measured public
// hops. The controller verifies the private source seals against the live owner.
enum RouterVPNSelectedPublicInventory {
    static let fields: Set<String> = ["schema", "source_sha256", "config_sha256", "generation_sha256", "selected_execution", "nodes"]
    static func valid(_ capture: [String: Any], nodes: [[String: Any]]) -> Bool {
        let positions = nodes.indices.filter { nodes[$0]["kind"] as? String == "public-path" }
        guard positions.allSatisfy({ $0 > 0 && $0 < nodes.count - 1 }) else { return false }
        guard capture.keys.contains("multiple_imported") else {
            return Set(capture.keys) == fields && positions.allSatisfy { $0 == nodes.count - 2 }
        }
        func integer(_ value: Any?, _ expected: Int) -> Bool {
            guard let n = value as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID() else { return false }
            return n.doubleValue == Double(expected)
        }
        func digest(_ value: Any?) -> Bool {
            guard let s = value as? String else { return false }
            return s.utf8.count == 64 && s.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
        }
        guard Set(capture.keys) == fields.union(["multiple_imported"]),
              let original = capture["multiple_imported"] as? [String: Any],
              Set(original.keys) == Set(["schema", "original_source_sha256", "public"]),
              integer(original["schema"], 6), digest(original["original_source_sha256"]),
              let rows = original["public"] as? [[String: Any]], rows.count == positions.count,
              positions.contains(where: { $0 < nodes.count - 2 }) else { return false }
        return zip(rows, positions).allSatisfy { row, position in
            guard Set(row.keys) == Set(["position", "tag", "source_sha256"]),
                  integer(row["position"], position), digest(row["source_sha256"]),
                  let tag = row["tag"] as? String, !tag.isEmpty, tag.utf8.count <= 128,
                  tag.utf8.allSatisfy({ (33...126).contains($0) }) else { return false }
            return true
        }
    }
}

// One object owns one loopback request. Close/Cancel never invalidate a newer
// dialog's session; the controller also checks its captured generation.
final class RouterVPNMacSpeedLabTransport: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var session: URLSession?
    private var task: URLSessionDataTask?
    private var data = Data()
    private var status = 0
    private var failure: Error?
    private var completion: ((Result<Data, Error>) -> Void)?
    private var finished = false
    private static let limit = 2 * 1024 * 1024

    init(url: URL, body: [String: Any]?, timeout: TimeInterval, completion: @escaping (Result<Data, Error>) -> Void) throws {
        let savedBase = "/api/multihop/saved-candidates"
        let candidateBase = url.path == savedBase || url.path.hasPrefix(savedBase + "/") ? savedBase : "/api/multihop/prefix-candidates"
        let prefixCatalog = candidateBase == savedBase && url.query?.range(of: "^prefix_position=[0-7]&scope=saved-prefix-local$", options: .regularExpression) != nil
        let candidateCatalog = url.path == candidateBase + "/catalog" && (prefixCatalog || url.query?.range(of: "^prefix_position=[0-7]$", options: .regularExpression) != nil)
        let candidateStatus = url.path == candidateBase && url.query?.range(of: "^request_id=[a-f0-9]{32}$", options: .regularExpression) != nil
        let orderedBase = "/api/speed-lab/ordered-latency"
        let orderedStatus = url.path == orderedBase && url.query?.range(of: "^request_id=[a-f0-9]{32}$", options: .regularExpression) != nil
        guard url.scheme == "http", url.host == "127.0.0.1", url.user == nil, url.password == nil,
              ["/api/speed-lab/options", "/api/speed-lab/run", "/api/profile/fastest",
               "/api/profiles", "/api/multihop/status", "/api/connection/live-latency",
               "/api/connection/speed-test", "/api/profile/latency", "/api/multihop/speed-test",
               candidateBase, candidateBase + "/catalog", candidateBase + "/cancel", candidateBase + "/save-profile",
               orderedBase, orderedBase + "/cancel"].contains(url.path), (url.query == nil || candidateCatalog || candidateStatus || orderedStatus), url.fragment == nil else {
            throw NSError(domain: "RouterVPNSpeedLab", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid local Speed Lab endpoint."])
        }
        if url.path == "/api/profile/fastest" {
            guard timeout.isFinite, timeout > 0, timeout <= 185, let body,
                  Set(body.keys) == Set(["samples", "select"]),
                  (body["samples"] as? NSNumber)?.doubleValue == 50,
                  let selected = body["select"] as? NSNumber,
                  CFGetTypeID(selected) == CFBooleanGetTypeID(), selected.boolValue else {
                throw NSError(domain: "RouterVPNSpeedLab", code: 1, userInfo: [NSLocalizedDescriptionKey: "Fastest requires a bounded 50-sample selection request."])
            }
        }
        // Performance uses this same owned transport, with explicit bounded
        // schemas. Adding read/measurement endpoints does not grant mutation API access.
        func bounded(_ maximum: TimeInterval) -> Bool { timeout.isFinite && timeout > 0 && timeout <= maximum }
        func number(_ key: String, equals expected: Double) -> Bool {
            guard let value = body?[key] as? NSNumber, CFGetTypeID(value) != CFBooleanGetTypeID() else { return false }
            return value.doubleValue == expected
        }
        func identifier(_ key: String) -> String? {
            guard let value = body?[key] as? String, !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return nil }
            return value
        }
        let performanceValid: Bool
        switch url.path {
        case orderedBase, orderedBase + "/cancel":
            if body == nil {
                performanceValid = url.path == orderedBase && (url.query == nil || orderedStatus) && bounded(6)
            } else {
                let capture = body?["capture"] as? [String: Any] ?? [:]
                let text: (Any?, Int) -> Bool = { value, limit in
                    guard let value = value as? String else { return false }
                    return !value.isEmpty && value.utf8.count <= limit && !value.unicodeScalars.contains { $0.value < 32 || $0.value == 127 }
                }
                let hex: (Any?, Int) -> Bool = { value, count in
                    guard let value = value as? String else { return false }
                    return value.utf8.count == count && value.range(of: "^[a-f0-9]+$", options: .regularExpression) != nil
                }
                let session = capture["session_id"] as? String ?? ""
                let position = body?["position"] as? NSNumber
                let ordinaryKeys = Set(["session_id", "profile_id", "profile_token", "source_sha256", "config_sha256", "generation_sha256"])
                func selectedCaptureValid() -> Bool {
                    if !capture.keys.contains("selected_capture") { return Set(capture.keys) == ordinaryKeys }
                    guard Set(capture.keys) == ordinaryKeys.union(["selected_capture"]),
                          let raw = capture["selected_capture"] as? String, !raw.isEmpty, raw.utf8.count <= 8192,
                          let data = raw.data(using: .utf8),
                          let selected = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                          let schema = selected["schema"] as? NSNumber, CFGetTypeID(schema) != CFBooleanGetTypeID(), schema.doubleValue == 1,
                          ["source_sha256", "config_sha256", "generation_sha256"].allSatisfy({ selected[$0] as? String == capture[$0] as? String }),
                          let execution = selected["selected_execution"] as? String, ["local", "server"].contains(execution),
                          let nodes = selected["nodes"] as? [[String: Any]], (2...8).contains(nodes.count),
                          RouterVPNSelectedPublicInventory.valid(selected, nodes: nodes), let position,
                          CFGetTypeID(position) != CFBooleanGetTypeID(), position.doubleValue.rounded() == position.doubleValue,
                          nodes.indices.contains(position.intValue), nodes[position.intValue]["node_id"] as? String == body?["node_id"] as? String else { return false }
                    var ids = Set<String>()
                    for (index, node) in nodes.enumerated() {
                        let role = index == 0 ? "entry" : index == nodes.count-1 ? "exit" : "intermediate"
                        guard Set(node.keys) == Set(["node_id", "position", "role", "kind"]), text(node["node_id"], 128),
                              let id = node["node_id"] as? String, ids.insert(id).inserted,
                              let capturedPosition = node["position"] as? NSNumber, CFGetTypeID(capturedPosition) != CFBooleanGetTypeID(),
                              capturedPosition.doubleValue == Double(index), node["role"] as? String == role,
                              let kind = node["kind"] as? String,
                              kind == "private-node" || kind == "public-path" else { return false }
                    }
                    return true
                }
                performanceValid = url.query == nil && bounded(6) && Set(body!.keys) == Set(["capture", "node_id", "position", "request_id"]) &&
                    selectedCaptureValid() &&
                    session.utf8.count <= 64 && session.range(of: "^session-[0-9]+-[0-9]+$", options: .regularExpression) != nil &&
                    text(capture["profile_id"], 128) && ["profile_token", "source_sha256", "config_sha256", "generation_sha256"].allSatisfy({ hex(capture[$0], 64) }) &&
                    text(body?["node_id"], 128) && hex(body?["request_id"], 32) && position != nil && CFGetTypeID(position!) != CFBooleanGetTypeID() &&
                    position!.doubleValue.rounded() == position!.doubleValue && (0...7).contains(position!.intValue)
            }
        case candidateBase + "/catalog": performanceValid = candidateCatalog && body == nil && bounded(25)
        case candidateBase, candidateBase + "/cancel", candidateBase + "/save-profile":
            func token(_ key: String, _ count: Int) -> Bool { guard let id = identifier(key) else {return false};return id.utf8.count == count && id.range(of:"^[a-f0-9]+$",options:.regularExpression) != nil }
            let suppliedKeys = Set(body?.keys.map { $0 } ?? [])
            if suppliedKeys.contains("scope") {
                guard candidateBase == savedBase, let scope=body?["scope"] as? String, ["saved-prefix-local","saved-complete-local"].contains(scope) else {
                    throw NSError(domain:"RouterVPNSpeedLab",code:1,userInfo:[NSLocalizedDescriptionKey:"Invalid saved candidate purpose."])
                }
            }
            let keys = suppliedKeys.subtracting(["scope"])
            let original = token("request_id",32)
            if url.path == candidateBase + "/cancel" {
                let saved = candidateBase == savedBase
                performanceValid = original && (!saved || token("view_token",64)) && keys == (saved ? Set(["request_id","view_token"]) : Set(["request_id"])) && bounded(25)
            } else if url.path == candidateBase && body == nil {
                performanceValid = candidateStatus && bounded(25)
            } else if url.path == candidateBase {
                let ids = body?["candidate_ids"] as? [String] ?? []
                let position = body?["prefix_position"] as? NSNumber
                performanceValid = url.query == nil && original && token("view_token",64) && keys == Set(["request_id","view_token","prefix_position","candidate_ids","samples"]) && number("samples",equals:50) && bounded(180) &&
                    position != nil && CFGetTypeID(position!) != CFBooleanGetTypeID() && position!.doubleValue.rounded() == position!.doubleValue && (0...7).contains(position!.intValue) &&
                    !ids.isEmpty && ids.count <= 64 && Set(ids).count == ids.count && ids.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 128 })
            } else {
                let nodes = body?["proposed_path"] as? [[String:Any]] ?? []
                let name = identifier("name") ?? ""
                performanceValid = original && token("view_token",64) && identifier("candidate_id") != nil && keys == Set(["request_id","view_token","candidate_id","name","proposed_path"]) && bounded(25) &&
                    !name.isEmpty && name.utf8.count <= 64 && (2...8).contains(nodes.count) && nodes.allSatisfy { node in
                        Set(node.keys) == Set(["id","mode"]) && !(node["id"] as? String ?? "").isEmpty && ["wg","awg2-fast","awg2-strong","shadowsocks"].contains(node["mode"] as? String ?? "")
                    }
            }
        case "/api/profiles", "/api/multihop/status": performanceValid = body == nil && bounded(5)
        case "/api/connection/live-latency": performanceValid = Set(body?.keys.map { $0 } ?? []) == Set(["samples"]) && number("samples", equals: 5) && bounded(12)
        case "/api/connection/speed-test": performanceValid = Set(body?.keys.map { $0 } ?? []) == Set(["bytes"]) && number("bytes", equals: 8388608) && bounded(45)
        case "/api/profile/latency": performanceValid = Set(body?.keys.map { $0 } ?? []) == Set(["id", "samples"]) && identifier("id") != nil && number("samples", equals: 50) && bounded(180)
        case "/api/multihop/speed-test":
            let keys = Set(body?.keys.map { $0 } ?? [])
            let pair = keys == Set(["entry_id", "exit_id", "bytes"]) && number("bytes", equals: 4194304) && bounded(70)
            let ordered = keys == Set(["entry_id", "exit_id", "bytes", "ordered_capture"]) &&
                identifier("ordered_capture")?.utf8.count == 64 && identifier("ordered_capture")?.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil && number("bytes", equals: 8388608) && bounded(100)
            performanceValid = identifier("entry_id") != nil && identifier("exit_id") != nil && identifier("entry_id") != identifier("exit_id") && (pair || ordered)
        default: performanceValid = true
        }
        guard performanceValid else {
            throw NSError(domain: "RouterVPNSpeedLab", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid bounded Performance request."])
        }
        var request = URLRequest(url: url)
        request.httpMethod = body == nil ? "GET" : "POST"
        request.timeoutInterval = timeout
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let body { request.httpBody = try JSONSerialization.data(withJSONObject: body); request.setValue("application/json", forHTTPHeaderField: "Content-Type") }
        try RouterVPNMacLocalAuthorization.shared.authorize(&request)
        self.completion = completion
        super.init()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.connectionProxyDictionary = [:]
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.timeoutIntervalForRequest = timeout
        configuration.timeoutIntervalForResource = timeout
        let queue = OperationQueue(); queue.maxConcurrentOperationCount = 1
        let session = URLSession(configuration: configuration, delegate: self, delegateQueue: queue)
        self.session = session
        task = session.dataTask(with: request)
    }

    func start() { lock.lock(); let owned = finished ? nil : task; lock.unlock(); owned?.resume() }

    func cancel() {
        lock.lock(); let owned = finished ? nil : task; lock.unlock()
        owned?.cancel()
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        lock.lock()
        guard !finished else { lock.unlock(); completionHandler(.cancel); return }
        status = (response as? HTTPURLResponse)?.statusCode ?? 0
        let oversized = response.expectedContentLength > Int64(Self.limit)
        if oversized { failure = NSError(domain: "RouterVPNSpeedLab", code: 2, userInfo: [NSLocalizedDescriptionKey: "Speed Lab response exceeded its size limit."]) }
        lock.unlock()
        completionHandler(oversized ? .cancel : .allow)
        // A rejected response already has a terminal result. Complete the
        // captured owner once even if Foundation defers its cancellation event.
        if oversized { finish(nil, cancelOwnedTask: true) }
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive bytes: Data) {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        let oversized = data.count > Self.limit - bytes.count
        if oversized { failure = NSError(domain: "RouterVPNSpeedLab", code: 2, userInfo: [NSLocalizedDescriptionKey: "Speed Lab response exceeded its size limit."]) }
        else { data.append(bytes) }
        lock.unlock()
        if oversized { finish(nil, cancelOwnedTask: true) }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        finish(error, cancelOwnedTask: false)
    }

    private func finish(_ error: Error?, cancelOwnedTask: Bool) {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        finished = true
        let callback = completion; completion = nil
        let response = data; data.removeAll(keepingCapacity: false)
        let explicitError = failure ?? error
        let code = status
        let ownedTask = task; let ownedSession = session
        self.task = nil; self.session = nil
        lock.unlock()
        if cancelOwnedTask { ownedTask?.cancel(); ownedSession?.invalidateAndCancel() }
        else { ownedSession?.finishTasksAndInvalidate() }
        let result: Result<Data, Error>
        if let explicitError { result = .failure(explicitError) }
        else if !(200..<300).contains(code) {
            let message = String(data: response.prefix(4096), encoding: .utf8) ?? "Local controller request failed."
            result = .failure(NSError(domain: "RouterVPNSpeedLab", code: code, userInfo: [NSLocalizedDescriptionKey: message]))
        } else { result = .success(response) }
        callback?(result)
    }
}
