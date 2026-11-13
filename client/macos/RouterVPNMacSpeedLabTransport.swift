import Foundation
import CoreFoundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

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
        let candidateCatalog = url.path == candidateBase + "/catalog" && url.query?.range(of: "^prefix_position=[0-7]$", options: .regularExpression) != nil
        let candidateStatus = url.path == candidateBase && url.query?.range(of: "^request_id=[a-f0-9]{32}$", options: .regularExpression) != nil
        guard url.scheme == "http", url.host == "127.0.0.1", url.user == nil, url.password == nil,
              ["/api/speed-lab/options", "/api/speed-lab/run", "/api/profile/fastest",
               "/api/profiles", "/api/multihop/status", "/api/connection/live-latency",
               "/api/connection/speed-test", "/api/profile/latency", "/api/multihop/speed-test",
               candidateBase, candidateBase + "/catalog", candidateBase + "/cancel", candidateBase + "/save-profile"].contains(url.path), (url.query == nil || candidateCatalog || candidateStatus), url.fragment == nil else {
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
        case candidateBase + "/catalog": performanceValid = candidateCatalog && body == nil && bounded(25)
        case candidateBase, candidateBase + "/cancel", candidateBase + "/save-profile":
            func token(_ key: String, _ count: Int) -> Bool { guard let id = identifier(key) else {return false};return id.utf8.count == count && id.range(of:"^[a-f0-9]+$",options:.regularExpression) != nil }
            let keys = Set(body?.keys.map { $0 } ?? [])
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
