import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

struct RouterVPNMacMTUReply {
    let code: Int
    let data: Data
}

protocol RouterVPNMacMTURequest: AnyObject {
    func start()
    func cancel()
}

// Each task owns its delegate, response buffer and cancellation. No shared
// URLSession can invalidate another window's Retest or a replacement request.
final class RouterVPNMacMTUTransport: NSObject, RouterVPNMacMTURequest, URLSessionDataDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var session: URLSession?
    private var task: URLSessionDataTask?
    private var data = Data()
    private var code = 0
    private var failure: Error?
    private var completion: ((Result<RouterVPNMacMTUReply, Error>) -> Void)?
    private var finished = false
    private static let limit = 2 * 1024 * 1024

    static func validRequestID(_ value: String) -> Bool {
        value.utf8.count == 32 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }

    private static func identity(_ value: Any?) -> Bool {
        guard let text = value as? String, !text.isEmpty, text.utf8.count <= 128 else { return false }
        return !text.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
    }

    init(url: URL, body: [String: Any]?, timeout: TimeInterval,
         completion: @escaping (Result<RouterVPNMacMTUReply, Error>) -> Void) throws {
        func invalid() -> NSError {
            NSError(domain: "RouterVPNMTU", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid captured local MTU request."])
        }
        guard url.scheme == "http", url.host == "127.0.0.1", url.user == nil, url.password == nil,
              url.fragment == nil, let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              timeout > 0, timeout <= 150 else { throw invalid() }
        if url.path == "/api/mtu/status" {
            guard body == nil else { throw invalid() }
            let items = components.queryItems ?? []
            let names = items.map { $0.name }
            guard Set(names).count == names.count, Set(names).isSubset(of: ["request_id", "session_id"]) else { throw invalid() }
            let fields = Dictionary(uniqueKeysWithValues: items.map { ($0.name, $0.value ?? "") })
            if let sessionID = fields["session_id"], !Self.identity(sessionID) { throw invalid() }
            if let requestID = fields["request_id"], (!Self.validRequestID(requestID) || fields["session_id"] == nil) { throw invalid() }
        } else {
            guard ["/api/mtu/retest", "/api/mtu/cancel"].contains(url.path), url.query == nil,
                  let body, let requestID = body["request_id"] as? String, Self.validRequestID(requestID),
                  Self.identity(body["session_id"]) else { throw invalid() }
            let keys: Set<String> = url.path == "/api/mtu/retest" ? ["request_id", "session_id", "profile_id"] : ["request_id", "session_id"]
            guard Set(body.keys) == keys else { throw invalid() }
            if url.path == "/api/mtu/retest", !Self.identity(body["profile_id"]) { throw invalid() }
        }
        var request = URLRequest(url: url)
        request.httpMethod = body == nil ? "GET" : "POST"
        request.timeoutInterval = timeout
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let body {
            request.httpBody = try JSONSerialization.data(withJSONObject: body)
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
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
    func cancel() { lock.lock(); let owned = finished ? nil : task; lock.unlock(); owned?.cancel() }

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        lock.lock()
        guard !finished else { lock.unlock(); completionHandler(.cancel); return }
        code = (response as? HTTPURLResponse)?.statusCode ?? 0
        let oversized = response.expectedContentLength > Int64(Self.limit)
        if oversized { failure = Self.sizeError() }
        lock.unlock()
        completionHandler(oversized ? .cancel : .allow)
        if oversized { finish(nil, cancelOwnedTask: true) }
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive bytes: Data) {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        let oversized = data.count > Self.limit - bytes.count
        if oversized { failure = Self.sizeError() } else { data.append(bytes) }
        lock.unlock()
        if oversized { finish(nil, cancelOwnedTask: true) }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        finish(error, cancelOwnedTask: false)
    }

    private static func sizeError() -> NSError {
        NSError(domain: "RouterVPNMTU", code: 2, userInfo: [NSLocalizedDescriptionKey: "MTU response exceeded its size limit."])
    }

    private func finish(_ error: Error?, cancelOwnedTask: Bool) {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        finished = true
        let callback = completion; completion = nil
        let reply = RouterVPNMacMTUReply(code: code, data: data); data.removeAll(keepingCapacity: false)
        let explicitError = failure ?? error
        let ownedTask = task; let ownedSession = session
        task = nil; session = nil
        lock.unlock()
        if cancelOwnedTask { ownedTask?.cancel(); ownedSession?.invalidateAndCancel() }
        else { ownedSession?.finishTasksAndInvalidate() }
        if let explicitError { callback?(.failure(explicitError)) } else { callback?(.success(reply)) }
    }
}
