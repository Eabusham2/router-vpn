import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

struct RouterVPNMacDNSReply {
    let code: Int
    let data: Data
}

protocol RouterVPNMacDNSRequest: AnyObject {
    func start()
    func cancel()
}

// Each task owns its delegate, response buffer and cancellation. No shared
// URLSession can invalidate another window's Retest or a replacement request.
final class RouterVPNMacDNSTransport: NSObject, RouterVPNMacDNSRequest, URLSessionDataDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var session: URLSession?
    private var task: URLSessionDataTask?
    private var data = Data()
    private var code = 0
    private var failure: Error?
    private var completion: ((Result<RouterVPNMacDNSReply, Error>) -> Void)?
    private var finished = false
    private static let limit = 2 * 1024 * 1024

    static func validRequestID(_ value: String) -> Bool {
        value.utf8.count == 32 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }

    static func validIdentity(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 128 else { return false }
        return value.utf8.allSatisfy { (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || [45,46,95].contains($0) }
    }

    static func validToken(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }

    init(url: URL, body: [String: Any]?, timeout: TimeInterval,
         completion: @escaping (Result<RouterVPNMacDNSReply, Error>) -> Void) throws {
        func invalid() -> NSError {
            NSError(domain: "RouterVPNDNS", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid captured local DNS request."])
        }
        guard url.scheme == "http", url.host == "127.0.0.1", url.user == nil, url.password == nil,
              url.fragment == nil, let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              timeout > 0, timeout <= 30 else { throw invalid() }
        if body == nil {
            guard ["/api/dns/measurement", "/api/status"].contains(url.path) else { throw invalid() }
            let items = components.queryItems ?? []
            guard items.isEmpty || url.path == "/api/dns/measurement" && items.count == 1 && items[0].name == "request_id" && Self.validRequestID(items[0].value ?? "") else { throw invalid() }
        } else if url.path == "/api/dns/policy" {
            guard url.query == nil, let body,
                  Set(body.keys) == ["profile_id", "profile_token", "mode", "protocol", "host", "port", "server_name", "path", "measurement_id", "result_id"] else { throw invalid() }
            let draft = try JSONDecoder().decode(RouterVPNMacDNSDraft.self, from: JSONSerialization.data(withJSONObject: body))
            try draft.validate()
        } else {
            guard url.query == nil, let body,
                  let profile = body["profile_id"] as? String, Self.validIdentity(profile),
                  let token = body["profile_token"] as? String, Self.validToken(token),
                  let session = body["session_id"] as? String, Self.validRequestID(session),
                  let requestID = body["request_id"] as? String, Self.validRequestID(requestID) else { throw invalid() }
            var keys: Set<String> = ["profile_id", "profile_token", "session_id", "request_id"]
            switch url.path {
            case "/api/dns/measurement":
                keys.insert("public_transport")
                guard let value = body["public_transport"] as? String, ["tcp", "tls", "https"].contains(value) else { throw invalid() }
            case "/api/dns/measurement/cancel": break
            case "/api/dns/measurement/select":
                keys.insert("result_id")
                guard let value = body["result_id"] as? String, Self.validIdentity(value) else { throw invalid() }
            default: throw invalid()
            }
            guard Set(body.keys) == keys else { throw invalid() }
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
        NSError(domain: "RouterVPNDNS", code: 2, userInfo: [NSLocalizedDescriptionKey: "DNS response exceeded its size limit."])
    }

    private func finish(_ error: Error?, cancelOwnedTask: Bool) {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        finished = true
        let callback = completion; completion = nil
        let reply = RouterVPNMacDNSReply(code: code, data: data); data.removeAll(keepingCapacity: false)
        let explicitError = failure ?? error
        let ownedTask = task; let ownedSession = session
        task = nil; session = nil
        lock.unlock()
        if cancelOwnedTask { ownedTask?.cancel(); ownedSession?.invalidateAndCancel() }
        else { ownedSession?.finishTasksAndInvalidate() }
        if let explicitError { callback?(.failure(explicitError)) } else { callback?(.success(reply)) }
    }
}
