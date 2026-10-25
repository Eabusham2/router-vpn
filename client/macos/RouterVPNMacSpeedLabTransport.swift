import Foundation
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
        guard url.scheme == "http", url.host == "127.0.0.1", url.user == nil, url.password == nil,
              ["/api/speed-lab/options", "/api/speed-lab/run"].contains(url.path), url.query == nil, url.fragment == nil else {
            throw NSError(domain: "RouterVPNSpeedLab", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid local Speed Lab endpoint."])
        }
        var request = URLRequest(url: url)
        request.httpMethod = body == nil ? "GET" : "POST"
        request.timeoutInterval = timeout
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let body { request.httpBody = try JSONSerialization.data(withJSONObject: body); request.setValue("application/json", forHTTPHeaderField: "Content-Type") }
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
        status = (response as? HTTPURLResponse)?.statusCode ?? 0
        let oversized = response.expectedContentLength > Int64(Self.limit)
        if oversized { failure = NSError(domain: "RouterVPNSpeedLab", code: 2, userInfo: [NSLocalizedDescriptionKey: "Speed Lab response exceeded its size limit."]) }
        lock.unlock()
        completionHandler(oversized ? .cancel : .allow)
        // Explicit cancellation also drives the owned task's completion on
        // Foundation implementations that leave a rejected response suspended.
        if oversized { dataTask.cancel() }
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive bytes: Data) {
        lock.lock()
        let oversized = data.count > Self.limit - bytes.count
        if oversized { failure = NSError(domain: "RouterVPNSpeedLab", code: 2, userInfo: [NSLocalizedDescriptionKey: "Speed Lab response exceeded its size limit."]) }
        else { data.append(bytes) }
        lock.unlock()
        if oversized { dataTask.cancel() }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        finished = true
        let callback = completion; completion = nil
        let response = data; data.removeAll(keepingCapacity: false)
        let explicitError = failure ?? error
        let code = status
        self.task = nil; self.session = nil
        lock.unlock()
        session.finishTasksAndInvalidate()
        let result: Result<Data, Error>
        if let explicitError { result = .failure(explicitError) }
        else if !(200..<300).contains(code) {
            let message = String(data: response.prefix(4096), encoding: .utf8) ?? "Local controller request failed."
            result = .failure(NSError(domain: "RouterVPNSpeedLab", code: code, userInfo: [NSLocalizedDescriptionKey: message]))
        } else { result = .success(response) }
        callback?(result)
    }
}
