import Foundation
#if canImport(Security)
import Security
#endif

// The adapter is provided only by PacketTunnel's through-tunnel connection API.
// The executable fixture supplies a delayed socket boundary to exercise joins.
enum RouterVPNTelemetryConnectionState: Sendable { case connected, cancelled, failed }
protocol RouterVPNTelemetryConnection: AnyObject, Sendable {
    func observe(_ update: @escaping @Sendable (RouterVPNTelemetryConnectionState) -> Void)
    func write(_ data: Data, completion: @escaping @Sendable (Error?) -> Void)
    func read(_ maximum: Int, completion: @escaping @Sendable (Data?, Error?) -> Void)
    func cancel()
    func retire()
}

/// Queue-confined, bounded HTTP/1.1. Completion means all issued I/O callbacks
/// and the native cancelled event have joined, including a timeout or failure.
final class RouterVPNTelemetryTransport: @unchecked Sendable {
    struct Response: Sendable { let wire: Data; let bytes: Int; let seconds: Double }
    typealias Completion = @Sendable (Result<Response, Error>) -> Void
    private let queue: DispatchQueue
    private let connection: RouterVPNTelemetryConnection
    private let headers: Data
    private let uploadBytes: Int
    private let bodyLimit: Int
    private let expectedBytes: Int?
    private let keepBody: Bool
    private let deadlineSeconds: Double
    private var completion: Completion?
    private var deadline: DispatchSourceTimer?
    private var outcome: Result<Response, Error>?
    private var nativeCancelled = false
    private var started = false
    private var pendingIO = 0
    private var sent = 0
    private var received = 0
    private var head = Data()
    private var body = Data()
    private var contentLength: Int?
    private var startedAt: UInt64 = 0

    init(queue: DispatchQueue, connection: RouterVPNTelemetryConnection, headers: Data,
         uploadBytes: Int = 0, bodyLimit: Int, expectedBytes: Int? = nil,
         keepBody: Bool = true, timeout: Double, completion: @escaping Completion) {
        self.queue = queue; self.connection = connection; self.headers = headers
        self.uploadBytes = uploadBytes; self.bodyLimit = bodyLimit; self.expectedBytes = expectedBytes
        self.keepBody = keepBody; self.deadlineSeconds = timeout; self.completion = completion
    }
    func start() {
        startedAt = DispatchTime.now().uptimeNanoseconds
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + deadlineSeconds)
        timer.setEventHandler { [weak self] in self?.finish(.failure(IOSTelemetryProtocol.issue("The private-node transfer timed out."))) }
        deadline = timer; timer.resume()
        connection.observe { [self] state in queue.async { [self] in
            switch state {
            case .connected:
                guard outcome == nil, !started else { return }; started = true
                write(headers) { [self] in writeBody() }
            case .failed: finish(.failure(IOSTelemetryProtocol.issue("The captured tunnel connection failed.")))
            case .cancelled:
                nativeCancelled = true
                if outcome == nil { finish(.failure(CancellationError())) }
                deliver()
            }
        } }
    }
    func cancel() { finish(.failure(CancellationError())) }

    private func write(_ data: Data, next: @escaping @Sendable () -> Void) {
        guard outcome == nil else { deliver(); return }
        pendingIO += 1
        connection.write(data) { [self] error in queue.async { [self] in
            pendingIO -= 1
            if outcome == nil {
                if let error { finish(.failure(error)) } else { next() }
            }
            deliver()
        } }
    }
    private func writeBody() {
        guard outcome == nil else { return }
        guard sent < uploadBytes else { read(); return }
        let count = min(64 << 10, uploadBytes - sent)
        var bytes = Data(count: count)
        #if canImport(Security)
        let status = bytes.withUnsafeMutableBytes { raw in
            SecRandomCopyBytes(kSecRandomDefault, raw.count, raw.baseAddress!)
        }
        guard status == errSecSuccess else { finish(.failure(IOSTelemetryProtocol.issue("Could not prepare the private upload."))); return }
        #else
        bytes = Data((0..<count).map { _ in UInt8.random(in: .min ... .max) })
        #endif
        sent += count
        write(bytes) { [self] in writeBody() }
    }
    private func read() {
        guard outcome == nil else { return }
        pendingIO += 1
        connection.read(64 << 10) { [self] data, error in queue.async { [self] in
            pendingIO -= 1
            if outcome == nil {
                if let error { finish(.failure(error)) }
                else if let data, !data.isEmpty {
                    do { try consume(data) } catch { finish(.failure(error)) }
                } else { finish(.failure(IOSTelemetryProtocol.issue("The private node ended an incomplete response."))) }
            }
            deliver()
        } }
    }
    private func consume(_ data: Data) throws {
        var payload = data
        if contentLength == nil {
            head.append(data)
            guard let split = head.range(of: Data("\r\n\r\n".utf8)) else {
                guard head.count <= 8192 else { throw IOSTelemetryProtocol.issue("Private response headers exceed their bound.") }
                read(); return
            }
            guard split.lowerBound <= 8192,
                  let text = String(data: head[..<split.lowerBound], encoding: .utf8) else { throw CancellationError() }
            let lines = text.components(separatedBy: "\r\n"), status = (text.components(separatedBy: "\r\n").first ?? "").split(separator: " ")
            guard status.count >= 2, ["HTTP/1.0", "HTTP/1.1"].contains(String(status[0])), status[1] == "200" else {
                throw IOSTelemetryProtocol.issue("The private benchmark was refused; redirects are never followed.")
            }
            var fields: [String: String] = [:]
            for line in lines.dropFirst() {
                guard let colon = line.firstIndex(of: ":"), !line.hasPrefix(" "), !line.hasPrefix("\t") else { throw CancellationError() }
                let key = line[..<colon].lowercased()
                guard fields[key] == nil else { throw IOSTelemetryProtocol.issue("Ambiguous private response headers.") }
                fields[key] = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            }
            guard fields["transfer-encoding"] == nil, fields["content-range"] == nil,
                  fields["content-encoding"] == nil || fields["content-encoding"] == "identity",
                  let length = fields["content-length"].flatMap(Int.init), length >= 0, length <= bodyLimit,
                  expectedBytes == nil || expectedBytes == length else { throw IOSTelemetryProtocol.issue("The private transfer has invalid byte framing.") }
            if keepBody {
                guard fields["content-type"]?.lowercased().hasPrefix("application/json") == true else { throw CancellationError() }
            } else {
                guard fields["content-type"]?.lowercased().hasPrefix("application/octet-stream") == true else { throw CancellationError() }
            }
            payload = Data(head[split.upperBound...]); head = Data(head[..<split.upperBound]); contentLength = length
        }
        guard let contentLength, received + payload.count <= contentLength else { throw IOSTelemetryProtocol.issue("The private transfer exceeded its declared bytes.") }
        received += payload.count
        if keepBody { body.append(payload) }
        if received == contentLength {
            let seconds = Double(DispatchTime.now().uptimeNanoseconds - startedAt) / 1_000_000_000
            guard seconds.isFinite, seconds > 0 else { throw CancellationError() }
            finish(.success(Response(wire: head + body, bytes: received, seconds: seconds)))
        } else { read() }
    }
    private func finish(_ value: Result<Response, Error>) {
        guard outcome == nil else { return }
        outcome = value; deadline?.cancel(); deadline = nil
        connection.cancel()
        deliver()
    }
    private func deliver() {
        guard nativeCancelled, pendingIO == 0, let outcome, let completion else { return }
        self.completion = nil; connection.retire()
        completion(outcome)
    }
}
