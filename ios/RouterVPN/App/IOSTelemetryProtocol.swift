import Foundation

/// The app requests a bounded operation, never an address or a private token.
/// Both independent native epochs and the preallocated nonce travel unchanged.
enum IOSTelemetryProtocol {
    static let bytes = 8 << 20
    static let operations: Set<String> = ["telemetry-info", "telemetry-start", "telemetry-status", "telemetry-cancel"]
    struct Command: Decodable, Sendable {
        let operation: String
        let request_id: String
        let session_id: String
        let native_session_id: String
        let node_id: String
        let kind: String
    }
    struct Binding: Equatable, Sendable {
        let request: String
        let providerSession: String
        let nativeSession: String
        let nodeID: String
    }
    struct Result: Codable, Equatable, Sendable {
        let kind: String
        let response_ms: [Double]
        let download_bytes: Int?
        let upload_bytes: Int?
        let download_seconds: Double?
        let upload_seconds: Double?
        let server_receive_ms: Double?
        func validate(kind expected: String) throws {
            guard kind == expected, ["rtt", "speed"].contains(kind), response_ms.count == 2,
                  response_ms.allSatisfy({ $0.isFinite && $0 > 0 && $0 <= 30_000 }) else {
                throw issue("The private node returned an invalid response-time measurement.")
            }
            if kind == "rtt" {
                guard download_bytes == nil, upload_bytes == nil, download_seconds == nil,
                      upload_seconds == nil, server_receive_ms == nil else { throw issue("An RTT reply cannot claim transferred bytes.") }
            } else {
                guard download_bytes == bytes, upload_bytes == bytes,
                      let down = download_seconds, let up = upload_seconds,
                      down.isFinite, down > 0, down <= 90, up.isFinite, up > 0, up <= 90,
                      server_receive_ms.map({ $0.isFinite && $0 >= 0 && $0 <= 90_000 }) ?? true else {
                    throw issue("The private node did not verify both bounded transfers.")
                }
            }
        }
    }
    struct Status: Codable, Sendable {
        let schema: Int
        let request_id: String
        let ack_id: String
        let session_id: String
        let native_session_id: String
        let node_id: String
        let stage: String
        let complete: Bool
        let drained: Bool
        let results: [Result]
        let failure: String?

        var binding: Binding { Binding(request: request_id, providerSession: session_id, nativeSession: native_session_id, nodeID: node_id) }
        static func info(_ data: Data, request: String, node: String) throws -> Self {
            let value = try decode(data)
            guard value.request_id == request, value.node_id == node, value.stage == "ready",
                  !value.complete, value.drained, value.results.isEmpty, value.failure == nil else { throw CancellationError() }
            return value
        }
        static func decode(_ data: Data, binding: Binding? = nil) throws -> Self {
            guard !data.isEmpty, data.count <= 8192 else { throw issue("The tunnel did not return a bounded measurement acknowledgement.") }
            let value = try JSONDecoder().decode(Self.self, from: data)
            guard value.schema == 1, validRequest(value.request_id), value.ack_id == value.request_id,
                  UUID(uuidString: value.session_id) != nil, UUID(uuidString: value.native_session_id) != nil,
                  validNode(value.node_id), value.results.count <= 1,
                  ["ready", "proving", "measuring", "draining", "complete", "cancelled", "failed"].contains(value.stage),
                  value.failure.map({ !$0.isEmpty && $0.utf8.count <= 512 && !$0.contains("\0") }) ?? true,
                  binding == nil || value.binding == binding,
                  value.results.isEmpty || (value.complete && value.drained && value.failure == nil) else { throw CancellationError() }
            return value
        }
        func data() throws -> Data { try JSONEncoder().encode(self) }
    }
    static func command(_ data: Data) throws -> Command {
        guard !data.isEmpty, data.count <= 1024,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == Set(["operation", "request_id", "session_id", "native_session_id", "node_id", "kind"]) else {
            throw issue("Unsupported telemetry message.")
        }
        let value = try JSONDecoder().decode(Command.self, from: data)
        guard operations.contains(value.operation), validRequest(value.request_id), validNode(value.node_id) else { throw CancellationError() }
        if value.operation == "telemetry-info" {
            guard value.session_id.isEmpty, value.native_session_id.isEmpty, value.kind.isEmpty else { throw CancellationError() }
        } else {
            guard UUID(uuidString: value.session_id) != nil, UUID(uuidString: value.native_session_id) != nil,
                  value.operation == "telemetry-start" ? ["rtt", "speed"].contains(value.kind) : value.kind.isEmpty else { throw CancellationError() }
        }
        return value
    }
    static func validRequest(_ value: String) -> Bool { value.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil }
    static func validNode(_ value: String) -> Bool {
        value.range(of: "^[A-Za-z0-9._-]{1,128}$", options: .regularExpression) != nil && !value.contains("..")
    }
    static func issue(_ text: String) -> NSError {
        NSError(domain: "RouterVPN.Telemetry", code: 1, userInfo: [NSLocalizedDescriptionKey: text])
    }
    /// The existing protected store keeps only native cleanup acknowledgements.
    /// A receipt recovered from disk must never become an RTT/speed result.
    static func cleanupReceipt(_ binding: Binding) -> Data? {
        guard let data = IOSDNSRetirementReceipts.shared.drained(providerSession: binding.providerSession,
            nativeSession: binding.nativeSession, request: binding.request, nodeID: binding.nodeID),
              let checked = try? Status.decode(data, binding: binding), checked.complete, checked.drained,
              checked.results.isEmpty else { return nil }
        return try? Status(schema: 1, request_id: binding.request, ack_id: binding.request,
            session_id: binding.providerSession, native_session_id: binding.nativeSession, node_id: binding.nodeID,
            stage: "cancelled", complete: true, drained: true, results: [],
            failure: "The captured private-node measurement finished cleanup after provider messaging ended.").data()
    }
}
