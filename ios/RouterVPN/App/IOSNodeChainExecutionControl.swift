import Foundation
import CoreFoundation

/// App-side ownership of one original provider's opaque restore capsule.
/// Source/Last values are private history; only the provider token can restore
/// its joined native owner. A timed-out capture is retired by its exact nonce.
@MainActor final class IOSNodeChainExecutionControl {
    typealias Send = @MainActor (Data) async throws -> Data
    struct Observation {
        let process: String, generation: String
        let last: IOSNodeChainExecutionSession.Last
        let selected: String
    }
    let source: IOSNodeChainExecutionSession.Source
    let owner: UUID
    private let send: Send
    private let current: @MainActor () throws -> Void
    private var observation: Observation?
    private var captureRequest: String?
    private(set) var restoration: IOSNodeChainExecutionSession.Restoration?
    private var consumed = false
    private static var retiring: [UUID: IOSNodeChainExecutionControl] = [:]
    private let retirementID = UUID()

    init(source: IOSNodeChainExecutionSession.Source, owner: UUID, send: @escaping Send,
         current: @escaping @MainActor () throws -> Void) {
        self.source = source; self.owner = owner; self.send = send; self.current = current
    }
    static func startupLast(input: String, finalProfile: RouterProfile) throws -> [String: NSObject] {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let profile = String(decoding: try encoder.encode(finalProfile), as: UTF8.self)
        let source = try IOSNodeChainExecutionSession.Source.reopen(input, controlProfileJSON: profile)
        guard let record = try IOSNodeChainExecutionLastStore.stored(for: source) else { throw IOSNodeChainExecutionSession.issue() }
        try source.validateLast(record)
        return [IOSNodeChainExecutionSession.lastKey: record as NSString]
    }

    static func requireAvailable() async throws {
        for value in Array(retiring.values) { try await value.retire() }
    }
    private static func nonce() -> String { UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased() }
    private static func encode(_ body: [String: String]) throws -> Data {
        let data = try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])
        guard data.count <= 1024 else { throw IOSNodeChainExecutionSession.issue() }; return data
    }
    private static func object(_ data: Data, limit: Int) throws -> [String: Any] {
        guard !data.isEmpty, data.count <= limit,
              let value = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) == data else { throw IOSNodeChainExecutionSession.issue() }
        return value
    }
    static func observe(source: IOSNodeChainExecutionSession.Source, send: Send,
                        current: @MainActor () throws -> Void) async throws -> Observation {
        try current()
        let id = nonce()
        let data = try await send(encode(["operation": "ordered-execution-owner", "request_id": id,
            "session_id": "", "owner_id": "", "token": ""]))
        try current()
        var value = try object(data, limit: IOSOrderedLastBounds.envelope(source.lastRecordLimit))
        guard Set(value.keys) == Set(["schema", "kind", "request_id", "session_id", "source_sha256", "preparation_config_sha256", "last", "process_id", "registry_generation"]),
              value["kind"] as? String == "routervpn-ordered-execution-owner",
              let process = value.removeValue(forKey: "process_id") as? String, UUID(uuidString: process)?.uuidString == process,
              let generation = value.removeValue(forKey: "registry_generation") as? String,
              let number = UInt64(generation), String(number) == generation else { throw IOSNodeChainExecutionSession.issue() }
        value["kind"] = "routervpn-ordered-execution-last"
        let last = try IOSNodeChainExecutionSession.Last.decode(JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]), source: source, request: id)
        guard let record = try JSONSerialization.jsonObject(with: Data(last.record.utf8)) as? [String: Any],
              let selected = record["execution"] as? String, ["local", "server"].contains(selected),
              source.requested == "auto" || source.requested == selected else { throw IOSNodeChainExecutionSession.issue() }
        try current()
        return Observation(process: process, generation: generation, last: last, selected: selected)
    }
    func capture() async throws {
        guard observation == nil, restoration == nil, !consumed else { throw IOSNodeChainExecutionSession.issue() }
        try await Self.requireAvailable()
        let observed = try await Self.observe(source: source, send: send, current: current)
        observation = observed
        let request = Self.nonce(); captureRequest = request // before the asynchronous provider worker
        do {
            try current()
            let input = try Self.encode(["operation": "ordered-execution-capture", "request_id": request,
                "session_id": observed.last.session, "owner_id": owner.uuidString, "token": "",
                "process_id": observed.process, "registry_generation": observed.generation])
            let data = try await send(input)
            let receipt = try IOSNodeChainExecutionSession.Restoration.decode(data, source: source, request: request, owner: owner)
            guard receipt.session == observed.last.session, receipt.execution == observed.selected else { throw IOSNodeChainExecutionSession.issue() }
            restoration = receipt
            try current()
        } catch {
            let failure = error
            Self.retiring[retirementID] = self
            try await retire()
            throw failure
        }
    }
    func verify() async throws {
        try current()
        guard let restoration, !consumed else { throw IOSNodeChainExecutionSession.issue() }
        let id = Self.nonce()
        let data = try await send(IOSNodeChainExecutionSession.request(operation: "ordered-execution-verify", id: id,
            session: restoration.session, owner: owner, token: restoration.token))
        try current()
        let receipt = try IOSNodeChainExecutionSession.Restoration.decode(data, source: source, request: id, owner: owner)
        guard receipt == restoration else { throw IOSNodeChainExecutionSession.issue() }
    }
    func options() throws -> [String: NSObject] {
        guard let restoration, !consumed else { throw IOSNodeChainExecutionSession.issue() }
        return restoration.options
    }
    func proveRestored(send: Send, current: @MainActor () throws -> Void) async throws {
        guard let original = observation, let restoration, !consumed else { throw IOSNodeChainExecutionSession.issue() }
        let fresh = try await Self.observe(source: source, send: send, current: current)
        guard fresh.process == original.process, fresh.generation != original.generation,
              fresh.last.session != restoration.session, fresh.selected == restoration.execution else { throw IOSNodeChainExecutionSession.issue() }
        try current(); consumed = true
        try IOSNodeChainExecutionLastStore.record(fresh.last)
    }
    /// May be retried after cancellation. It uses only the retained transport
    /// and exact original process/generation/session/capture nonce.
    func retire() async throws {
        guard !consumed, let observation, let captureRequest else { Self.retiring.removeValue(forKey: retirementID); return }
        Self.retiring[retirementID] = self
        let id = Self.nonce()
        let data = try await send(Self.encode(["operation": "ordered-execution-capture-release", "request_id": id,
            "session_id": observation.last.session, "owner_id": owner.uuidString, "capture_request_id": captureRequest,
            "process_id": observation.process, "registry_generation": observation.generation]))
        let value = try Self.object(data, limit: 20 * 1024)
        guard Set(value.keys) == Set(["schema", "kind", "request_id", "session_id", "owner_id", "capture_request_id", "released", "process_id", "registry_generation"]),
              value["schema"] as? Int == 1, value["kind"] as? String == "routervpn-ordered-execution-capture-release",
              value["request_id"] as? String == id, value["session_id"] as? String == observation.last.session,
              value["owner_id"] as? String == owner.uuidString, value["capture_request_id"] as? String == captureRequest,
              value["process_id"] as? String == observation.process, value["registry_generation"] as? String == observation.generation,
              let released = value["released"] as? NSNumber, CFGetTypeID(released) == CFBooleanGetTypeID(), released.boolValue else { throw IOSNodeChainExecutionSession.issue() }
        consumed = true; Self.retiring.removeValue(forKey: retirementID)
    }
}
