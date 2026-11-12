import Foundation
import CryptoKit

/// Ordinary private source equality and bounded provider messages. None of
/// these values replaces PacketTunnel's process-owned native restore capsule.
enum IOSNodeChainExecutionSession {
    static let restoreKey = "routervpn_node_chain_execution_restore"
    static let restoreOwnerKey = "routervpn_node_chain_execution_restore_owner"
    static let lastKey = "routervpn_node_chain_execution_last"

    struct Source: Equatable, Sendable {
        let input: String, sourceSHA256: String, configSHA256: String
        let requested: String, finalID: String, finalMode: String, finalProfileJSON: String
        let strict: Bool, homeLANAccess: Bool
        private init(_ capture: IOSNodeChainExecutionCapture) throws {
            guard let final = capture.members.last else { throw issue() }
            input = capture.ordinaryLaunchInput; sourceSHA256 = capture.sourceSHA256; configSHA256 = capture.configSHA256
            requested = capture.requested; finalID = final.id; finalMode = final.mode
            finalProfileJSON = String(decoding: try JSONSerialization.data(withJSONObject: capture.finalProfile, options: [.sortedKeys]), as: UTF8.self)
            strict = capture.strict; homeLANAccess = capture.homeLANAccess
        }
        /// Run on a worker. Native source-only objects never cross the return.
        static func compile(_ bundles: [Data], requested: String) throws -> Source {
            let capture = try IOSNodeChainExecutionCapture.compile(bundles: bundles, requested: requested)
            defer { try? capture.close() }
            return try Source(capture)
        }
        static func reopen(_ input: String, finalProfileJSON: String) throws -> Source {
            let profile = try object(finalProfileJSON, limit: 256 * 1024)
            let capture = try IOSNodeChainExecutionCapture.reopen(input, selectedProfile: profile)
            defer { try? capture.close() }
            return try Source(capture)
        }
        static func capture(_ identity: IOSSessionIdentity) throws -> Source {
            guard let bytes = identity.nodeChainExecutionSource, let input = String(data: bytes, encoding: .utf8),
                  let root = try JSONSerialization.jsonObject(with: identity.bundleData) as? [String: Any],
                  let selected = root["selectedRouterID"] as? String,
                  let profiles = root["routerProfiles"] as? [[String: Any]],
                  profiles.filter({ $0["id"] as? String == selected }).count == 1,
                  let profile = profiles.first(where: { $0["id"] as? String == selected }) else { throw issue() }
            let text = String(decoding: try JSONSerialization.data(withJSONObject: profile, options: [.sortedKeys]), as: UTF8.self)
            let source = try reopen(input, finalProfileJSON: text)
            guard source.finalID == selected, source.matches(identity) else { throw issue() }
            return source
        }
        func matches(_ identity: IOSSessionIdentity) -> Bool {
            identity.engine == "multihop-libbox" && identity.rawProfile == finalMode &&
                identity.entryBundleData == nil && identity.nodeChainSource == nil &&
                identity.nodeChainExecutionSource == Data(input.utf8)
        }
        func validateLast(_ raw: String) throws {
            let profile = try object(finalProfileJSON, limit: 256 * 1024)
            let capture = try IOSNodeChainExecutionCapture.reopenLast(input, selectedProfile: profile, record: raw)
            defer { try? capture.close() }
            guard capture.sourceSHA256 == sourceSHA256, capture.ordinaryLaunchInput == input else { throw issue() }
        }
    }

    struct Restoration: Equatable, Sendable {
        let source: Source
        let owner: String, token: String, session: String, execution: String, preparationConfigSHA256: String
        private init(source: Source, owner: String, token: String, session: String, execution: String, preparationConfigSHA256: String) {
            self.source = source; self.owner = owner; self.token = token; self.session = session
            self.execution = execution; self.preparationConfigSHA256 = preparationConfigSHA256
        }
        static func decode(_ data: Data, source: Source, request: String, owner: UUID) throws -> Restoration {
            let value = try reply(data, request: request, kind: "routervpn-ordered-execution-restore", fields:
                ["schema", "kind", "request_id", "session_id", "owner_id", "token", "execution", "source_sha256", "preparation_config_sha256"])
            guard value["source_sha256"] as? String == source.sourceSHA256,
                  let token = value["token"] as? String, validToken(token),
                  value["owner_id"] as? String == owner.uuidString,
                  let selected = value["execution"] as? String, ["local", "server"].contains(selected),
                  source.requested == "auto" || source.requested == selected,
                  let config = value["preparation_config_sha256"] as? String, validHash(config),
                  let session = value["session_id"] as? String else { throw issue() }
            return Restoration(source: source, owner: owner.uuidString, token: token, session: session,
                               execution: selected, preparationConfigSHA256: config)
        }
        var options: [String: NSObject] { [restoreKey: token as NSString, restoreOwnerKey: owner as NSString] }
    }

    struct Last: Sendable {
        let source: Source, session: String, record: String
        private init(source: Source, session: String, record: String) { self.source = source; self.session = session; self.record = record }
        /// The shared compiler validates every descriptor/DNS/key/source pin;
        /// parsing this durable record grants no live or cleanup authority.
        static func decode(_ data: Data, source: Source, request: String) throws -> Last {
            let value = try reply(data, request: request, kind: "routervpn-ordered-execution-last", fields:
                ["schema", "kind", "request_id", "session_id", "source_sha256", "preparation_config_sha256", "last"])
            guard value["source_sha256"] as? String == source.sourceSHA256,
                  let config = value["preparation_config_sha256"] as? String, validHash(config),
                  let record = value["last"] as? String, !record.isEmpty, record.utf8.count <= 16 * 1024,
                  let session = value["session_id"] as? String else { throw issue() }
            try source.validateLast(record)
            return Last(source: source, session: session, record: record)
        }
    }

    static func request(operation: String, id: String, session: String = "", owner: UUID? = nil, token: String = "") throws -> Data {
        guard validToken(id), session.isEmpty || validUUID(session),
              ["ordered-execution-capture", "ordered-execution-verify", "ordered-execution-release", "ordered-execution-last"].contains(operation) else { throw issue() }
        if operation == "ordered-execution-last" { guard owner == nil, token.isEmpty else { throw issue() } }
        else {
            guard owner != nil else { throw issue() }
            if operation == "ordered-execution-capture" { guard token.isEmpty else { throw issue() } }
            else { guard !session.isEmpty, validToken(token) else { throw issue() } }
        }
        let data = try JSONSerialization.data(withJSONObject: ["operation": operation, "request_id": id,
            "session_id": session, "owner_id": owner?.uuidString ?? "", "token": token], options: [.sortedKeys])
        guard data.count <= 1024 else { throw issue() }
        return data
    }

    private static func reply(_ data: Data, request: String, kind: String, fields: Set<String>) throws -> [String: Any] {
        guard !data.isEmpty, data.count <= 20 * 1024, validToken(request),
              let value = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(value.keys) == fields,
              value["schema"] as? Int == 1, value["kind"] as? String == kind, value["request_id"] as? String == request,
              let session = value["session_id"] as? String, validUUID(session),
              try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) == data else { throw issue() }
        return value
    }
    private static func object(_ raw: String, limit: Int) throws -> [String: Any] {
        guard !raw.isEmpty, raw.utf8.count <= limit,
              let value = try JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any] else { throw issue() }
        return value
    }
    private static func validHash(_ value: String) -> Bool { value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }
    private static func validToken(_ value: String) -> Bool { value.utf8.count == 32 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }
    private static func validUUID(_ value: String) -> Bool { UUID(uuidString: value)?.uuidString == value }
    static func issue() -> NSError { NSError(domain: "RouterVPN.OrderedExecutionSession", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "The original ordered execution source or provider receipt changed."]) }
}

/// Separate private history for ordered executions. A saved record contains
/// public identity pins and hashes; every launch repeats native discovery/proof.
@MainActor enum IOSNodeChainExecutionLastStore {
    private static let filename = "ordered-execution-last-v1.json"
    private static let limit = 2 * 1024 * 1024
    private struct Record: Codable { let node: String, source: String, last: String }
    private struct Envelope: Codable { let schema: Int; var records: [Record] }

    static func record(_ receipt: IOSNodeChainExecutionSession.Last) throws {
        let source = receipt.source
        let key = SHA256.hash(data: Data(source.finalID.utf8)).map { String(format: "%02x", $0) }.joined()
        var records = try load()
        records.removeAll { $0.node == key }
        records.append(Record(node: key, source: source.sourceSHA256, last: receipt.record))
        if records.count > 64 { records.removeFirst(records.count - 64) }
        try IOSPrivateJSONStore.write(JSONEncoder().encode(Envelope(schema: 1, records: records)), filename: filename, maximumBytes: limit)
    }

    /// Worker native validation follows this read before any system start. No
    /// missing/stale record can silently rerun Compare as Startup Last.
    static func stored(for source: IOSNodeChainExecutionSession.Source) throws -> String? {
        let key = SHA256.hash(data: Data(source.finalID.utf8)).map { String(format: "%02x", $0) }.joined()
        guard let record = try load().first(where: { $0.node == key }), record.source == source.sourceSHA256 else { return nil }
        return record.last
    }
    private static func load() throws -> [Record] {
        guard let data = try IOSPrivateJSONStore.read(filename, maximumBytes: limit) else { return [] }
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(object.keys) == Set(["schema", "records"]),
              let rows = object["records"] as? [[String: Any]], rows.count <= 64,
              rows.allSatisfy({ Set($0.keys) == Set(["node", "source", "last"]) }) else { throw IOSNodeChainExecutionSession.issue() }
        let envelope = try JSONDecoder().decode(Envelope.self, from: data)
        guard envelope.schema == 1, Set(envelope.records.map(\.node)).count == envelope.records.count,
              envelope.records.allSatisfy({ row in
                  [row.node, row.source].allSatisfy { $0.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil } &&
                      !row.last.isEmpty && row.last.utf8.count <= 16 * 1024
              }) else { throw IOSNodeChainExecutionSession.issue() }
        return envelope.records
    }
}
