import Foundation

/// An optional previous execution choice, not a cached connection proof.
/// Only hashes and Local/Server are durable; every launch must prove its path.
@MainActor enum IOSStartupLastChoice {
    private static let filename = "startup-execution-choices.json"
    private static let maximumBytes = 64 * 1024

    private struct Record: Codable {
        let node: String
        let bundle: String
        let entry: String
        let execution: String

        var valid: Bool {
            [node, bundle, entry].allSatisfy { $0.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil } &&
                ["local", "server"].contains(execution)
        }
    }

    private struct Envelope: Codable {
        let schema: Int
        var records: [Record]
    }

    static func record(configuration: [String: Any], receipt: IOSMultihopExecution.Capture,
                       digest: (Data) -> String) throws {
        let source = try IOSMultihopExecution.Source(configuration: configuration, digest: digest)
        // Revalidate the actual provider receipt before dropping its ephemeral
        // request/session identity from the durable record.
        let verified = try IOSMultihopExecution.Capture.decode(receipt.encoded(), source: source)
        let key = digest(Data(source.exitID.utf8))
        let record = try Record(node: key, bundle: fingerprint(configuration["bundle"], digest: digest),
                                entry: fingerprint(configuration["external_entry_bundle"], digest: digest),
                                execution: verified.execution)
        guard record.valid else { throw IOSMultihopExecution.issue() }
        var records = try load()
        records.removeAll { $0.node == key }
        records.append(record)
        if records.count > 64 { records.removeFirst(records.count - 64) }
        let data = try JSONEncoder().encode(Envelope(schema: 1, records: records))
        try IOSPrivateJSONStore.write(data, filename: filename, maximumBytes: maximumBytes)
    }

    static func restored(configuration: [String: Any], digest: (Data) -> String) throws -> IOSMultihopExecution.StartupChoice? {
        let source = try IOSMultihopExecution.Source(configuration: configuration, digest: digest)
        let key = digest(Data(source.exitID.utf8))
        guard let record = try load().first(where: { $0.node == key }),
              record.bundle == (try fingerprint(configuration["bundle"], digest: digest)),
              record.entry == (try fingerprint(configuration["external_entry_bundle"], digest: digest)),
              source.requested == "auto" || source.requested == record.execution else { return nil }
        return try IOSMultihopExecution.StartupChoice(source: source, execution: record.execution)
    }

    private static func fingerprint(_ raw: Any?, digest: (Data) -> String) throws -> String {
        guard let data = raw as? Data, !data.isEmpty, data.count <= 32 * 1024 * 1024,
              var object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let selected = object["selectedRouterID"] as? String,
              var profiles = object["routerProfiles"] as? [[String: Any]] else { throw IOSMultihopExecution.issue() }
        let matches = profiles.indices.filter { profiles[$0]["id"] as? String == selected }
        guard matches.count == 1 else { throw IOSMultihopExecution.issue() }
        // Startup preferences and historical readback do not select the new
        // transport, credentials, DNS, protection or graph. Requested MTU
        // policy/manual values remain bound; old measurements are never proof.
        for key in ["startup_mode", "auto_connect", "effective_mtu", "effective_mtu_source",
                    "effective_mtu_path_key", "effective_underlay_pmtu", "effective_mtu_tested_at",
                    "effective_mtu_network_fingerprint", "effective_mtu_profile_fingerprint",
                    "effective_mtu_mbps", "effective_mtu_median_rtt_ms", "effective_mtu_success_ratio"] {
            profiles[matches[0]].removeValue(forKey: key)
        }
        object["routerProfiles"] = profiles
        return digest(try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]))
    }

    private static func load() throws -> [Record] {
        guard let data = try IOSPrivateJSONStore.read(filename, maximumBytes: maximumBytes) else { return [] }
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == Set(["schema", "records"]),
              let records = object["records"] as? [[String: Any]], records.count <= 64,
              records.allSatisfy({ Set($0.keys) == Set(["node", "bundle", "entry", "execution"]) }) else {
            throw IOSMultihopExecution.issue()
        }
        let envelope = try JSONDecoder().decode(Envelope.self, from: data)
        guard envelope.schema == 1, envelope.records.allSatisfy(\.valid),
              Set(envelope.records.map(\.node)).count == envelope.records.count else { throw IOSMultihopExecution.issue() }
        return envelope.records
    }
}
