import Foundation

/// Routed HTTPS history never becomes the direct TCP node ranking. The key
/// binds the complete native source, paired entry and selected policy; only
/// their digests are persisted, without credentials or an imported profile.
@MainActor enum IOSExternalNodeStatistics {
    static let filename = "external-node-response-v1.json"
    private static let maximumBytes = 256 * 1024
    private static let maximumRecords = 128

    struct PathReceipt: Codable, Equatable {
        let execution: IOSHopExecutionReceipt
        let sessionDigest: String
        let networkGeneration: UInt64
        var valid: Bool { execution.valid && validKey(sessionDigest) && networkGeneration > 0 }
        @MainActor init(binding: IOSHopMeasurementBinding, requested: String, network: UInt64) throws {
            guard let execution = binding.execution, execution.valid, execution.requested == requested,
                  UUID(uuidString: binding.session_id) != nil, UUID(uuidString: binding.mtu_session_id) != nil,
                  network > 0 else { throw issue() }
            self.execution = execution; networkGeneration = network
            sessionDigest = IOSNodeUsage.digest(try IOSNodeUsage.canonical([binding.session_id, binding.mtu_session_id]))
        }
    }

    struct Record: Codable, Equatable {
        let key: String
        let measuredAt: Date
        let benchmark: IOSHopMeasurementResult.Benchmark
        let path: PathReceipt
        var detail: String {
            let execution = path.execution
            let choice = execution.requested == "auto" ? "Compare both → " + execution.selected.capitalized : execution.selected.capitalized
            return benchmark.detail + "\nExecution: " + choice + "\nSaved " + measuredAt.formatted(date: .abbreviated, time: .standard) +
                " • historical result for this exact saved path"
        }
    }
    private struct Envelope: Codable { let schema: Int; var records: [Record] }

    static func key(node: String, bundle: Data, entry: Data?) throws -> String {
        guard !node.isEmpty, node.utf8.count <= 128, !bundle.isEmpty, bundle.count <= 32 * 1024 * 1024,
              entry == nil || (!entry!.isEmpty && entry!.count <= 32 * 1024 * 1024) else { throw issue() }
        let source = try IOSNodeUsage.canonicalJSON(bundle)
        let predecessor = try entry.map(IOSNodeUsage.canonicalJSON)
        return IOSNodeUsage.digest(try IOSNodeUsage.canonical([
            "schema": "1", "node": node, "source": IOSNodeUsage.digest(source),
            "entry": predecessor.map(IOSNodeUsage.digest) ?? ""
        ]))
    }

    static func selectedKey(_ model: RouterVPNModel) throws -> String {
        guard let bundle = model.bundle, let selected = model.unifiedSelectedProfile,
              selected.normalizedNodeKind == "external" else { throw issue() }
        return try key(node: selected.id, bundle: model.externalRuntimeBundleData(source: bundle, profile: selected),
                       entry: model.externalTorEntryData(source: bundle))
    }

    static func requestedExecution(node: String, bundle: Data) throws -> String {
        let source = try JSONDecoder().decode(ClientBundle.self, from: bundle)
        guard let profile = source.routerProfiles.first(where: { $0.id == node }),
              profile.normalizedNodeKind == "external" else { throw issue() }
        let value = profile.multihopExecution ?? "local"
        let requested = value.isEmpty ? "local" : value
        guard ["local", "server", "auto"].contains(requested) else { throw issue() }
        return requested
    }

    static func saved(key: String) throws -> Record? {
        guard validKey(key) else { throw issue() }
        return try load().first { $0.key == key }
    }

    static func save(key: String, benchmark: IOSHopMeasurementResult.Benchmark, path: PathReceipt, at date: Date = Date()) throws -> Record {
        guard validKey(key), benchmark.valid, path.valid, validDate(date), date >= Date().addingTimeInterval(-300) else { throw issue() }
        var records = try load()
        let record = Record(key: key, measuredAt: date, benchmark: benchmark, path: path)
        records.removeAll { $0.key == key }
        records.append(record)
        records.sort { $0.measuredAt == $1.measuredAt ? $0.key < $1.key : $0.measuredAt < $1.measuredAt }
        if records.count > maximumRecords { records.removeFirst(records.count - maximumRecords) }
        let data = try IOSNodeUsage.canonical(Envelope(schema: 1, records: records))
        try IOSPrivateJSONStore.write(data, filename: filename, maximumBytes: maximumBytes)
        return record
    }

    private static func load() throws -> [Record] {
        guard let data = try IOSPrivateJSONStore.read(filename, maximumBytes: maximumBytes) else { return [] }
        let envelope = try JSONDecoder().decode(Envelope.self, from: data)
        guard envelope.schema == 1, envelope.records.count <= maximumRecords,
              try IOSNodeUsage.canonical(envelope) == data,
              Set(envelope.records.map(\.key)).count == envelope.records.count,
              envelope.records.allSatisfy({ validKey($0.key) && validDate($0.measuredAt) && $0.benchmark.valid && $0.path.valid }) else { throw issue() }
        return envelope.records
    }

    nonisolated private static func validKey(_ key: String) -> Bool {
        key.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
    }
    private static func validDate(_ date: Date) -> Bool {
        date.timeIntervalSince1970.isFinite && date.timeIntervalSince1970 >= 0 && date <= Date().addingTimeInterval(60)
    }
    static func issue() -> NSError {
        NSError(domain: "RouterVPN.ExternalNodeStatistics", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "The external-node result or its private history is invalid. The previous saved measurements were kept."])
    }
}
