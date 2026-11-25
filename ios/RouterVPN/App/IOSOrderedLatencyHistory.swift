import Foundation
import CoreFoundation

/// The app's preparation identifies the saved route. Only the borrowed native
/// facade can identify the selected graph and the particular measured generation.
struct IOSOrderedLatencyExecution: Sendable {
    struct Binding: Codable, Sendable {
        let preparation_source_sha256: String, preparation_config_sha256: String
        let requested_execution: String, capture: String
    }
    let binding: Binding
    let source: String, config: String, generation: String, selected: String
    let ids: [String], kinds: [String]
    let originalSource: String?
    let extended: IOSOrderedLatencyExtendedLocal?

    init(_ binding: Binding, extended: IOSOrderedLatencyExtendedLocal? = nil) throws {
        self.extended = extended
        if let extended {
            guard binding.preparation_source_sha256 == extended.source, binding.preparation_config_sha256 == extended.config else { throw IOSOrderedLatencyRecord.issue() }
        }
        typealias R = IOSOrderedLatencyRecord
        let v = try R.object(binding.capture, maximum: extended?.statusLimit ?? 8192)
        var fields = ["schema", "source_sha256", "config_sha256", "generation_sha256", "selected_execution", "nodes"]
        var publicRows: [[String: Any]]?
        if v["multiple_imported"] != nil {
            fields.append("multiple_imported")
            guard let imported = v["multiple_imported"] as? [String: Any] else { throw R.issue() }
            try R.keys(imported, ["schema", "original_source_sha256", "public"])
            let original = try R.text(imported, "original_source_sha256")
            guard try R.integer(imported, "schema") == 6, R.hex(original), let rows = imported["public"] as? [[String: Any]],
                  !rows.isEmpty else { throw R.issue() }
            originalSource = original; publicRows = rows
        } else { originalSource = nil }
        try R.keys(v, fields)
        source = try R.text(v, "source_sha256"); config = try R.text(v, "config_sha256")
        generation = try R.text(v, "generation_sha256"); selected = try R.text(v, "selected_execution")
        guard try R.integer(v, "schema") == 1, [source, config, generation, binding.preparation_source_sha256, binding.preparation_config_sha256].allSatisfy({ R.hex($0) }),
              ["local", "server"].contains(selected), ["server", "auto"].contains(binding.requested_execution),
              binding.requested_execution != "server" || selected == "server",
              let nodes = v["nodes"] as? [[String: Any]], extended.map({ nodes.count == $0.ids.count && publicRows?.count == $0.kinds.filter({ $0 == "public-path" }).count }) ?? (2...8).contains(nodes.count) else { throw R.issue() }
        var ids = [String](), kinds = [String]()
        var publicIndex = 0
        for (position, member) in nodes.enumerated() {
            try R.keys(member, ["position", "node_id", "role", "kind"])
            let id = try R.text(member, "node_id"), kind = try R.text(member, "kind")
            guard try R.integer(member, "position") == Int64(position),
                  try R.text(member, "role") == (position == 0 ? "entry" : position == nodes.count - 1 ? "exit" : "intermediate"),
                  id.range(of: "\\A[A-Za-z0-9_-]{1,64}\\z", options: .regularExpression) != nil, !ids.contains(id),
                  kind == "private-node" || (kind == "public-path" && position > 0 && position < nodes.count - 1 &&
                    (publicRows != nil || position == nodes.count - 2)) else { throw R.issue() }
            if kind == "public-path", let rows = publicRows {
                guard rows.indices.contains(publicIndex) else { throw R.issue() }
                let row = rows[publicIndex]
                try R.keys(row, ["position", "tag", "source_sha256"])
                guard try R.integer(row, "position") == Int64(position), try !R.text(row, "tag").isEmpty,
                      try R.hex(R.text(row, "source_sha256")) else { throw R.issue() }
                publicIndex += 1
            }
            ids.append(id); kinds.append(kind)
        }
        if let rows = publicRows, rows.count != publicIndex { throw R.issue() }
        if let extended {
            let pairedStreams = kinds.indices.dropFirst().dropLast().filter { kinds[$0] == "private-node" }
            guard ids == extended.ids, kinds == extended.kinds, kinds.first == "private-node", kinds.last == "private-node",
                  !pairedStreams.contains(1) else { throw R.issue() }
        }
        self.binding = binding; self.ids = ids; self.kinds = kinds
    }
}

/// Captured from the reopened native original and its exact member inventory. Historical labels alone
/// never create this binding. Reordered, renamed or substituted slots have to
/// satisfy the exact captured source, configuration, kind and position.
struct IOSOrderedLatencyExtendedLocal: Sendable {
    let source: String, config: String, ids: [String], kinds: [String]
    let externalFinal: Bool
    var statusLimit: Int { max(16384, 512 + 1536 * ids.count) }
    init(source: String, config: String, ids: [String], kinds: [String], provedCount: Int, pairedPrefixNodes: Int = 0, provedKinds: [String]? = nil, externalFinal: Bool = false) throws {
        self.externalFinal = externalFinal
        if externalFinal {
            guard provedKinds == kinds, kinds.first == "private-node", kinds.dropFirst().allSatisfy({ $0 == "public-path" }),
                  pairedPrefixNodes == 0 else { throw IOSOrderedLatencyRecord.issue() }
        }
        guard ((externalFinal ? 3 : 9)...IOSMultihopNodeSelection.physicalTraversalDepth).contains(provedCount),
              provedCount == ids.count, Set(ids).count == ids.count, kinds.count == ids.count,
              IOSOrderedLatencyRecord.hex(source), IOSOrderedLatencyRecord.hex(config) else { throw IOSOrderedLatencyRecord.issue() }
        guard pairedPrefixNodes == 0 || (1..<ids.count-1).contains(pairedPrefixNodes) else { throw IOSOrderedLatencyRecord.issue() }
        if let provedKinds {
            guard provedKinds == kinds, kinds.first == "private-node", kinds.last == (externalFinal ? "public-path" : "private-node"),
                  kinds.allSatisfy({ $0 == "private-node" || $0 == "public-path" }),
                  kinds.prefix(pairedPrefixNodes).allSatisfy({ $0 == "private-node" }) else { throw IOSOrderedLatencyRecord.issue() }
        }
        let paired = pairedPrefixNodes == 0 && kinds.allSatisfy { $0 == "private-node" }
        for (index, id) in ids.enumerated() {
            guard id.range(of: "\\A[A-Za-z0-9_-]{1,64}\\z", options: .regularExpression) != nil,
                  provedKinds != nil || paired || kinds[index] == (pairedPrefixNodes > 0 && index < pairedPrefixNodes ? "private-node" : Self.kind(index, ids.count)) else { throw IOSOrderedLatencyRecord.issue() }
        }
        self.source = source; self.config = config; self.ids = ids; self.kinds = kinds
    }
    static func kind(_ position: Int, _ count: Int) -> String {
        position == 0 || position == count - 1 ? "private-node" : "public-path"
    }
}

/// Historical cumulative-path responses only. Never direct-node ranking or
/// connection authority. The closed receipt grammar excludes labels/secrets.
struct IOSOrderedLatencyRecord: Sendable {
    let execution: IOSOrderedLatencyExecution?
    let extended: IOSOrderedLatencyExtendedLocal?
    let raw: String, source: String, config: String, generation: String, node: String, request: String, kind: String
    let position: Int, count: Int, measuredAt: Int64
    let minimum: Double, median: Double, average: Double, trimmed: Double, p90: Double, maximum: Double, jitter: Double
    static func issue() -> NSError { NSError(domain: "RouterVPN.OrderedLatency", code: 1, userInfo: [NSLocalizedDescriptionKey: "No complete, correctly bound 50-response ordered benchmark."]) }
    static func hex(_ value: String, _ count: Int = 64) -> Bool {
        value.utf8.count == count && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    static func object(_ raw: String, maximum: Int = 16384) throws -> [String: Any] {
        let data = Data(raw.utf8)
        guard !data.isEmpty, data.count <= maximum else { throw issue() }
        try IOSExternalExecution.validatePrivateNodeJSON(data)
        guard let result = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw issue() }
        return result
    }
    static func keys(_ value: [String: Any], _ expected: [String]) throws {
        guard Set(value.keys) == Set(expected) else { throw issue() }
    }
    static func text(_ value: [String: Any], _ key: String) throws -> String {
        guard let result = value[key] as? String else { throw issue() }; return result
    }
    static func number(_ value: [String: Any], _ key: String) throws -> Double {
        guard let result = value[key] as? NSNumber, CFGetTypeID(result) != CFBooleanGetTypeID(), result.doubleValue.isFinite else { throw issue() }
        return result.doubleValue
    }
    static func integer(_ value: [String: Any], _ key: String) throws -> Int64 {
        let result = try number(value, key)
        guard result.rounded() == result, result >= 0, result < Double(Int64.max) else { throw issue() }; return Int64(result)
    }
    static func boolean(_ value: [String: Any], _ key: String) throws -> Bool {
        guard let result = value[key] as? NSNumber, CFGetTypeID(result) == CFBooleanGetTypeID() else { throw issue() }; return result.boolValue
    }
    init(_ raw: String, now: Date = Date(), execution: IOSOrderedLatencyExecution? = nil, extended: IOSOrderedLatencyExtendedLocal? = nil) throws {
        try self.init(raw, now: now, execution: execution, extended: extended, stored: false)
    }
    fileprivate init(_ raw: String, now: Date = Date(), execution: IOSOrderedLatencyExecution?, extended: IOSOrderedLatencyExtendedLocal?, stored: Bool) throws {
        self.execution = execution; self.extended = extended
        guard execution == nil || extended == nil else { throw Self.issue() }
        let limit = execution?.extended?.ids.count ?? extended?.ids.count ?? ((stored && execution == nil) ? IOSMultihopNodeSelection.physicalTraversalDepth : 8)
        let v = try Self.object(raw, maximum: 8192)
        try Self.keys(v, ["schema", "source_sha256", "config_sha256", "generation_sha256", "position", "node_id", "request_id", "measured_at", "result"])
        source = try Self.text(v, "source_sha256"); config = try Self.text(v, "config_sha256"); generation = try Self.text(v, "generation_sha256")
        node = try Self.text(v, "node_id"); request = try Self.text(v, "request_id")
        let p = try Self.integer(v, "position"); measuredAt = try Self.integer(v, "measured_at")
        guard try Self.integer(v, "schema") == 1, Self.hex(source), Self.hex(config), Self.hex(generation), Self.hex(request, 32),
              node.range(of: "\\A[A-Za-z0-9_-]{1,64}\\z", options: .regularExpression) != nil,
              p < limit, measuredAt > 0, Double(measuredAt) <= now.timeIntervalSince1970 * 1000 + 60000,
              let result = v["result"] as? [String: Any] else { throw Self.issue() }
        position = Int(p)
        try Self.keys(result, ["node_id", "role", "kind", "label", "ready", "benchmark"])
        kind = try Self.text(result, "kind")
        let incomingLabel = try Self.text(result, "label")
        let prefix = execution.map { "Cumulative " + $0.selected + " path through " } ?? "Cumulative path through "
        let label: String
        if kind == "public-path" {
            let fields = incomingLabel.split(separator: " ")
            let shift = execution == nil ? 0 : 1
            guard fields.count == 11 + shift, let capturedCount = Int(fields[7 + shift]), (3...limit).contains(capturedCount),
                  (position > 0 || capturedCount == 3), (position < capturedCount - 1 || position == capturedCount - 1 && extended?.externalFinal == true && execution == nil) else { throw Self.issue() }
            count = capturedCount; label = prefix + "custom node \(position + 1) of \(capturedCount) → Cloudflare edge"
        } else {
            guard kind == "private-node", let suffix = incomingLabel.split(separator: " ").last, let capturedCount = Int(suffix), (2...limit).contains(capturedCount), position < capturedCount else { throw Self.issue() }
            count = capturedCount; label = prefix + "node \(position + 1) of \(capturedCount)"
        }
        if count > 8 {
            if let original = execution?.extended ?? extended {
                guard original.kinds.indices.contains(position), kind == original.kinds[position] else { throw Self.issue() }
            } else {
                guard stored, execution == nil, kind == "private-node" || kind == IOSOrderedLatencyExtendedLocal.kind(position, count) else { throw Self.issue() }
            }
        }
        if let extended {
            guard source == extended.source, config == extended.config, count == extended.ids.count,
                  extended.ids[position] == node, extended.kinds[position] == kind else { throw Self.issue() }
        }
        if let execution {
            guard source == execution.source, config == execution.config, generation == execution.generation,
                  count == execution.ids.count, execution.ids[position] == node, execution.kinds[position] == kind else { throw Self.issue() }
        }
        let role = position == 0 ? "entry" : position == count - 1 ? "exit" : "intermediate"
        guard try Self.text(result, "node_id") == node, try Self.text(result, "role") == role,
              try Self.text(result, "label") == label, try Self.boolean(result, "ready"),
              let benchmark = result["benchmark"] as? [String: Any], let d = benchmark["distribution"] as? [String: Any] else { throw Self.issue() }
        try Self.keys(benchmark, ["schema", "measurement", "endpoint", "attempts", "failed", "distribution", "trimmed_mean_ms"])
        try Self.keys(d, ["samples", "min_ms", "median_ms", "average_ms", "p90_ms", "max_ms", "jitter_ms"])
        guard try Self.integer(benchmark, "schema") == 1, try Self.integer(benchmark, "attempts") == 50, try Self.integer(benchmark, "failed") == 0,
              try Self.integer(d, "samples") == 50,
              try Self.text(benchmark, "measurement") == (kind == "public-path" ? "routed-https-response-after-tls" : "routed-private-response-including-connection"),
              try Self.text(benchmark, "endpoint") == (kind == "public-path" ? "https://speed.cloudflare.com/__down?bytes=1" : "") else { throw Self.issue() }
        minimum = try Self.number(d, "min_ms"); median = try Self.number(d, "median_ms"); average = try Self.number(d, "average_ms")
        p90 = try Self.number(d, "p90_ms"); maximum = try Self.number(d, "max_ms"); jitter = try Self.number(d, "jitter_ms"); trimmed = try Self.number(benchmark, "trimmed_mean_ms")
        guard [minimum, median, average, p90, maximum, trimmed].allSatisfy({ $0 > 0 && $0 <= 60000 }),
              minimum <= median, median <= p90, p90 <= maximum, minimum <= average, average <= maximum,
              minimum <= trimmed, trimmed <= maximum, jitter >= 0, jitter <= maximum - minimum + 1e-9 else { throw Self.issue() }
        self.raw = raw
    }
    var key: String {
        if let e = execution { return "\(e.binding.preparation_source_sha256):\(e.binding.preparation_config_sha256):\(e.binding.requested_execution):\(e.selected):\(position):\(node):\(kind)" }
        return "\(source):\(config):\(position):\(node):\(kind)"
    }
    var detail: String {
        let meaning = kind == "public-path" ? "HTTPS responses through the custom node, timed after DNS, TCP and TLS preparation." : "Authenticated private HTTP responses through the ordered prefix, including connection establishment."
        let selection = execution.map { "Selected execution: " + $0.selected.capitalized + ($0.binding.requested_execution == "auto" ? " (Compare)" : "") + "\n" } ?? ""
        return selection + String(format: "Historical • 50 successful responses, 0 failed\nMedian %.2f ms • min %.2f • average %.2f\n10%% trimmed mean %.2f • p90 %.2f • max %.2f • jitter %.2f\n", median, minimum, average, trimmed, p90, maximum, jitter) +
            Date(timeIntervalSince1970: Double(measuredAt) / 1000).formatted() + "\n" + meaning + " Not ICMP or a server-to-server link measurement."
    }
    static func status(_ raw: String, request: String) throws -> [String: Any] {
        let v = try object(raw)
        try keys(v, ["request_id", "stage", "complete", "drained", "results"] + (v["failure"] == nil ? [] : ["failure"]))
        guard try text(v, "request_id") == request, try text(v, "stage").utf8.count <= 160,
              let results = v["results"] as? [[String: Any]], results.count <= 1 else { throw issue() }
        _ = try boolean(v, "complete"); _ = try boolean(v, "drained")
        if v["failure"] != nil { _ = try text(v, "failure") }
        return v
    }
    static func completed(status raw: String, saved: String, source: String, config: String, node: String, position: Int, request: String, execution: IOSOrderedLatencyExecution? = nil, extended: IOSOrderedLatencyExtendedLocal? = nil) throws -> Self {
        let status = try status(raw, request: request), result = try Self(saved, execution: execution, extended: extended)
        guard try boolean(status, "complete"), try boolean(status, "drained"), try text(status, "stage") == "complete",
              (status["failure"] as? String ?? "").isEmpty, result.source == source, result.config == config,
              result.node == node, result.position == position, result.request == request,
              let list = status["results"] as? [[String: Any]], list.count == 1,
              let savedResult = try object(saved)["result"] as? [String: Any], try JSONSerialization.data(withJSONObject: list[0], options: [.sortedKeys]) == JSONSerialization.data(withJSONObject: savedResult, options: [.sortedKeys]) else { throw issue() }
        return result
    }
}

@MainActor enum IOSOrderedLatencyHistory {
    static let filename = "ordered-node-fifty-v1.json", maximumBytes = 1024 * 1024
    static let selectedFilename = "ordered-selected-node-fifty-v1.json"
    struct Entry: Codable {
        let profile_sha256: String, receipt: String
        let execution: IOSOrderedLatencyExecution.Binding?
        init(profile_sha256: String, receipt: String, execution: IOSOrderedLatencyExecution.Binding? = nil) {
            self.profile_sha256 = profile_sha256; self.receipt = receipt; self.execution = execution
        }
        func record(extended: IOSOrderedLatencyExtendedLocal? = nil) throws -> IOSOrderedLatencyRecord {
            try IOSOrderedLatencyRecord(receipt, execution: execution.map { try IOSOrderedLatencyExecution($0, extended: extended) }, extended: extended?.externalFinal == true && execution == nil ? extended : nil, stored: true)
        }
    }
    struct Envelope: Codable { let schema: Int; let records: [Entry] }
    static func entries(_ data: Data?, selected: Bool = false, extended: IOSOrderedLatencyExtendedLocal? = nil) throws -> [Entry] {
        guard let data else { return [] }
        guard data.count <= maximumBytes, let raw = String(data: data, encoding: .utf8) else { throw IOSOrderedLatencyRecord.issue() }
        let v = try IOSOrderedLatencyRecord.object(raw, maximum: maximumBytes)
        try IOSOrderedLatencyRecord.keys(v, ["schema", "records"])
        guard try IOSOrderedLatencyRecord.integer(v, "schema") == 1, let records = v["records"] as? [[String: Any]], records.count <= 128 else { throw IOSOrderedLatencyRecord.issue() }
        let decoded = try JSONDecoder().decode(Envelope.self, from: data)
        var keys = Set<String>()
        for (item, entry) in zip(records, decoded.records) {
            try IOSOrderedLatencyRecord.keys(item, selected ? ["profile_sha256", "receipt", "execution"] : ["profile_sha256", "receipt"])
            if selected {
                guard let binding = item["execution"] as? [String: Any] else { throw IOSOrderedLatencyRecord.issue() }
                try IOSOrderedLatencyRecord.keys(binding, ["preparation_source_sha256", "preparation_config_sha256", "requested_execution", "capture"])
            }
            let profile = entry.profile_sha256, record = try entry.record(extended: extended)
            guard IOSOrderedLatencyRecord.hex(profile), keys.insert(profile + ":" + record.key).inserted else { throw IOSOrderedLatencyRecord.issue() }
        }
        return decoded.records
    }
    private static func localFile(_ binding: IOSOrderedLatencyExtendedLocal?) -> String {
        guard let binding, binding.externalFinal else { return filename }
        return "external-exit-node-fifty-" + binding.source + ".json"
    }

    static func load(profile: String, source: String, config: String, position: Int, node: String, extended: IOSOrderedLatencyExtendedLocal? = nil) throws -> IOSOrderedLatencyRecord? {
        for entry in try entries(IOSPrivateJSONStore.read(localFile(extended), maximumBytes: maximumBytes), extended: extended) where entry.profile_sha256 == profile {
            let r = try entry.record(extended: extended)
            if r.source == source && r.config == config && r.position == position && r.node == node {
                return try IOSOrderedLatencyRecord(r.raw, extended: extended)
            }
        }
        return nil
    }
    static func local(profile: String, source: String, config: String, ids: [String], kinds: [String],
                      extended: IOSOrderedLatencyExtendedLocal?) throws -> [IOSOrderedLatencyRecord] {
        let data = try IOSPrivateJSONStore.read(localFile(extended), maximumBytes: maximumBytes)
        return try entries(data, extended: extended).compactMap { entry in
            guard entry.profile_sha256 == profile else { return nil }
            let row = try entry.record(extended: extended)
            guard row.source == source && row.config == config else { return nil }
            guard row.count == ids.count, kinds.count == ids.count, ids.indices.contains(row.position),
                  row.node == ids[row.position], row.kind == kinds[row.position] else { throw IOSOrderedLatencyRecord.issue() }
            return try IOSOrderedLatencyRecord(row.raw, extended: extended)
        }
    }
    static func selected(profile: String, source: String, config: String, requested: String, ids: [String], kinds: [String], extended: IOSOrderedLatencyExtendedLocal? = nil) throws -> [IOSOrderedLatencyRecord] {
        let positions = extended.map { Array($0.ids.indices) } ?? [0]
        var records: [IOSOrderedLatencyRecord] = []
        for position in positions {
            let data = try IOSPrivateJSONStore.read(selectedFile(extended, position: position), maximumBytes: maximumBytes)
            let values = try selected(entries(data, selected: true, extended: extended), profile: profile, source: source,
                                      config: config, requested: requested, ids: ids, kinds: kinds, extended: extended)
            guard extended == nil || values.allSatisfy({ $0.position == position }) else { throw IOSOrderedLatencyRecord.issue() }
            records.append(contentsOf: values)
        }
        return records.sorted { $0.measuredAt > $1.measuredAt }
    }
    private static func selectedFile(_ extended: IOSOrderedLatencyExtendedLocal?, position: Int) -> String {
        guard let extended else { return selectedFilename }
        // Each saved position retains its own full selected-generation proof. A
        // complete history can have a different native generation at every slot.
        return "selected-node-fifty-" + extended.source + "-" + String(position) + ".json"
    }
    private static func selected(_ entries: [Entry], profile: String, source: String, config: String, requested: String, ids: [String], kinds: [String], extended: IOSOrderedLatencyExtendedLocal?) throws -> [IOSOrderedLatencyRecord] {
        try entries.compactMap { entry in
            guard entry.profile_sha256 == profile, let binding = entry.execution,
                  binding.preparation_source_sha256 == source, binding.preparation_config_sha256 == config,
                  binding.requested_execution == requested else { return nil }
            let record = try entry.record(extended: extended)
            guard record.execution?.ids == ids, record.execution?.kinds == kinds else { throw IOSOrderedLatencyRecord.issue() }
            return record
        }.sorted { $0.measuredAt > $1.measuredAt }
    }
    /// No suspension inside private read-modify-write or readback. A failed
    /// guard rolls back only our own exact bytes, never a later writer.
    @discardableResult static func save(_ record: IOSOrderedLatencyRecord, profile: String, current: () throws -> Void) throws -> [IOSOrderedLatencyRecord] {
        try current(); guard IOSOrderedLatencyRecord.hex(profile) else { throw IOSOrderedLatencyRecord.issue() }
        let checked = try IOSOrderedLatencyRecord(record.raw, execution: record.execution, extended: record.extended)
        let selected = record.execution != nil
        let originalSelection = checked.execution?.extended ?? (checked.extended?.externalFinal == true ? checked.extended : nil)
        let filename = selected ? selectedFile(originalSelection, position: checked.position) : localFile(originalSelection)
        let original = try IOSPrivateJSONStore.read(filename, maximumBytes: maximumBytes)
        var values = try entries(original, selected: selected, extended: originalSelection)
        if let index = try values.firstIndex(where: { entry in
            guard entry.profile_sha256 == profile else { return false }
            return try entry.record(extended: originalSelection).key == checked.key
        }) {
            let previous = try values[index].record(extended: originalSelection)
            guard previous.request != checked.request, previous.measuredAt <= checked.measuredAt else { throw IOSOrderedLatencyRecord.issue() }
            values.remove(at: index)
        }
        guard values.count < 128 else { throw IOSOrderedLatencyRecord.issue() }
        values.append(Entry(profile_sha256: profile, receipt: checked.raw, execution: checked.execution?.binding))
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let written = try encoder.encode(Envelope(schema: 1, records: values)); _ = try entries(written, selected: selected, extended: originalSelection)
        var history = [checked]
        if let e = checked.execution {
            history = try Self.selected(values, profile: profile, source: e.binding.preparation_source_sha256, config: e.binding.preparation_config_sha256,
                                        requested: e.binding.requested_execution, ids: e.ids, kinds: e.kinds, extended: originalSelection).filter { $0.node == checked.node }
        }
        try current()
        do {
            try IOSPrivateJSONStore.write(written, filename: filename, maximumBytes: maximumBytes)
            guard try IOSPrivateJSONStore.read(filename, maximumBytes: maximumBytes) == written else { throw IOSOrderedLatencyRecord.issue() }
            try current()
        } catch {
            if (try? IOSPrivateJSONStore.read(filename, maximumBytes: maximumBytes)) == written {
                if let original { try IOSPrivateJSONStore.write(original, filename: filename, maximumBytes: maximumBytes) }
                else { try IOSPrivateJSONStore.remove(filename) }
            }
            throw error
        }
        return history
    }
}
