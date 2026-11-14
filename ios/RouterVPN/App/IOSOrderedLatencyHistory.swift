import Foundation
import CoreFoundation

/// Historical cumulative-path responses only. Never direct-node ranking or
/// connection authority. The closed receipt grammar excludes labels/secrets.
struct IOSOrderedLatencyRecord: Sendable {
    let raw: String, source: String, config: String, generation: String, node: String, request: String, kind: String
    let position: Int, measuredAt: Int64
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
    init(_ raw: String, now: Date = Date()) throws {
        let v = try Self.object(raw, maximum: 8192)
        try Self.keys(v, ["schema", "source_sha256", "config_sha256", "generation_sha256", "position", "node_id", "request_id", "measured_at", "result"])
        source = try Self.text(v, "source_sha256"); config = try Self.text(v, "config_sha256"); generation = try Self.text(v, "generation_sha256")
        node = try Self.text(v, "node_id"); request = try Self.text(v, "request_id")
        let p = try Self.integer(v, "position"); measuredAt = try Self.integer(v, "measured_at")
        guard try Self.integer(v, "schema") == 1, Self.hex(source), Self.hex(config), Self.hex(generation), Self.hex(request, 32),
              node.range(of: "\\A[A-Za-z0-9_-]{1,64}\\z", options: .regularExpression) != nil,
              p < 3, measuredAt > 0, Double(measuredAt) <= now.timeIntervalSince1970 * 1000 + 60000,
              let result = v["result"] as? [String: Any] else { throw Self.issue() }
        position = Int(p)
        try Self.keys(result, ["node_id", "role", "kind", "label", "ready", "benchmark"])
        kind = try Self.text(result, "kind")
        let role = position == 0 ? "entry" : position == 2 ? "exit" : "intermediate"
        let expectedKind = position == 1 ? "public-path" : "private-node"
        let label = position == 1 ? "Cumulative path through custom node 2 of 3 → Cloudflare edge" : "Cumulative path through node \(position + 1) of 3"
        guard try Self.text(result, "node_id") == node, try Self.text(result, "role") == role,
              try Self.text(result, "label") == label, try Self.boolean(result, "ready"), kind == expectedKind,
              let benchmark = result["benchmark"] as? [String: Any], let d = benchmark["distribution"] as? [String: Any] else { throw Self.issue() }
        try Self.keys(benchmark, ["schema", "measurement", "endpoint", "attempts", "failed", "distribution", "trimmed_mean_ms"])
        try Self.keys(d, ["samples", "min_ms", "median_ms", "average_ms", "p90_ms", "max_ms", "jitter_ms"])
        guard try Self.integer(benchmark, "schema") == 1, try Self.integer(benchmark, "attempts") == 50, try Self.integer(benchmark, "failed") == 0,
              try Self.integer(d, "samples") == 50,
              try Self.text(benchmark, "measurement") == (position == 1 ? "routed-https-response-after-tls" : "routed-private-response-including-connection"),
              try Self.text(benchmark, "endpoint") == (position == 1 ? "https://speed.cloudflare.com/__down?bytes=1" : "") else { throw Self.issue() }
        minimum = try Self.number(d, "min_ms"); median = try Self.number(d, "median_ms"); average = try Self.number(d, "average_ms")
        p90 = try Self.number(d, "p90_ms"); maximum = try Self.number(d, "max_ms"); jitter = try Self.number(d, "jitter_ms"); trimmed = try Self.number(benchmark, "trimmed_mean_ms")
        guard [minimum, median, average, p90, maximum, trimmed].allSatisfy({ $0 > 0 && $0 <= 60000 }),
              minimum <= median, median <= p90, p90 <= maximum, minimum <= average, average <= maximum,
              minimum <= trimmed, trimmed <= maximum, jitter >= 0, jitter <= maximum - minimum + 1e-9 else { throw Self.issue() }
        self.raw = raw
    }
    var key: String { "\(source):\(config):\(position):\(node):\(kind)" }
    var detail: String {
        let meaning = position == 1 ? "HTTPS responses through the custom middle, timed after DNS, TCP and TLS preparation." : "Authenticated private HTTP responses through the ordered prefix, including connection establishment."
        return String(format: "Historical • 50 successful responses, 0 failed\nMedian %.2f ms • min %.2f • average %.2f\n10%% trimmed mean %.2f • p90 %.2f • max %.2f • jitter %.2f\n", median, minimum, average, trimmed, p90, maximum, jitter) +
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
    static func completed(status raw: String, saved: String, source: String, config: String, node: String, position: Int, request: String) throws -> Self {
        let status = try status(raw, request: request), result = try Self(saved)
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
    struct Entry: Codable { let profile_sha256: String; let receipt: String }
    struct Envelope: Codable { let schema: Int; let records: [Entry] }
    static func entries(_ data: Data?) throws -> [Entry] {
        guard let data else { return [] }
        guard data.count <= maximumBytes, let raw = String(data: data, encoding: .utf8) else { throw IOSOrderedLatencyRecord.issue() }
        let v = try IOSOrderedLatencyRecord.object(raw, maximum: maximumBytes)
        try IOSOrderedLatencyRecord.keys(v, ["schema", "records"])
        guard try IOSOrderedLatencyRecord.integer(v, "schema") == 1, let records = v["records"] as? [[String: Any]], records.count <= 128 else { throw IOSOrderedLatencyRecord.issue() }
        var keys = Set<String>()
        for item in records {
            try IOSOrderedLatencyRecord.keys(item, ["profile_sha256", "receipt"])
            let profile = try IOSOrderedLatencyRecord.text(item, "profile_sha256"), record = try IOSOrderedLatencyRecord(IOSOrderedLatencyRecord.text(item, "receipt"))
            guard IOSOrderedLatencyRecord.hex(profile), keys.insert(profile + ":" + record.key).inserted else { throw IOSOrderedLatencyRecord.issue() }
        }
        return try JSONDecoder().decode(Envelope.self, from: data).records
    }
    static func load(profile: String, source: String, config: String, position: Int, node: String) throws -> IOSOrderedLatencyRecord? {
        for entry in try entries(IOSPrivateJSONStore.read(filename, maximumBytes: maximumBytes)) where entry.profile_sha256 == profile {
            let r = try IOSOrderedLatencyRecord(entry.receipt)
            if r.source == source && r.config == config && r.position == position && r.node == node { return r }
        }
        return nil
    }
    /// No suspension inside private read-modify-write or readback. A failed
    /// guard rolls back only our own exact bytes, never a later writer.
    static func save(_ record: IOSOrderedLatencyRecord, profile: String, current: () throws -> Void) throws {
        try current(); guard IOSOrderedLatencyRecord.hex(profile) else { throw IOSOrderedLatencyRecord.issue() }
        let checked = try IOSOrderedLatencyRecord(record.raw)
        let original = try IOSPrivateJSONStore.read(filename, maximumBytes: maximumBytes)
        var values = try entries(original)
        if let index = try values.firstIndex(where: { entry in
            guard entry.profile_sha256 == profile else { return false }
            return try IOSOrderedLatencyRecord(entry.receipt).key == checked.key
        }) {
            let previous = try IOSOrderedLatencyRecord(values[index].receipt)
            guard previous.request != checked.request, previous.measuredAt <= checked.measuredAt else { throw IOSOrderedLatencyRecord.issue() }
            values.remove(at: index)
        }
        guard values.count < 128 else { throw IOSOrderedLatencyRecord.issue() }
        values.append(Entry(profile_sha256: profile, receipt: checked.raw))
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let written = try encoder.encode(Envelope(schema: 1, records: values)); _ = try entries(written)
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
    }
}
