import Foundation

struct IOSNodeCandidateMetadata: Decodable {
    struct Target: Decodable { let id: String; let source_sha256: String }
    let schema: Int
    let capture_sha256: String
    let prefix_position: Int
    let prefix_id: String
    let source_sha256: String
    let config_sha256: String
    let targets: [Target]
    var measurement: String? = nil
    var metric: String { measurement ?? "routed-tcp-connect" }
    static func label(_ metric: String) -> String {
        switch metric {
        case "routed-public-candidate-response": return "verified public-exit HTTPS responses"
        case "routed-candidate-response": return "private-agent responses"
        default: return "TCP connections"
        }
    }
    var preparation_source_sha256: String? = nil
    var preparation_config_sha256: String? = nil
    var requested_execution: String? = nil
    var execution: String? = nil
    var selection_epoch: Int64? = nil
    func validate(prefix: IOSNodeCandidatePrefix, source: String, config: String, ids: Set<String>,
                  requestedExecution: String? = nil, selectedExecution: String? = nil, selectedPositions: [Int] = [0],
                  selectedResponse: IOSNodeCandidatePrefix? = nil) throws {
        if let requestedExecution, let selectedExecution {
            guard ["server", "auto"].contains(requestedExecution), ["local", "server"].contains(selectedExecution),
                  requestedExecution == "auto" || requestedExecution == selectedExecution,
                  requested_execution == requestedExecution, execution == selectedExecution,
                  preparation_source_sha256 == source, preparation_config_sha256 == config,
                  selectedPositions.contains(prefix_position), prefix.supported, let selection_epoch, selection_epoch > 0,
                  IOSCandidateCatalogPublication.isDigest(source_sha256), IOSCandidateCatalogPublication.isDigest(config_sha256) else { throw IOSNodeCandidateResult.issue() }
        } else {
            guard requestedExecution == nil, selectedExecution == nil, preparation_source_sha256 == nil,
                  preparation_config_sha256 == nil, requested_execution == nil, execution == nil, selection_epoch == nil,
                  source_sha256 == source, config_sha256 == config else { throw IOSNodeCandidateResult.issue() }
        }
        guard prefix.supported, metric == prefix.metric, requestedExecution == nil || metric == "routed-tcp-connect" ||
                metric == "routed-candidate-response" && selectedResponse == prefix,
              schema == 1, prefix_position == prefix.position, prefix_id == prefix.profile_id,
              IOSCandidateCatalogPublication.isDigest(capture_sha256), !targets.isEmpty,
              Set(targets.map(\.id)) == ids, Set(targets.map(\.id)).count == targets.count,
              targets.allSatisfy({ IOSCandidateCatalogPublication.isDigest($0.source_sha256) }) else { throw IOSNodeCandidateResult.issue() }
    }
}
struct IOSNodeCandidateResult: Decodable {
    struct Distribution: Decodable {
        let samples: Int
        let min_ms: Double, median_ms: Double, average_ms: Double, p90_ms: Double, max_ms: Double, jitter_ms: Double
        var valid: Bool {
            let values = [min_ms, median_ms, average_ms, p90_ms, max_ms, jitter_ms]
            return samples == 50 && values.allSatisfy({ $0.isFinite && $0 >= 0 && $0 <= 60000 }) && min_ms > 0 &&
                min_ms <= median_ms && median_ms <= p90_ms && p90_ms <= max_ms && min_ms <= average_ms && average_ms <= max_ms && jitter_ms <= max_ms - min_ms
        }
    }
    struct Benchmark: Decodable {
        let schema: Int, attempts: Int, failed: Int
        let measurement: String
        let endpoint: String?
        let distribution: Distribution
        let trimmed_mean_ms: Double
        var valid: Bool {
            schema == 1 && attempts == 50 && failed == 0 &&
                (measurement == "routed-public-candidate-response" ? endpoint == "https://1.1.1.1/cdn-cgi/trace" : endpoint?.isEmpty != false) && ["routed-tcp-connect", "routed-candidate-response", "routed-public-candidate-response"].contains(measurement) && distribution.valid &&
                trimmed_mean_ms.isFinite && trimmed_mean_ms >= distribution.min_ms && trimmed_mean_ms <= distribution.max_ms
        }
    }
    struct Row: Decodable {
        let node_id: String, role: String, kind: String
        let ready: Bool
        let failure: String?
        let benchmark: Benchmark?
        let candidate_disposition: String?
    }
    let schema: Int
    let measurement: String
    let request_id: String
    let complete: Bool, drained: Bool
    let stage: String
    let failure: String?
    let capture_sha256: String
    let prefix_position: Int
    let prefix_id: String
    let candidate_id: String
    let candidate_source_sha256: String
    let measured_at: Int64
    let expires_at: Int64
    let results: [Row]
    private func originalRow(request: String, target: IOSNodeCandidateMetadata.Target, metadata: IOSNodeCandidateMetadata, now: Int64) throws -> Row {
        let kind: String
        switch measurement {
        case "routed-tcp-connect": kind = "tcp-connect"
        case "routed-candidate-response": kind = "private-agent-response"
        case "routed-public-candidate-response":
            guard metadata.requested_execution == nil, metadata.execution == nil, metadata.selection_epoch == nil else { throw Self.issue() }
            kind = "public-exit-response"
        default: throw Self.issue()
        }
        guard schema == 1, measurement == metadata.metric, request_id == request, complete, drained,
              stage == "complete", failure?.isEmpty != false, capture_sha256 == metadata.capture_sha256,
              prefix_position == metadata.prefix_position, prefix_id == metadata.prefix_id,
              candidate_id == target.id, candidate_source_sha256 == target.source_sha256,
              measured_at > 0, measured_at <= now, expires_at > measured_at, expires_at - measured_at == 120000, now < expires_at,
              results.count == 1, let row = results.first, row.node_id == target.id,
              row.role == "candidate", row.kind == kind else { throw Self.issue() }
        return row
    }
    func selectedServerScore(request: String, target: IOSNodeCandidateMetadata.Target, metadata: IOSNodeCandidateMetadata, now: Int64) throws -> Benchmark? {
        guard metadata.execution == "server", metadata.metric == "routed-candidate-response" else { throw Self.issue() }
        let row = try originalRow(request: request, target: target, metadata: metadata, now: now)
        if !row.ready {
            guard row.failure?.isEmpty == false, row.benchmark == nil,
                  row.candidate_disposition == nil || row.candidate_disposition == "not-registered" else { throw Self.issue() }
            return nil
        }
        return try scored(row)
    }
    func score(request: String, target: IOSNodeCandidateMetadata.Target, metadata: IOSNodeCandidateMetadata, now: Int64) throws -> Benchmark {
        try scored(originalRow(request: request, target: target, metadata: metadata, now: now))
    }
    private func scored(_ row: Row) throws -> Benchmark {
        guard row.candidate_disposition == nil, row.ready, row.failure?.isEmpty != false,
              let benchmark = row.benchmark, benchmark.measurement == measurement, benchmark.valid else { throw Self.issue() }
        return benchmark
    }
    static func issue() -> NSError { NSError(domain: "RouterVPN.CandidateResult", code: 1, userInfo: [NSLocalizedDescriptionKey: "Candidate timing is incomplete, expired or belongs to another source or prefix."]) }
}
