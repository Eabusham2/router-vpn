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
    func validate(prefix: IOSNodeCandidatePrefix, source: String, config: String, ids: Set<String>) throws {
        guard schema == 1, prefix_position == prefix.position, prefix_id == prefix.profile_id,
              source_sha256 == source, config_sha256 == config,
              IOSCandidateCatalogPublication.isDigest(capture_sha256), (1...64).contains(targets.count),
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
        let distribution: Distribution
        let trimmed_mean_ms: Double
        var valid: Bool {
            schema == 1 && attempts == 50 && failed == 0 && measurement == "routed-tcp-connect" && distribution.valid &&
                trimmed_mean_ms.isFinite && trimmed_mean_ms >= distribution.min_ms && trimmed_mean_ms <= distribution.max_ms
        }
    }
    struct Row: Decodable {
        let node_id: String, role: String, kind: String
        let ready: Bool
        let failure: String?
        let benchmark: Benchmark?
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
    func score(request: String, target: IOSNodeCandidateMetadata.Target, metadata: IOSNodeCandidateMetadata, now: Int64) throws -> Benchmark {
        guard schema == 1, measurement == "routed-tcp-connect", request_id == request, complete, drained,
              stage == "complete", failure?.isEmpty != false, capture_sha256 == metadata.capture_sha256,
              prefix_position == metadata.prefix_position, prefix_id == metadata.prefix_id,
              candidate_id == target.id, candidate_source_sha256 == target.source_sha256,
              measured_at > 0, measured_at <= now, expires_at > measured_at, expires_at - measured_at == 120000, now < expires_at,
              results.count == 1, let row = results.first, row.node_id == target.id,
              row.role == "candidate", row.kind == "tcp-connect", row.ready, row.failure?.isEmpty != false,
              let benchmark = row.benchmark, benchmark.valid else { throw Self.issue() }
        return benchmark
    }
    static func issue() -> NSError { NSError(domain: "RouterVPN.CandidateResult", code: 1, userInfo: [NSLocalizedDescriptionKey: "Candidate timing is incomplete, expired or belongs to another source or prefix."]) }
}
