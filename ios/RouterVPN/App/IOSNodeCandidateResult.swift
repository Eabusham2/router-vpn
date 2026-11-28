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
    var candidate_mode: String? = nil
    var candidate_kind: String? = nil
    var purpose: String? = nil
    var append_source_metadata_sha256: String? = nil
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
    var original_source_sha256: String? = nil
    var execution_source_sha256: String? = nil
    var execution_capture_sha256: String? = nil
    var original_preparation_source_sha256: String? = nil
    var original_preparation_capture_sha256: String? = nil
    func validateAppendExecution(prefix: IOSNodeCandidatePrefixCapture, ids: Set<String>) throws {
        guard prefix.isAppendExecution, prefix.native.isExecution, schema == 1,
              purpose == "draft-prefix-append-execution", metric == "routed-candidate-response", candidate_mode == prefix.responseMode,
              IOSNodeCandidateAppendSource.executionNextModes.contains(candidate_mode ?? ""), candidate_kind == nil,
              requested_execution == prefix.requestedExecution, ["server", "auto"].contains(requested_execution ?? ""),
              capture_sha256.isEmpty, execution_capture_sha256 == "", execution_source_sha256 == prefix.sourceSHA256,
              source_sha256 == prefix.sourceSHA256, config_sha256 == prefix.configSHA256, original_source_sha256 == prefix.originalSourceSHA256,
              original_preparation_source_sha256 == prefix.metadata.original_preparation_source_sha256,
              original_preparation_capture_sha256 == prefix.metadata.original_preparation_capture_sha256,
              preparation_source_sha256 == nil, preparation_config_sha256 == nil, execution == nil, selection_epoch == nil,
              append_source_metadata_sha256 == prefix.appendSourceMetadataSHA256,
              prefix_position == prefix.metadata.prefix_position, prefix_id == prefix.metadata.prefix_id,
              (1...50).contains(targets.count), targets.map(\.id) == prefix.metadata.targets.map(\.id),
              targets.map(\.source_sha256) == prefix.metadata.targets.map(\.source_sha256),
              Set(targets.map(\.id)) == ids, ids.count == targets.count,
              targets.allSatisfy({ !$0.id.isEmpty && $0.id.utf8.count <= 128 && IOSCandidateCatalogPublication.isDigest($0.source_sha256) }) else { throw IOSNodeCandidateResult.issue() }
    }
    func validate(prefix: IOSNodeCandidatePrefix, source: String, config: String, ids: Set<String>,
                  requestedExecution: String? = nil, selectedExecution: String? = nil, selectedPositions: [Int] = [0],
                  selectedResponse: IOSNodeCandidatePrefix? = nil) throws {
        guard execution_source_sha256 == nil, execution_capture_sha256 == nil,
              original_preparation_source_sha256 == nil, original_preparation_capture_sha256 == nil,
              purpose == prefix.purpose, candidate_mode == prefix.candidate_mode, candidate_kind == prefix.candidate_kind,
              (purpose == nil ? append_source_metadata_sha256 == nil && candidate_kind == nil :
                purpose == "draft-prefix-append" && IOSCandidateCatalogPublication.isDigest(append_source_metadata_sha256 ?? "")),
              candidate_mode == nil || (prefix.pairedFinalResponse || prefix.purpose == "draft-prefix-append") &&
                requestedExecution == nil && selectedExecution == nil ||
                 candidate_mode != nil && IOSMultihopNodeSelection.supportsNativePrefix(candidate_mode ?? "") &&
                 prefix.purpose == nil && requestedExecution != nil && selectedExecution != nil &&
                 selectedResponse == prefix && metric == "routed-candidate-response" else { throw IOSNodeCandidateResult.issue() }
        if let requestedExecution, let selectedExecution {
            guard ["server", "auto"].contains(requestedExecution), ["local", "server"].contains(selectedExecution),
                  requestedExecution == "auto" || requestedExecution == selectedExecution,
                  requested_execution == requestedExecution, execution == selectedExecution,
                  preparation_source_sha256 == source, preparation_config_sha256 == config,
                  metric != "routed-public-candidate-response" || source_sha256 != source,
                  selectedPositions.contains(prefix_position), prefix.supported, let selection_epoch, selection_epoch > 0,
                  IOSCandidateCatalogPublication.isDigest(source_sha256), IOSCandidateCatalogPublication.isDigest(config_sha256) else { throw IOSNodeCandidateResult.issue() }
        } else {
            guard requestedExecution == nil, selectedExecution == nil, preparation_source_sha256 == nil,
                  preparation_config_sha256 == nil, requested_execution == nil, execution == nil, selection_epoch == nil,
                  source_sha256 == source, config_sha256 == config else { throw IOSNodeCandidateResult.issue() }
        }
        guard prefix.supported, metric == prefix.metric, requestedExecution == nil || metric == "routed-tcp-connect" ||
                ["routed-candidate-response", "routed-public-candidate-response"].contains(metric) && selectedResponse == prefix,
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
    var purpose: String? = nil
    var source_sha256: String? = nil
    var execution_source_sha256: String? = nil
    var execution_capture_sha256: String? = nil
    var requested_execution: String? = nil
    var winning_execution: String? = nil
    var selection: AppendComparison? = nil
    struct AppendComparison: Decodable {
        struct Candidate: Decodable, Equatable {
            let execution: String, transport: String, entry_id: String, exit_id: String
            func validate(entry: String, exit: String) throws {
                guard ["local", "server"].contains(execution), transport == "ordered-prefix-append", entry_id == entry, exit_id == exit,
                      !entry.isEmpty, !exit.isEmpty, entry != exit else { throw IOSNodeCandidateResult.issue() }
            }
        }
        struct Measurement: Decodable {
            let candidate: Candidate, eligible: Bool
            let last_node_ms: Double?, external_ms: Double?, score_ms: Double?, failure: String?
            func score(entry: String, exit: String) throws -> Double? {
                try candidate.validate(entry: entry, exit: exit)
                let observed = [last_node_ms, external_ms, score_ms].compactMap { $0 }
                guard observed.allSatisfy({ $0.isFinite && $0 >= 0 && $0 <= 60000 }) else { throw IOSNodeCandidateResult.issue() }
                if !eligible {
                    guard score_ms == nil, failure?.isEmpty == false else { throw IOSNodeCandidateResult.issue() }
                    return nil
                }
                guard let last = last_node_ms, let external = external_ms, let score = score_ms,
                      last > 0, external > 0, score > 0, failure?.isEmpty != false,
                      abs(score - (last / 2 + external / 2)) <= 0.000001 else { throw IOSNodeCandidateResult.issue() }
                return score
            }
        }
        let target: String, measurements: [Measurement], winner: Candidate, final: Measurement
        func validate(entry: String, exit: String, execution: String) throws {
            guard ["https://1.1.1.1/cdn-cgi/trace", "https://1.0.0.1/cdn-cgi/trace"].contains(target), measurements.count == 2,
                  Set(measurements.map { $0.candidate.execution }) == ["local", "server"] else { throw IOSNodeCandidateResult.issue() }
            var minimum = Double.infinity, selected: Double?
            for lane in measurements {
                if let score = try lane.score(entry: entry, exit: exit) {
                    minimum = min(minimum, score); if lane.candidate.execution == execution { selected = score }
                }
            }
            try winner.validate(entry: entry, exit: exit)
            let finalScore = try final.score(entry: entry, exit: exit)
            guard let selected, selected <= minimum, winner.execution == execution, final.candidate == winner,
                  finalScore != nil else { throw IOSNodeCandidateResult.issue() }
        }
        var summary: String {
            let lanes = measurements.map { lane in
                let name = lane.candidate.execution == "server" ? "Server" : "Local"
                return lane.eligible ? name + String(format: " %.2f ms", lane.score_ms ?? 0) : name + " failed"
            }.joined(separator: " • ")
            return lanes + " • Winner " + (winner.execution == "server" ? "Server" : "Local") + String(format: "; final recheck %.2f ms", final.score_ms ?? 0)
        }
    }
    var appendExecutionDetails: String? {
        guard purpose == "draft-prefix-append-execution" else { return nil }
        return requested_execution == "server" ? "Server private response" : selection.map { "Compare both • " + $0.summary }
    }
    private struct ExecutionHeader: Decodable {
        let schema: Int, prefix_position: Int
        let request_id: String, stage: String, measurement: String, prefix_id: String, capture_sha256: String
        let purpose: String, source_sha256: String, execution_source_sha256: String, execution_capture_sha256: String
        let requested_execution: String, winning_execution: String
        let complete: Bool, drained: Bool
    }
    static func validateAppendExecutionStatus(_ raw: Data, request: String, prefix: IOSNodeCandidatePrefixCapture,
                                             runtimeCapture: String, completed: Bool) throws {
        let required: Set<String> = ["request_id","stage","complete","drained","results","schema","measurement","prefix_position","prefix_id","capture_sha256","purpose","source_sha256","execution_source_sha256","execution_capture_sha256","requested_execution","winning_execution"]
        let optional: Set<String> = ["failure","candidate_id","candidate_source_sha256","measured_at","expires_at","selection"]
        guard raw.count <= 65536, prefix.isAppendExecution, IOSCandidateCatalogPublication.validRequest(request),
              IOSCandidateCatalogPublication.isDigest(runtimeCapture),
              let object = try JSONSerialization.jsonObject(with: raw) as? [String: Any], required.isSubset(of: object.keys), Set(object.keys).isSubset(of: required.union(optional)),
              object["results"] is [[String: Any]], object["failure"] == nil || object["failure"] is String else { throw issue() }
        let value = try JSONDecoder().decode(ExecutionHeader.self, from: raw)
        guard value.schema == 1, value.request_id == request, !completed || value.complete && value.drained,
              value.purpose == "draft-prefix-append-execution", value.measurement == "routed-candidate-response",
              value.source_sha256 == prefix.originalSourceSHA256, value.execution_source_sha256 == prefix.sourceSHA256,
              value.requested_execution == prefix.requestedExecution, ["server", "auto"].contains(value.requested_execution),
              value.capture_sha256 == runtimeCapture, value.execution_capture_sha256 == runtimeCapture,
              value.prefix_position == prefix.metadata.prefix_position, value.prefix_id == prefix.metadata.prefix_id,
              ["", "local", "server"].contains(value.winning_execution), value.requested_execution == "auto" || value.winning_execution != "local" else { throw issue() }
    }
    private static func comparisonFields(_ value: [String: Any]) throws {
        func keys(_ value: [String: Any], required: Set<String>, optional: Set<String> = []) throws {
            guard required.isSubset(of: value.keys), Set(value.keys).isSubset(of: required.union(optional)) else { throw issue() }
        }
        func candidate(_ value: Any?) throws {
            guard let value = value as? [String: Any] else { throw issue() }
            try keys(value, required: ["execution","transport","entry_id","exit_id"])
        }
        func measurement(_ value: Any?) throws {
            guard let value = value as? [String: Any] else { throw issue() }
            try keys(value, required: ["candidate","eligible"], optional: ["last_node_ms","external_ms","score_ms","failure"])
            try candidate(value["candidate"])
        }
        try keys(value, required: ["target","measurements","winner","final"])
        guard let lanes = value["measurements"] as? [Any] else { throw issue() }
        for lane in lanes { try measurement(lane) }; try candidate(value["winner"]); try measurement(value["final"])
    }
    func requireAppendExecution(prefix: IOSNodeCandidatePrefixCapture, runtimeCapture: String) throws {
        guard prefix.isAppendExecution, purpose == "draft-prefix-append-execution", requested_execution == prefix.requestedExecution,
              measurement == "routed-candidate-response", prefix_position == prefix.metadata.prefix_position, prefix_id == prefix.metadata.prefix_id,
              source_sha256 == prefix.originalSourceSHA256, execution_source_sha256 == prefix.sourceSHA256,
              IOSCandidateCatalogPublication.isDigest(runtimeCapture), capture_sha256 == runtimeCapture, execution_capture_sha256 == runtimeCapture,
              IOSCandidateCatalogPublication.validRequest(request_id), let winner = winning_execution,
              ["local", "server"].contains(winner) else { throw Self.issue() }
        if requested_execution == "server" { guard winner == "server", selection == nil else { throw Self.issue() } }
        else {
            guard requested_execution == "auto", let selection, let entry = prefix.responseSourceNodes?.first?.id else { throw Self.issue() }
            try selection.validate(entry: entry, exit: candidate_id, execution: winner)
        }
    }
    static func measuredAppendExecution(_ raw: Data, request: String, target: IOSNodeCandidateMetadata.Target,
                                       metadata: IOSNodeCandidateMetadata, prefix: IOSNodeCandidatePrefixCapture,
                                       runtimeCapture: String, now: Int64) throws -> (Self, Benchmark)? {
        try validateAppendExecutionStatus(raw, request: request, prefix: prefix, runtimeCapture: runtimeCapture, completed: true)
        guard let body = try JSONSerialization.jsonObject(with: raw) as? [String: Any] else { throw issue() }
        if body["stage"] as? String != "complete" || (body["failure"] as? String)?.isEmpty == false { return nil }
        guard let rows = body["results"] as? [[String: Any]], rows.count == 1, rows[0]["ready"] as? Bool == true else { return nil }
        if prefix.requestedExecution == "auto" {
            guard let selection = body["selection"] as? [String: Any] else { throw issue() }
            try comparisonFields(selection)
        } else { guard body["selection"] == nil else { throw issue() } }
        let value = try JSONDecoder().decode(Self.self, from: raw)
        return (value, try value.scoreAppendExecution(request: request, target: target, metadata: metadata, prefix: prefix, runtimeCapture: runtimeCapture, now: now))
    }
    func scoreAppendExecution(request: String, target: IOSNodeCandidateMetadata.Target, metadata: IOSNodeCandidateMetadata,
                              prefix: IOSNodeCandidatePrefixCapture, runtimeCapture: String, now: Int64) throws -> Benchmark {
        try requireAppendExecution(prefix: prefix, runtimeCapture: runtimeCapture)
        guard metadata.purpose == "draft-prefix-append-execution", metadata.capture_sha256.isEmpty,
              metadata.execution_capture_sha256 == "", metadata.source_sha256 == prefix.sourceSHA256,
              metadata.requested_execution == requested_execution else { throw Self.issue() }
        return try scored(originalRow(request: request, target: target, metadata: metadata, now: now, selectedPublic: nil, expectedCapture: runtimeCapture))
    }
    private func originalRow(request: String, target: IOSNodeCandidateMetadata.Target, metadata: IOSNodeCandidateMetadata, now: Int64, selectedPublic: IOSNodeCandidatePrefix?, expectedCapture: String? = nil) throws -> Row {
        let kind: String
        switch measurement {
        case "routed-tcp-connect": kind = "tcp-connect"
        case "routed-candidate-response": kind = "private-agent-response"
        case "routed-public-candidate-response":
            if let requested = metadata.requested_execution {
                guard let selectedPublic, selectedPublic.supported, selectedPublic.metric == measurement,
                      selectedPublic.position == metadata.prefix_position, selectedPublic.profile_id == metadata.prefix_id,
                      ["server", "auto"].contains(requested), let winner = metadata.execution,
                      ["local", "server"].contains(winner), requested == "auto" || requested == winner,
                      (metadata.selection_epoch ?? 0) > 0,
                      metadata.source_sha256 != metadata.preparation_source_sha256,
                      IOSCandidateCatalogPublication.isDigest(metadata.preparation_source_sha256 ?? ""),
                      IOSCandidateCatalogPublication.isDigest(metadata.preparation_config_sha256 ?? "") else { throw Self.issue() }
            } else {
                guard metadata.execution == nil, metadata.selection_epoch == nil,
                      metadata.preparation_source_sha256 == nil, metadata.preparation_config_sha256 == nil else { throw Self.issue() }
            }
            kind = "public-exit-response"
        default: throw Self.issue()
        }
        guard schema == 1, measurement == metadata.metric, request_id == request, complete, drained,
              stage == "complete", failure?.isEmpty != false, capture_sha256 == (expectedCapture ?? metadata.capture_sha256),
              prefix_position == metadata.prefix_position, prefix_id == metadata.prefix_id,
              candidate_id == target.id, candidate_source_sha256 == target.source_sha256,
              measured_at > 0, measured_at <= now, expires_at > measured_at, expires_at - measured_at == 120000, now < expires_at,
              results.count == 1, let row = results.first, row.node_id == target.id,
              row.role == "candidate", row.kind == kind else { throw Self.issue() }
        if measurement == "routed-public-candidate-response", metadata.execution == "server",
           let benchmark = row.benchmark, benchmark.distribution.max_ms > 2500 { throw Self.issue() }
        return row
    }
    static func measuredScore(_ raw: Data, request: String, target: IOSNodeCandidateMetadata.Target,
                              metadata: IOSNodeCandidateMetadata, now: Int64,
                              selectedPublic: IOSNodeCandidatePrefix) throws -> (Self, Benchmark)? {
        let selectedPublicResponse = metadata.execution != nil && metadata.metric == "routed-public-candidate-response"
        let selectedPrivateResponse = metadata.execution == "server" && metadata.metric == "routed-candidate-response"
        if selectedPublicResponse || selectedPrivateResponse {
            let receipt = try JSONDecoder().decode(Self.self, from: raw)
            let row = try receipt.originalRow(request: request, target: target, metadata: metadata, now: now, selectedPublic: selectedPublic)
            if !row.ready {
                guard row.failure?.isEmpty == false, row.benchmark == nil,
                      row.candidate_disposition == nil || metadata.execution == "server" && row.candidate_disposition == "not-registered" else { throw Self.issue() }
                return nil
            }
            return (receipt, try receipt.scored(row))
        }
        guard let receipt = try? JSONDecoder().decode(Self.self, from: raw),
              let score = try? receipt.score(request: request, target: target, metadata: metadata, now: now, selectedPublic: selectedPublic) else { return nil }
        return (receipt, score)
    }
    func score(request: String, target: IOSNodeCandidateMetadata.Target, metadata: IOSNodeCandidateMetadata, now: Int64, selectedPublic: IOSNodeCandidatePrefix? = nil) throws -> Benchmark {
        guard purpose != "draft-prefix-append-execution", execution_source_sha256 == nil, execution_capture_sha256 == nil else { throw Self.issue() }
        return try scored(originalRow(request: request, target: target, metadata: metadata, now: now, selectedPublic: selectedPublic))
    }
    private func scored(_ row: Row) throws -> Benchmark {
        guard row.candidate_disposition == nil, row.ready, row.failure?.isEmpty != false,
              let benchmark = row.benchmark, benchmark.measurement == measurement, benchmark.valid else { throw Self.issue() }
        return benchmark
    }
    static func issue() -> NSError { NSError(domain: "RouterVPN.CandidateResult", code: 1, userInfo: [NSLocalizedDescriptionKey: "Candidate timing is incomplete, expired or belongs to another source or prefix."]) }
}
