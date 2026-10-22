import Foundation

/// A direct-node TCP sample set. Routed candidate and live-tunnel measurements
/// use different types and cannot become this durable ranking accidentally.
struct IOSLatencyResult: Identifiable, Hashable, Sendable {
    let id: String
    let name: String
    let medianMs: Double
    let minMs: Double
    let averageMs: Double
    let trimmedMeanMs: Double
    let p90Ms: Double
    let maxMs: Double
    let samples: Int
    let failed: Int
    let measuredAt: Date

    var shortLabel: String { String(format: "%.1f ms", medianMs) }
    var detail: String {
        String(format: "%@ — direct TCP median %.1f ms • min %.1f • avg %.1f • 10%% trimmed %.1f • p90 %.1f • max %.1f • %d ok / %d failed",
            name, medianMs, minMs, averageMs, trimmedMeanMs, p90Ms, maxMs, samples, failed)
    }

    static func summarize(id: String, name: String, values: [Double], failed: Int,
                          measuredAt: Date = Date()) throws -> Self {
        guard !id.isEmpty, !values.isEmpty, values.count + failed <= 50, failed >= 0,
              values.allSatisfy({ $0.isFinite && $0 > 0 && $0 <= 60_000 }),
              measuredAt.timeIntervalSince1970.isFinite else { throw issue("The node returned no complete, valid latency sample set.") }
        let sorted = values.sorted(), trim = sorted.count / 10
        let middle = sorted[trim..<(sorted.count - trim)]
        func rounded(_ value: Double) -> Double { max(0.001, (value * 1000).rounded() / 1000) }
        return Self(id: id, name: name, medianMs: rounded(percentile(sorted, 0.5)), minMs: rounded(sorted[0]),
            averageMs: rounded(sorted.reduce(0, +) / Double(sorted.count)),
            trimmedMeanMs: rounded(middle.reduce(0, +) / Double(middle.count)),
            p90Ms: rounded(percentile(sorted, 0.9)), maxMs: rounded(sorted[sorted.count - 1]),
            samples: sorted.count, failed: failed, measuredAt: measuredAt)
    }

    func applying(to source: RouterProfile) throws -> RouterProfile {
        guard source.id == id, samples == 50, failed == 0,
              [minMs, medianMs, averageMs, trimmedMeanMs, p90Ms, maxMs].allSatisfy({ $0.isFinite && $0 > 0 }),
              minMs <= medianMs, medianMs <= p90Ms, p90Ms <= maxMs,
              minMs <= averageMs, averageMs <= maxMs, minMs <= trimmedMeanMs, trimmedMeanMs <= maxMs,
              measuredAt <= Date().addingTimeInterval(30), measuredAt >= Date().addingTimeInterval(-300) else {
            throw Self.issue("A durable node benchmark requires all 50 fresh direct samples; the previous ranking was kept.")
        }
        var value = source
        value.latencySamples = samples
        value.latencyMinMs = minMs; value.latencyMedianMs = medianMs
        value.latencyTrimmedMeanMs = trimmedMeanMs; value.latencyAverageMs = averageMs
        value.latencyP90Ms = p90Ms; value.latencyMaxMs = maxMs
        value.latencyLastTest = ISO8601DateFormatter().string(from: measuredAt)
        return value
    }

    static func percentile(_ sorted: [Double], _ fraction: Double) -> Double {
        guard sorted.count > 1 else { return sorted.first ?? 0 }
        let position = fraction * Double(sorted.count - 1), low = Int(floor(position)), high = Int(ceil(position))
        return low == high ? sorted[low] : sorted[low] * (Double(high) - position) + sorted[high] * (position - Double(low))
    }
    static func issue(_ text: String) -> NSError {
        NSError(domain: "RouterVPN.NodeLatency", code: 1, userInfo: [NSLocalizedDescriptionKey: text])
    }
}
