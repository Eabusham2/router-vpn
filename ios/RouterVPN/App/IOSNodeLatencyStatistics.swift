import Foundation
import CryptoKit

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

    func applying(to source: RouterProfile, network: UInt64) throws -> RouterProfile {
        guard source.id == id, source.normalizedNodeKind == "router-vpn", source.external == nil, source.multihopEnabled != true, network > 0, samples == 50, failed == 0,
              [minMs, medianMs, averageMs, trimmedMeanMs, p90Ms, maxMs].allSatisfy({ $0.isFinite && $0 > 0 && $0 <= 60_000 }),
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
        value.latencyReceipt = IOSNodeLatencyReceipt(schema: 1, measurement: "disconnected-direct-tcp-handshake", attempts: 50, failed: 0,
            sourceToken: try IOSNodeLatencyReceipt.source(source), networkMetadata: "ios-network-generation:\(network)")
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

// This is saved historical ranking, not a claim about the current network.
// A changed private node/policy cannot inherit eligibility from old fields.
extension IOSNodeLatencyReceipt {
    static func source(_ profile: RouterProfile) throws -> String {
        guard var identity = try JSONSerialization.jsonObject(with: JSONEncoder().encode(profile)) as? [String: Any] else { throw IOSLatencyResult.issue("The saved node identity is invalid.") }
        for key in Array(identity.keys) where key.hasPrefix("latency_") || key.hasPrefix("fastest_dns_") ||
            (key.hasPrefix("effective_mtu_") && key != "effective_mtu") ||
            ["name", "location", "latitude", "longitude", "use_count", "last_used_at", "public_ip", "dns_results"].contains(key) {
            identity.removeValue(forKey: key)
        }
        let data = try JSONSerialization.data(withJSONObject: identity, options: [.sortedKeys])
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    static func eligible(_ profile: RouterProfile) -> Bool {
        guard profile.normalizedNodeKind == "router-vpn", profile.external == nil, profile.multihopEnabled != true,
              let receipt = profile.latencyReceipt, receipt.schema == 1,
              receipt.measurement == "disconnected-direct-tcp-handshake", receipt.attempts == 50, receipt.failed == 0,
              profile.latencySamples == 50, !receipt.networkMetadata.isEmpty,
              let current = try? source(profile), receipt.sourceToken == current,
              let stamp = profile.latencyLastTest, let measured = ISO8601DateFormatter().date(from: stamp),
              measured.timeIntervalSince1970 > 0, measured <= Date().addingTimeInterval(30),
              let min = profile.latencyMinMs, let median = profile.latencyMedianMs,
              let trimmed = profile.latencyTrimmedMeanMs, let average = profile.latencyAverageMs,
              let p90 = profile.latencyP90Ms, let max = profile.latencyMaxMs,
              [min, median, trimmed, average, p90, max].allSatisfy({ $0.isFinite && $0 > 0 && $0 <= 60_000 }),
              min <= median, median <= p90, p90 <= max, min <= trimmed, trimmed <= max,
              min <= average, average <= max else { return false }
        return true
    }

    static func lower(_ lhs: RouterProfile, _ rhs: RouterProfile) -> Bool {
        let left = lhs.latencyTrimmedMeanMs ?? .infinity, right = rhs.latencyTrimmedMeanMs ?? .infinity
        return left == right ? lhs.id < rhs.id : left < right
    }
}
