import Foundation
import Network

struct IOSLatencyResult: Identifiable, Hashable {
    let id: String
    let name: String
    let medianMs: Double
    let minMs: Double
    let averageMs: Double
    let p90Ms: Double
    let maxMs: Double
    let samples: Int
    let failed: Int

    var shortLabel: String { String(format: "%.1f ms", medianMs) }
    var detail: String {
        String(format: "%@ — median %.1f ms • min %.1f • avg %.1f • p90 %.1f • max %.1f • %d ok / %d failed", name, medianMs, minMs, averageMs, p90Ms, maxMs, samples, failed)
    }
}

@MainActor
final class IOSUnifiedTelemetry: ObservableObject {
    @Published private(set) var latencyByID: [String: Double] = [:]
    @Published private(set) var livePathMs: Double?
    @Published private(set) var isTestingFastest = false
    @Published private(set) var lastError = ""
    @Published private(set) var animationPhase: Double = 0

    private static let cacheKey = "routervpn.ios.live-latency.v1"
    private static let probePorts: [UInt16] = [443, 8388, 10443, 11443, 12443, 13443, 14443, 15443, 51820, 51822]
    private var ticker: Timer?
    private var liveProbeBusy = false

    init() {
        if let stored = UserDefaults.standard.dictionary(forKey: Self.cacheKey) as? [String: Double] { latencyByID = stored }
        ticker = Timer.scheduledTimer(withTimeInterval: 0.45, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                self.animationPhase += 0.08
                if self.animationPhase >= 1 { self.animationPhase -= 1 }
            }
        }
    }

    deinit { ticker?.invalidate() }

    func cached(_ id: String) -> Double? { latencyByID[id] }

    func measureAll(_ profiles: [RouterProfile], samples: Int = 3) async -> [IOSLatencyResult] {
        isTestingFastest = true
        lastError = ""
        defer { isTestingFastest = false }
        var results: [IOSLatencyResult] = []
        for profile in profiles where !profile.endpoint.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            do {
                let value = try await Self.measure(profile: profile, samples: min(max(samples, 1), 10))
                results.append(value)
                latencyByID[profile.id] = value.medianMs
            } catch { }
        }
        if results.isEmpty { lastError = "No node returned a live TCP latency result." }
        persist()
        return results.sorted { $0.medianMs < $1.medianMs }
    }

    func measureOne(_ profile: RouterProfile, samples: Int = 5) async throws -> IOSLatencyResult {
        let value = try await Self.measure(profile: profile, samples: min(max(samples, 1), 50))
        latencyByID[profile.id] = value.medianMs
        persist()
        return value
    }

    func refreshLivePath(profile: RouterProfile?, connected: Bool) async {
        guard connected, let profile, !liveProbeBusy else { if !connected { livePathMs = nil }; return }
        guard let base = URL(string: profile.routerAPI), !profile.routerAPI.isEmpty else { livePathMs = nil; return }
        liveProbeBusy = true
        defer { liveProbeBusy = false }
        do {
            let url = base.appending(path: "health")
            var values: [Double] = []
            for _ in 0..<2 {
                var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 1.8)
                if !profile.apiToken.isEmpty { request.setValue("Bearer \(profile.apiToken)", forHTTPHeaderField: "Authorization") }
                let started = ContinuousClock.now
                let (_, response) = try await URLSession.shared.data(for: request)
                guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else { throw URLError(.badServerResponse) }
                let elapsed = started.duration(to: .now)
                values.append(Self.durationMs(elapsed))
            }
            values.sort()
            livePathMs = Self.percentile(values, 0.5)
        } catch { livePathMs = nil }
    }

    private func persist() { UserDefaults.standard.set(latencyByID, forKey: Self.cacheKey) }

    nonisolated private static func measure(profile: RouterProfile, samples: Int) async throws -> IOSLatencyResult {
        let host = endpointHost(profile.endpoint)
        guard !host.isEmpty else { throw URLError(.badURL) }
        var port: UInt16?
        for candidate in probePorts {
            if (try? await probeTCP(host: host, port: candidate, timeoutMs: 500)) != nil { port = candidate; break }
        }
        guard let port else { throw URLError(.cannotConnectToHost) }
        var values: [Double] = []
        var failed = 0
        for _ in 0..<samples {
            do { values.append(try await probeTCP(host: host, port: port, timeoutMs: 950)) }
            catch { failed += 1 }
            try? await Task.sleep(for: .milliseconds(25))
        }
        guard !values.isEmpty else { throw URLError(.timedOut) }
        values.sort()
        return IOSLatencyResult(
            id: profile.id, name: profile.name.isEmpty ? profile.id : profile.name,
            medianMs: round3(percentile(values, 0.5)), minMs: round3(values[0]), averageMs: round3(values.reduce(0,+) / Double(values.count)),
            p90Ms: round3(percentile(values, 0.9)), maxMs: round3(values[values.count-1]), samples: values.count, failed: failed
        )
    }

    nonisolated private static func probeTCP(host: String, port: UInt16, timeoutMs: Int) async throws -> Double {
        try await withCheckedThrowingContinuation { continuation in
            let queue = DispatchQueue(label: "routervpn.ios.telemetry.\(UUID().uuidString)")
            let connection = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!, using: .tcp)
            let lock = NSLock()
            var finished = false
            let started = DispatchTime.now().uptimeNanoseconds
            let finish: @Sendable (Result<Double, Error>) -> Void = { result in
                lock.lock(); defer { lock.unlock() }
                guard !finished else { return }
                finished = true
                connection.stateUpdateHandler = nil
                connection.cancel()
                continuation.resume(with: result)
            }
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    let elapsed = Double(DispatchTime.now().uptimeNanoseconds - started) / 1_000_000
                    finish(.success(elapsed))
                case .failed(let error): finish(.failure(error))
                case .cancelled: break
                default: break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + .milliseconds(timeoutMs)) { finish(.failure(URLError(.timedOut))) }
        }
    }

    nonisolated private static func endpointHost(_ value: String) -> String {
        let raw = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if let url = URL(string: raw.contains("://") ? raw : "tcp://\(raw)"), let host = url.host { return host }
        if raw.hasPrefix("["), let end = raw.firstIndex(of: "]") { return String(raw[raw.index(after: raw.startIndex)..<end]) }
        if raw.filter({ $0 == ":" }).count == 1, let colon = raw.lastIndex(of: ":") { return String(raw[..<colon]) }
        return raw
    }
    nonisolated private static func percentile(_ values: [Double], _ p: Double) -> Double { guard values.count > 1 else { return values.first ?? 0 }; let index = p * Double(values.count - 1); let lo = Int(floor(index)), hi = Int(ceil(index)); if lo == hi { return values[lo] }; return values[lo] * (Double(hi)-index) + values[hi] * (index-Double(lo)) }
    nonisolated private static func round3(_ value: Double) -> Double { (value * 1000).rounded() / 1000 }
    nonisolated private static func durationMs(_ duration: Duration) -> Double { let c = duration.components; return Double(c.seconds) * 1000 + Double(c.attoseconds) / 1_000_000_000_000_000 }
}
