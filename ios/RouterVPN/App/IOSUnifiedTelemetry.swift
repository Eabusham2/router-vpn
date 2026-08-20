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

struct IOSSpeedResult: Hashable {
    let downloadMbps: Double
    let uploadMbps: Double
    let bytes: Int
    let downloadMs: Double
    let uploadMs: Double
    let serverReceiveMs: Double?
    let measuredAt: Date

    var detail: String {
        var value = String(format: "Download %.1f Mbps • Upload %.1f Mbps\n%d MiB each way • %.0f ms down • %.0f ms up", downloadMbps, uploadMbps, bytes / (1 << 20), downloadMs, uploadMs)
        if let serverReceiveMs { value += String(format: " • server received upload in %.0f ms", serverReceiveMs) }
        return value
    }
}

private final class IOSProbeOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var finished = false

    func claim() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !finished else { return false }
        finished = true
        return true
    }
}

@MainActor
final class IOSUnifiedTelemetry: ObservableObject {
    @Published private(set) var latencyByID: [String: Double] = [:]
    @Published private(set) var livePathMs: Double?
    @Published private(set) var isTestingFastest = false
    @Published private(set) var isSpeedTesting = false
    @Published private(set) var lastSpeedResult: IOSSpeedResult?
    @Published private(set) var lastError = ""

    private static let cacheKey = "routervpn.ios.live-latency.v1"
    nonisolated private static let probePorts: [UInt16] = [443, 8388, 10443, 11443, 12443, 13443, 14443, 15443, 51820, 51822]
    private var liveProbeBusy = false

    init() {
        if let stored = UserDefaults.standard.dictionary(forKey: Self.cacheKey) as? [String: Double] { latencyByID = stored }
    }

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
            let url = base.appendingPathComponent("health")
            var values: [Double] = []
            for _ in 0..<2 {
                var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 1.8)
                if !profile.apiToken.isEmpty { request.setValue("Bearer \(profile.apiToken)", forHTTPHeaderField: "Authorization") }
                let started = Date()
                let (_, response) = try await URLSession.shared.data(for: request)
                guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else { throw URLError(.badServerResponse) }
                values.append(Date().timeIntervalSince(started) * 1000)
            }
            values.sort()
            livePathMs = Self.percentile(values, 0.5)
        } catch { livePathMs = nil }
    }

    func speedTest(profile: RouterProfile?, connected: Bool, bytes requestedBytes: Int = 8 << 20) async throws -> IOSSpeedResult {
        guard connected else { throw NSError(domain: "RouterVPN", code: 1, userInfo: [NSLocalizedDescriptionKey: "Connect Router VPN before testing path speed."]) }
        guard let profile, profile.normalizedNodeKind == "router-vpn" else { throw NSError(domain: "RouterVPN", code: 2, userInfo: [NSLocalizedDescriptionKey: "Private path speed test requires a Router VPN node, not an external-only exit."]) }
        guard !profile.apiToken.isEmpty, let base = URL(string: profile.routerAPI), !profile.routerAPI.isEmpty else { throw NSError(domain: "RouterVPN", code: 3, userInfo: [NSLocalizedDescriptionKey: "Selected node has no private benchmark API/token."]) }
        let byteCount = min(max(requestedBytes, 1 << 20), 16 << 20)
        isSpeedTesting = true
        lastError = ""
        defer { isSpeedTesting = false }

        var downloadComponents = URLComponents(url: base.appendingPathComponent("api/benchmark/download"), resolvingAgainstBaseURL: false)
        downloadComponents?.queryItems = [URLQueryItem(name: "bytes", value: String(byteCount))]
        guard let downloadURL = downloadComponents?.url else { throw URLError(.badURL) }
        var downloadRequest = URLRequest(url: downloadURL, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 30)
        downloadRequest.setValue("Bearer \(profile.apiToken)", forHTTPHeaderField: "Authorization")
        downloadRequest.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        let downloadStarted = Date()
        let (downloadData, downloadResponse) = try await URLSession.shared.data(for: downloadRequest)
        let downloadSeconds = Date().timeIntervalSince(downloadStarted)
        guard let downloadHTTP = downloadResponse as? HTTPURLResponse, (200..<300).contains(downloadHTTP.statusCode), downloadData.count == byteCount else { throw URLError(.badServerResponse) }

        let uploadURL = base.appendingPathComponent("api/benchmark/upload")
        var uploadRequest = URLRequest(url: uploadURL, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 30)
        uploadRequest.httpMethod = "POST"
        uploadRequest.setValue("Bearer \(profile.apiToken)", forHTTPHeaderField: "Authorization")
        uploadRequest.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        uploadRequest.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        let uploadPayload = Data(count: byteCount)
        let uploadStarted = Date()
        let (uploadData, uploadResponse) = try await URLSession.shared.upload(for: uploadRequest, from: uploadPayload)
        let uploadSeconds = Date().timeIntervalSince(uploadStarted)
        guard let uploadHTTP = uploadResponse as? HTTPURLResponse, (200..<300).contains(uploadHTTP.statusCode) else { throw URLError(.badServerResponse) }
        struct UploadReply: Decodable { let bytes: Int; let server_receive_ms: Double? }
        let reply = try JSONDecoder().decode(UploadReply.self, from: uploadData)
        guard reply.bytes == byteCount else { throw URLError(.cannotParseResponse) }

        let mbits = Double(byteCount * 8) / 1_000_000
        let result = IOSSpeedResult(
            downloadMbps: Self.round3(mbits / max(downloadSeconds, 0.000001)),
            uploadMbps: Self.round3(mbits / max(uploadSeconds, 0.000001)),
            bytes: byteCount,
            downloadMs: Self.round3(downloadSeconds * 1000),
            uploadMs: Self.round3(uploadSeconds * 1000),
            serverReceiveMs: reply.server_receive_ms,
            measuredAt: Date()
        )
        lastSpeedResult = result
        return result
    }

    private func persist() { UserDefaults.standard.set(latencyByID, forKey: Self.cacheKey) }

    private static func measure(profile: RouterProfile, samples: Int) async throws -> IOSLatencyResult {
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
            guard let endpointPort = NWEndpoint.Port(rawValue: port) else { continuation.resume(throwing: URLError(.badURL)); return }
            let connection = NWConnection(host: NWEndpoint.Host(host), port: endpointPort, using: .tcp)
            let once = IOSProbeOnce()
            let started = DispatchTime.now().uptimeNanoseconds
            let finish: @Sendable (Result<Double, Error>) -> Void = { result in
                guard once.claim() else { return }
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

    private static func endpointHost(_ value: String) -> String {
        let raw = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if let url = URL(string: raw.contains("://") ? raw : "tcp://\(raw)"), let host = url.host { return host }
        if raw.hasPrefix("["), let end = raw.firstIndex(of: "]") { return String(raw[raw.index(after: raw.startIndex)..<end]) }
        if raw.filter({ $0 == ":" }).count == 1, let colon = raw.lastIndex(of: ":") { return String(raw[..<colon]) }
        return raw
    }
    private static func percentile(_ values: [Double], _ p: Double) -> Double { guard values.count > 1 else { return values.first ?? 0 }; let index = p * Double(values.count - 1); let lo = Int(floor(index)), hi = Int(ceil(index)); if lo == hi { return values[lo] }; return values[lo] * (Double(hi)-index) + values[hi] * (index-Double(lo)) }
    private static func round3(_ value: Double) -> Double { (value * 1000).rounded() / 1000 }
}
