import Foundation
import Security

struct IOSSpeedLabDuration: Hashable, Sendable {
    enum Mode: String, CaseIterable, Identifiable, Sendable {
        case auto
        case custom
        var id: String { rawValue }
    }

    let mode: Mode
    let minSeconds: Double
    let maxSeconds: Double

    static let automatic = IOSSpeedLabDuration(mode: .auto, minSeconds: 4, maxSeconds: 12)

    static func normalized(mode: Mode, minSeconds: Double, maxSeconds: Double) throws -> IOSSpeedLabDuration {
        if mode == .auto { return .automatic }
        guard minSeconds.isFinite, maxSeconds.isFinite,
              minSeconds >= 1, minSeconds <= 60,
              maxSeconds >= 1, maxSeconds <= 60,
              maxSeconds >= minSeconds else {
            throw NSError(domain: "RouterVPN.SpeedLab", code: 1, userInfo: [NSLocalizedDescriptionKey: "Custom Speed Lab time must satisfy 1s ≤ min ≤ max ≤ 60s."])
        }
        return IOSSpeedLabDuration(mode: .custom, minSeconds: minSeconds, maxSeconds: maxSeconds)
    }
}

struct IOSSpeedLabLatencyStats: Hashable, Sendable {
    let samples: Int
    let failed: Int
    let minMs: Double
    let medianMs: Double
    let averageMs: Double
    let p90Ms: Double
    let maxMs: Double
    let jitterMs: Double
}

struct IOSSpeedLabDirectionResult: Hashable, Sendable {
    let direction: String
    let mbps: Double
    let bytes: Int64
    let seconds: Double
    let rounds: Int
    let loadedLatency: IOSSpeedLabLatencyStats
    let bufferbloatMs: Double
    let stoppedStable: Bool
}

struct IOSSpeedLabMeasurement: Hashable, Sendable {
    let provider: String
    let duration: IOSSpeedLabDuration
    let idle: IOSSpeedLabLatencyStats
    let download: IOSSpeedLabDirectionResult
    let upload: IOSSpeedLabDirectionResult
    let startedAt: Date
    let finishedAt: Date

    var compactSummary: String {
        String(
            format: "Idle %.1f ms  •  ↓ %.1f Mbps / %.1f ms loaded  •  ↑ %.1f Mbps / %.1f ms loaded",
            idle.medianMs,
            download.mbps, download.loadedLatency.medianMs,
            upload.mbps, upload.loadedLatency.medianMs
        )
    }

    var detailedSummary: String {
        [
            "Router VPN Speed Lab",
            compactSummary,
            String(format: "Idle: min %.1f • median %.1f • avg %.1f • p90 %.1f • max %.1f • jitter %.1f ms", idle.minMs, idle.medianMs, idle.averageMs, idle.p90Ms, idle.maxMs, idle.jitterMs),
            String(format: "Download: %.1f Mbps • loaded %.1f ms • +%.1f ms bufferbloat • %.1f s • %d rounds", download.mbps, download.loadedLatency.medianMs, download.bufferbloatMs, download.seconds, download.rounds),
            String(format: "Upload: %.1f Mbps • loaded %.1f ms • +%.1f ms bufferbloat • %.1f s • %d rounds", upload.mbps, upload.loadedLatency.medianMs, upload.bufferbloatMs, upload.seconds, upload.rounds),
            "Provider: \(provider)"
        ].joined(separator: "\n")
    }
}

enum IOSSpeedLabEngine {
    private static let downloadURL = URL(string: "https://speed.cloudflare.com/__down")!
    private static let uploadURL = URL(string: "https://speed.cloudflare.com/__up")!
    private static let providerHost = "speed.cloudflare.com"

    static func run(duration requested: IOSSpeedLabDuration) async throws -> IOSSpeedLabMeasurement {
        let duration = try IOSSpeedLabDuration.normalized(mode: requested.mode, minSeconds: requested.minSeconds, maxSeconds: requested.maxSeconds)
        let started = Date()
        let idle = try await measureIdleLatency()
        try Task.checkCancellation()
        let download = try await measureDirection("download", duration: duration, idleMedian: idle.medianMs)
        try Task.checkCancellation()
        let upload = try await measureDirection("upload", duration: duration, idleMedian: idle.medianMs)
        try Task.checkCancellation()
        return IOSSpeedLabMeasurement(
            provider: "Cloudflare Speed Test edge (built-in Router VPN Speed Lab)",
            duration: duration,
            idle: idle,
            download: download,
            upload: upload,
            startedAt: started,
            finishedAt: Date()
        )
    }

    private static func ephemeralSession(timeout: TimeInterval) -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = timeout
        config.timeoutIntervalForResource = timeout
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        config.urlCache = nil
        config.httpShouldSetCookies = false
        config.httpCookieAcceptPolicy = .never
        config.httpAdditionalHeaders = ["User-Agent": "RouterVPN-SpeedLab/1", "Cache-Control": "no-store", "Accept-Encoding": "identity"]
        return URLSession(configuration: config)
    }

    private static func validatedHTTP(_ response: URLResponse, expectedBytes: Int? = nil) throws -> HTTPURLResponse {
        guard let http = response as? HTTPURLResponse,
              (200..<300).contains(http.statusCode),
              http.url?.host?.lowercased() == providerHost else {
            throw URLError(.badServerResponse)
        }
        if let expectedBytes, let length = http.value(forHTTPHeaderField: "Content-Length"), let parsed = Int(length), parsed != expectedBytes {
            throw NSError(domain: "RouterVPN.SpeedLab", code: 2, userInfo: [NSLocalizedDescriptionKey: "Speed Lab provider returned an unexpected Content-Length."])
        }
        return http
    }

    private static func probeOnce() async throws -> Double {
        var components = URLComponents(url: downloadURL, resolvingAgainstBaseURL: false)!
        components.queryItems = [
            URLQueryItem(name: "bytes", value: "1"),
            URLQueryItem(name: "r", value: String(DispatchTime.now().uptimeNanoseconds))
        ]
        guard let url = components.url else { throw URLError(.badURL) }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 2.5)
        request.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        let session = ephemeralSession(timeout: 2.5)
        defer { session.invalidateAndCancel() }
        let started = ContinuousClock.now
        let (data, response) = try await session.data(for: request)
        _ = try validatedHTTP(response, expectedBytes: 1)
        guard data.count == 1 else { throw URLError(.cannotParseResponse) }
        return round3(elapsedSeconds(since: started) * 1000)
    }

    private static func measureIdleLatency() async throws -> IOSSpeedLabLatencyStats {
        var values: [Double] = []
        var failed = 0
        for index in 0..<10 {
            try Task.checkCancellation()
            do { values.append(try await probeOnce()) }
            catch is CancellationError { throw CancellationError() }
            catch { failed += 1 }
            if index != 9 { try? await Task.sleep(for: .milliseconds(60)) }
        }
        guard values.count >= 3 else {
            throw NSError(domain: "RouterVPN.SpeedLab", code: 3, userInfo: [NSLocalizedDescriptionKey: "Too few idle-latency probes succeeded."])
        }
        return stats(values, failed: failed)
    }

    private static func loadedLatencyTask() -> Task<IOSSpeedLabLatencyStats, Error> {
        Task {
            var values: [Double] = []
            var failed = 0
            while !Task.isCancelled {
                do { values.append(try await probeOnce()) }
                catch is CancellationError { break }
                catch { if !Task.isCancelled { failed += 1 } }
                if Task.isCancelled { break }
                try? await Task.sleep(for: .milliseconds(110))
            }
            guard values.count >= 2 else {
                throw NSError(domain: "RouterVPN.SpeedLab", code: 4, userInfo: [NSLocalizedDescriptionKey: "Too few loaded-latency probes succeeded."])
            }
            return stats(values, failed: failed)
        }
    }

    private static func measureDirection(_ direction: String, duration: IOSSpeedLabDuration, idleMedian: Double) async throws -> IOSSpeedLabDirectionResult {
        guard direction == "download" || direction == "upload" else { throw URLError(.unsupportedURL) }
        let minSeconds = duration.minSeconds
        let maxSeconds = duration.maxSeconds
        let loadedTask = loadedLatencyTask()
        var totalBytes: Int64 = 0
        var transferSeconds = 0.0
        var rates: [Double] = []
        var stoppedStable = false
        let started = ContinuousClock.now
        do {
            while elapsedSeconds(since: started) < maxSeconds {
                try Task.checkCancellation()
                let bytes = roundBytes(previousMbps: rates.last ?? 0)
                let round: (Int64, Double)
                if direction == "download" { round = try await downloadRound(bytes: bytes) }
                else { round = try await uploadRound(bytes: bytes) }
                guard round.0 > 0, round.1 > 0 else { throw URLError(.zeroByteResource) }
                totalBytes += round.0
                transferSeconds += round.1
                rates.append(Double(round.0 * 8) / 1_000_000 / round.1)
                if elapsedSeconds(since: started) >= minSeconds && stable(rates) {
                    stoppedStable = true
                    break
                }
            }
            loadedTask.cancel()
            let loaded = try await loadedTask.value
            guard totalBytes > 0, transferSeconds > 0 else { throw URLError(.zeroByteResource) }
            let mbps = Double(totalBytes * 8) / 1_000_000 / transferSeconds
            return IOSSpeedLabDirectionResult(
                direction: direction,
                mbps: round3(mbps),
                bytes: totalBytes,
                seconds: round3(elapsedSeconds(since: started)),
                rounds: rates.count,
                loadedLatency: loaded,
                bufferbloatMs: round3(max(0, loaded.medianMs - idleMedian)),
                stoppedStable: stoppedStable
            )
        } catch {
            loadedTask.cancel()
            _ = try? await loadedTask.value
            throw error
        }
    }

    private static func downloadRound(bytes: Int) async throws -> (Int64, Double) {
        var components = URLComponents(url: downloadURL, resolvingAgainstBaseURL: false)!
        components.queryItems = [
            URLQueryItem(name: "bytes", value: String(bytes)),
            URLQueryItem(name: "r", value: String(DispatchTime.now().uptimeNanoseconds))
        ]
        guard let url = components.url else { throw URLError(.badURL) }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 20)
        request.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        let session = ephemeralSession(timeout: 20)
        defer { session.invalidateAndCancel() }
        let started = ContinuousClock.now
        let (data, response) = try await session.data(for: request)
        _ = try validatedHTTP(response, expectedBytes: bytes)
        guard data.count == bytes else { throw URLError(.cannotParseResponse) }
        return (Int64(data.count), max(0.000001, elapsedSeconds(since: started)))
    }

    private static func uploadRound(bytes: Int) async throws -> (Int64, Double) {
        var payload = Data(count: bytes)
        let randomStatus: Int32 = payload.withUnsafeMutableBytes { raw in
            guard let address = raw.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, raw.count, address)
        }
        guard randomStatus == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(randomStatus), userInfo: [NSLocalizedDescriptionKey: "Speed Lab could not prepare an incompressible upload payload."])
        }
        var request = URLRequest(url: uploadURL, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 20)
        request.httpMethod = "POST"
        request.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        let session = ephemeralSession(timeout: 20)
        defer { session.invalidateAndCancel() }
        let started = ContinuousClock.now
        let (_, response) = try await session.upload(for: request, from: payload)
        _ = try validatedHTTP(response)
        return (Int64(bytes), max(0.000001, elapsedSeconds(since: started)))
    }

    private static func roundBytes(previousMbps: Double) -> Int {
        guard previousMbps > 0 else { return 8 << 20 }
        let target = Int(previousMbps * 1_000_000 / 8 * 0.70)
        return min(max(target, 1 << 20), 16 << 20)
    }

    private static func stable(_ rates: [Double]) -> Bool {
        guard rates.count >= 3 else { return false }
        let values = Array(rates.suffix(3))
        let mean = values.reduce(0, +) / Double(values.count)
        guard mean > 0, let low = values.min(), let high = values.max() else { return false }
        return (high - low) / mean <= 0.04
    }

    private static func stats(_ input: [Double], failed: Int) -> IOSSpeedLabLatencyStats {
        let values = input.sorted()
        let mean = values.reduce(0, +) / Double(values.count)
        let variance = values.reduce(0) { partial, value in let delta = value - mean; return partial + delta * delta } / Double(values.count)
        return IOSSpeedLabLatencyStats(
            samples: values.count,
            failed: failed,
            minMs: round3(values.first ?? 0),
            medianMs: round3(percentile(values, 0.50)),
            averageMs: round3(mean),
            p90Ms: round3(percentile(values, 0.90)),
            maxMs: round3(values.last ?? 0),
            jitterMs: round3(sqrt(variance))
        )
    }

    private static func percentile(_ values: [Double], _ p: Double) -> Double {
        guard values.count > 1 else { return values.first ?? 0 }
        let position = p * Double(values.count - 1)
        let low = Int(floor(position)), high = Int(ceil(position))
        if low == high { return values[low] }
        let fraction = position - Double(low)
        return values[low] * (1 - fraction) + values[high] * fraction
    }

    private static func elapsedSeconds(since start: ContinuousClock.Instant) -> Double {
        let components = start.duration(to: .now).components
        return Double(components.seconds) + Double(components.attoseconds) / 1_000_000_000_000_000_000
    }

    private static func round3(_ value: Double) -> Double { (value * 1000).rounded() / 1000 }
}
