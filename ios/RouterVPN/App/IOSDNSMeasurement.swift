import Foundation

struct IOSDNSMeasurementInfo: Decodable, Sendable {
    let schema: Int
    let ack_id: String
    let node_id: String
    let session_id: String
    let native_session_id: String
    let failure: String?

    static func decode(_ data: Data, request: String, node: String) throws -> Self {
        guard !data.isEmpty, data.count <= 2048 else { throw IOSDNSMeasurementStatus.issue("The DNS owner did not return a bounded session receipt.") }
        let value = try JSONDecoder().decode(Self.self, from: data)
        guard value.schema == 1, value.ack_id == request, value.node_id == node,
              UUID(uuidString: value.session_id) != nil, UUID(uuidString: value.native_session_id) != nil else {
            throw IOSDNSMeasurementStatus.issue("DNS measurement belongs to another node or native session.")
        }
        if let failure = value.failure, !failure.isEmpty {
            throw IOSDNSMeasurementStatus.issue(String(failure.prefix(1024)))
        }
        return value
    }
}

struct IOSDNSMeasurementResult: Decodable, Identifiable, Sendable, Equatable {
    let id: String
    let name: String
    let kind: String
    let address: String
    let port: Int
    let transport: String
    let server_name: String?
    let path: String?
    let route: String
    let route_label: String
    let samples: Int
    let failed: Int
    let ready: Bool
    let median_ms: Double?
    let failure: String?

    var transportLabel: String {
        ["udp": "UDP", "tcp": "TCP", "tls": "DoT", "https": "DoH", "h3": "DoH3"][transport] ?? transport
    }
    var detail: String { "\(address):\(port) • \(transportLabel) • \(route_label)" }
    var timing: String {
        guard ready, let median_ms else { return "Unavailable" }
        return String(format: "%.2f ms · median of %d", median_ms, samples)
    }

    func validate(publicTransport: String, tor: Bool) throws {
        guard Self.text(name, maximum: 160), Self.text(address, maximum: 253),
              Self.text(route, maximum: 128), Self.text(route_label, maximum: 160),
              (1...65535).contains(port), ["udp", "tcp", "tls", "https", "h3"].contains(transport),
              Self.optionalText(server_name, maximum: 253), Self.optionalText(path, maximum: 2048),
              Self.optionalText(failure, maximum: 512) else { throw IOSDNSMeasurementStatus.issue("DNS result endpoint or route is invalid.") }
        if kind == "selected" {
            guard id == "selected", route_label == "Selected DNS via " + route else {
                throw IOSDNSMeasurementStatus.issue("The selected DNS result lost its exact route.")
            }
        } else {
            guard kind == "public", let catalog = Self.catalog[id], address == catalog.0,
                  transport == publicTransport, route == "exit",
                  route_label == (tor ? "Current Tor connection" : "Current external exit"),
                  port == (transport == "tcp" ? 53 : transport == "tls" ? 853 : 443),
                  (server_name ?? "") == (transport == "tcp" ? "" : catalog.1),
                  (path ?? "") == (transport == "https" ? "/dns-query" : "") else {
                throw IOSDNSMeasurementStatus.issue("A public DNS result does not match its captured transport and catalog endpoint.")
            }
        }
        if ready {
            guard samples == 3, failed == 0, failure?.isEmpty != false,
                  let median_ms, median_ms.isFinite, median_ms > 0 else {
                throw IOSDNSMeasurementStatus.issue("DNS timing requires three valid matching answers.")
            }
        } else {
            guard (0...2).contains(samples), failed == 3 - samples, median_ms == nil,
                  failure?.isEmpty == false else {
                throw IOSDNSMeasurementStatus.issue("An incomplete DNS result cannot contain a timing value.")
            }
        }
    }

    private static func text(_ value: String, maximum: Int) -> Bool {
        !value.isEmpty && value.utf8.count <= maximum && !value.contains(where: { $0.isNewline || $0 == "\0" })
    }
    private static func optionalText(_ value: String?, maximum: Int) -> Bool {
        value == nil || value == "" || text(value!, maximum: maximum)
    }
    static let catalog: [String: (String, String)] = [
        "cf4a": ("1.1.1.1", "cloudflare-dns.com"), "cf4b": ("1.0.0.1", "cloudflare-dns.com"),
        "cf6a": ("2606:4700:4700::1111", "cloudflare-dns.com"), "cf6b": ("2606:4700:4700::1001", "cloudflare-dns.com"),
        "g4a": ("8.8.8.8", "dns.google"), "g4b": ("8.8.4.4", "dns.google"),
        "g6a": ("2001:4860:4860::8888", "dns.google"), "g6b": ("2001:4860:4860::8844", "dns.google"),
        "q4a": ("9.9.9.9", "dns.quad9.net"), "q4b": ("149.112.112.112", "dns.quad9.net"),
        "q6a": ("2620:fe::fe", "dns.quad9.net"), "q6b": ("2620:fe::9", "dns.quad9.net")
    ]
}

struct IOSDNSMeasurementStatus: Decodable, Sendable {
    let schema: Int
    let request_id: String
    let ack_id: String
    let node_id: String
    let session_id: String
    let native_session_id: String
    let public_transport: String
    let stage: String
    let complete: Bool
    let drained: Bool
    let failure: String?
    let results: [IOSDNSMeasurementResult]

    static func issue(_ text: String) -> NSError {
        NSError(domain: "RouterVPN.DNSMeasurement", code: 1, userInfo: [NSLocalizedDescriptionKey: text])
    }
    static func decode(_ data: Data, request: String, owner: IOSDNSMeasurementInfo) throws -> Self {
        guard !data.isEmpty, data.count <= 65536 else { throw issue("The captured DNS owner did not return a bounded response.") }
        let value = try JSONDecoder().decode(Self.self, from: data)
        guard value.schema == 1, value.request_id == request, value.ack_id == request,
              value.node_id == owner.node_id, value.session_id == owner.session_id,
              value.native_session_id == owner.native_session_id, value.results.count <= 13,
              !value.stage.isEmpty, value.stage.utf8.count <= 64,
              value.failure.map({ $0.utf8.count <= 1024 }) ?? true else {
            throw issue("The DNS reply is stale or belongs to another captured native owner.")
        }
        return value
    }
    func validatedResults(transport: String, tor: Bool) throws -> [IOSDNSMeasurementResult] {
        guard complete, drained, failure?.isEmpty != false, public_transport == transport,
              ["tcp", "tls", "https"].contains(transport), results.count == 13,
              results.first?.id == "selected",
              Set(results.map(\.id)) == Set(IOSDNSMeasurementResult.catalog.keys).union(["selected"]) else {
            throw Self.issue(failure ?? "DNS comparison did not finish with every captured resolver accounted for.")
        }
        for value in results { try value.validate(publicTransport: transport, tor: tor) }
        return results.sorted {
            if $0.kind != $1.kind { return $0.kind == "selected" }
            if $0.ready != $1.ready { return $0.ready }
            if $0.median_ms != $1.median_ms { return ($0.median_ms ?? .greatestFiniteMagnitude) < ($1.median_ms ?? .greatestFiniteMagnitude) }
            return $0.id < $1.id
        }
    }
}

/// The host keeps its native MTU hold and transaction lease while this actual
/// request is running or awaiting a real drain acknowledgement.
@MainActor final class IOSDNSMeasurementTransaction {
    typealias Send = @MainActor (String) async throws -> Data
    private let id: String
    private let owner: IOSDNSMeasurementInfo
    private let transport: String
    private let tor: Bool
    private let send: Send
    private let recovered: @MainActor () -> Data?
    private let pause: @MainActor () async -> Void
    private var cancelled = false
    private var cancellation: Task<IOSDNSMeasurementStatus?, Never>?

    init(id: String, owner: IOSDNSMeasurementInfo, transport: String, tor: Bool, send: @escaping Send,
         recovered: @escaping @MainActor () -> Data? = { nil },
         pause: @escaping @MainActor () async -> Void = { try? await Task.sleep(for: .milliseconds(350)) }) throws {
        guard id.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil,
              ["tcp", "tls", "https"].contains(transport) else { throw CancellationError() }
        self.id = id; self.owner = owner; self.transport = transport; self.tor = tor
        self.send = send; self.recovered = recovered; self.pause = pause
    }
    private func status(_ operation: String) async throws -> IOSDNSMeasurementStatus {
        try IOSDNSMeasurementStatus.decode(await send(operation), request: id, owner: owner)
    }
    func cancel() {
        cancelled = true
        guard cancellation == nil else { return }
        cancellation = Task { @MainActor in try? await self.status("dns-measure-cancel") }
    }
    private func drain(pending: @MainActor () -> Void) async {
        if let value = await cancellation?.value, value.complete && value.drained { return }
        pending()
        while true {
            // Disk can acknowledge cleanup only. It never enters run's
            // successful-result path or restores comparison timings.
            if let data = recovered(),
               let value = try? IOSDNSMeasurementStatus.decode(data, request: id, owner: owner),
               value.complete && value.drained && value.results.isEmpty && value.failure?.isEmpty == false { return }
            if let value = try? await status("dns-measure-drain"), value.complete && value.drained { return }
            await pause()
        }
    }
    func run(current: @MainActor () async -> Bool, pending: @escaping @MainActor () -> Void,
             update: @MainActor (String) -> Void) async throws -> [IOSDNSMeasurementResult] {
        do {
            var operation = "dns-measure-start"
            let deadline = ProcessInfo.processInfo.systemUptime + 90
            while !cancelled && !Task.isCancelled && ProcessInfo.processInfo.systemUptime < deadline {
                guard await current(), !cancelled, !Task.isCancelled else { throw CancellationError() }
                let value = try await status(operation)
                guard await current(), !cancelled, !Task.isCancelled else { throw CancellationError() }
                update(value.stage)
                if value.complete && value.drained { return try value.validatedResults(transport: transport, tor: tor) }
                operation = "dns-measure-status"
                await pause()
            }
            throw CancellationError()
        } catch {
            cancel()
            let cleanup = Task { @MainActor in await self.drain(pending: pending) }
            await cleanup.value
            throw error
        }
    }
}
