import Foundation
@preconcurrency import Network

/// A process-wide physical-path epoch invalidates receipts across interface
/// changes without counting this measurement's own temporary VPN interface.
final class IOSViaEntryNetwork: @unchecked Sendable {
    static let shared = IOSViaEntryNetwork()
    private let lock = NSLock()
    private let monitor = NWPathMonitor(prohibitedInterfaceTypes: [.other, .loopback])
    private var generation: UInt64 = 0
    private var available = false
    private var physical: NWInterface?

    private init() {
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            let physical = path.availableInterfaces.first {
                [.wifi, .cellular, .wiredEthernet].contains($0.type) && path.usesInterfaceType($0.type)
            }
            self.lock.lock(); self.generation &+= 1
            self.available = path.status == .satisfied && physical != nil; self.physical = physical
            self.lock.unlock()
        }
        monitor.start(queue: DispatchQueue(label: "routervpn.via-entry.network"))
    }

    var current: UInt64? { lock.lock(); defer { lock.unlock() }; return available ? generation : nil }

    func physicalInterface(for captured: UInt64) -> NWInterface? {
        lock.lock(); defer { lock.unlock() }
        return available && generation == captured ? physical : nil
    }

    func snapshot() async throws -> UInt64 {
        for _ in 0..<40 {
            try Task.checkCancellation()
            if let value = current { return value }
            try await Task.sleep(for: .milliseconds(50))
        }
        throw URLError(.notConnectedToInternet)
    }
}

/// Copy only the probe's immutable input across the main-actor boundary.
/// The private profile and its source/selection ownership remain on MainActor.
struct IOSViaEntryTCPTarget: Sendable {
    let id: String
    let name: String
    let endpoint: String
}

enum IOSViaEntryTCP {
    static func endpointHost(_ endpoint: String) -> String {
        let text = endpoint.trimmingCharacters(in: .whitespacesAndNewlines)
        if let address = IPv4Address(text) { return address.debugDescription }
        if let address = IPv6Address(text) { return address.debugDescription }
        guard let parts = URLComponents(string: text.contains("://") ? text : "tcp://" + text),
              parts.user == nil, parts.password == nil, parts.path.isEmpty, parts.query == nil, parts.fragment == nil,
              let host = parts.host else { return "" }
        return host.trimmingCharacters(in: CharacterSet(charactersIn: "[]")).lowercased()
    }

    static func publicHost(_ value: String) -> Bool {
        if let ip = IPv4Address(value) {
            let b = [UInt8](ip.rawValue)
            return b[0] != 0 && b[0] != 10 && b[0] != 127 && b[0] < 224 &&
                !(b[0] == 169 && b[1] == 254) && !(b[0] == 172 && (16...31).contains(b[1])) &&
                !(b[0] == 192 && b[1] == 168) && !(b[0] == 100 && (64...127).contains(b[1]))
        }
        if let ip = IPv6Address(value) {
            let b = [UInt8](ip.rawValue)
            // Only global unicast; reject mapped/local/multicast addresses
            // that might follow a saved LAN or native-endpoint exclusion.
            return b[0] & 0xe0 == 0x20
        }
        return false
    }

    static func measure(_ target: IOSViaEntryTCPTarget, excluding excluded: Set<String>, allowIPv6: Bool = true) async throws -> IOSViaEntryValue {
        let name = target.name.isEmpty ? target.id : target.name
        let host = endpointHost(target.endpoint)
        func unavailable(_ reason: String) -> IOSViaEntryValue {
            IOSViaEntryValue(id: target.id, name: name, medianMS: nil, samples: 0, failed: 5, reason: reason)
        }
        guard publicHost(host), !excluded.contains(host), allowIPv6 || IPv6Address(host) == nil else {
            return unavailable("This candidate has no distinct public literal endpoint that can be proved through the entry.")
        }
        var ports: [UInt16] = []
        if let parts = URLComponents(string: target.endpoint.contains("://") ? target.endpoint : "tcp://" + target.endpoint),
           let port = parts.port, (1...65535).contains(port) { ports.append(UInt16(port)) }
        ports += [443, 8388, 10443, 11443, 12443, 13443, 14443, 15443]
        var tried = Set<UInt16>(), selected: UInt16?
        for port in ports where tried.insert(port).inserted {
            try Task.checkCancellation()
            do { _ = try await probe(host: host, port: port, timeoutMS: 300); selected = port; break }
            catch is CancellationError { throw CancellationError() }
            catch { }
        }
        guard let selected else { return unavailable("No TCP response endpoint answered through this entry.") }
        var values: [Double] = [], failed = 0
        for _ in 0..<5 {
            try Task.checkCancellation()
            do { values.append(try await probe(host: host, port: selected, timeoutMS: 950)) }
            catch is CancellationError { throw CancellationError() }
            catch { failed += 1 }
        }
        try Task.checkCancellation()
        values.sort()
        let median: Double?
        if values.isEmpty { median = nil }
        else if values.count % 2 == 0 { median = (values[values.count / 2 - 1] + values[values.count / 2]) / 2 }
        else { median = values[values.count / 2] }
        return IOSViaEntryValue(id: target.id, name: name, medianMS: median, samples: values.count, failed: failed,
            reason: failed == 0 ? "Five TCP connect response samples through the captured entry." : "At least one response failed; excluded from automatic selection.")
    }

    static func probe(host: String, port: UInt16, timeoutMS: Int) async throws -> Double {
        try await probe(host: host, port: port, timeoutMS: timeoutMS, physical: nil)
    }

    /// Direct rankings must bypass any other installed VPN. A missing or
    /// changed physical interface is a failure, never an unbound fallback.
    static func probeDirect(host: String, port: UInt16, timeoutMS: Int, network: UInt64) async throws -> Double {
        guard let physical = IOSViaEntryNetwork.shared.physicalInterface(for: network) else { throw CancellationError() }
        return try await probe(host: host, port: port, timeoutMS: timeoutMS, physical: physical)
    }

    private static func probe(host: String, port: UInt16, timeoutMS: Int, physical: NWInterface?) async throws -> Double {
        let state = Probe()
        let result = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                state.start(host: host, port: port, timeoutMS: timeoutMS, physical: physical, continuation: continuation)
            }
        } onCancel: { state.cancel() }
        try Task.checkCancellation()
        return result
    }

    /// All state is queue-confined. Completion waits for NWConnection's
    /// cancelled event, so the temporary tunnel cannot retire ahead of sockets.
    private final class Probe: @unchecked Sendable {
        private let queue = DispatchQueue(label: "routervpn.via-entry.tcp.\(UUID().uuidString)")
        private var connection: NWConnection?
        private var continuation: CheckedContinuation<Double, Error>?
        private var outcome: Result<Double, Error>?

        func start(host: String, port: UInt16, timeoutMS: Int, physical: NWInterface?, continuation: CheckedContinuation<Double, Error>) {
            queue.async {
                self.continuation = continuation
                if self.outcome != nil { self.deliver(); return }
                guard let port = NWEndpoint.Port(rawValue: port) else { self.finish(.failure(URLError(.badURL))); return }
                let parameters = NWParameters.tcp
                if let physical { parameters.requiredInterface = physical }
                let connection = NWConnection(host: NWEndpoint.Host(host), port: port, using: parameters)
                self.connection = connection
                let started = DispatchTime.now().uptimeNanoseconds
                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready:
                        let elapsed = Double(DispatchTime.now().uptimeNanoseconds - started) / 1_000_000
                        self.finish(elapsed.isFinite && elapsed > 0 ? .success(elapsed) : .failure(URLError(.badServerResponse)))
                    case .failed(let error): self.finish(.failure(error))
                    case .cancelled:
                        connection.stateUpdateHandler = nil; self.connection = nil
                        if self.outcome == nil { self.outcome = .failure(CancellationError()) }
                        self.deliver()
                    default: break
                    }
                }
                connection.start(queue: self.queue)
                self.queue.asyncAfter(deadline: .now() + .milliseconds(timeoutMS)) { self.finish(.failure(URLError(.timedOut))) }
            }
        }

        func cancel() { queue.async { self.finish(.failure(CancellationError())) } }
        private func finish(_ value: Result<Double, Error>) {
            guard outcome == nil else { return }
            outcome = value
            if let connection { connection.cancel() } else { deliver() }
        }
        private func deliver() {
            guard connection == nil, let continuation, let outcome else { return }
            self.continuation = nil; continuation.resume(with: outcome)
        }
    }
}
