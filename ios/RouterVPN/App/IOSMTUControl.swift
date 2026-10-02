import Foundation
@preconcurrency import NetworkExtension

private final class IOSMTUReply: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data, Error>?
    init(_ continuation: CheckedContinuation<Data, Error>) { self.continuation = continuation }
    func finish(_ data: Data?) {
        lock.lock(); let pending = continuation; continuation = nil; lock.unlock()
        guard let pending else { return }
        guard let data, !data.isEmpty, data.count <= 32768 else {
            pending.resume(throwing: NSError(domain: "RouterVPN.MTU", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "The captured VPN did not return a bounded MTU reply."]))
            return
        }
        pending.resume(returning: data)
    }
}

@MainActor enum IOSMTUControl {
    struct Binding {
        let connection: NETunnelProviderSession
        let connectedDate: Date
        let identity: IOSSessionIdentity
        let session: String
    }
    static func failure(_ text: String) -> NSError {
        NSError(domain: "RouterVPN.MTU", code: 1, userInfo: [NSLocalizedDescriptionKey: text])
    }
    static func send(_ connection: NETunnelProviderSession, operation: String,
                     request: String, session: String) async throws -> Data {
        let payload = try JSONSerialization.data(withJSONObject:
            ["operation": operation, "request_id": request, "session_id": session])
        guard payload.count <= 256 else { throw failure("MTU ownership message exceeds its bound") }
        return try await withCheckedThrowingContinuation { continuation in
            let reply = IOSMTUReply(continuation)
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 3) { reply.finish(nil) }
            do { try connection.sendProviderMessage(payload) { reply.finish($0) } }
            catch { reply.finish(nil) }
        }
    }
    static func capture(_ model: RouterVPNModel) async throws -> Binding {
        guard model.connected, model.activeEngine.contains("libbox"), let identity = model.activeSessionIdentity else {
            throw failure("Live Auto-MTU requires this session's native Libbox TUN. A saved MTU is not a measurement.")
        }
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        let owned = managers.filter { ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == "com.eabusham.routervpn.PacketTunnel" }
        guard owned.count == 1, let connection = owned[0].connection as? NETunnelProviderSession,
              connection.status == .connected, let date = connection.connectedDate,
              model.connected, model.activeSessionIdentity == identity else { throw CancellationError() }
        let request = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        let data = try await send(connection, operation: "mtu-status", request: request, session: "")
        guard let body = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let session = body["session_id"] as? String, UUID(uuidString: session) != nil,
              body["ack_id"] as? String == request, connection.status == .connected,
              connection.connectedDate == date, model.connected, model.activeSessionIdentity == identity else { throw CancellationError() }
        return Binding(connection: connection, connectedDate: date, identity: identity, session: session)
    }
    static func current(_ binding: Binding, model: RouterVPNModel) -> Bool {
        model.connected && model.activeSessionIdentity == binding.identity &&
        binding.connection.status == .connected && binding.connection.connectedDate == binding.connectedDate
    }
    static func message(_ binding: Binding, model: RouterVPNModel, operation: String, request: String) async throws -> Data {
        guard current(binding, model: model) else { throw CancellationError() }
        let data = try await send(binding.connection, operation: operation, request: request, session: binding.session)
        guard current(binding, model: model),
              let body = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              body["session_id"] as? String == binding.session, body["ack_id"] as? String == request else { throw CancellationError() }
        if let error = body["command_failure"] as? String { throw failure(error) }
        return data
    }
    static func holdCurrent(_ model: RouterVPNModel, request: String) async throws {
        await model.refreshTunnelStatus()
        // WireGuardKit has no adaptive MTU owner in this integration. There is
        // no native mutation to drain; never invent an MTU measurement for it.
        guard model.connected, model.activeEngine.contains("libbox") else { return }
        let binding = try await capture(model)
        var operation = "mtu-hold"
        let deadline = ProcessInfo.processInfo.systemUptime + 12
        while ProcessInfo.processInfo.systemUptime < deadline {
            try Task.checkCancellation()
            let data = try await message(binding, model: model, operation: operation, request: request)
            guard let body = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  body["measurement_hold"] as? Bool == true,
                  body["measurement_lease"] as? String == request else { throw failure("MTU comparison lease was not granted") }
            if body["measurement_ready"] as? Bool == true { return }
            operation = "mtu-status"
            try await Task.sleep(for: .milliseconds(100))
        }
        throw failure("MTU cancellation/readback did not finish; throughput measurement was not started.")
    }
    static func releaseCurrent(_ model: RouterVPNModel, request: String) async throws {
        await model.refreshTunnelStatus()
        guard model.connected, model.activeEngine.contains("libbox") else { return }
        let binding = try await capture(model)
        let data = try await message(binding, model: model, operation: "mtu-release", request: request)
        guard let body = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              body["measurement_hold"] as? Bool == false else { throw failure("MTU comparison lease release was not confirmed") }
    }
    static func withHold<T>(model: RouterVPNModel, operation: @MainActor () async throws -> T) async throws -> T {
        let lease = IOSMTUMeasurementGate.acquire()
        do {
            try await holdCurrent(model, request: lease.request)
            let result = try await operation()
            if IOSMTUMeasurementGate.release(lease) { try await releaseCurrent(model, request: lease.request) }
            return result
        } catch {
            if IOSMTUMeasurementGate.release(lease) { try? await releaseCurrent(model, request: lease.request) }
            throw error
        }
    }
}
