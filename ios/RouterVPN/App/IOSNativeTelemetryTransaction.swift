import Foundation

/// A lost IPC reply is not drain. Cleanup is uncancelled and can recover only
/// the exact native acknowledgement, never a timing result, from shared storage.
@MainActor final class IOSNativeTelemetryTransaction {
    typealias Send = @MainActor (String) async throws -> Data
    private let binding: IOSTelemetryProtocol.Binding
    private let kind: String
    private let send: Send
    private let recovered: @MainActor () -> Data?
    private let pause: @MainActor () async -> Void
    private let pending: @MainActor () -> Void
    private var cancelled = false
    private var cancellation: Task<IOSTelemetryProtocol.Status?, Never>?
    init(binding: IOSTelemetryProtocol.Binding, kind: String, send: @escaping Send,
         recovered: @escaping @MainActor () -> Data?, pending: @escaping @MainActor () -> Void,
         pause: @escaping @MainActor () async -> Void = { try? await Task.sleep(for: .milliseconds(250)) }) {
        self.binding = binding; self.kind = kind; self.send = send
        self.recovered = recovered; self.pause = pause; self.pending = pending
    }
    private func status(_ operation: String) async throws -> IOSTelemetryProtocol.Status {
        try IOSTelemetryProtocol.Status.decode(await send(operation), binding: binding)
    }
    func cancel() {
        cancelled = true
        guard cancellation == nil else { return }
        cancellation = Task { @MainActor in try? await self.status("telemetry-cancel") }
    }
    private func drain() async {
        if let reply = await cancellation?.value, reply.complete && reply.drained { return }
        pending()
        while true {
            if let reply = try? await status("telemetry-cancel"), reply.complete && reply.drained { return }
            if let data = recovered(), let reply = try? IOSTelemetryProtocol.Status.decode(data, binding: binding),
               reply.complete, reply.drained, reply.results.isEmpty { return }
            await pause()
        }
    }
    func run(current: @MainActor () async -> Bool) async throws -> IOSTelemetryProtocol.Result {
        do {
            var operation = "telemetry-start"
            let deadline = ProcessInfo.processInfo.systemUptime + (kind == "rtt" ? 10 : 100)
            while !cancelled, !Task.isCancelled, ProcessInfo.processInfo.systemUptime < deadline {
                guard await current(), !cancelled, !Task.isCancelled else { throw CancellationError() }
                let reply = try await status(operation)
                guard await current(), !cancelled, !Task.isCancelled else { throw CancellationError() }
                if reply.complete && reply.drained {
                    guard reply.failure == nil, reply.results.count == 1 else {
                        throw IOSTelemetryProtocol.issue(reply.failure ?? "The private-node measurement did not finish.")
                    }
                    try reply.results[0].validate(kind: kind)
                    return reply.results[0]
                }
                operation = "telemetry-status"; await pause()
            }
            throw CancellationError()
        } catch {
            cancel()
            let cleanup = Task { @MainActor in await self.drain() }
            await cleanup.value
            throw error
        }
    }
}
