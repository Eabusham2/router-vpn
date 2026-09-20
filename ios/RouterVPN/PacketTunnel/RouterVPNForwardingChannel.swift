import Foundation
@preconcurrency import NetworkExtension

// Only the running extension can create this transport. Even a reconnect or LAN
// route overlap cannot redirect node credentials onto an ordinary connection.
final class RouterVPNForwardingChannel: @unchecked Sendable {
    private typealias Policy = RouterVPNForwardingPolicy
    private let queue = DispatchQueue(label: "com.eabusham.routervpn.forwarding")
    private let queueKey = DispatchSpecificKey<Bool>()
    private weak var provider: NEPacketTunnelProvider?
    private var endpoint: Policy.Endpoint?
    private var sessionID = ""
    private var operationID: UUID?
    private var reply: Reply?
    private var transport: HTTPTask?

    init(provider: NEPacketTunnelProvider) {
        self.provider = provider
        queue.setSpecific(key: queueKey, value: true)
    }

    func activate(profile: [String: Any], proofID: String) {
        let checked = try? Policy.Endpoint(profile: profile, proofID: proofID)
        serial {
            invalidateLocked()
            endpoint = checked
            if checked != nil { sessionID = UUID().uuidString }
        }
    }

    func invalidate() { serial { invalidateLocked() } }

    func handle(_ message: Data, completion: @escaping (Data?) -> Void) {
        let once = Reply(completion)
        // Bound the message before retaining it on the asynchronous queue.
        guard message.count <= Policy.maxMessage else {
            once.send(Policy.failure("Forwarding message exceeds its safety limit.")); return
        }
        queue.async { [self] in
            do {
                let command = try Policy.decode(message)
                guard let endpoint, !sessionID.isEmpty else {
                    throw Policy.issue("Connect and prove a Router VPN node before using forwarding master.")
                }
                try Policy.authorize(command, endpoint: endpoint, sessionID: sessionID)
                guard operationID == nil else { throw Policy.issue("A forwarding operation is still settling; retry after it finishes.") }
                let id = UUID(), lease = sessionID
                operationID = id; reply = once
                // Prove the exact API endpoint through the existing tunnel before
                // releasing its token, rather than trusting saved node selection.
                exchange(Policy.request(endpoint: endpoint, proof: true), endpoint: endpoint, id: id, lease: lease) { [self] result in
                    do {
                        try Policy.verifyProof(Policy.response(try result.get()), endpoint: endpoint)
                        master(command: command, endpoint: endpoint, id: id, lease: lease)
                    } catch { fail(id: id) }
                }
            } catch { once.send(Policy.failure(error.localizedDescription)) }
        }
    }

    private func master(command: Policy.Command, endpoint: Policy.Endpoint, id: UUID, lease: String) {
        exchange(Policy.request(endpoint: endpoint, enabled: command.enabled), endpoint: endpoint, id: id, lease: lease) { [self] result in
            do {
                let enabled = try Policy.master(Policy.response(try result.get()), expected: command.enabled)
                if command.action == "set" {
                    // An acknowledged PUT is not enough: read the live server
                    // state back independently before showing a successful toggle.
                    exchange(Policy.request(endpoint: endpoint), endpoint: endpoint, id: id, lease: lease) { [self] readback in
                        do {
                            let verified = try Policy.master(Policy.response(try readback.get()), expected: enabled)
                            finish(id: id, data: Policy.reply(sessionID: lease, nodeID: endpoint.nodeID, enabled: verified))
                        } catch { fail(id: id) }
                    }
                } else {
                    finish(id: id, data: Policy.reply(sessionID: lease, nodeID: endpoint.nodeID, enabled: enabled))
                }
            } catch { fail(id: id) }
        }
    }

    private func exchange(_ bytes: Data, endpoint: Policy.Endpoint, id: UUID, lease: String,
                          completion: @escaping @Sendable (Result<Data, Error>) -> Void) {
        guard operationID == id, sessionID == lease, let provider else { fail(id: id); return }
        guard let port = UInt16(exactly: endpoint.port),
              let connection = RVPNTunnelTCPConnection(provider: provider, host: endpoint.host, port: port) else {
            fail(id: id); return
        }
        let task = HTTPTask(connection: connection, bytes: bytes, queue: queue) { [weak self] result in
            guard let self, self.operationID == id, self.sessionID == lease else { return }
            completion(result)
        }
        transport = task
        task.start()
    }

    private func fail(id: UUID) {
        finish(id: id, data: Policy.failure("Forwarding request could not be verified on the same tunnel. The server may have applied a change; refresh its state before retrying."))
    }

    private func finish(id: UUID, data: Data) {
        guard operationID == id else { return }
        let waiting = reply
        operationID = nil; reply = nil
        let old = transport; transport = nil; old?.cancel()
        waiting?.send(data)
    }

    private func invalidateLocked() {
        endpoint = nil; sessionID = ""
        if let id = operationID { fail(id: id) }
    }

    private func serial(_ body: () -> Void) {
        if DispatchQueue.getSpecific(key: queueKey) == true { body() }
        else { queue.sync(execute: body) }
    }

    private final class Reply: @unchecked Sendable {
        private let lock = NSLock()
        private var callback: ((Data?) -> Void)?
        init(_ callback: @escaping (Data?) -> Void) { self.callback = callback }
        func send(_ data: Data) {
            lock.lock(); let callback = self.callback; self.callback = nil; lock.unlock()
            callback?(data)
        }
    }

    // All mutable members are confined to the channel queue. A bounded read of
    // Connection: close HTTP avoids redirects, proxies, cookies and DNS fallback.
    private final class HTTPTask: @unchecked Sendable {
        let connection: RVPNTunnelTCPConnection
        let bytes: Data
        let queue: DispatchQueue
        var observation: NSKeyValueObservation?
        var deadline: DispatchWorkItem?
        var callback: (@Sendable (Result<Data, Error>) -> Void)?
        var received = Data()
        var written = false

        init(connection: RVPNTunnelTCPConnection, bytes: Data, queue: DispatchQueue,
             callback: @escaping @Sendable (Result<Data, Error>) -> Void) {
            self.connection = connection; self.bytes = bytes; self.queue = queue; self.callback = callback
        }

        func start() {
            let timer = DispatchWorkItem { [weak self] in self?.cancel() }
            deadline = timer; queue.asyncAfter(deadline: .now() + 6, execute: timer)
            observation = connection.observe(\.state, options: [.initial, .new]) { [weak self] _, _ in
                guard let self else { return }
                self.queue.async { [self] in stateChanged() }
            }
        }

        func cancel() { finish(.failure(Policy.issue("Tunnel request cancelled or timed out."))) }

        private func stateChanged() {
            guard callback != nil else { return }
            switch connection.state {
            case .connected:
                guard !written else { return }; written = true
                connection.write(bytes) { [weak self] error in
                    guard let self else { return }
                    self.queue.async { [self] in
                        if let error { finish(.failure(error)) } else { read() }
                    }
                }
            case .cancelled: cancel()
            case .disconnected:
                if !written { cancel() }
            default: break
            }
        }

        private func read() {
            guard callback != nil else { return }
            connection.readMinimumLength(1, maximumLength: 4096) { [weak self] data, error in
                guard let self else { return }
                self.queue.async { [self] in
                    guard callback != nil else { return }
                    if let error { finish(.failure(error)); return }
                    guard let data, !data.isEmpty else { finish(.success(received)); return }
                    guard received.count + data.count <= Policy.maxResponse else { cancel(); return }
                    received.append(data); read()
                }
            }
        }

        private func finish(_ result: Result<Data, Error>) {
            guard let callback else { return }
            self.callback = nil
            deadline?.cancel(); deadline = nil
            observation?.invalidate(); observation = nil
            connection.cancel()
            callback(result)
        }
    }
}
