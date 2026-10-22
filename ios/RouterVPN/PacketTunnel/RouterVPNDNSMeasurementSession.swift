import Foundation
import Libbox

/// The proof-bound native handle stays reachable by its original provider
/// epoch until cancellation has joined every native worker and socket.
final class RouterVPNDNSMeasurementSession: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let native: LibboxRouterDNSMeasurement
    let epoch: String
    private let nativeSession: String
    private let nodeID: String
    private var active = ""
    private var retired = false
    private var invalidated = false
    private var closed = false
    private var receipts: [String: Data] = [:]
    private var reservations: Set<String> = []
    private var persisted: Set<String> = []
    private var retirementRetry: DispatchSourceTimer?

    init(native: LibboxRouterDNSMeasurement, epoch: String, nodeID: String) throws {
        let raw = Data(native.statusJSON().utf8)
        guard UUID(uuidString: epoch) != nil, raw.count <= 65536,
              let status = try JSONSerialization.jsonObject(with: raw) as? [String: Any],
              status["schema"] as? Int == 1, status["node_id"] as? String == nodeID,
              let session = status["session_id"] as? String, UUID(uuidString: session) != nil else {
            throw Self.failure("DNS measurement did not capture the proved native node and session.")
        }
        self.native = native; self.epoch = epoch; self.nodeID = nodeID; nativeSession = session
    }

    private static func failure(_ text: String) -> NSError {
        NSError(domain: "RouterVPN.DNSMeasurement", code: 1, userInfo: [NSLocalizedDescriptionKey: text])
    }

    var isClosed: Bool { lock.lock(); defer { lock.unlock() }; return closed }

    func info(request: String) -> Data? {
        lock.lock(); defer { lock.unlock() }
        guard !retired, !invalidated, !closed, Self.validRequest(request),
              reservations.contains(request) || reservations.count < 128 else { return nil }
        var value: [String: Any] = ["schema": 1, "ack_id": request,
            "session_id": epoch, "native_session_id": nativeSession, "node_id": nodeID]
        do {
            try IOSDNSRetirementReceipts.shared.requireAvailable()
            // Reserve before acknowledging Info. If Start is dropped or races
            // system Disconnect, Close still tombstones and drains this nonce.
            reservations.insert(request)
        } catch { value["failure"] = error.localizedDescription }
        return try? JSONSerialization.data(withJSONObject: value)
    }

    private static func validRequest(_ value: String) -> Bool {
        value.utf8.count == 32 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }

    private func status(request: String) -> Data? {
        let raw = Data(native.statusJSON().utf8)
        guard !raw.isEmpty, raw.count <= 65536,
              var value = try? JSONSerialization.jsonObject(with: raw) as? [String: Any],
              value["schema"] as? Int == 1, value["request_id"] as? String == request,
              value["session_id"] as? String == nativeSession, value["node_id"] as? String == nodeID else { return nil }
        value["native_session_id"] = nativeSession
        value["session_id"] = epoch
        value["ack_id"] = request
        if invalidated || retired {
            value["results"] = []
            value["failure"] = "The captured DNS measurement path was retired or changed."
        }
        guard let data = try? JSONSerialization.data(withJSONObject: value), data.count <= 65536 else { return nil }
        return data
    }

    private func completeAndDrained(_ data: Data) -> Bool {
        guard let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return false }
        return value["complete"] as? Bool == true && value["drained"] as? Bool == true
    }

    private func failureReceipt(_ request: String, transport: String, message: String) -> Data? {
        try? JSONSerialization.data(withJSONObject: ["schema": 1, "request_id": request, "ack_id": request,
            "node_id": nodeID, "session_id": epoch, "native_session_id": nativeSession,
            "public_transport": transport, "stage": "cancelled", "complete": true, "drained": true,
            "results": [], "failure": message])
    }

    private func save(_ data: Data, request: String) {
        guard completeAndDrained(data) else { return }
        receipts[request] = data
        // A live native acknowledgement remains valid when persistence fails.
        // Close retries these writes before releasing its recovery owner.
        try? persist(data, request: request)
    }

    private func persist(_ data: Data, request: String) throws {
        guard !persisted.contains(request) else { return }
        try IOSDNSRetirementReceipts.shared.storeDrained(data)
        persisted.insert(request)
    }

    private func retireUnstarted(_ request: String, transport: String, message: String) -> Data? {
        native.cancel(request)
        do { try native.drain(request) } catch { return nil }
        guard let data = failureReceipt(request, transport: transport, message: message) else { return nil }
        save(data, request: request)
        return data
    }

    /// Calls are bounded by the native API. Drain may wait five seconds; its
    /// timeout never becomes a successful receipt or releases this handle.
    func reply(operation: String, request: String, session: String,
               nativeSession: String, transport: String) -> Data? {
        lock.lock(); defer { lock.unlock() }
        guard session == epoch, nativeSession == self.nativeSession,
              reservations.contains(request) else { return nil }
        if let receipt = receipts[request] {
            try? persist(receipt, request: request)
            if invalidated || retired {
                return failureReceipt(request, transport: "", message: "The measured native path has changed.")
            }
            return receipt
        }
        if operation == "dns-measure-start" {
            guard !retired, !invalidated, !closed, ["tcp", "tls", "https"].contains(transport) else { return nil }
            if request == active { return status(request: request) }
            if !active.isEmpty {
                guard let previous = status(request: active), completeAndDrained(previous) else {
                    return retireUnstarted(request, transport: transport,
                        message: "Another captured DNS request is still draining.")
                }
                save(previous, request: active)
            }
            active = request
            do { try native.start(request, transport: transport) }
            catch {
                native.cancel(request)
                do {
                    try native.drain(request)
                    if let data = status(request: request) { save(data, request: request); return data }
                    let data = failureReceipt(request, transport: transport, message: error.localizedDescription)
                    if let data { save(data, request: request) }
                    return data
                } catch { return status(request: request) }
            }
        } else if operation == "dns-measure-cancel" || operation == "dns-measure-drain" {
            guard request == active else {
                // Tombstone before activation: a queued Start using this
                // nonce returns this receipt and can never launch workers.
                return retireUnstarted(request, transport: "", message: "DNS comparison cancelled before activation.")
            }
            native.cancel(request)
            if operation == "dns-measure-drain" { try? native.drain(request) }
        } else if operation != "dns-measure-status" { return nil }
        guard request == active, let data = status(request: request) else { return nil }
        save(data, request: request)
        return data
    }

    func networkChanged() {
        lock.lock(); invalidated = true; lock.unlock()
        native.networkChanged()
    }

    func close() throws {
        networkChanged()
        lock.lock(); defer { lock.unlock() }
        retired = true; invalidated = true
        guard !closed else { return }
        do {
            try native.close()
            for request in reservations.sorted() {
                // This includes Info whose Start never reached the extension.
                // A receipt follows native drain, never disconnected OS state.
                native.cancel(request)
                try native.drain(request)
                let data = receipts[request] ?? status(request: request) ?? failureReceipt(request,
                    transport: "", message: "The captured DNS request was retired before activation.")
                guard let data, completeAndDrained(data) else {
                    throw Self.failure("The native DNS workers have not confirmed retirement.")
                }
                receipts[request] = data
                try persist(data, request: request)
            }
            closed = true
            retirementRetry?.setEventHandler {}; retirementRetry?.cancel(); retirementRetry = nil
        } catch {
            scheduleRetirementRetry()
            throw error
        }
    }

    private func scheduleRetirementRetry() {
        guard retirementRetry == nil else { return }
        // System Disconnect can remove IPC after native cleanup but before a
        // receipt write succeeds. Retain this exact owner and retry locally;
        // the app never needs to manufacture an acknowledgement or reconnect.
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "routervpn.dns-retirement.\(epoch)", qos: .utility))
        timer.schedule(deadline: .now() + 1, repeating: .seconds(2), leeway: .milliseconds(250))
        timer.setEventHandler { [self] in try? close() }
        retirementRetry = timer
        timer.resume()
    }
}

/// Provider IPC can still address a captured request after the current engine
/// pointer changes. Completed sessions are bounded; unclosed owners stay held.
final class RouterVPNDNSMeasurementRegistry: @unchecked Sendable {
    static let shared = RouterVPNDNSMeasurementRegistry()
    private let lock = NSLock()
    private var sessions: [String: RouterVPNDNSMeasurementSession] = [:]
    private var order: [String] = []

    func retain(_ session: RouterVPNDNSMeasurementSession) {
        lock.lock(); defer { lock.unlock() }
        if sessions[session.epoch] == nil { order.append(session.epoch) }
        sessions[session.epoch] = session
        while order.count > 128 {
            guard let index = order.firstIndex(where: { sessions[$0]?.isClosed == true }) else { break }
            sessions.removeValue(forKey: order.remove(at: index))
        }
    }

    func reply(operation: String, request: String, session: String,
               nativeSession: String, transport: String) -> Data? {
        guard ["dns-measure-status", "dns-measure-cancel", "dns-measure-drain"].contains(operation) else { return nil }
        lock.lock(); let captured = sessions[session]; lock.unlock()
        return captured?.reply(operation: operation, request: request, session: session,
            nativeSession: nativeSession, transport: transport)
    }
}
