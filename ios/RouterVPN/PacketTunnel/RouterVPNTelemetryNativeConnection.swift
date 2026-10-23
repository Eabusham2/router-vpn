import Foundation
@preconcurrency import NetworkExtension

/// The only shipping factory for the transport's socket boundary.
final class RouterVPNTelemetryNativeConnection: RouterVPNTelemetryConnection, @unchecked Sendable {
    private final class ProviderReference: @unchecked Sendable {
        weak var provider: NEPacketTunnelProvider?
        init(_ provider: NEPacketTunnelProvider) { self.provider = provider }
    }
    static func factory(_ provider: NEPacketTunnelProvider, current: @escaping @Sendable () -> Bool) -> RouterVPNTelemetryChannel.Factory {
        let reference = ProviderReference(provider)
        return { endpoint in
            guard current(), let provider = reference.provider, let port = UInt16(exactly: endpoint.port) else { return nil }
            return RouterVPNTelemetryNativeConnection(provider: provider, host: endpoint.host, port: port)
        }
    }
    private let connection: RVPNTunnelTCPConnection
    private var observation: NSKeyValueObservation?
    init?(provider: NEPacketTunnelProvider, host: String, port: UInt16) {
        guard let connection = RVPNTunnelTCPConnection(provider: provider, host: host, port: port) else { return nil }
        self.connection = connection
    }
    func observe(_ update: @escaping @Sendable (RouterVPNTelemetryConnectionState) -> Void) {
        observation = connection.observe(\.state, options: [.initial, .new]) { connection, _ in
            switch connection.state {
            case .connected: update(.connected)
            case .cancelled: update(.cancelled)
            case .disconnected, .invalid: update(.failed)
            default: break
            }
        }
    }
    func write(_ data: Data, completion: @escaping @Sendable (Error?) -> Void) { connection.write(data, completionHandler: completion) }
    func read(_ maximum: Int, completion: @escaping @Sendable (Data?, Error?) -> Void) {
        // The Objective-C boundary imports NSUInteger as UInt. Reject an
        // invalid signed limit before conversion or issuing a native read.
        guard maximum > 0, let length = UInt(exactly: maximum) else {
            completion(nil, NSError(domain: "RouterVPNTelemetryNativeConnection", code: 1,
                                    userInfo: [NSLocalizedDescriptionKey: "Invalid native telemetry read size"]))
            return
        }
        connection.readMinimumLength(1, maximumLength: length, completionHandler: completion)
    }
    func cancel() { connection.cancel() }
    func retire() { observation?.invalidate(); observation = nil }
}
