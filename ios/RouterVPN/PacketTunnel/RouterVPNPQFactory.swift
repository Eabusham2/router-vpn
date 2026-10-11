import Foundation
import Libbox
import RouterVPNPQ

/// Socket-free protocol host; the Go owner retains network and peer policy.
final class RouterVPNPQFactory: NSObject, LibboxRouterPQFactoryProtocol, @unchecked Sendable {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var installed = false
    static func install() throws {
        lock.lock(); defer { lock.unlock() }
        if installed { return }
        guard routervpn_rp_abi_version() == 1 else { throw pqError("Native PQ ABI mismatch") }
        var error: NSError?
        LibboxRouterInstallPQFactory(RouterVPNPQFactory(), &error)
        if let error { throw error }
        installed = true
    }
    func createProtocol(_ secretKey: Data?, publicKey: Data?, peerKey: Data?, version: Int32) throws -> (any LibboxRouterPQProtocolProtocol)? {
        guard let secretKey, let publicKey, let peerKey,
              secretKey.count == routervpn_rp_secret_size(), publicKey.count == routervpn_rp_public_size(),
              peerKey.count == publicKey.count, version == 2 || version == 3 else { throw pqError("Invalid native PQ keys") }
        var handle: UInt64 = 0
        let result = secretKey.withUnsafeBytes { s in publicKey.withUnsafeBytes { p in peerKey.withUnsafeBytes { r in
            routervpn_rp_new(s.bindMemory(to: UInt8.self).baseAddress, s.count,
                            p.bindMemory(to: UInt8.self).baseAddress, p.count,
                            r.bindMemory(to: UInt8.self).baseAddress, r.count, UInt32(version), &handle)
        } } }
        guard result == 0, handle != 0 else { if handle != 0 { _ = routervpn_rp_close(handle) }; throw pqError("Native PQ construction failed") }
        return RouterVPNPQProtocol(handle: handle)
    }
}
private func pqError(_ message: String) -> NSError {
    NSError(domain: "RouterVPN.NativePQ", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
}
final class RouterVPNPQProtocol: NSObject, LibboxRouterPQProtocolProtocol, @unchecked Sendable {
    private let lock = NSLock()
    private var handle: UInt64
    private var closeError: NSError?
    init(handle: UInt64) { self.handle = handle; super.init() }
    deinit { if handle != 0 { _ = routervpn_rp_close(handle) } }
    func processEvent(_ kind: Int32, packet: Data?) throws -> LibboxRouterPQEvent? {
        lock.lock(); defer { lock.unlock() }
        let packet = packet ?? Data()
        guard handle != 0, (0...2).contains(kind), packet.count <= 65535 else { throw pqError("Native PQ owner or event is invalid") }
        var output = [UInt8](repeating: 0, count: Int(ROUTERVPN_PQ_FRAME_CAPACITY))
        defer { output.withUnsafeMutableBytes { routervpn_pq_erase($0.baseAddress, $0.count) } }
        var size = 0
        let result = packet.withUnsafeBytes { input in
            routervpn_pq_event(handle, UInt32(kind), input.bindMemory(to: UInt8.self).baseAddress, input.count,
                              &output, output.count, &size)
        }
        guard result == 0, size >= 44, size <= output.count else { throw pqError("Native PQ event failed") }
        return try Self.decode(output, size: size)
    }
    static func decode(_ data: [UInt8], size: Int) throws -> LibboxRouterPQEvent {
        guard size >= 44, size <= 65579, size <= data.count else { throw pqError("Invalid native PQ event size") }
        func word(_ offset: Int) -> UInt32 {
            UInt32(data[offset]) | UInt32(data[offset+1]) << 8 | UInt32(data[offset+2]) << 16 | UInt32(data[offset+3]) << 24
        }
        let status = Int32(bitPattern: word(0)), wait = word(4), flags = word(8)
        guard (status == 0 || status == -2), wait <= 1000, flags & ~3 == 0, flags != 3,
              !(status == -2 && (flags != 0 || size != 44)),
              flags & 1 != 0 || data[12..<44].allSatisfy({ $0 == 0 }) else { throw pqError("Invalid native PQ event policy") }
        let event = LibboxRouterPQEvent()
        event.waitMilliseconds = Int32(wait); event.rejected = status == -2; event.expired = flags & 2 != 0
        event.packet = Data(data[44..<size])
        if flags & 1 != 0 { event.key = Data(data[12..<44]) }
        return event
    }
    func stop() throws {
        lock.lock(); defer { lock.unlock() }
        let old = handle; handle = 0
        if old != 0 && routervpn_rp_close(old) != 0 { closeError = pqError("Native PQ cleanup failed") }
        if let closeError { throw closeError }
    }
}
