import Foundation
import Libbox
@preconcurrency import Network
import dnssd
import Darwin

/// One public DNS-SD query on a captured physical interface. This receiver
/// never installs a process resolver or opens its own unscoped DNS socket.
/// DNSServiceRef access, callbacks and deallocation share one serial queue.
final class RouterVPNMAXDNSOwner: NSObject, LibboxRouterMAXEndpointResolverProtocol, @unchecked Sendable {
    private let identity = UUID().uuidString.lowercased()
    private let lock = NSLock()
    private let queue = DispatchQueue(label: "routervpn.max.physical-dns", qos: .userInitiated)
    private let queueKey = DispatchSpecificKey<Bool>()
    private let monitor = NWPathMonitor()
    private let captured = DispatchSemaphore(value: 0)
    private let completed = DispatchSemaphore(value: 0)
    private var canceled = false
    private var pathStarted = false
    private var pathReady = false
    private var interfaceIndex: UInt32 = 0
    private var pathSignature = ""
    private var queryStarted = false
    private var queryFinished = false
    private var queryFailure = false
    private var queryName = ""
    private var answers: [String] = []
    // These values are confined to queue, including the raw callback context.
    private var reference: DNSServiceRef?
    private var retirementScheduled = false

    override init() {
        super.init()
        queue.setSpecific(key: queueKey, value: true)
    }

    func ownerID() -> String { identity }
    func current() -> Bool {
        lock.lock(); defer { lock.unlock() }
        return !canceled && pathReady && interfaceIndex != 0
    }

    /// Capturing the path performs no DNS. Register this receiver with the
    /// pending VPN owner before calling capture, so Stop can retire it here.
    func capture() throws {
        lock.lock()
        guard !canceled, !pathStarted else { lock.unlock(); throw Self.issue() }
        pathStarted = true
        lock.unlock()
        queue.async { [self] in
            guard !isCanceled else { finishPathFailure(); return }
            monitor.pathUpdateHandler = { [weak self] path in self?.observe(path) }
            monitor.start(queue: queue)
        }
        if captured.wait(timeout: .now() + 3) == .timedOut { cancel(); throw Self.issue() }
        queue.sync {}
        guard current() else { throw Self.issue() }
    }

    private var isCanceled: Bool { lock.lock(); defer { lock.unlock() }; return canceled }

    private func observe(_ path: NWPath) {
        guard !isCanceled else { finishPathFailure(); return }
        guard let snapshot = RouterVPNPhysicalPath.snapshot(path), path.supportsDNS,
              let selected = path.availableInterfaces.first(where: { $0.name == snapshot.name }),
              selected.index > 0, let index = UInt32(exactly: selected.index) else {
            invalidateOnQueue(); return
        }
        lock.lock()
        if !pathReady {
            interfaceIndex = index; pathSignature = snapshot.signature; pathReady = true
            lock.unlock(); captured.signal(); return
        }
        let same = interfaceIndex == index && pathSignature == snapshot.signature
        lock.unlock()
        if !same { invalidateOnQueue() }
    }

    private func invalidateOnQueue() {
        lock.lock(); canceled = true; lock.unlock()
        finishPathFailure()
        finishQueryOnQueue(failed: true)
        monitor.cancel()
    }

    private func finishPathFailure() { captured.signal() }

    // The generated nonnull NSString result keeps the NSError out-parameter;
    // Swift does not import this foreign callback as a throwing method.
    func lookup(_ hostname: String?, error failure: NSErrorPointer) -> String {
        do { return try resolve(hostname) }
        catch { failure?.pointee = error as NSError; return "" }
    }

    private func resolve(_ hostname: String?) throws -> String {
        guard let hostname, Self.validAbsoluteInput(hostname) else { throw Self.issue() }
        lock.lock()
        guard !canceled, pathReady, !queryStarted, interfaceIndex != 0 else { lock.unlock(); throw Self.issue() }
        queryStarted = true; queryName = hostname
        let index = interfaceIndex
        lock.unlock()
        // A terminal dot prevents resolver search-domain expansion. Keep the
        // original spelling in the native answer envelope and TLS capture.
        let absolute = hostname.hasSuffix(".") ? hostname : hostname + "."
        queue.sync { [self] in
            guard current() else { finishQueryOnQueue(failed: true); return }
            let error = DNSServiceGetAddrInfo(&reference, 0, index,
                DNSServiceProtocol(kDNSServiceProtocol_IPv4 | kDNSServiceProtocol_IPv6), absolute,
                { ref, flags, interface, error, name, address, _, context in
                    guard let context else { return }
                    let owner = Unmanaged<RouterVPNMAXDNSOwner>.fromOpaque(context).takeUnretainedValue()
                    owner.receive(ref, flags: flags, interface: interface, error: error, name: name, address: address)
                }, Unmanaged.passUnretained(self).toOpaque())
            guard error == kDNSServiceErr_NoError, let reference else { finishQueryOnQueue(failed: true); return }
            guard DNSServiceSetDispatchQueue(reference, queue) == kDNSServiceErr_NoError else {
                finishQueryOnQueue(failed: true); return
            }
        }
        // Native Run has its own five-second deadline and invokes Cancel.
        // This bound also protects a direct foreign caller of this receiver.
        if completed.wait(timeout: .now() + 6) == .timedOut { cancel() }
        queue.sync {} // joins deallocation and every admitted callback
        lock.lock()
        let valid = !canceled && !queryFailure && queryFinished && !answers.isEmpty
        let values = answers
        lock.unlock()
        guard valid, values.count <= 32, current() else { throw Self.issue() }
        let data = try JSONSerialization.data(withJSONObject: ["owner_id": identity, "hostname": hostname, "addresses": values], options: [.sortedKeys])
        guard data.count <= 4096 else { throw Self.issue() }
        return String(decoding: data, as: UTF8.self)
    }

    private func receive(_ ref: DNSServiceRef?, flags: DNSServiceFlags, interface: UInt32,
                         error: DNSServiceErrorType, name: UnsafePointer<CChar>?, address: UnsafePointer<sockaddr>?) {
        guard !retirementScheduled, ref == reference else { return }
        lock.lock()
        let live = !canceled && pathReady && !queryFinished
        let expectedIndex = interfaceIndex
        lock.unlock()
        guard live, error == kDNSServiceErr_NoError,
              interface == expectedIndex || interface == 0,
              let name, strnlen(name, 256) < 256,
              let address, flags & DNSServiceFlags(kDNSServiceFlagsAdd) != 0,
              let literal = Self.literal(address) else { scheduleRetirement(failed: true); return }
        // mDNSResponder reports the answer's InterfaceID/name, not the query's:
        // unicast may use index 0 and CNAME answers may use their canonical
        // name. The exact reference/context and nonzero query scope own them.
        // apple-oss-distributions/mDNSResponder@d4658af3, uds_daemon.c:3822-3888.
        lock.lock()
        if !answers.contains(literal) { answers.append(literal) }
        let bounded = answers.count <= 32
        lock.unlock()
        guard bounded else { scheduleRetirement(failed: true); return }
        if flags & DNSServiceFlags(kDNSServiceFlagsMoreComing) == 0 { scheduleRetirement(failed: false) }
    }

    private func scheduleRetirement(failed: Bool) {
        guard !retirementScheduled else { return }
        retirementScheduled = true
        // Leave the C callback before freeing its reference. Any already
        // admitted callback runs on this queue and rejects retired admission.
        queue.async { [self] in finishQueryOnQueue(failed: failed) }
    }

    private func finishQueryOnQueue(failed: Bool) {
        retirementScheduled = true
        if let old = reference { reference = nil; DNSServiceRefDeallocate(old) }
        lock.lock()
        queryFailure = queryFailure || failed
        let first = !queryFinished; queryFinished = true
        lock.unlock()
        if first { completed.signal() }
    }

    /// The provider uses this immediate signal while the native request owns
    /// the foreign Cancel call and its completion barrier.
    func beginCancel() {
        lock.lock(); canceled = true; lock.unlock()
        queue.async { [self] in
            finishPathFailure(); finishQueryOnQueue(failed: true); monitor.cancel()
        }
    }

    func cancel() {
        beginCancel()
        if DispatchQueue.getSpecific(key: queueKey) != true { queue.sync {} }
    }

    private static func validAbsoluteInput(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 253, !value.contains("\0"),
              IPv4Address(value) == nil, IPv6Address(value) == nil,
              value.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 || $0 == 46 }) else { return false }
        let host = value.hasSuffix(".") ? String(value.dropLast()) : value
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        return host.lowercased() != "localhost" && labels.allSatisfy { !$0.isEmpty && $0.utf8.count <= 63 && !$0.hasPrefix("-") && !$0.hasSuffix("-") }
    }

    private static func literal(_ address: UnsafePointer<sockaddr>) -> String? {
        var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let result: UnsafePointer<CChar>?
        if address.pointee.sa_family == sa_family_t(AF_INET) {
            var value = address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
            result = inet_ntop(AF_INET, &value, &output, socklen_t(output.count))
        } else if address.pointee.sa_family == sa_family_t(AF_INET6) {
            let socket = address.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
            guard socket.sin6_scope_id == 0 else { return nil }
            var value = socket.sin6_addr
            result = inet_ntop(AF_INET6, &value, &output, socklen_t(output.count))
        } else { return nil }
        guard result != nil else { return nil }
        return String(cString: output)
    }

    private static func issue() -> NSError {
        NSError(domain: "RouterVPN.MAXDNS", code: 1, userInfo: [NSLocalizedDescriptionKey:
            "The captured physical DNS query failed or its network owner changed."])
    }
}
