import Foundation
import Libbox

/// The only mutable native MTU owner for one PacketTunnel lifetime. Native
/// callbacks may arrive on Go threads; every Swift state transition is locked.
/// No method creates a socket or falls back to an ambient/default interface.
final class RouterVPNMTUSession: NSObject, LibboxRouterMTUPlatformProtocol, @unchecked Sendable {
    private let stateLock = NSRecursiveLock()
    private let commandLock = NSLock()
    private let cacheLock = NSLock()
    private let sessionID = UUID().uuidString
    private var physicalName = ""
    private var physicalSignature = ""
    private var nativePhysicalHash = ""
    private var interfaceName = ""
    private var readerID = ""
    private var expectedMTU: Int32 = 0
    private var opening: UUID?
    private var changing = false
    private var stopped = false
    private var invalid = false
    private var activated = false
    private var automaticPending = false
    private var heldBy = ""
    private var core: LibboxRouterMTU?
    private var unavailable = "MTU measurement has not been activated for this native session."
    private var abortHandler: (@Sendable (String) -> Void)?
    private let cacheURL: URL?

    override init() {
        cacheURL = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first?
            .appendingPathComponent("RouterVPN-MTU", isDirectory: true).appendingPathComponent("cache-v3.json")
        super.init()
    }

    private func failure(_ text: String) -> NSError {
        NSError(domain: "RouterVPN.NativeMTU", code: 1, userInfo: [NSLocalizedDescriptionKey: text])
    }
    private static func validRequest(_ request: String) -> Bool {
        request.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil
    }

    /// The platform supplies a fingerprint of the selected physical NWPath,
    /// including its native address hash. A duplicate TUN-settings callback is
    /// not a new physical route and must not reset the encrypted endpoints.
    @discardableResult
    func observePhysicalPath(name: String, signature: String) -> Bool {
        var nativeError: NSError?
        let nativeHash = name.isEmpty ? nil : LibboxRouterMTUPhysicalPath(name, &nativeError)
        stateLock.lock()
        defer { stateLock.unlock() }
        guard !stopped else { return false }
        let changed = !physicalSignature.isEmpty &&
            (physicalName != name || physicalSignature != signature || nativePhysicalHash != nativeHash)
        if name.isEmpty || signature.isEmpty || nativeError != nil || nativeHash == nil || nativeHash == "" {
            if !physicalSignature.isEmpty { invalid = true; core?.networkChanged() }
            return true
        }
        if changed { invalid = true; core?.networkChanged() }
        if !invalid {
            physicalName = name; physicalSignature = signature; nativePhysicalHash = nativeHash!
        }
        return changed || readerID.isEmpty
    }

    func initialMeasurementHold(_ lease: String) throws {
        stateLock.lock(); defer { stateLock.unlock() }
        guard readerID.isEmpty, !activated, !stopped else { throw failure("MTU startup ownership is already established") }
        guard lease.isEmpty || Self.validRequest(lease) else { throw failure("Invalid MTU comparison lease") }
        heldBy = lease
    }
    func beforeOpen(mtu: Int32) throws -> UUID {
        stateLock.lock(); defer { stateLock.unlock() }
        guard !stopped, !invalid, (1280...9000).contains(mtu), opening == nil,
              readerID.isEmpty || changing else { throw failure("Unowned or stale MTU TUN replacement") }
        let token = UUID(); opening = token
        return token
    }
    func didOpen(_ token: UUID, mtu: Int32) throws {
        stateLock.lock(); defer { stateLock.unlock() }
        guard !stopped, !invalid, opening == token else { throw failure("MTU TUN opened after its owner changed") }
        expectedMTU = mtu; readerID = UUID().uuidString; opening = nil
    }
    func failedOpen(_ token: UUID) {
        stateLock.lock(); defer { stateLock.unlock() }
        if opening == token { opening = nil }
    }
    func registerInterface(_ name: String?) {
        stateLock.lock(); defer { stateLock.unlock() }
        guard !stopped, !invalid, let name, name.hasPrefix("utun"), name.count <= 64 else { return }
        interfaceName = name
    }
    var measurementReady: Bool {
        guard let data = statusData(ack: String(repeating: "0", count: 32)),
              let body = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return false }
        return body["measurement_ready"] as? Bool == true
    }
    var hasOwner: Bool {
        stateLock.lock(); defer { stateLock.unlock() }
        return activated
    }
    var isChanging: Bool {
        stateLock.lock(); defer { stateLock.unlock() }
        return changing || opening != nil
    }
    func invalidate() {
        stateLock.lock(); invalid = true; let captured = core; stateLock.unlock()
        captured?.networkChanged()
    }
    func stop() {
        stateLock.lock()
        stopped = true; invalid = true; let captured = core; core = nil; abortHandler = nil
        stateLock.unlock()
        try? captured?.close()
    }

    func activate(server: LibboxCommandServer, config: String, profile: String,
                  onAbort: @escaping @Sendable (String) -> Void) {
        commandLock.lock(); defer { commandLock.unlock() }
        stateLock.lock()
        guard !stopped, !invalid, !activated else { stateLock.unlock(); return }
        activated = true; abortHandler = onAbort
        stateLock.unlock()
        var createError: NSError?
        let next = LibboxNewRouterMTU(server, self, config, profile, &createError)
        stateLock.lock()
        guard !stopped, !invalid else { stateLock.unlock(); try? next?.close(); return }
        guard let next, createError == nil else {
            unavailable = "This native path could not provide a safe MTU measurement owner."
            stateLock.unlock(); return
        }
        core = next
        let hold = !heldBy.isEmpty
        stateLock.unlock()
        // The shared profile parser owns policy validation. Manual/fixed/Jumbo
        // never silently become automatic; do not start a test for those modes.
        let policy = (try? JSONSerialization.jsonObject(with: Data(profile.utf8))) as? [String: Any]
        let automatic = (policy?["mtu_policy"] as? String ?? "auto").lowercased() == "auto"
        stateLock.lock(); automaticPending = automatic && policy?["jumbo_tun"] as? Bool != true && hold; stateLock.unlock()
        if automatic && policy?["jumbo_tun"] as? Bool != true && !hold {
            try? next.start(UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased(), force: false)
        }
    }

    func captureMTU() -> LibboxRouterMTUState? {
        stateLock.lock(); defer { stateLock.unlock() }
        guard !stopped, !invalid, opening == nil, !readerID.isEmpty, !interfaceName.isEmpty,
              !physicalName.isEmpty, !nativePhysicalHash.isEmpty else { return nil }
        var physicalError: NSError?
        guard LibboxRouterMTUPhysicalPath(physicalName, &physicalError) == nativePhysicalHash,
              physicalError == nil else { return nil }
        var mtu: Int32 = 0, readError: NSError?
        guard LibboxRouterReadMTUInterface(interfaceName, &mtu, &readError), readError == nil,
              mtu == expectedMTU, (1280...9000).contains(mtu) else { return nil }
        let value = LibboxRouterMTUState()
        value.session = sessionID; value.path = physicalSignature
        value.interface = readerID; value.mtu = mtu
        return value
    }
    private func same(_ lhs: LibboxRouterMTUState?, _ rhs: LibboxRouterMTUState?) -> Bool {
        guard let lhs, let rhs else { return false }
        return lhs.session == rhs.session && lhs.path == rhs.path &&
            lhs.interface == rhs.interface && lhs.mtu == rhs.mtu
    }
    func beginMTUChange(_ expected: LibboxRouterMTUState?) throws {
        stateLock.lock(); defer { stateLock.unlock() }
        guard !changing, opening == nil, same(captureMTU(), expected) else { throw failure("Stale MTU mutation") }
        changing = true
    }
    func endMTUChange() throws {
        defer { stateLock.lock(); changing = false; stateLock.unlock() }
        let deadline = ProcessInfo.processInfo.systemUptime + 2.5
        repeat {
            if captureMTU() != nil { return }
            stateLock.lock(); let dead = stopped || invalid; stateLock.unlock()
            if dead { break }
            Thread.sleep(forTimeInterval: 0.02)
        } while ProcessInfo.processInfo.systemUptime < deadline
        throw failure("MTU OS readback did not confirm the captured TUN")
    }
    func bindMTUSocket(_ expected: LibboxRouterMTUState?, fd: Int64) throws {
        stateLock.lock(); defer { stateLock.unlock() }
        guard same(captureMTU(), expected), fd >= 0, fd <= Int64(Int32.max) else { throw failure("Stale MTU socket") }
        var bindError: NSError?
        guard LibboxRouterMTUBindInterface(fd, interfaceName, &bindError), bindError == nil,
              same(captureMTU(), expected) else { throw bindError ?? failure("MTU socket could not be bound to the owned utun") }
    }
    func abortMTU(_ reason: String?) {
        stateLock.lock(); invalid = true; let callback = abortHandler; stateLock.unlock()
        // Never re-enter Go Close or the engine while its ChangeMTU lock is held.
        DispatchQueue.global(qos: .utility).async { callback?("The native MTU transaction lost its owned TUN; reconnect to prove a fresh session.") }
    }

    private func readCache() throws -> String {
        guard let cacheURL else { throw failure("Private MTU cache location is unavailable") }
        let fm = FileManager.default
        let directory = cacheURL.deletingLastPathComponent()
        if fm.fileExists(atPath: directory.path) {
            let values = try directory.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
            guard values.isDirectory == true, values.isSymbolicLink != true else { throw failure("Unsafe MTU cache directory") }
        }
        guard fm.fileExists(atPath: cacheURL.path) else { return "" }
        let values = try cacheURL.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey])
        guard values.isRegularFile == true, values.isSymbolicLink != true,
              let size = values.fileSize, size <= 65536 else { throw failure("Unsafe MTU cache record") }
        let data = try Data(contentsOf: cacheURL)
        guard data.count <= 65536, let result = String(data: data, encoding: .utf8) else { throw failure("Invalid MTU cache encoding") }
        return result
    }
    func readMTUCache() -> String {
        cacheLock.lock(); defer { cacheLock.unlock() }
        // The Go preference boundary rejects this oversized sentinel; a broken
        // read must not masquerade as an empty cache eligible for overwriting.
        return (try? readCache()) ?? String(repeating: "!", count: 65537)
    }
    func compareAndSwapMTUCache(_ expected: String?, replacement: String?) -> Bool {
        cacheLock.lock(); defer { cacheLock.unlock() }
        stateLock.lock(); defer { stateLock.unlock() }
        guard let expected, let replacement, expected.utf8.count <= 65536,
              replacement.utf8.count <= 65536, let cacheURL, captureMTU() != nil else { return false }
        do {
            guard try readCache() == expected else { return false }
            let directory = cacheURL.deletingLastPathComponent()
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try Data(replacement.utf8).write(to: cacheURL, options: [.atomic])
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: cacheURL.path)
            let file = try FileHandle(forWritingTo: cacheURL)
            defer { try? file.close() }
            try file.synchronize()
            return try readCache() == replacement && captureMTU() != nil
        } catch { return false }
    }

    /// IPC parameters contain only opaque ownership IDs, never probe targets,
    /// credentials, interfaces or arbitrary native commands.
    func request(operation: String, request: String, session: String) -> Data? {
        commandLock.lock(); defer { commandLock.unlock() }
        guard Self.validRequest(request) else { return nil }
        stateLock.lock()
        guard !stopped, !invalid, session.isEmpty || session == sessionID,
              operation == "mtu-status" || session == sessionID else { stateLock.unlock(); return nil }
        let captured = core
        if operation == "mtu-hold" {
            guard heldBy.isEmpty || heldBy == request else { stateLock.unlock(); return nil }
            heldBy = request
        } else if operation == "mtu-release" {
            guard heldBy == request else { stateLock.unlock(); return nil }
            heldBy = ""
        } else if operation == "mtu-start" {
            guard heldBy.isEmpty, let captured else { stateLock.unlock(); return statusData(ack: request) }
            stateLock.unlock()
            do { try captured.start(request, force: true) }
            catch { return statusData(ack: request, commandFailure: "MTU Retest could not start for this frozen native policy.") }
            return statusData(ack: request)
        } else if operation != "mtu-status" && operation != "mtu-cancel" { stateLock.unlock(); return nil }
        stateLock.unlock()
        if operation == "mtu-release" {
            stateLock.lock(); let pending = automaticPending; automaticPending = false; stateLock.unlock()
            if pending { try? captured?.start(UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased(), force: false) }
        }
        if operation == "mtu-cancel" { captured?.cancel(request) }
        if operation == "mtu-hold", let captured,
           let data = captured.statusJSON().data(using: .utf8),
           let current = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let active = current["request_id"] as? String { captured.cancel(active) }
        return statusData(ack: request)
    }
    private func statusData(ack: String, commandFailure: String? = nil) -> Data? {
        stateLock.lock(); let captured = core, lease = heldBy, dead = stopped || invalid, message = unavailable
        stateLock.unlock()
        var status: [String: Any] = ["phase": "unavailable", "running": false, "complete": true,
                                   "measured": false, "source": "unmeasured", "failure": message, "candidates": []]
        if let captured, let data = captured.statusJSON().data(using: .utf8), data.count <= 32768,
           let native = try? JSONSerialization.jsonObject(with: data) as? [String: Any] { status = native }
        status["session_id"] = sessionID; status["ack_id"] = ack
        status["measurement_hold"] = !lease.isEmpty; status["measurement_lease"] = lease
        let actual = captureMTU()
        let active = captured?.running() ?? false
        let readbackMatches = captured == nil || (status["effective_mtu"] as? Int) == actual.map { Int($0.mtu) }
        status["measurement_ready"] = !dead && !lease.isEmpty && !active && !isChanging && actual != nil && readbackMatches
        if dead { status["measured"] = false; status["source"] = "unmeasured"; status["effective_mtu"] = 0 }
        if let commandFailure { status["command_failure"] = commandFailure }
        guard let data = try? JSONSerialization.data(withJSONObject: status), data.count <= 32768 else { return nil }
        return data
    }
}
