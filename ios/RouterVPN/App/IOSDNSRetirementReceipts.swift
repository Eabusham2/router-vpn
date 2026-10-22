import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// A PacketTunnel may finish draining after the app loses provider messaging.
/// Only the native owner writes these receipts. They acknowledge cleanup for
/// one exact request; they cannot publish a measurement, select DNS, or prove a
/// new connection. The app and extension share this small protected container.
final class IOSDNSRetirementReceipts: @unchecked Sendable {
    static let groupIdentifier = "group.com.eabusham.routervpn"
    static let shared = IOSDNSRetirementReceipts(container: sharedContainer())
    static let maximumAge: TimeInterval = 7 * 24 * 60 * 60
    static let maximumRecords = 256
    private static let maximumBytes = 4096
    private let lock = NSLock()
    private let container: URL?
    private let now: @Sendable () -> Date

    /// The explicit container/clock are filesystem-test seams, never IPC input.
    init(container: URL?, now: @escaping @Sendable () -> Date = { Date() }) {
        self.container = container?.resolvingSymlinksInPath()
        self.now = now
    }

    private static func sharedContainer() -> URL? {
        #if canImport(Darwin)
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: groupIdentifier)
        #else
        nil
        #endif
    }

    private struct NativeReceipt: Decodable {
        let schema: Int
        let request_id: String
        let ack_id: String
        let node_id: String
        let session_id: String
        let native_session_id: String
        let complete: Bool
        let drained: Bool
    }

    private struct StoredReceipt: Codable {
        let schema: Int
        let kind: String
        let request_id: String
        let node_id: String
        let session_id: String
        let native_session_id: String
        let written_at: TimeInterval

        var fileName: String { "dns-\(session_id.lowercased())-\(request_id).json" }
        var validIdentity: Bool {
            schema == 1 && kind == "native-dns-retirement" &&
            IOSDNSRetirementReceipts.validRequest(request_id) &&
            IOSDNSRetirementReceipts.validUUID(session_id) &&
            IOSDNSRetirementReceipts.validUUID(native_session_id) &&
            IOSDNSRetirementReceipts.validNode(node_id) && written_at.isFinite
        }
    }

    private static func validRequest(_ value: String) -> Bool {
        value.utf8.count == 32 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    private static func validUUID(_ value: String) -> Bool {
        value.utf8.count == 36 && UUID(uuidString: value)?.uuidString.lowercased() == value.lowercased()
    }
    private static func validNode(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        func alphanumeric(_ byte: UInt8) -> Bool { (48...57).contains(byte) || (65...90).contains(byte) || (97...122).contains(byte) }
        return !bytes.isEmpty && bytes.count <= 128 && alphanumeric(bytes[0]) &&
            bytes.allSatisfy { alphanumeric($0) || $0 == 45 || $0 == 46 || $0 == 95 }
    }
    private static func issue(_ text: String) -> NSError {
        NSError(domain: "RouterVPN.DNSRetirement", code: 1, userInfo: [NSLocalizedDescriptionKey: text])
    }

    /// Reject missing signing/storage capabilities before native work starts.
    /// A zero-byte private probe verifies writes without inventing a receipt.
    func requireAvailable() throws {
        lock.lock(); defer { lock.unlock() }
        let (_, directory) = try openDirectory(create: true)
        defer { _ = close(directory) }
        let temporary = ".dns-preflight-\(UUID().uuidString.lowercased()).tmp"
        let file = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard file >= 0 else { throw Self.issue("The DNS cleanup container is not writable.") }
        _ = close(file)
        guard unlinkat(directory, temporary, 0) == 0 else { throw Self.issue("The DNS cleanup container could not retire its write probe.") }
    }

    /// Call only after the exact native request acknowledges complete drain.
    /// Extra provider fields are deliberately discarded, including all results.
    func storeDrained(_ data: Data) throws {
        guard !data.isEmpty, data.count <= 65536 else { throw Self.issue("DNS cleanup receipt exceeds its bound.") }
        let native = try JSONDecoder().decode(NativeReceipt.self, from: data)
        guard native.schema == 1, native.complete, native.drained, native.request_id == native.ack_id else {
            throw Self.issue("DNS cleanup has not been acknowledged by its native owner.")
        }
        let stored = StoredReceipt(schema: 1, kind: "native-dns-retirement", request_id: native.request_id,
            node_id: native.node_id, session_id: native.session_id, native_session_id: native.native_session_id,
            written_at: now().timeIntervalSince1970)
        guard stored.validIdentity else { throw Self.issue("DNS cleanup receipt identity is invalid.") }
        let encoded = try JSONEncoder().encode(stored)
        guard encoded.count <= Self.maximumBytes else { throw Self.issue("DNS cleanup receipt exceeds its storage bound.") }
        lock.lock(); defer { lock.unlock() }
        let (directory, descriptor) = try openDirectory(create: true)
        defer { _ = close(descriptor) }
        // Repeated acknowledgements are idempotent and never refresh retention.
        if let previous = read(stored.fileName, directory: descriptor), previous.validIdentity,
           previous.request_id == stored.request_id, previous.node_id == stored.node_id,
           previous.session_id == stored.session_id, previous.native_session_id == stored.native_session_id, current(previous) {
            return
        }
        let temporary = ".dns-\(UUID().uuidString.lowercased()).tmp"
        let file = openat(descriptor, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard file >= 0 else { throw Self.issue("Could not create a private DNS cleanup receipt.") }
        defer { _ = close(file); _ = unlinkat(descriptor, temporary, 0) }
        #if os(iOS)
        try FileManager.default.setAttributes([.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
            ofItemAtPath: directory.appendingPathComponent(temporary).path)
        #endif
        try encoded.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let written = write(file, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
                if written < 0 && errno == EINTR { continue }
                guard written > 0 else { throw Self.issue("Could not finish the DNS cleanup receipt.") }
                offset += written
            }
        }
        guard fsync(file) == 0, renameat(descriptor, temporary, descriptor, stored.fileName) == 0 else {
            throw Self.issue("Could not commit the DNS cleanup receipt.")
        }
        // Losing an unflushed receipt can only retain ownership, never release
        // it incorrectly. Some Apple filesystems do not support directory fsync.
        _ = fsync(descriptor)
        prune(directory: directory, descriptor: descriptor, keeping: stored.fileName)
    }

    /// Cleanup-only fallback. The returned response is always cancelled with
    /// empty results; consumers must never use it as a successful measurement.
    func drained(providerSession: String, nativeSession: String, request: String, nodeID: String) -> Data? {
        guard Self.validUUID(providerSession), Self.validUUID(nativeSession),
              Self.validRequest(request), Self.validNode(nodeID) else { return nil }
        lock.lock(); defer { lock.unlock() }
        guard let (_, descriptor) = try? openDirectory(create: false) else { return nil }
        defer { _ = close(descriptor) }
        let fileName = "dns-\(providerSession.lowercased())-\(request).json"
        guard let receipt = read(fileName, directory: descriptor), receipt.validIdentity,
              receipt.fileName == fileName, receipt.session_id == providerSession,
              receipt.native_session_id == nativeSession, receipt.request_id == request,
              receipt.node_id == nodeID, current(receipt) else { return nil }
        return try? JSONSerialization.data(withJSONObject: ["schema": 1, "request_id": request, "ack_id": request,
            "session_id": providerSession, "native_session_id": nativeSession, "node_id": nodeID,
            "public_transport": "", "stage": "cancelled", "complete": true, "drained": true,
            "results": [], "failure": "The captured DNS request finished cleanup after provider messaging ended."])
    }

    private func current(_ receipt: StoredReceipt) -> Bool {
        let age = now().timeIntervalSince1970 - receipt.written_at
        return age >= -300 && age <= Self.maximumAge
    }

    private func openDirectory(create: Bool) throws -> (URL, Int32) {
        guard let container, container.isFileURL else {
            throw Self.issue("The signed app and tunnel require their shared DNS cleanup container.")
        }
        let directory = container.appendingPathComponent("DNSRetirement", isDirectory: true)
        if create {
            do { try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                attributes: [.posixPermissions: 0o700]) }
            catch {
                // An existing directory is verified through the opened handle.
                guard (error as NSError).code == NSFileWriteFileExistsError else { throw error }
            }
        }
        let descriptor = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw Self.issue("The DNS cleanup directory is unavailable.") }
        var info = stat()
        guard fstat(descriptor, &info) == 0, info.st_uid == geteuid(), info.st_mode & 0o077 == 0 else {
            _ = close(descriptor)
            throw Self.issue("The DNS cleanup directory is not private.")
        }
        return (directory, descriptor)
    }

    private func read(_ name: String, directory: Int32) -> StoredReceipt? {
        let descriptor = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard descriptor >= 0 else { return nil }
        let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? file.close() }
        var info = stat()
        guard fstat(descriptor, &info) == 0, info.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              info.st_uid == geteuid(), info.st_nlink == 1, info.st_mode & 0o077 == 0,
              info.st_size > 0, info.st_size <= Self.maximumBytes,
              let bytes = try? file.read(upToCount: Self.maximumBytes + 1),
              bytes.count == Int(info.st_size), bytes.count <= Self.maximumBytes else { return nil }
        return try? JSONDecoder().decode(StoredReceipt.self, from: bytes)
    }

    private func prune(directory: URL, descriptor: Int32, keeping: String) {
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: directory.path) else { return }
        var eligible: [(String, StoredReceipt)] = []
        for name in names where name != keeping && name.hasPrefix("dns-") && name.hasSuffix(".json") {
            guard let receipt = read(name, directory: descriptor), receipt.validIdentity, receipt.fileName == name else { continue }
            if !current(receipt) { _ = unlinkat(descriptor, name, 0) }
            else { eligible.append((name, receipt)) }
        }
        eligible.sort { $0.1.written_at < $1.1.written_at }
        for item in eligible.prefix(max(0, eligible.count + 1 - Self.maximumRecords)) {
            _ = unlinkat(descriptor, item.0, 0)
        }
    }
}
