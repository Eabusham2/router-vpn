import Foundation
import CryptoKit
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// The app alone publishes catalog generations from its private durable store.
/// PacketTunnel can observe these bounded source seals without opening that
/// private store or accepting a copied inventory as proof of freshness.
final class IOSCandidateCatalogPublication: @unchecked Sendable {
    static let shared = IOSCandidateCatalogPublication(container: sharedContainer())
    static let maximumInventoryBytes = 40 * 1024 * 1024
    private let container: URL?
    private let lock = NSLock()
    init(container: URL?) { self.container = container }

    struct Stamp: Codable, Equatable {
        let schema: Int
        let epoch: String
        let generation: UInt64
        let ready: Bool
        let sources_sha256: String
        var valid: Bool {
            schema == 1 && UUID(uuidString: epoch) != nil && generation > 0 &&
                (ready ? IOSCandidateCatalogPublication.isDigest(sources_sha256) : sources_sha256.isEmpty)
        }
        var revision: String { IOSCandidateCatalogPublication.digest(Data("\(epoch):\(generation):\(sources_sha256)".utf8)) }
    }
    struct FileIdentity: Equatable {
        let device: UInt64, inode: UInt64, size: Int64
        let modifiedSeconds: Int64, modifiedNanos: Int64, changedSeconds: Int64, changedNanos: Int64
        init(_ value: stat) {
            device = UInt64(value.st_dev); inode = UInt64(value.st_ino); size = Int64(value.st_size)
            #if canImport(Darwin)
            modifiedSeconds = Int64(value.st_mtimespec.tv_sec); modifiedNanos = Int64(value.st_mtimespec.tv_nsec)
            changedSeconds = Int64(value.st_ctimespec.tv_sec); changedNanos = Int64(value.st_ctimespec.tv_nsec)
            #else
            modifiedSeconds = Int64(value.st_mtim.tv_sec); modifiedNanos = Int64(value.st_mtim.tv_nsec)
            changedSeconds = Int64(value.st_ctim.tv_sec); changedNanos = Int64(value.st_ctim.tv_nsec)
            #endif
        }
    }
    struct CapturedFile {
        let data: Data
        let identity: FileIdentity
    }
    struct Capture {
        let stamp: Stamp
        let publication: CapturedFile
        let request: String
        let inventory: CapturedFile
        var inventorySHA256: String { IOSCandidateCatalogPublication.digest(inventory.data) }
    }
    private static func sharedContainer() -> URL? {
        #if canImport(Darwin)
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: "group.com.eabusham.routervpn")
        #else
        nil
        #endif
    }
    static func digest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    static func isDigest(_ value: String) -> Bool { value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }
    static func validRequest(_ value: String) -> Bool { value.utf8.count == 32 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }
    static func sourcesDigest(_ records: [String: Data]) throws -> String {
        // Include every original record, even if it has no supported candidate.
        let sources = records.keys.sorted().map { [$0, digest(records[$0]!)] }
        return digest(try JSONSerialization.data(withJSONObject: sources, options: [.sortedKeys]))
    }
    private static func issue() -> NSError { NSError(domain: "RouterVPN.CandidateCatalog", code: 1, userInfo: [NSLocalizedDescriptionKey: "The saved candidate catalog or protected source publication changed."]) }
    private func directory() throws -> Int32 {
        guard let container else { throw Self.issue() }
        let parent = open(container.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw Self.issue() }
        defer { _ = close(parent) }
        let name = "candidate-sources-v1"
        if mkdirat(parent, name, mode_t(0o700)) != 0 && errno != EEXIST { throw Self.issue() }
        let fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw Self.issue() }
        var status = stat()
        guard fstat(fd, &status) == 0, status.st_uid == geteuid(), status.st_mode & 0o077 == 0 else { _ = close(fd); throw Self.issue() }
        return fd
    }
    private func readFile(_ name: String, maximum: Int, directory: Int32) throws -> CapturedFile {
        let fd = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw Self.issue() }
        defer { _ = close(fd) }
        var before = stat(), after = stat()
        guard fstat(fd, &before) == 0, before.st_mode & S_IFMT == S_IFREG, before.st_uid == geteuid(),
              before.st_mode & 0o077 == 0, before.st_size > 0, before.st_size <= maximum else { throw Self.issue() }
        var data = Data(count: Int(before.st_size)), offset = 0
        try data.withUnsafeMutableBytes { bytes in
            while offset < bytes.count {
                let count = read(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw Self.issue() }; offset += count
            }
        }
        guard fstat(fd, &after) == 0, FileIdentity(before) == FileIdentity(after) else { throw Self.issue() }
        return CapturedFile(data: data, identity: FileIdentity(after))
    }
    private func writeFile(_ name: String, data: Data, directory: Int32, exclusive: Bool = false) throws {
        let temporary = ".\(UUID().uuidString).tmp"
        let fd = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard fd >= 0 else { throw Self.issue() }
        defer { _ = close(fd); _ = unlinkat(directory, temporary, 0) }
        #if os(iOS)
        guard let container else { throw Self.issue() }
        try FileManager.default.setAttributes([.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
            ofItemAtPath: container.appendingPathComponent("candidate-sources-v1").appendingPathComponent(temporary).path)
        #endif
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw Self.issue() }; offset += count
            }
        }
        guard fsync(fd) == 0 else { throw Self.issue() }
        if exclusive {
            guard linkat(directory, temporary, directory, name, 0) == 0 else { throw Self.issue() }
        } else {
            guard renameat(directory, temporary, directory, name) == 0 else { throw Self.issue() }
        }
        guard fsync(directory) == 0 else { throw Self.issue() }
    }
    private func stamp(_ directory: Int32) throws -> (Stamp, CapturedFile) {
        let file = try readFile("catalog.json", maximum: 4096, directory: directory)
        let value = try JSONDecoder().decode(Stamp.self, from: file.data)
        guard value.valid else { throw Self.issue() }; return (value, file)
    }
    /// Invalidate before writing private records. Even a failed durable update
    /// advances the generation, so changing away and back cannot revive a run.
    func beginChange() throws -> Stamp {
        lock.lock(); defer { lock.unlock() }
        let fd = try directory(); defer { _ = close(fd) }
        let previous = try? stamp(fd).0
        guard previous?.generation != UInt64.max else { throw Self.issue() }
        let next = Stamp(schema: 1, epoch: previous?.epoch ?? UUID().uuidString.lowercased(),
            generation: (previous?.generation ?? 0) + 1, ready: false, sources_sha256: "")
        try writeFile("catalog.json", data: JSONEncoder().encode(next), directory: fd)
        return next
    }
    func finishChange(_ change: Stamp, records: [String: Data]) throws {
        lock.lock(); defer { lock.unlock() }
        let fd = try directory(); defer { _ = close(fd) }
        guard try stamp(fd).0 == change, !change.ready else { throw Self.issue() }
        let next = Stamp(schema: 1, epoch: change.epoch, generation: change.generation, ready: true,
            sources_sha256: try Self.sourcesDigest(records))
        try writeFile("catalog.json", data: JSONEncoder().encode(next), directory: fd)
    }
    func publish(_ records: [String: Data]) throws { let change = try beginChange(); try finishChange(change, records: records) }
    func current(records: [String: Data]) throws -> Stamp {
        lock.lock(); defer { lock.unlock() }
        let fd = try directory(); defer { _ = close(fd) }
        let value = try stamp(fd).0
        guard value.ready, value.sources_sha256 == (try Self.sourcesDigest(records)) else { throw Self.issue() }
        return value
    }
    func capture(request: String, inventory: Data, expected: Stamp) throws -> Capture {
        guard Self.validRequest(request), !inventory.isEmpty, inventory.count <= Self.maximumInventoryBytes,
              let object = try JSONSerialization.jsonObject(with: inventory) as? [String: Any],
              object["schema"] as? Int == 1, object["revision"] as? String == expected.revision else { throw Self.issue() }
        lock.lock(); defer { lock.unlock() }
        let fd = try directory(); defer { _ = close(fd) }
        guard try stamp(fd).0 == expected, expected.ready else { throw Self.issue() }
        try writeFile("\(request).json", data: inventory, directory: fd, exclusive: true)
        return try reopen(request: request, directory: fd)
    }
    private func reopen(request: String, directory fd: Int32) throws -> Capture {
        let (value, publication) = try stamp(fd)
        let inventory = try readFile("\(request).json", maximum: Self.maximumInventoryBytes, directory: fd)
        guard value.ready, let object = try JSONSerialization.jsonObject(with: inventory.data) as? [String: Any],
              object["schema"] as? Int == 1, object["revision"] as? String == value.revision else { throw Self.issue() }
        return Capture(stamp: value, publication: publication, request: request, inventory: inventory)
    }
    func reopen(request: String) throws -> Capture {
        guard Self.validRequest(request) else { throw Self.issue() }
        lock.lock(); defer { lock.unlock() }
        let fd = try directory(); defer { _ = close(fd) }; return try reopen(request: request, directory: fd)
    }
    func current(_ capture: Capture) -> Bool {
        guard let now = try? reopen(request: capture.request) else { return false }
        return now.stamp == capture.stamp && now.publication.identity == capture.publication.identity &&
            now.publication.data == capture.publication.data && now.inventory.identity == capture.inventory.identity &&
            now.inventory.data == capture.inventory.data
    }
    /// Called only after the original native factory/handle has actually joined.
    /// A stale close may not unlink a replacement file with identical bytes.
    func remove(_ capture: Capture) throws {
        lock.lock(); defer { lock.unlock() }
        let fd = try directory(); defer { _ = close(fd) }
        let file = try readFile("\(capture.request).json", maximum: Self.maximumInventoryBytes, directory: fd)
        guard file.identity == capture.inventory.identity, file.data == capture.inventory.data,
              unlinkat(fd, "\(capture.request).json", 0) == 0 else { throw Self.issue() }
    }
}
