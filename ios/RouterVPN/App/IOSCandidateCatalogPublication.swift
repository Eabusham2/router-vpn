import Foundation
import CoreFoundation
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
        // Match the existing private retirement store: data is fsynced before
        // atomic publication; some Apple filesystems reject directory fsync.
        _ = fsync(directory)
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
        guard try stamp(fd).0 == expected, expected.ready, let container else { throw Self.issue() }
        let names = try FileManager.default.contentsOfDirectory(atPath: container.appendingPathComponent("candidate-sources-v1").path)
        guard names.filter({ $0.hasPrefix("closed-") }).count < 512,
              names.filter({ $0.hasSuffix(".json") && $0 != "catalog.json" && !$0.hasPrefix("closed-") }).count < 64 else { throw Self.issue() }
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
    private func closedName(epoch: String, request: String) throws -> String {
        guard UUID(uuidString: epoch)?.uuidString.lowercased() == epoch.lowercased(), Self.validRequest(request) else { throw Self.issue() }
        return "closed-\(epoch.lowercased())-\(request).json"
    }
    /// Only the original extension registry calls this after actual join (or
    /// a registered cancel-before-factory tombstone). It carries no score.
    func storeClosed(epoch: String, request: String) throws {
        let name = try closedName(epoch: epoch, request: request)
        lock.lock(); defer { lock.unlock() }
        let fd = try directory(); defer { _ = close(fd) }
        let data = try JSONSerialization.data(withJSONObject: ["schema": 1, "kind": "candidate-native-closed", "session_id": epoch, "owner_request": request], options: [.sortedKeys])
        // Bound durable recovery storage. Refuse new work/acknowledgements at
        // capacity rather than discard another pending owner's only receipt.
        guard let container else { throw Self.issue() }
        let names = try FileManager.default.contentsOfDirectory(atPath: container.appendingPathComponent("candidate-sources-v1").path)
        guard names.contains(name) || names.filter({ $0.hasPrefix("closed-") }).count < 512 else { throw Self.issue() }
        try writeFile(name, data: data, directory: fd)
    }
    func closed(epoch: String, request: String) -> Bool {
        guard let name = try? closedName(epoch: epoch, request: request) else { return false }
        lock.lock(); defer { lock.unlock() }
        guard let fd = try? directory() else { return false }; defer { _ = close(fd) }
        guard let file = try? readFile(name, maximum: 1024, directory: fd),
              let value = try? JSONSerialization.jsonObject(with: file.data) as? [String: Any] else { return false }
        return Set(value.keys) == Set(["schema", "kind", "session_id", "owner_request"]) && value["schema"] as? Int == 1 &&
            value["kind"] as? String == "candidate-native-closed" && value["session_id"] as? String == epoch && value["owner_request"] as? String == request
    }

    /// The app consumes only a receipt it has already validated. The live
    /// extension registry keeps its tombstone until its process retires.
    func acknowledgeClosed(epoch: String, request: String) throws {
        guard closed(epoch: epoch, request: request) else { throw Self.issue() }
        let name = try closedName(epoch: epoch, request: request)
        lock.lock(); defer { lock.unlock() }
        let fd = try directory(); defer { _ = close(fd) }
        guard unlinkat(fd, name, 0) == 0 else { throw Self.issue() }
    }

}

// MARK: Candidate metadata pages
/// Reassembles only the public target inventory of one original native owner.
/// Header and digest are immutable across frames; offsets come from accepted rows.
struct IOSCandidateMetadataPages {
    enum Family { case ordinary, selected, preparation, appendPreparation }
    private let family: Family
    private let selectedResponse: (position: Int, id: String)?
    private let selectedResponseMetric: String
    private let selectedResponseMode: String?
    private var header: [String: Any]?
    private var headerBytes: Data?
    private var total = 0
    private var expectedDigest = ""
    private var ids = Set<Data>()
    private var rows = [[String: String]]()
    private var canonical = Data([0x5b])
    private var legacy: Data?
    private let budget: Int
    private let legacyLimit: Int
    var nextOffset: Int32? { legacy == nil && rows.count < total ? Int32(exactly: rows.count) : nil }

    init(_ first: String, inventoryBytes: Int, legacyLimit: Int, family: Family = .ordinary,
         selectedResponse: (position: Int, id: String)? = nil, selectedResponseMetric: String = "routed-candidate-response", selectedResponseMode: String? = nil) throws {
        guard inventoryBytes > 0, inventoryBytes <= IOSCandidateCatalogPublication.maximumInventoryBytes else { throw Self.issue() }
        self.selectedResponse = selectedResponse
        self.selectedResponseMetric = selectedResponseMetric
        self.selectedResponseMode = selectedResponseMode
        self.family = family; self.budget = inventoryBytes; self.legacyLimit = legacyLimit
        try append(first)
    }
    private static func issue() -> NSError { NSError(domain: "RouterVPN.CandidateMetadataPages", code: 1) }
    private static func integer(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(), number.doubleValue.isFinite,
              number.doubleValue >= 0, number.doubleValue <= Double(Int32.max), number.doubleValue == Double(number.intValue) else { return nil }
        return number.intValue
    }
    private static func canonicalTarget(_ row: [String: String]) throws -> Data {
        let data = try JSONSerialization.data(withJSONObject: row, options: [.sortedKeys, .withoutEscapingSlashes])
        // Match Go encoding/json's HTML-sensitive escapes and JSONP separators.
        let text = String(decoding: data, as: UTF8.self)
            .replacingOccurrences(of: "&", with: "\\u0026")
            .replacingOccurrences(of: "<", with: "\\u003c")
            .replacingOccurrences(of: ">", with: "\\u003e")
            .replacingOccurrences(of: "\u{2028}", with: "\\u2028")
            .replacingOccurrences(of: "\u{2029}", with: "\\u2029")
        return Data(text.utf8)
    }
    /// Native fields have fixed ASCII names. Foundation accepts duplicate keys;
    /// reject duplicate or escaped field spellings at every object depth before
    /// adopting the decoded values. JSONSerialization verifies the JSON grammar.
    private static func canonicalKeys(_ data: Data) throws {
        let bytes = Array(data)
        var objects = [Set<String>]()
        var cursor = 0
        while cursor < bytes.count {
            switch bytes[cursor] {
            case 123: objects.append([])
            case 125:
                guard !objects.isEmpty else { throw issue() }
                objects.removeLast()
            case 34:
                let start = cursor + 1
                var end = start, escaped = false
                while end < bytes.count && bytes[end] != 34 {
                    if bytes[end] == 92 { escaped = true; end += 1 }
                    end += 1
                }
                guard end < bytes.count else { throw issue() }
                var next = end + 1
                while next < bytes.count && [9,10,13,32].contains(bytes[next]) { next += 1 }
                if next < bytes.count && bytes[next] == 58 {
                    guard !escaped, !objects.isEmpty else { throw issue() }
                    let name = String(decoding: bytes[start..<end], as: UTF8.self)
                    guard objects[objects.count - 1].insert(name).inserted else { throw issue() }
                }
                cursor = end
            default: break
            }
            cursor += 1
        }
        guard objects.isEmpty else { throw issue() }
    }
    private func validateFields(_ body: [String: Any], paged: Bool) throws {
        var fields: Set<String> = ["schema","capture_sha256","prefix_position","prefix_id","source_sha256","config_sha256","targets"]
        if let metric = body["measurement"] {
            guard let value = metric as? String, value == "routed-tcp-connect" ||
                    ["routed-public-candidate-response", "routed-candidate-response"].contains(value) && (family != .selected || value == selectedResponseMetric &&
                        (body["requested_execution"] as? String == "auto" && body["execution"] as? String == "local" ||
                         ["server", "auto"].contains(body["requested_execution"] as? String ?? "") && body["execution"] as? String == "server") && selectedResponse != nil &&
                        Self.integer(body["prefix_position"]) == selectedResponse?.position && body["prefix_id"] as? String == selectedResponse?.id) else { throw Self.issue() }
            fields.insert("measurement")
        }
        if let mode = body["candidate_mode"] {
            guard let mode = mode as? String,
                  (family == .appendPreparation ? IOSNodeCandidateAppendSource.supportsNextMode(mode) :
                    ["hysteria2", "wg", "awg2-fast", "awg2-strong"].contains(mode)),
                  body["measurement"] as? String == "routed-candidate-response",
                  family != .selected || mode == selectedResponseMode && IOSMultihopNodeSelection.supportsNativePrefix(mode) &&
                    selectedResponse != nil && Self.integer(body["prefix_position"]) == selectedResponse?.position &&
                    body["prefix_id"] as? String == selectedResponse?.id else { throw Self.issue() }
            fields.insert("candidate_mode")
        }
        if paged { fields.formUnion(["target_total","target_offset","targets_sha256"]) }
        if family == .selected {
            guard body["candidate_mode"] as? String == selectedResponseMode else { throw Self.issue() }
            fields.formUnion(["preparation_source_sha256","preparation_config_sha256","requested_execution","execution","selection_epoch"])
        } else if family == .appendPreparation {
            fields.formUnion(["purpose","append_position","draft_revision","device_revision","device_source_sha256","device_mtu_revision",
                "original_source_sha256","prefix_count","prefixes_sha256","mtu_sha256","append_source_metadata_sha256",
                "application_open","dns_open","ready","stage","mtu_measurement"])
            guard body["purpose"] as? String == "draft-prefix-append",
                  body["measurement"] as? String == "routed-candidate-response",
                  IOSNodeCandidateAppendSource.supportsNextMode(body["candidate_mode"] as? String ?? ""),
                  let count = Self.integer(body["prefix_count"]), (1..<IOSMultihopNodeSelection.physicalTraversalDepth).contains(count),
                  Self.integer(body["append_position"]) == count, Self.integer(body["prefix_position"]) == count - 1,
                  ["device_source_sha256","original_source_sha256","prefixes_sha256","mtu_sha256","append_source_metadata_sha256"].allSatisfy({
                      IOSCandidateCatalogPublication.isDigest(body[$0] as? String ?? "")
                  }), ["draft_revision","device_revision"].allSatisfy({ (body[$0] as? String)?.isEmpty == false }),
                  body["device_mtu_revision"] is String else { throw Self.issue() }
        } else if family == .preparation {
            fields.formUnion(["original_source_sha256","prefixes","application_open","dns_open","ready","stage","mtu","mtu_measurement"])
            let required: Set<String> = ["position","profile_id","node_id","mode","start_layer","source_sha256","tag"]
            let permitted = required.union(["node_kind","kind"])
            guard let prefixes = body["prefixes"] as? [[String: Any]], !prefixes.isEmpty,
                  prefixes.allSatisfy({ required.isSubset(of: $0.keys) && Set($0.keys).isSubset(of: permitted) }),
                  let mtu = body["mtu"] as? [String: Any], Set(mtu.keys) == ["original","ceiling","tun_tag","prefixes"],
                  let bounds = mtu["prefixes"] as? [[String: Any]], bounds.count == prefixes.count,
                  bounds.allSatisfy({ Set($0.keys) == ["position","tag","ceiling"] }) else { throw Self.issue() }
        }
        guard Set(body.keys) == fields,
              let targets = body["targets"] as? [[String: String]], !targets.isEmpty,
              targets.allSatisfy({ Set($0.keys) == ["id","source_sha256"] }) else { throw Self.issue() }
    }
    mutating func append(_ raw: String) throws {
        guard !raw.isEmpty, raw.utf8.count <= legacyLimit, legacy == nil else { throw Self.issue() }
        let data = Data(raw.utf8)
        try Self.canonicalKeys(data)
        guard var body = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw Self.issue() }
        try validateFields(body, paged: Self.integer(body["schema"]) == 2)
        if Self.integer(body["schema"]) == 1 {
            guard header == nil, body["target_total"] == nil, body["target_offset"] == nil, body["targets_sha256"] == nil else { throw Self.issue() }
            legacy = data; return
        }
        guard data.count <= 12 * 1024, Self.integer(body["schema"]) == 2,
              let count = Self.integer(body["target_total"]), count > 0, count <= budget,
              Self.integer(body.removeValue(forKey: "target_offset")) == rows.count,
              let hash = body["targets_sha256"] as? String, IOSCandidateCatalogPublication.isDigest(hash),
              let page = body.removeValue(forKey: "targets") as? [[String: String]], !page.isEmpty,
              page.count <= count - rows.count else { throw Self.issue() }
        let bytes = try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys, .withoutEscapingSlashes])
        if let headerBytes { guard headerBytes == bytes else { throw Self.issue() } }
        else { header = body; headerBytes = bytes; total = count; expectedDigest = hash }
        for row in page {
            guard row.count == 2, let id = row["id"], !id.isEmpty, id.utf8.count <= 128,
                  let hash = row["source_sha256"], IOSCandidateCatalogPublication.isDigest(hash),
                  ids.insert(Data(id.utf8)).inserted else { throw Self.issue() }
            let encoded = try Self.canonicalTarget(row)
            if !rows.isEmpty { canonical.append(0x2c) }
            guard encoded.count < budget - canonical.count else { throw Self.issue() }
            canonical.append(encoded); rows.append(row)
        }
    }
    mutating func result() throws -> Data {
        if let legacy { return legacy }
        guard var body = header, rows.count == total else { throw Self.issue() }
        canonical.append(0x5d)
        guard IOSCandidateCatalogPublication.digest(canonical) == expectedDigest else { throw Self.issue() }
        body["schema"] = 1; body["targets"] = rows
        body.removeValue(forKey:"target_total"); body.removeValue(forKey:"targets_sha256")
        return try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys, .withoutEscapingSlashes])
    }
}
