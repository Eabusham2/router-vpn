import CryptoKit
import Foundation

/// Usage is optional private history. It never rewrites a linked bundle or
/// the frozen NetworkExtension source, and it is never connection authority.
@MainActor enum IOSNodeUsage {
    static let filename = "node-usage-v1.json"
    private static let maximumBytes = 512 * 1024
    private static let maximumRecords = 256
    private static let maximumReceipts = 16
    private static var saveWarning: String?

    private struct Record: Codable {
        let key: String
        var count: Int
        var lastUsed: String
        var receipts: [String]
    }

    private struct Envelope: Codable {
        let schema: Int
        var records: [Record]
    }

    struct Display {
        let profiles: [RouterProfile]
        let warning: String?
    }

    static func canonical<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(value)
    }

    static func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    /// Compare the original JSON values, not a model decoder that fills or
    /// normalizes compatibility fields from the selected profile.
    static func canonicalJSON(_ data: Data) throws -> Data {
        let value = try JSONSerialization.jsonObject(with: data)
        return try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
    }

    /// The durable metric belongs to this authenticated node, independent of
    /// saved DNS/MTU/mode, display metadata and historical measurements. Router
    /// client tunnel-key refresh retains usage for the same proof/API identity.
    /// Full private source equality is checked separately at final adoption.
    static func key(_ profile: RouterProfile) throws -> String {
        guard !profile.id.isEmpty, profile.id.utf8.count <= 128 else { throw issue() }
        var identity: [String: Any] = ["schema": 1, "id": profile.id, "kind": profile.normalizedNodeKind]
        if profile.normalizedNodeKind == "router-vpn" {
            guard let proof = profile.nodeProofID, hex(proof), !profile.apiToken.isEmpty else { throw issue() }
            identity["proof"] = proof
            identity["credential"] = profile.apiToken
        } else {
            guard profile.normalizedNodeKind == "external", let external = profile.external,
                  let object = try JSONSerialization.jsonObject(with: canonical(external)) as? [String: Any] else { throw issue() }
            let names = ["wireguard": "wireguard", "amneziawg": "amneziawg", "shadowsocks": "shadowsocks",
                         "socks5": "socks5", "http-connect": "http_connect", "https-connect": "https_connect",
                         "hysteria2": "hysteria2", "openvpn": "openvpn", "tor-bridge": "tor_bridge"]
            identity["protocol"] = external.protocolName
            if external.protocolName == "tor" {
                guard object["tor_bridge"] == nil else { throw issue() }
            } else {
                guard let name = names[external.protocolName], var transport = object[name] as? [String: Any] else { throw issue() }
                if ["wireguard", "amneziawg"].contains(external.protocolName) {
                    // Address/route/MTU/DNS choices do not replace these peer
                    // credentials or their actual configured remote endpoint.
                    let keys: Set<String> = ["private_key", "peer_public_key", "preshared_key", "endpoint", "parameters"]
                    transport = transport.filter { keys.contains($0.key) }
                } else if external.protocolName == "tor-bridge" {
                    transport.removeValue(forKey: "socks_port")
                }
                identity["transport"] = transport
            }
        }
        return digest(try JSONSerialization.data(withJSONObject: identity, options: [.sortedKeys]))
    }

    /// One atomic sidecar update counts each distinct final node once. Imported
    /// counts are a baseline, never an amount added again on every UI refresh.
    /// Recent receipts deduplicate retries; the app's current-generation guard
    /// independently prevents old requests from replaying after newer adopts.
    static func record(profiles: [RouterProfile], adoption: String, at date: Date = Date()) throws {
        do {
            try save(profiles: profiles, adoption: adoption, at: date)
            saveWarning = nil
        } catch {
            reportFailure()
            throw error
        }
    }

    static func reportFailure() {
        saveWarning = "The latest connection's usage history could not be saved."
    }

    private static func save(profiles: [RouterProfile], adoption: String, at date: Date) throws {
        guard hex(adoption), !profiles.isEmpty, profiles.count <= 8,
              date.timeIntervalSince1970.isFinite, date.timeIntervalSince1970 >= 0,
              date <= Date().addingTimeInterval(60) else { throw issue() }
        var nodes: [String: (String, RouterProfile)] = [:]
        for profile in profiles {
            let selected = try key(profile)
            if let previous = nodes[profile.id] {
                guard previous.0 == selected else { throw issue() }
            } else { nodes[profile.id] = (selected, profile) }
        }
        var records = try load(), changed = false
        let timestamp = formatter().string(from: date)
        for (_, node) in nodes.sorted(by: { $0.key < $1.key }) {
            let (selected, profile) = node
            if let index = records.firstIndex(where: { $0.key == selected }) {
                if records[index].receipts.contains(adoption) { continue }
                let baseline = max(records[index].count, max(0, profile.useCount ?? 0))
                records[index].count = baseline == Int.max ? Int.max : baseline + 1
                records[index].lastUsed = formatter().string(from: max(date, parsedDate(records[index].lastUsed) ?? date))
                records[index].receipts.append(adoption)
                if records[index].receipts.count > maximumReceipts { records[index].receipts.removeFirst(records[index].receipts.count - maximumReceipts) }
            } else {
                let baseline = max(0, profile.useCount ?? 0)
                records.append(Record(key: selected, count: baseline == Int.max ? Int.max : baseline + 1,
                                      lastUsed: timestamp, receipts: [adoption]))
            }
            changed = true
        }
        guard changed else { return }
        records.sort { $0.lastUsed == $1.lastUsed ? $0.key < $1.key : $0.lastUsed < $1.lastUsed }
        if records.count > maximumRecords { records.removeFirst(records.count - maximumRecords) }
        let data = try canonical(Envelope(schema: 1, records: records))
        try IOSPrivateJSONStore.write(data, filename: filename, maximumBytes: maximumBytes)
    }

    /// Only Node Manager uses these copies. allNodeProfiles and every private
    /// selection/measurement/serialization continue using the original source.
    static func display(_ profiles: [RouterProfile]) -> Display {
        do {
            let records = try load()
            return Display(profiles: profiles.map { original in
                guard let selected = try? key(original), let record = records.first(where: { $0.key == selected }) else { return original }
                var profile = original
                profile.useCount = max(max(0, original.useCount ?? 0), record.count)
                let imported = parsedDate(original.lastUsedAt)
                if imported == nil || parsedDate(record.lastUsed)! >= imported! { profile.lastUsedAt = record.lastUsed }
                return profile
            }, warning: saveWarning)
        } catch {
            return Display(profiles: profiles, warning: "Local usage history is unavailable. Showing imported usage values.")
        }
    }

    static func parsedDate(_ value: String?) -> Date? {
        guard let value, !value.isEmpty, value.utf8.count <= 64 else { return nil }
        guard let date = formatter().date(from: value) ?? ISO8601DateFormatter().date(from: value),
              date.timeIntervalSince1970 >= 0, date <= Date().addingTimeInterval(60) else { return nil }
        return date
    }

    private static func formatter() -> ISO8601DateFormatter {
        let value = ISO8601DateFormatter()
        value.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return value
    }

    private static func load() throws -> [Record] {
        guard let data = try IOSPrivateJSONStore.read(filename, maximumBytes: maximumBytes) else { return [] }
        let envelope = try JSONDecoder().decode(Envelope.self, from: data)
        // Canonical readback also rejects extra/duplicate keys and ambiguous
        // integer encodings. Corruption is never overwritten as an empty file.
        guard envelope.schema == 1, envelope.records.count <= maximumRecords, try canonical(envelope) == data,
              Set(envelope.records.map(\.key)).count == envelope.records.count,
              envelope.records.allSatisfy({ record in
                  hex(record.key) && record.count >= 0 && parsedDate(record.lastUsed) != nil &&
                    !record.receipts.isEmpty && record.receipts.count <= maximumReceipts &&
                    Set(record.receipts).count == record.receipts.count && record.receipts.allSatisfy(hex)
              }) else { throw issue() }
        return envelope.records
    }

    nonisolated private static func hex(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }

    private static func issue() -> NSError {
        NSError(domain: "RouterVPN.NodeUsage", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Node usage history could not be read or saved for its captured source."])
    }
}

enum IOSNodeSort: String, CaseIterable, Identifiable {
    case current = "Current / recent"
    case latency = "Lowest latency"
    case recent = "Last used"
    case used = "Most used"
    case name = "Name"
    var id: String { rawValue }

    @MainActor func ordered(_ profiles: [RouterProfile], selectedID: String) -> [RouterProfile] {
        profiles.sorted { lhs, rhs in
            let lname = lhs.name.isEmpty ? lhs.id.lowercased() : lhs.name.lowercased()
            let rname = rhs.name.isEmpty ? rhs.id.lowercased() : rhs.name.lowercased()
            let left = IOSNodeUsage.parsedDate(lhs.lastUsedAt) ?? .distantPast
            let right = IOSNodeUsage.parsedDate(rhs.lastUsedAt) ?? .distantPast
            switch self {
            case .name: break
            case .used:
                let lc = max(0, lhs.useCount ?? 0), rc = max(0, rhs.useCount ?? 0)
                if lc != rc { return lc > rc }
                if left != right { return left > right }
            case .recent:
                if left != right { return left > right }
                if (lhs.useCount ?? 0) != (rhs.useCount ?? 0) { return (lhs.useCount ?? 0) > (rhs.useCount ?? 0) }
            case .latency:
                let lm = IOSNodeLatencyReceipt.eligible(lhs)
                let rm = IOSNodeLatencyReceipt.eligible(rhs)
                if lm != rm { return lm }
                if lm { return IOSNodeLatencyReceipt.lower(lhs, rhs) }
            case .current:
                let lc = lhs.id == selectedID, rc = rhs.id == selectedID
                if lc != rc { return lc }
                if left != right { return left > right }
            }
            return lname == rname ? lhs.id < rhs.id : lname < rname
        }
    }
}
