import Foundation
import CoreFoundation
import Libbox
#if canImport(CryptoKit)
import CryptoKit
#endif

/// A native receipt describes outgoing Tor link cells, not delivery to a
/// remote peer. Its deadlines come from completed DNS/path proofs and the
/// native lease; reading it again grants no new lifetime.
struct RouterVPNTorPaddingReceipt: Equatable, Sendable {
    let generation: UInt64
    let cells: UInt64
    let bytes: UInt64
    let observed: Int64
    let expires: Int64
    let pathChecked: Int64
    let dnsChecked: Int64

    struct Policy: Sendable {
        let enabled: Bool
        let rate: Int
        let sessionSHA256: String
        let sourceSHA256: String

        static func capture(config: String, profile: String, sessionID: String, execution: String) throws -> Policy {
            guard let value = try JSONSerialization.jsonObject(with: Data(profile.utf8)) as? [String: Any],
                  ["local", "server"].contains(execution), !sessionID.isEmpty else { throw issue() }
            let selected: Bool
            if let raw = value["daita_enabled"] {
                guard let number = raw as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else { throw issue() }
                selected = number.boolValue
            } else { selected = false }
            var rate = 0
            if let raw = value["daita_rate_kbps"] {
                guard let number = integer(raw), number <= 192, number == 0 || number >= 32 else { throw issue() }
                rate = Int(number)
            }
            if selected && rate == 0 { rate = 192 }
            let source: String
            if execution == "local" {
                var failure: NSError?
                source = LibboxRouterTorPaddingSource(config, profile, sessionID, &failure)
                if let failure { throw failure }
                guard selected ? digest(source) : source.isEmpty else { throw issue() }
            } else { source = "" }
            return Policy(enabled: selected && execution == "local", rate: rate,
                sessionSHA256: SHA256.hash(data: Data(sessionID.utf8)).map { String(format: "%02x", $0) }.joined(), sourceSHA256: source)
        }

        func validate(_ text: String, previous: RouterVPNTorPaddingReceipt?, now: Date) throws -> RouterVPNTorPaddingReceipt? {
            guard enabled else {
                guard text.isEmpty, previous == nil else { throw issue() }
                return nil
            }
            let milliseconds = now.timeIntervalSince1970 * 1000
            guard milliseconds.isFinite, milliseconds > 0, milliseconds < Double(Int64.max),
                  (32...192).contains(rate), digest(sessionSHA256), digest(sourceSHA256),
                  !text.isEmpty, text.utf8.count <= 4096,
                  let status = try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any],
                  Set(status.keys) == ["receipt", "path_checked_at", "dns_checked_at"],
                  let receipt = status["receipt"] as? [String: Any],
                  Set(receipt.keys) == ["direction", "accounting", "session_sha256", "source_sha256", "generation", "rate_kbps", "channel_cells", "channel_cell_bytes", "observed_at", "expires_at"],
                  receipt["direction"] as? String == "outgoing", receipt["accounting"] as? String == "tor-link-cell",
                  receipt["session_sha256"] as? String == sessionSHA256, receipt["source_sha256"] as? String == sourceSHA256,
                  let generation = integer(receipt["generation"]), generation > 0, generation <= UInt64(Int64.max),
                  integer(receipt["rate_kbps"]) == UInt64(rate),
                  let cells = integer(receipt["channel_cells"]), cells > 0, cells <= UInt64.max / 514,
                  let bytes = integer(receipt["channel_cell_bytes"]), bytes >= cells * 512, bytes <= cells * 514, bytes % 2 == 0,
                  let observed = timestamp(receipt["observed_at"]), let expires = timestamp(receipt["expires_at"]),
                  let path = timestamp(status["path_checked_at"]), let dns = timestamp(status["dns_checked_at"]) else { throw issue() }
            let clock = Int64(milliseconds.rounded(.down))
            guard dns <= path, path <= clock, observed <= clock, clock - observed <= 5000,
                  expires > clock, observed <= Int64.max - 10000, expires <= observed + 10000,
                  dns <= Int64.max - 30000, expires <= dns + 30000 else { throw issue() }
            let next = RouterVPNTorPaddingReceipt(generation: generation, cells: cells, bytes: bytes,
                observed: observed, expires: expires, pathChecked: path, dnsChecked: dns)
            if let previous {
                guard next.generation == previous.generation, next.cells >= previous.cells, next.bytes >= previous.bytes,
                      next.observed >= previous.observed, next.pathChecked >= previous.pathChecked,
                      next.dnsChecked >= previous.dnsChecked else { throw issue() }
            }
            return next
        }
    }

    private static func integer(_ raw: Any?) -> UInt64? {
        guard let number = raw as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
        return UInt64(number.stringValue)
    }
    private static func timestamp(_ raw: Any?) -> Int64? {
        guard let value = integer(raw), value > 0, value <= UInt64(Int64.max) else { return nil }
        return Int64(value)
    }
    private static func digest(_ text: String) -> Bool {
        text.utf8.count == 64 && text.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    private static func issue() -> NSError {
        NSError(domain: "RouterVPN.TorPadding", code: 1, userInfo: [NSLocalizedDescriptionKey: "Tor padding has no current receipt for this session, source and selected DNS/path proof."])
    }
}
