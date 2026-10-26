import Foundation

/// Native evidence only. The caller must also bind replies to its live VPN.
/// Stored values, cache hits and restoration are not fresh measurements.
struct IOSMTUStatus: Decodable, Sendable {
    struct Transfer: Decodable, Sendable {
        let bytes: Int64?
        let seconds: Double?
        let mbps: Double?
        var valid: Bool {
            guard bytes == 262144, let seconds, seconds.isFinite, seconds > 0,
                  let mbps, mbps.isFinite, mbps > 0 else { return false }
            let expected = 262144.0 * 8.0 / seconds / 1_000_000.0
            return abs(expected - mbps) <= max(0.000001, expected * 0.000001)
        }
    }
    struct Candidate: Decodable, Sendable {
        let mtu: Int?
        let working: Bool?
        let packets_sent: Int?
        let packets_received: Int?
        let datagram_bytes: Int?
        let median_rtt_ms: Double?
        let latency_kind: String?
        let download: Transfer?
        let upload: Transfer?
        let failure: String?
        func valid(source: String) -> Bool {
            guard let mtu, (1280...1500).contains(mtu), working == true,
                  let median_rtt_ms, median_rtt_ms.isFinite, median_rtt_ms > 0,
                  download?.valid == true, upload?.valid == true,
                  failure == nil || failure == "" else { return false }
            if ["measured-public-system-tun-transfer", "measured-tor-system-tun-transfer"].contains(source) {
                return latency_kind == "https-response" && packets_sent == 0 && packets_received == 0 && datagram_bytes == 0
            }
            guard source == "measured-private-system-tun", latency_kind == nil || latency_kind == "",
                  packets_sent == 6, packets_received == 6,
                  let datagram_bytes, [mtu - 28, mtu - 48].contains(datagram_bytes) else { return false }
            return true
        }
    }
    let session_id: String?
    let request_id: String?
    let phase: String?
    let running: Bool?
    let complete: Bool?
    let measured: Bool?
    let restored: Bool?
    let effective_mtu: Int?
    let original_mtu: Int?
    let source: String?
    let failure: String?
    let candidates: [Candidate]?
    let measurement_hold: Bool?
    let interface_readback_valid: Bool?
    let optimization_allowed: Bool?
    let tor_connection: Bool?
    let policy_note: String?

    var verified: Bool {
        guard let session_id, UUID(uuidString: session_id) != nil,
              let request_id, request_id.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil,
              phase == "complete", complete == true, running == false, measured == true, restored != true,
              interface_readback_valid == true,
              let source, ["measured-private-system-tun", "measured-public-system-tun-transfer", "measured-tor-system-tun-transfer"].contains(source), let effective_mtu,
              (1280...1500).contains(effective_mtu), let original_mtu,
              (1280...9000).contains(original_mtu), let candidates,
              (1...5).contains(candidates.count), Set(candidates.compactMap(\.mtu)).count == candidates.count,
              failure == nil || failure == "" else { return false }
        return candidates.contains { $0.mtu == effective_mtu && $0.valid(source: source) }
    }
    var configuredCapacity: Int? {
        guard let session_id, UUID(uuidString: session_id) != nil,
              source == "configured-unmeasured", measured == false, running == false,
              restored != true, interface_readback_valid == true,
              let effective_mtu, (1280...9000).contains(effective_mtu),
              failure == nil || failure == "" else { return nil }
        return effective_mtu
    }
    var summary: String {
        if verified, let effective_mtu {
            let evidence = source == "measured-private-system-tun" ? "authenticated packets and transfer tests" : "HTTPS response and transfer tests"
            let path = source == "measured-tor-system-tun-transfer" ? "this proved Tor session" : "this VPN"
            return "Verified current MTU: \(effective_mtu) bytes • \(evidence) through \(path)"
        }
        if running == true { return "MTU test: \(phase ?? "measuring") • result not yet verified" }
        if restored == true { return "Original MTU restored • no new measurement adopted" }
        if let capacity = configuredCapacity {
            let retained = optimization_allowed == false ? " • Auto MTU and Retest are disabled by the captured policy" : ""
            return "Configured interface capacity: \(capacity) bytes • not a measured path MTU\(retained)"
        }
        return "MTU measurement unavailable — \(failure ?? "no fresh result for this VPN session")"
    }
}
