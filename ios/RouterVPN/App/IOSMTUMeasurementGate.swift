import Foundation

/// Main-actor ownership survives temporary VPN generations and nests selection
/// inside Speed Lab. Only the final matching token can release the opaque lease.
@MainActor enum IOSMTUMeasurementGate {
    struct Lease: Sendable { let token: UUID; let request: String }
    private static var owners: Set<UUID> = []
    private static var request = ""
    static var current: String { request }
    static var held: Bool { !owners.isEmpty }
    static func acquire() -> Lease {
        if owners.isEmpty { request = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased() }
        let token = UUID(); owners.insert(token)
        return Lease(token: token, request: request)
    }
    static func release(_ lease: Lease) -> Bool {
        guard lease.request == request, owners.remove(lease.token) != nil else { return false }
        if owners.isEmpty { request = ""; return true }
        return false
    }
}
