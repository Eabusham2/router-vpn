import Foundation
import Libbox

/// Settings use the same DNS parser as native runtime compilation. A missing
/// Home entry may be saved as a draft; connection still requires its exact
/// captured entry and the live DNS, private-node and public-exit proofs.
enum IOSExternalDNSPolicy {
    static let protocols: Set<String> = ["wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn"]

    static func validate(_ profile: RouterProfile, entry: RouterProfile? = nil) throws {
        guard profile.normalizedNodeKind == "external", protocols.contains(profile.external?.protocolName ?? "") else {
            throw issue("Select an ordinary external node for this DNS policy.")
        }
        let encoder = JSONEncoder()
        let captured = String(decoding: try encoder.encode(profile), as: UTF8.self)
        let predecessor = try entry.map { String(decoding: try encoder.encode($0), as: UTF8.self) } ?? ""
        var failure: NSError?
        let valid = LibboxRouterValidateExternalDNS(captured, predecessor, &failure)
        if let failure { throw failure }
        guard valid else { throw issue("External DNS policy validation did not complete.") }
    }

    private static func issue(_ text: String) -> NSError { NSError(domain: "RouterVPN.ExternalDNS", code: 1, userInfo: [NSLocalizedDescriptionKey: text]) }
}
