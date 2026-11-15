import Foundation
import Libbox

/// Source-only admission for one unlayered, literal OpenVPN middle. The native
/// compiler validates the complete original transport; this creates no VPN or
/// connected generation and supplies no Router pairing identity.
enum IOSImportedOpenVPNSource {
    static func eligible(_ profile: RouterProfile) -> Bool {
        (try? capture(profile)) != nil
    }

    static func capture(_ profile: RouterProfile) throws -> (config: String, capture: String) {
        guard profile.normalizedNodeKind == "external", let external = profile.external,
              external.protocolName == "openvpn", let original = external.openVPN,
              external.startLayer == nil, [nil, "", "off"].contains(profile.startLayer),
              [nil, ""].contains(profile.nodeProofID), profile.routerAPI.isEmpty, profile.apiToken.isEmpty else {
            throw IOSMultihopNodeSelection.issue("Choose an original OpenVPN intermediate with Start Layer Off.")
        }
        var failure: NSError?
        let raw = LibboxRouterOpenVPNEndpoint(original.config, original.username ?? "", original.password ?? "", "custom-exit", "", &failure)
        guard failure == nil,
              let endpoint = try JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any],
              endpoint["type"] as? String == "openvpn-client", endpoint["system"] as? Bool == false,
              endpoint["tag"] as? String == "custom-exit", endpoint["detour"] == nil else {
            throw failure ?? IOSMultihopNodeSelection.issue("The original OpenVPN transport could not be compiled.")
        }
        let graph: [String: Any] = ["inbounds": [["type": "tun", "tag": "tun-in", "address": ["172.29.94.1/30", "fd29:94::1/126"], "mtu": 1280, "auto_route": true, "strict_route": true, "stack": "system"]], "endpoints": [endpoint], "outbounds": [], "route": ["final": "custom-exit", "auto_detect_interface": true]]
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let frozen = try JSONSerialization.jsonObject(with: encoder.encode(profile))
        let selected: [String: Any] = ["schema": 1, "exit_id": profile.id, "protocol": "openvpn", "expected_public_ip": external.expectedPublicIP, "profile": frozen]
        let config = String(decoding: try JSONSerialization.data(withJSONObject: graph, options: [.sortedKeys]), as: UTF8.self)
        let capture = String(decoding: try JSONSerialization.data(withJSONObject: selected, options: [.sortedKeys]), as: UTF8.self)
        // The same shared constructor used by launch decides remote count,
        // literal address, original endpoint and credential/source equality.
        let member = LibboxRouterNodeChainImportedOpenVPNMemberInput(config, capture, &failure)
        guard failure == nil, !member.isEmpty else {
            throw failure ?? IOSMultihopNodeSelection.issue("The OpenVPN intermediate requires one captured literal TCP or UDP remote.")
        }
        return (config, capture)
    }
}
