import Foundation
import Libbox

/// Explicit preset selection. It never turns an unresolved Home intention
/// into a public resolver or treats historical timing as a fresh winner.
enum IOSDNSQuickSelection {
    static func applying(_ requested: String, to source: RouterProfile, entry: RouterProfile?) throws -> RouterProfile {
        let mode = requested.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard ["home", "rescue"].contains(mode) else {
            throw issue("Use DNS details / Retest to measure and select a resolver, or to configure its transport.")
        }
        let external = source.normalizedNodeKind == "external"
        let tor = external && ["tor", "tor-bridge"].contains(source.external?.protocolName ?? "")
        guard source.normalizedNodeKind == "router-vpn" ||
              (external && (tor || IOSExternalDNSPolicy.protocols.contains(source.external?.protocolName ?? ""))) else {
            throw issue("Select one linked node with a native DNS policy.")
        }
        var profile = source
        if mode == "home" {
            let home: RouterProfile
            if external {
                guard let entry, entry.normalizedNodeKind == "router-vpn", entry.id != source.id,
                      source.multihopEnabled == true, source.multihopEntryID == entry.id,
                      source.multihopExitID == source.id, source.multihopExitMode == source.external?.protocolName,
                      entry.nodeProofID?.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
                      !entry.apiToken.isEmpty, !entry.routerAPI.isEmpty else {
                    throw issue("Home AdGuard requires the selected paired Router VPN entry. Choose that entry in Multihop before selecting Home.")
                }
                home = entry
            } else { home = source }
            let addresses = [home.adGuardIPv4, home.adGuardIPv6].filter { !$0.isEmpty }
            guard let address = addresses.first else { throw issue("The captured home node has no saved AdGuard address.") }
            if (source.dnsMode ?? "").lowercased() == "home" {
                // Re-selecting an explicit Home policy preserves its chosen
                // encrypted transport, port, path and address family.
                guard (source.dnsHost ?? "").isEmpty || addresses.contains(source.dnsHost ?? "") else {
                    throw issue("The saved Home resolver belongs to another node. Edit DNS before saving it.")
                }
            } else {
                profile.dnsProtocol = "udp"; profile.dnsHost = address; profile.dnsPort = 53
                profile.dnsServerName = ""; profile.dnsPath = ""; profile.dnsBootstrap = nil
            }
        } else {
            // Rescue is the existing explicit native preset, not an inferred
            // fallback for Home or a failed custom resolver.
            var https = IOSPairedRescueHTTPS.preset
            if !external && source.dnsMode?.lowercased() == "rescue",
               let saved = try IOSPairedRescueHTTPS.resolve(protocolName: source.dnsProtocol ?? "", host: source.dnsHost ?? "",
                   port: source.dnsPort ?? 0, serverName: source.dnsServerName ?? "", path: source.dnsPath ?? "") {
                https = saved
            } else { profile.dnsBootstrap = nil }
            profile.dnsProtocol = "https"; profile.dnsHost = https.host; profile.dnsPort = https.port
            profile.dnsServerName = https.serverName; profile.dnsPath = https.path
        }
        profile.dnsMode = mode
        if tor {
            var failure: NSError?
            let valid = LibboxRouterValidateTorProfile(String(decoding: try JSONEncoder().encode(profile), as: UTF8.self), &failure)
            if let failure { throw failure }
            guard valid else { throw issue("Tor DNS validation did not complete.") }
        } else if external {
            try IOSExternalDNSPolicy.validate(profile, entry: entry)
        } else { _ = try IOSDNSRuntimePolicy.resolve(profile) }
        return profile
    }

    private static func issue(_ text: String) -> NSError {
        NSError(domain: "RouterVPN.QuickDNS", code: 1, userInfo: [NSLocalizedDescriptionKey: text])
    }
}
