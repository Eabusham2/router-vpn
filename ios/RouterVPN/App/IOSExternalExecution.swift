import Foundation
import Libbox

/// Pure readiness checks. Passing these checks never means that the entry's
/// private relay registry accepted this node or that a candidate was proved.
enum IOSExternalExecution {
    static func validateImported(_ bundle: ClientBundle) throws {
        for profile in bundle.routerProfiles {
            guard let external = profile.external, let probe = external.responseProbe else { continue }
            guard profile.normalizedNodeKind == "external", external.protocolName == "shadowsocks",
                  let transport = external.shadowsocks else { throw issue() }
            try validate(probe, host: transport.server)
        }
    }

    static func responseProbe(host: String, url: String, serverName: String) throws -> ExternalResponseProbe? {
        if url.isEmpty && serverName.isEmpty { return nil }
        let probe = ExternalResponseProbe(url: url, serverName: serverName.isEmpty ? nil : serverName)
        try validate(probe, host: host)
        return probe
    }

    static func validate(_ probe: ExternalResponseProbe, host: String) throws {
        let data = try JSONEncoder().encode(probe)
        var failure: NSError?
        let valid = LibboxRouterValidateExternalResponseProbe(host, String(decoding: data, as: UTF8.self), &failure)
        if let failure { throw failure }
        guard valid else { throw issue() }
    }

    static func eligible(entry: RouterProfile, exit: RouterProfile) -> Bool {
        guard entry.id != exit.id, entry.normalizedNodeKind == "router-vpn",
              entry.nodeProofID?.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
              !entry.routerAPI.isEmpty, !entry.apiToken.isEmpty,
              exit.normalizedNodeKind == "external", let external = exit.external,
              external.protocolName == "shadowsocks", let transport = external.shadowsocks,
              !transport.password.isEmpty, let probe = external.responseProbe,
              [nil, "", "off"].contains(exit.startLayer) else { return false }
        do { try validate(probe, host: transport.server); return true }
        catch { return false }
    }

    static func require(selection: String, entry: RouterProfile, exit: RouterProfile) throws {
        guard ["local", "server", "auto"].contains(selection),
              selection == "local" || eligible(entry: entry, exit: exit) else { throw issue() }
    }

    static func issue() -> NSError {
        NSError(domain: "RouterVPN.ExternalExecution", code: 1,
            userInfo: [NSLocalizedDescriptionKey: "Server and Compare require a paired Router VPN entry and a Shadowsocks exit with an HTTPS response URL on its exact server IP. Configure this exit in the entry's private relay registry before connecting."])
    }
}
