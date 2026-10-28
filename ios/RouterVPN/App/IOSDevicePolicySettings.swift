import Foundation

/// The common visible device policy. Applying it changes only these fields;
/// native validation still checks the selected transport before persistence.
struct IOSDevicePolicySettings: Equatable {
    var homeLANAccess: Bool
    var killSwitchPolicy: String
    var ipv6Mode: String
    var mtuPolicy: String
    var manualMTU: String
    var jumboTUN: Bool
    var torPaddingEnabled: Bool
    var torPaddingRate: String

    init(profile: RouterProfile) {
        homeLANAccess = profile.homeLANAccess ?? true
        let kill = (profile.killSwitchPolicy ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if ["always", "strict", "enabled", "on", "lockdown"].contains(kill) { killSwitchPolicy = "always" }
        else if profile.killSwitch == true || kill == "on-connect" { killSwitchPolicy = "on-connect" }
        else { killSwitchPolicy = kill.isEmpty ? "off" : kill }
        let ipv6 = (profile.ipv6Mode ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        ipv6Mode = ipv6.isEmpty ? "on" : ipv6
        let mtu = (profile.mtuPolicy ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        mtuPolicy = mtu == "fixed" ? "manual" : mtu.isEmpty ? "auto" : mtu
        manualMTU = profile.manualMTU.map(String.init) ?? ""
        jumboTUN = profile.jumboTUN ?? false
        torPaddingEnabled = profile.daitaEnabled ?? false
        torPaddingRate = String((profile.daitaRateKbps ?? 0) == 0 ? 192 : profile.daitaRateKbps!)
    }

    func applying(to source: RouterProfile) throws -> RouterProfile {
        guard source.normalizedNodeKind == "external" else { throw issue("Select an external node for this device-policy editor.") }
        guard ["off", "on-connect", "always"].contains(killSwitchPolicy),
              ["on", "auto", "off"].contains(ipv6Mode),
              ["auto", "manual", "default"].contains(mtuPolicy) else {
            throw issue("Choose a supported kill-switch, IPv6 and MTU policy before saving.")
        }
        let fixed: Int
        if mtuPolicy == "manual" {
            guard let value = Int(manualMTU.trimmingCharacters(in: .whitespacesAndNewlines)), (1280...9000).contains(value) else {
                throw issue("Fixed MTU must be an integer from 1280 through 9000.")
            }
            fixed = value
        } else { fixed = 0 }
        let tor = ["tor", "tor-bridge"].contains(source.external?.protocolName.lowercased() ?? "")
        if tor && jumboTUN && mtuPolicy == "manual" && fixed != 9000 {
            throw issue("Tor Jumbo requires a 9000-byte virtual interface; choose Fixed 9000 or retain Auto/Runtime default.")
        }
        var profile = source
        profile.homeLANAccess = homeLANAccess
        profile.killSwitchPolicy = killSwitchPolicy; profile.killSwitch = killSwitchPolicy != "off"
        profile.ipv6Mode = ipv6Mode
        profile.mtuPolicy = mtuPolicy; profile.manualMTU = fixed
        if tor, jumboTUN != (source.jumboTUN ?? false) { profile.jumboTUN = jumboTUN }
        if tor {
            if torPaddingEnabled != (source.daitaEnabled ?? false) { profile.daitaEnabled = torPaddingEnabled }
            if torPaddingEnabled {
                guard let rate = Int(torPaddingRate.trimmingCharacters(in: .whitespacesAndNewlines)), (32...192).contains(rate) else {
                    throw issue("Tor padding rate must be an integer from 32 through 192 kbps.")
                }
                profile.daitaRateKbps = rate
            }
            // Off keeps the exact dormant rate, including an unset/default
            // value. Ordinary nodes never adopt these Tor-only controls.
        }
        return profile
    }

    private func issue(_ text: String) -> NSError {
        NSError(domain: "RouterVPN.DevicePolicy", code: 1, userInfo: [NSLocalizedDescriptionKey: text])
    }
}
