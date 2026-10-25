import Foundation

/// The common visible device policy. Applying it changes only these fields;
/// native validation still checks the selected transport before persistence.
struct IOSDevicePolicySettings: Equatable {
    var homeLANAccess: Bool
    var killSwitchPolicy: String
    var ipv6Mode: String
    var mtuPolicy: String
    var manualMTU: String

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
        var profile = source
        profile.homeLANAccess = homeLANAccess
        profile.killSwitchPolicy = killSwitchPolicy; profile.killSwitch = killSwitchPolicy != "off"
        profile.ipv6Mode = ipv6Mode
        profile.mtuPolicy = mtuPolicy; profile.manualMTU = fixed
        return profile
    }

    private func issue(_ text: String) -> NSError {
        NSError(domain: "RouterVPN.DevicePolicy", code: 1, userInfo: [NSLocalizedDescriptionKey: text])
    }
}
