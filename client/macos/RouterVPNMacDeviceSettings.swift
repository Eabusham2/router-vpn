import Foundation

// This projection contains only editable common policy and public readback.
// The source token also binds the private entry policy; no private node object
// is copied into the editor or reconstructed from its disabled controls.
struct MacProfileDeviceSettings: Decodable, Sendable {
    let profileID: String
    let profileToken: String
    let nodeKind: String
    let protocolName: String
    let devicePolicySupported: Bool
    let devicePolicyReason: String
    let homeLANAccess: Bool
    let killSwitchPolicy: String
    let ipv6Mode: String
    let mtuPolicy: String
    let manualMTU: Int
    let jumboTUN: Bool?
    let jumboTUNSupported: Bool?
    let effectiveMTU: Int?
    let mtuSource: String?
    let startupMode: String
    let autoConnect: Bool
    let note: String?

    enum CodingKeys: String, CodingKey {
        case profileID = "profile_id", profileToken = "profile_token", nodeKind = "node_kind"
        case protocolName = "protocol", devicePolicySupported = "device_policy_supported"
        case devicePolicyReason = "device_policy_reason", homeLANAccess = "home_lan_access"
        case killSwitchPolicy = "kill_switch_policy", ipv6Mode = "ipv6_mode", mtuPolicy = "mtu_policy"
        case manualMTU = "manual_mtu", effectiveMTU = "effective_mtu", mtuSource = "mtu_source"
        case jumboTUN = "jumbo_tun", jumboTUNSupported = "jumbo_tun_supported"
        case startupMode = "startup_mode", autoConnect = "auto_connect"
        case note
    }

    static func issue(_ message: String) -> NSError {
        NSError(domain: "RouterVPN.DeviceSettings", code: 1,
                userInfo: [NSLocalizedDescriptionKey: message])
    }

    static func validToken(_ token: String) -> Bool {
        token.utf8.count == 64 && token.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }

    static func capture(_ data: Data, displayedProfileID: String) throws -> Self {
        let value = try JSONDecoder().decode(Self.self, from: data)
        let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        let hasJumbo = object?["jumbo_tun"] != nil
        let hasJumboSupport = object?["jumbo_tun_supported"] != nil
        guard !displayedProfileID.isEmpty, value.profileID == displayedProfileID,
              validToken(value.profileToken), value.nodeKind == "external", !value.protocolName.isEmpty,
              ["off", "on-connect", "always"].contains(value.killSwitchPolicy),
              ["on", "off", "auto"].contains(value.ipv6Mode),
              ["auto", "manual", "default"].contains(value.mtuPolicy),
              ["auto", "smart-auto", "last", "manual"].contains(value.startupMode),
              (value.mtuPolicy == "manual" ? (1280...9000).contains(value.manualMTU) : value.manualMTU == 0),
              hasJumbo == hasJumboSupport,
              !hasJumbo || (value.jumboTUN != nil && value.jumboTUNSupported != nil) else {
            throw issue("The selected node or its device policy changed. Reopen Settings.")
        }
        return value
    }

    // Imported nodes use their saved protocol/graph for both historical AUTO
    // spellings. Displaying that alias must not rewrite the stored preference.
    var displayedStartup: String { startupMode == "smart-auto" ? "auto" : startupMode }

    struct Edits: Sendable {
        var homeLANAccess: Bool
        var killSwitchPolicy: String
        var ipv6Mode: String
        var mtuPolicy: String
        var manualMTUText: String
        var startupMode: String
        var autoConnect: Bool
        var jumboTUN: Bool? = nil
    }

    func saveData(displayedProfileID: String, edits: Edits) throws -> Data {
        guard profileID == displayedProfileID, !displayedProfileID.isEmpty,
              Self.validToken(profileToken), devicePolicySupported else {
            throw Self.issue("The selected node changed or this native runtime cannot apply its device policy.")
        }
        guard ["off", "on-connect", "always"].contains(edits.killSwitchPolicy),
              ["on", "off", "auto"].contains(edits.ipv6Mode),
              ["auto", "manual", "default"].contains(edits.mtuPolicy),
              ["auto", "smart-auto", "last", "manual"].contains(edits.startupMode) else {
            throw Self.issue("Choose a supported device policy and startup mode.")
        }
        guard edits.startupMode != "manual" || !edits.autoConnect else {
            throw Self.issue("Manual startup must remain disconnected.")
        }
        var fixed = 0
        if edits.mtuPolicy == "manual" {
            let text = edits.manualMTUText.trimmingCharacters(in: .whitespacesAndNewlines)
            guard (1...4).contains(text.utf8.count), text.utf8.allSatisfy({ (48...57).contains($0) }),
                  let value = Int(text), (1280...9000).contains(value) else {
                throw Self.issue("Fixed MTU must be a whole number from 1280 to 9000. The selected transport must also support it.")
            }
            fixed = value
        }
        let selectedJumbo = edits.jumboTUN ?? jumboTUN
        if let changed = edits.jumboTUN, changed != jumboTUN {
            guard jumboTUNSupported == true, jumboTUN != nil else {
                throw Self.issue("This captured native runtime cannot change Jumbo. Reopen Settings.")
            }
        }
        guard selectedJumbo != true || edits.mtuPolicy != "manual" || fixed == 9000 else {
            throw Self.issue("Jumbo uses a 9000-byte virtual interface. Choose Fixed 9000 or disable Jumbo; no MTU choice was changed.")
        }
        var body: [String: Any] = [
            "profile_id": profileID, "profile_token": profileToken,
            "home_lan_access": edits.homeLANAccess, "kill_switch_policy": edits.killSwitchPolicy,
            "ipv6_mode": edits.ipv6Mode, "mtu_policy": edits.mtuPolicy, "manual_mtu": fixed
        ]
        if edits.startupMode != displayedStartup || edits.autoConnect != autoConnect {
            body["startup_mode"] = edits.startupMode == displayedStartup ? startupMode : edits.startupMode
            body["auto_connect"] = edits.autoConnect
        }
        if let changed = edits.jumboTUN, changed != jumboTUN {
            body["jumbo_tun"] = changed
        }
        return try JSONSerialization.data(withJSONObject: body)
    }

    static func requireIdle(_ data: Data) throws {
        struct State: Decodable { let connected: Bool; let phase: String? }
        let state = try JSONDecoder().decode(State.self, from: data)
        let phase = (state.phase ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !state.connected && ["", "off", "failed"].contains(phase) else {
            throw issue("Disconnect Router VPN and let its active transition finish before saving Settings.")
        }
    }

    // The real UI uses this same transaction. A status lookup cannot replace
    // its captured source token or adopt another displayed node while waiting.
    func save(edits: Edits, displayedProfileID: () -> String, readStatus: () throws -> Data,
              persist: (Data) throws -> Data) throws {
        let body = try saveData(displayedProfileID: displayedProfileID(), edits: edits)
        try Self.requireIdle(readStatus())
        guard displayedProfileID() == profileID else {
            throw Self.issue("The selected node changed before Save. Reopen Settings.")
        }
        let response = try persist(body)
        let saved = try Self.capture(response, displayedProfileID: profileID)
        let request = try JSONSerialization.jsonObject(with: body) as? [String: Any]
        guard saved.devicePolicySupported,
              saved.homeLANAccess == edits.homeLANAccess, saved.killSwitchPolicy == edits.killSwitchPolicy,
              saved.ipv6Mode == edits.ipv6Mode, saved.mtuPolicy == edits.mtuPolicy,
              saved.manualMTU == (request?["manual_mtu"] as? Int),
              saved.startupMode == (request?["startup_mode"] as? String ?? startupMode),
              saved.autoConnect == (request?["auto_connect"] as? Bool ?? autoConnect),
              jumboTUN == nil || saved.jumboTUN == (request?["jumbo_tun"] as? Bool ?? jumboTUN),
              request?["jumbo_tun"] == nil || saved.jumboTUNSupported == true else {
            throw Self.issue("The controller did not confirm the captured device settings. Refresh Settings before retrying.")
        }
    }
}
