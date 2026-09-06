import Foundation
import Network
import SwiftUI

private let iosConnectionProfilesKey = "routervpn.connection-profiles.v1"
private let iosConnectionProfilesFile = "connection-profiles.json"
private let iosConnectionProfilesSchemaVersion = 4
private let iosConnectionProfilesMaximumBytes = 512 * 1024
private let iosConnectionModeKey = "routervpn.unified.mode.v1"
private let iosConnectionCustomPresetsKey = "routervpn.unified.custom-presets.v1"

private struct IOSConnectionCustomPresetMirror: Codable {
    var name: String
    var layers: [String]
}

private struct IOSConnectionSafePreferences: Codable, Hashable {
    var homeLANAccess: Bool
    var killSwitch: Bool
    var killSwitchPolicy: String
    var ipv6Mode: String
    var baseTunnel: String
    var baseFallback: Bool
    var startLayer: String
    var autoRequireEncrypted: Bool
    var autoRequireObfuscation: Bool
    var mtuPolicy: String
    var manualMTU: Int
    var startupMode: String
    var autoConnect: Bool
    var dnsMode: String
    var dnsProtocol: String
    var dnsHost: String
    var dnsPort: Int
    var dnsServerName: String
    var dnsPath: String

    enum CodingKeys: String, CodingKey {
        case homeLANAccess, killSwitch, killSwitchPolicy, ipv6Mode, baseTunnel, baseFallback, startLayer
        case autoRequireEncrypted, autoRequireObfuscation, mtuPolicy, manualMTU, startupMode, autoConnect
        case dnsMode, dnsProtocol, dnsHost, dnsPort, dnsServerName, dnsPath
    }
}

private extension IOSConnectionSafePreferences {
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        homeLANAccess = try c.decodeIfPresent(Bool.self, forKey: .homeLANAccess) ?? true
        killSwitch = try c.decodeIfPresent(Bool.self, forKey: .killSwitch) ?? false
        killSwitchPolicy = try c.decodeIfPresent(String.self, forKey: .killSwitchPolicy) ?? (killSwitch ? "always" : "off")
        ipv6Mode = try c.decodeIfPresent(String.self, forKey: .ipv6Mode) ?? "on"
        baseTunnel = try c.decodeIfPresent(String.self, forKey: .baseTunnel) ?? "auto"
        baseFallback = try c.decodeIfPresent(Bool.self, forKey: .baseFallback) ?? false
        startLayer = try c.decodeIfPresent(String.self, forKey: .startLayer) ?? "off"
        autoRequireEncrypted = try c.decodeIfPresent(Bool.self, forKey: .autoRequireEncrypted) ?? false
        autoRequireObfuscation = try c.decodeIfPresent(Bool.self, forKey: .autoRequireObfuscation) ?? false
        mtuPolicy = try c.decodeIfPresent(String.self, forKey: .mtuPolicy) ?? "auto"
        manualMTU = try c.decodeIfPresent(Int.self, forKey: .manualMTU) ?? 0
        startupMode = try c.decodeIfPresent(String.self, forKey: .startupMode) ?? "smart-auto"
        autoConnect = try c.decodeIfPresent(Bool.self, forKey: .autoConnect) ?? false
        dnsMode = try c.decodeIfPresent(String.self, forKey: .dnsMode) ?? "home"
        dnsProtocol = try c.decodeIfPresent(String.self, forKey: .dnsProtocol) ?? "udp"
        dnsHost = try c.decodeIfPresent(String.self, forKey: .dnsHost) ?? ""
        dnsPort = try c.decodeIfPresent(Int.self, forKey: .dnsPort) ?? 0
        dnsServerName = try c.decodeIfPresent(String.self, forKey: .dnsServerName) ?? ""
        dnsPath = try c.decodeIfPresent(String.self, forKey: .dnsPath) ?? ""
    }
}

private struct IOSConnectionProfileRecord: Identifiable, Codable, Hashable {
    var id: String
    var name: String
    var nodeID: String
    var nodeKind: String
    var mode: String
    var customLayers: [String]
    var preferences: IOSConnectionSafePreferences?
    var updatedAt: Date

    var autoRequirementsSummary: String {
        guard let preferences else { return "AUTO n/a" }
        if preferences.autoRequireEncrypted && preferences.autoRequireObfuscation { return "AUTO Encrypted+Obfuscation" }
        if preferences.autoRequireEncrypted { return "AUTO Encrypted" }
        if preferences.autoRequireObfuscation { return "AUTO Obfuscation" }
        return "AUTO Off"
    }
}

private struct IOSConnectionProfileEnvelope: Codable {
    var schemaVersion: Int
    var profiles: [IOSConnectionProfileRecord]

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case profiles
    }
}

@MainActor
private enum IOSConnectionProfileStore {
    private(set) static var lastStoreError = ""

    static func all() -> [IOSConnectionProfileRecord] {
        do {
            let values = try loadAll()
            lastStoreError = ""
            return values
        } catch {
            lastStoreError = error.localizedDescription
            return []
        }
    }

    private static func loadAll() throws -> [IOSConnectionProfileRecord] {
        let decoder = JSONDecoder()
        if let data = try IOSPrivateJSONStore.read(
            iosConnectionProfilesFile,
            maximumBytes: iosConnectionProfilesMaximumBytes
        ) {
            if let envelope = try? decoder.decode(IOSConnectionProfileEnvelope.self, from: data) {
                guard envelope.schemaVersion >= 1, envelope.schemaVersion <= iosConnectionProfilesSchemaVersion else {
                    throw issue("Unsupported connection profile store schema \(envelope.schemaVersion).")
                }
                let values = try validateStoredProfiles(envelope.profiles)
                if envelope.schemaVersion < iosConnectionProfilesSchemaVersion { try persist(values) }
                return sorted(values)
            }
            // The pre-v4 private store was a raw array. Treat that exact shape as
            // known schema v1, validate it fully, then atomically rewrite v4.
            let values = try validateStoredProfiles(decoder.decode([IOSConnectionProfileRecord].self, from: data))
            try persist(values)
            return sorted(values)
        }

        guard let legacy = UserDefaults.standard.data(forKey: iosConnectionProfilesKey) else { return [] }
        guard !legacy.isEmpty, legacy.count <= iosConnectionProfilesMaximumBytes else {
            throw issue("Legacy connection profile store has an invalid size.")
        }
        let values = try validateStoredProfiles(decoder.decode([IOSConnectionProfileRecord].self, from: legacy))
        try persist(values)
        UserDefaults.standard.removeObject(forKey: iosConnectionProfilesKey)
        return sorted(values)
    }

    static func snapshot(model: RouterVPNModel, name rawName: String, id: String? = nil) throws -> IOSConnectionProfileRecord {
        guard !model.profileMutationBlocked else { throw issue("Disconnect or let the active VPN transition finish before saving or updating a connection profile.") }
        let name = try cleanName(rawName)
        guard let selected = model.selectedNodeProfile else { throw issue("Select a linked Router or Custom node first.") }
        let mode = try normalizeMode(UserDefaults.standard.string(forKey: iosConnectionModeKey) ?? "smart-auto")
        let layers = try customLayers(for: mode)
        let prefs: IOSConnectionSafePreferences?
        if selected.normalizedNodeKind == "router-vpn" {
            if selected.multihopEnabled == true {
                throw issue("The selected Router node currently contains desktop-style multihop choices. Current iOS cannot execute full desktop multihop, so this setup is not saved as a misleading iOS connection profile. Disable multihop or save it from a supported desktop/Android path.")
            }
            prefs = IOSConnectionSafePreferences(
                homeLANAccess: selected.homeLANAccess ?? true,
                killSwitch: selected.killSwitch ?? false,
                killSwitchPolicy: (selected.killSwitchPolicy ?? "off").lowercased(),
                ipv6Mode: (selected.ipv6Mode ?? "on").lowercased(),
                baseTunnel: (selected.baseTunnel ?? "auto").lowercased(),
                baseFallback: selected.baseFallback ?? false,
                startLayer: (selected.startLayer ?? "off").lowercased(),
                autoRequireEncrypted: selected.autoRequireEncrypted ?? false,
                autoRequireObfuscation: selected.autoRequireObfuscation ?? false,
                mtuPolicy: (selected.mtuPolicy ?? "auto").lowercased(),
                manualMTU: selected.manualMTU ?? 0,
                startupMode: (selected.startupMode ?? "smart-auto").lowercased(),
                autoConnect: selected.autoConnect ?? false,
                dnsMode: (selected.dnsMode ?? "home").lowercased(),
                dnsProtocol: (selected.dnsProtocol ?? "udp").lowercased(),
                dnsHost: selected.dnsHost ?? "",
                dnsPort: selected.dnsPort ?? 0,
                dnsServerName: selected.dnsServerName ?? "",
                dnsPath: selected.dnsPath ?? ""
            )
        } else {
            prefs = nil
        }
        return IOSConnectionProfileRecord(id: id ?? UUID().uuidString.lowercased(), name: name, nodeID: selected.id,
                                          nodeKind: selected.normalizedNodeKind, mode: selected.normalizedNodeKind == "external" ? "external" : mode,
                                          customLayers: selected.normalizedNodeKind == "external" ? [] : layers, preferences: prefs, updatedAt: Date())
    }

    static func add(model: RouterVPNModel, name: String) throws -> IOSConnectionProfileRecord {
        var values = try loadAll(); guard values.count < 64 else { throw issue("Connection profile limit reached.") }
        let value = try snapshot(model: model, name: name); values.append(value); try persist(values); return value
    }

    static func update(model: RouterVPNModel, id: String, name: String) throws -> IOSConnectionProfileRecord {
        var values = try loadAll(); guard let index = values.firstIndex(where: { $0.id == id }) else { throw issue("Connection profile was not found.") }
        let value = try snapshot(model: model, name: name, id: id); values[index] = value; try persist(values); return value
    }

    static func delete(model: RouterVPNModel, id: String) throws {
        guard !model.profileMutationBlocked else { throw issue("Disconnect or let the active VPN transition finish before deleting a connection profile.") }
        var values = try loadAll(); let before = values.count; values.removeAll { $0.id == id }; guard values.count != before else { throw issue("Connection profile was not found.") }; try persist(values)
    }

    static func load(model: RouterVPNModel, id: String) throws -> IOSConnectionProfileRecord {
        guard !model.profileMutationBlocked else { throw issue("Disconnect or let the active VPN transition finish before loading a connection profile.") }
        guard let saved = try loadAll().first(where: { $0.id == id }) else { throw issue("Connection profile was not found.") }
        guard let linked = model.allNodeProfiles.first(where: { $0.id == saved.nodeID }), linked.normalizedNodeKind == saved.nodeKind else {
            throw issue("The linked node referenced by this connection profile is missing or changed type.")
        }
        guard var bundle = model.bundle,
              let index = bundle.routerProfiles.firstIndex(where: { $0.id == saved.nodeID }) else { throw issue("Linked node bundle could not be loaded.") }

        if saved.nodeKind == "external" {
            bundle.selectedRouterID = saved.nodeID
            do { try model.importBundle(JSONEncoder().encode(bundle)) }
            catch { throw issue("Could not select the saved Custom/external node: \(error.localizedDescription)") }
            UserDefaults.standard.set("smart-auto", forKey: iosConnectionModeKey)
            return saved
        }

        guard let prefs = saved.preferences else { throw issue("Router connection profile is missing its non-secret preference snapshot.") }
        let effectiveMode = try normalizeMode(saved.mode)
        let preparedPreset = try preparedCustomPresetData(mode: effectiveMode, layers: saved.customLayers)
        var profile = bundle.routerProfiles[index]
        profile.homeLANAccess = prefs.homeLANAccess
        profile.killSwitch = prefs.killSwitch
        profile.killSwitchPolicy = prefs.killSwitchPolicy
        profile.ipv6Mode = prefs.ipv6Mode
        profile.baseTunnel = prefs.baseTunnel
        profile.baseFallback = prefs.baseFallback
        profile.startLayer = prefs.startLayer
        profile.autoRequireEncrypted = prefs.autoRequireEncrypted
        profile.autoRequireObfuscation = prefs.autoRequireObfuscation
        profile.mtuPolicy = prefs.mtuPolicy
        profile.manualMTU = prefs.manualMTU
        profile.startupMode = prefs.startupMode
        profile.autoConnect = prefs.autoConnect
        profile.dnsMode = prefs.dnsMode
        profile.dnsProtocol = prefs.dnsProtocol
        profile.dnsHost = prefs.dnsHost
        profile.dnsPort = prefs.dnsPort
        profile.dnsServerName = prefs.dnsServerName
        profile.dnsPath = prefs.dnsPath
        profile.multihopEnabled = false
        profile.multihopEntryID = nil
        profile.multihopExitID = nil
        bundle.routerProfiles[index] = profile
        bundle.selectedRouterID = saved.nodeID
        bundle.profileSchemaVersion = max(bundle.profileSchemaVersion, 4)

        do { try model.importBundle(JSONEncoder().encode(bundle)) }
        catch { throw issue("Could not apply saved connection preferences: \(error.localizedDescription)") }
        UserDefaults.standard.set(effectiveMode, forKey: iosConnectionModeKey)
        if let preparedPreset { UserDefaults.standard.set(preparedPreset, forKey: iosConnectionCustomPresetsKey) }
        return saved
    }

    private static func persist(_ values: [IOSConnectionProfileRecord]) throws {
        let validated = try validateStoredProfiles(values)
        let envelope = IOSConnectionProfileEnvelope(schemaVersion: iosConnectionProfilesSchemaVersion, profiles: validated)
        let data = try JSONEncoder().encode(envelope)
        try IOSPrivateJSONStore.write(
            data,
            filename: iosConnectionProfilesFile,
            maximumBytes: iosConnectionProfilesMaximumBytes
        )
    }

    private static func validateStoredProfiles(_ values: [IOSConnectionProfileRecord]) throws -> [IOSConnectionProfileRecord] {
        guard values.count <= 64 else { throw issue("Connection profile limit exceeded.") }
        var ids = Set<String>()
        var validated: [IOSConnectionProfileRecord] = []
        validated.reserveCapacity(values.count)
        for value in values {
            var record = value
            record.name = try cleanName(value.name)
            guard !value.id.isEmpty, value.id.count <= 128, ids.insert(value.id).inserted else {
                throw issue("Connection profile store contains an invalid or duplicate id.")
            }
            let nodeID = value.nodeID.trimmingCharacters(in: .whitespacesAndNewlines)
            guard (value.nodeKind == "router-vpn" || value.nodeKind == "external"),
                  !nodeID.isEmpty, nodeID.count <= 128,
                  nodeID.unicodeScalars.allSatisfy({ CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-").contains($0) }) else {
                throw issue("Connection profile store contains an invalid node reference.")
            }
            record.nodeID = nodeID
            record.mode = try normalizeMode(value.mode)
            record.customLayers = try normalizeLayers(value.customLayers)
            if value.nodeKind == "router-vpn" {
                guard let preferences = value.preferences else {
                    throw issue("Router connection profile is missing its non-secret preference snapshot.")
                }
                record.preferences = try validatePreferences(preferences)
                if record.mode == "external" { throw issue("Router connection profile cannot use external mode.") }
            } else {
                guard value.preferences == nil, record.customLayers.isEmpty, record.mode == "external" else {
                    throw issue("External connection profile contains Router-only saved policy.")
                }
            }
            validated.append(record)
        }
        return validated
    }

    private static func validatePreferences(_ value: IOSConnectionSafePreferences) throws -> IOSConnectionSafePreferences {
        var p = value
        p.killSwitchPolicy = p.killSwitchPolicy.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard ["off", "on-connect", "always"].contains(p.killSwitchPolicy) else { throw issue("Connection profile contains an invalid kill-switch policy.") }
        p.killSwitch = p.killSwitchPolicy != "off"

        p.ipv6Mode = p.ipv6Mode.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard ["on", "auto", "off"].contains(p.ipv6Mode) else { throw issue("Connection profile contains an invalid IPv6 policy.") }
        p.baseTunnel = p.baseTunnel.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard ["auto", "wg", "awg"].contains(p.baseTunnel) else { throw issue("Connection profile contains an invalid WG/AWG base.") }
        p.startLayer = p.startLayer.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard ["off", "aes-256-gcm", "aes-256-gcm+xor-whitening"].contains(p.startLayer) else { throw issue("Connection profile contains an invalid Start Layer preference.") }
        p.mtuPolicy = p.mtuPolicy.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard ["auto", "manual", "default"].contains(p.mtuPolicy) else { throw issue("Connection profile contains an invalid MTU policy.") }
        if p.mtuPolicy == "manual" {
            guard (576...9000).contains(p.manualMTU) else { throw issue("Connection profile manual MTU must be 576–9000.") }
        } else {
            p.manualMTU = 0
        }
        p.startupMode = p.startupMode.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard ["smart-auto", "auto", "last", "manual"].contains(p.startupMode) else { throw issue("Connection profile contains an invalid startup policy.") }

        p.dnsMode = p.dnsMode.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        p.dnsProtocol = p.dnsProtocol.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        p.dnsHost = p.dnsHost.trimmingCharacters(in: .whitespacesAndNewlines)
        p.dnsServerName = p.dnsServerName.trimmingCharacters(in: .whitespacesAndNewlines)
        p.dnsPath = p.dnsPath.trimmingCharacters(in: .whitespacesAndNewlines)
        guard IOSDNSRuntimePolicy.modeIDs.contains(p.dnsMode) else { throw issue("Connection profile contains an invalid DNS mode.") }
        guard p.dnsHost.count <= 253, p.dnsServerName.count <= 253, p.dnsPath.count <= 2048 else { throw issue("Connection profile DNS fields are oversized.") }
        let invalidDNSScalar: (Unicode.Scalar) -> Bool = { $0.value < 0x21 || $0.value == 0x7f }
        guard !p.dnsHost.unicodeScalars.contains(where: invalidDNSScalar), !p.dnsServerName.unicodeScalars.contains(where: invalidDNSScalar) else {
            throw issue("Connection profile DNS host/server name contains invalid characters.")
        }
        switch p.dnsMode {
        case "home", "fastest", "rescue":
            p.dnsProtocol = "udp"; p.dnsHost = ""; p.dnsPort = 53; p.dnsServerName = ""; p.dnsPath = ""
        case "custom":
            if p.dnsProtocol.isEmpty { p.dnsProtocol = "udp" }
            guard ["udp", "tcp"].contains(p.dnsProtocol) else { throw issue("Custom DNS in a connection profile must use UDP or TCP.") }
            guard !p.dnsHost.isEmpty else { throw issue("Custom DNS in a connection profile requires a resolver host.") }
            if p.dnsPort == 0 { p.dnsPort = 53 }
            p.dnsServerName = ""; p.dnsPath = ""
        case "dot":
            p.dnsProtocol = "tls"
            guard !p.dnsHost.isEmpty else { throw issue("DoT connection profile requires a resolver host.") }
            if p.dnsPort == 0 { p.dnsPort = 853 }
            p.dnsPath = ""
        case "doh":
            p.dnsProtocol = "https"
            guard !p.dnsHost.isEmpty else { throw issue("DoH connection profile requires a resolver host.") }
            if p.dnsPort == 0 { p.dnsPort = 443 }
            if p.dnsPath.isEmpty { p.dnsPath = "/dns-query" }
            guard p.dnsPath.hasPrefix("/") else { throw issue("DoH connection profile path must begin with /.") }
        case "doh3":
            p.dnsProtocol = "h3"
            guard !p.dnsHost.isEmpty else { throw issue("DoH3 connection profile requires a resolver host.") }
            if p.dnsPort == 0 { p.dnsPort = 443 }
            if p.dnsPath.isEmpty { p.dnsPath = "/dns-query" }
            guard p.dnsPath.hasPrefix("/") else { throw issue("DoH3 connection profile path must begin with /.") }
        default: break
        }
        guard (1...65535).contains(p.dnsPort) else { throw issue("Connection profile contains an invalid DNS port.") }
        if ["dot", "doh", "doh3"].contains(p.dnsMode) {
            let literal = IPv4Address(p.dnsHost) != nil || IPv6Address(p.dnsHost) != nil
            if p.dnsServerName.isEmpty, !literal { p.dnsServerName = p.dnsHost }
            if literal && p.dnsServerName.isEmpty { throw issue("Encrypted DNS to a literal IP requires a TLS server name.") }
        }
        return p
    }

    private static func sorted(_ values: [IOSConnectionProfileRecord]) -> [IOSConnectionProfileRecord] {
        values.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }

    private static func cleanName(_ value: String) throws -> String {
        let clean = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !clean.isEmpty, clean.count <= 64, clean.unicodeScalars.allSatisfy({ $0.value >= 0x20 && $0.value != 0x7f }) else { throw issue("Connection profile name must be 1–64 printable characters.") }
        return clean
    }

    private static func normalizeMode(_ value: String) throws -> String {
        let clean = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let allowed = clean.count <= 80 && !clean.isEmpty && clean.unicodeScalars.allSatisfy { scalar in
            CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789._:-").contains(scalar)
        }
        guard allowed else { throw issue("Connection profile contains an invalid saved mode.") }
        if clean.hasPrefix("custom:") {
            let name = String(clean.dropFirst("custom:".count))
            guard !name.isEmpty, name.count <= 64, !name.contains(":") else { throw issue("Connection profile contains an invalid CUSTOM mode reference.") }
            return clean
        }
        guard !clean.contains(":") else { throw issue("Connection profile contains an invalid saved mode reference.") }
        return clean
    }

    private static func customLayers(for mode: String) throws -> [String] {
        guard mode.hasPrefix("custom:") else { return [] }
        guard let data = UserDefaults.standard.data(forKey: iosConnectionCustomPresetsKey),
              let values = try? JSONDecoder().decode([IOSConnectionCustomPresetMirror].self, from: data) else { return [] }
        let name = String(mode.dropFirst("custom:".count))
        return try normalizeLayers(values.first(where: { $0.name == name })?.layers ?? [])
    }

    private static func normalizeLayers(_ values: [String]) throws -> [String] {
        guard values.count <= 32 else { throw issue("Too many CUSTOM layers in connection profile.") }
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789._-")
        var unique = Set<String>()
        for raw in values {
            let clean = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            guard !clean.isEmpty, clean.count <= 64, clean.unicodeScalars.allSatisfy({ allowed.contains($0) }) else { throw issue("Connection profile contains an invalid CUSTOM layer.") }
            unique.insert(clean)
        }
        return unique.sorted()
    }

    private static func preparedCustomPresetData(mode: String, layers: [String]) throws -> Data? {
        guard mode.hasPrefix("custom:"), !layers.isEmpty else { return nil }
        let name = String(mode.dropFirst("custom:".count))
        guard !name.isEmpty else { throw issue("CUSTOM connection profile name is invalid.") }
        let normalized = try normalizeLayers(layers)
        var values: [IOSConnectionCustomPresetMirror] = []
        if let data = UserDefaults.standard.data(forKey: iosConnectionCustomPresetsKey),
           let existing = try? JSONDecoder().decode([IOSConnectionCustomPresetMirror].self, from: data) { values = existing }
        values.removeAll { $0.name == name }
        values.append(IOSConnectionCustomPresetMirror(name: name, layers: normalized))
        values.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        return try JSONEncoder().encode(values)
    }

    private static func issue(_ message: String) -> NSError { NSError(domain: "RouterVPN.ConnectionProfiles", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }
}

@MainActor
struct IOSConnectionProfilesView: View {
    @EnvironmentObject var model: RouterVPNModel
    @Environment(\.dismiss) private var dismiss
    @State private var profiles: [IOSConnectionProfileRecord] = []
    @State private var name = ""
    @State private var selectedID: String?
    @State private var status = ""

    var body: some View {
        NavigationStack {
            Form {
                Section("Connection profile") {
                    Text("A connection profile stores the selected node ID plus non-secret Mode/CUSTOM layers, home-LAN policy, DNS, kill switch, IPv6, WG/AWG base/fallback, Start Layer, AUTO encryption/obfuscation requirements, MTU, and startup/autoconnect choices. Router keys, API tokens, SOCKS credentials and external protocol secrets stay only in the linked node bundle/store.")
                        .font(.caption).foregroundStyle(.secondary)
                    TextField("Profile name", text: $name)
                    Picker("Saved profile", selection: $selectedID) {
                        Text("Select…").tag(String?.none)
                        ForEach(profiles) { profile in Text("\(profile.name) • \(profile.mode) • \(profile.nodeKind == "external" ? "Custom" : "Router") • \(profile.autoRequirementsSummary)").tag(Optional(profile.id)) }
                    }
                    HStack {
                        Button("Add") { add() }.disabled(model.profileMutationBlocked)
                        Button("Load") { load() }.disabled(model.profileMutationBlocked || selectedID == nil)
                        Button("Update") { update() }.disabled(model.profileMutationBlocked || selectedID == nil)
                        Button("Delete", role: .destructive) { delete() }.disabled(model.profileMutationBlocked || selectedID == nil)
                    }
                    if model.profileMutationBlocked {
                        Text("Disconnect or let the active VPN transition finish before Add / Load / Update / Delete.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    if !status.isEmpty { Text(status).font(.caption).foregroundStyle(.secondary) }
                }
                Section("Capability truth") {
                    Text("Current iOS preserves the Router node Start Layer choice in imported/saved profiles but does not execute the desktop Start-Layer relay itself. Current iOS also does not execute full desktop multihop. Unsupported runtime choices are preserved as profile metadata rather than falsely advertised as an active iOS dataplane feature.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Connection Profiles")
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
            .onAppear { refresh() }
            .onChange(of: selectedID) { _, value in if let value, let p = profiles.first(where: { $0.id == value }) { name = p.name } }
        }
    }

    private func refresh() {
        profiles = IOSConnectionProfileStore.all()
        if !IOSConnectionProfileStore.lastStoreError.isEmpty {
            status = "Connection profile store failed closed: \(IOSConnectionProfileStore.lastStoreError)"
        }
        if let selectedID, !profiles.contains(where: { $0.id == selectedID }) {
            self.selectedID = nil
        }
    }
    private func add() { do { let p = try IOSConnectionProfileStore.add(model: model, name: name); status = "Added \(p.name) • \(p.mode) • \(p.autoRequirementsSummary)."; refresh(); selectedID = p.id } catch { status = error.localizedDescription } }
    private func update() { guard let selectedID else { return }; do { let p = try IOSConnectionProfileStore.update(model: model, id: selectedID, name: name); status = "Updated \(p.name) • \(p.mode) • \(p.autoRequirementsSummary)."; refresh() } catch { status = error.localizedDescription } }
    private func load() { guard let selectedID else { return }; do { let p = try IOSConnectionProfileStore.load(model: model, id: selectedID); status = "Loaded \(p.name) • \(p.mode) • \(p.autoRequirementsSummary). Connect separately to prove the path." } catch { status = error.localizedDescription } }
    private func delete() { guard let selectedID else { return }; do { try IOSConnectionProfileStore.delete(model: model, id: selectedID); status = "Deleted saved connection profile."; self.selectedID = nil; refresh() } catch { status = error.localizedDescription } }
}

// iOS connection-profile contract: Add / Load / Update / Delete complete non-secret choices supported by the current iOS profile model, including Start Layer preservation and visible AUTO encryption/obfuscation requirements.
// Unsupported desktop Start-Layer runtime/multihop are not falsely advertised as native iOS dataplane capabilities; metadata remains round-trip safe.
// Profile mutation is blocked while connected or while NetworkExtension is connecting/reasserting/disconnecting.
// No RouterProfile/API token/private key/external secret payload is encoded into this store.
