import Foundation
import SwiftUI

private let iosConnectionProfilesKey = "routervpn.connection-profiles.v1"
private let iosConnectionProfilesFile = "connection-profiles.json"
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
        if let data = try IOSPrivateJSONStore.read(
            iosConnectionProfilesFile,
            maximumBytes: iosConnectionProfilesMaximumBytes
        ) {
            let values = try JSONDecoder().decode([IOSConnectionProfileRecord].self, from: data)
            guard values.count <= 64 else { throw issue("Connection profile limit exceeded.") }
            return values.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        }

        guard let legacy = UserDefaults.standard.data(forKey: iosConnectionProfilesKey) else { return [] }
        guard !legacy.isEmpty, legacy.count <= iosConnectionProfilesMaximumBytes else {
            throw issue("Legacy connection profile store has an invalid size.")
        }
        let values = try JSONDecoder().decode([IOSConnectionProfileRecord].self, from: legacy)
        guard values.count <= 64 else { throw issue("Legacy connection profile limit exceeded.") }
        try persist(values)
        UserDefaults.standard.removeObject(forKey: iosConnectionProfilesKey)
        return values.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }

    static func snapshot(model: RouterVPNModel, name rawName: String, id: String? = nil) throws -> IOSConnectionProfileRecord {
        guard !model.profileMutationBlocked else { throw issue("Disconnect or let the active VPN transition finish before saving or updating a connection profile.") }
        let name = try cleanName(rawName)
        guard let selected = model.selectedNodeProfile else { throw issue("Select a linked Router or Custom node first.") }
        let mode = normalizeMode(UserDefaults.standard.string(forKey: iosConnectionModeKey) ?? "smart-auto")
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
        let effectiveMode = normalizeMode(saved.mode)
        let preparedPreset = try preparedCustomPresetData(mode: effectiveMode, layers: saved.customLayers)
        var profile = bundle.routerProfiles[index]
        profile.homeLANAccess = prefs.homeLANAccess
        profile.killSwitch = prefs.killSwitch
        profile.killSwitchPolicy = prefs.killSwitchPolicy
        profile.ipv6Mode = prefs.ipv6Mode
        profile.baseTunnel = prefs.baseTunnel
        profile.baseFallback = prefs.baseFallback
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
        guard values.count <= 64 else { throw issue("Connection profile limit exceeded.") }
        let data = try JSONEncoder().encode(values)
        try IOSPrivateJSONStore.write(
            data,
            filename: iosConnectionProfilesFile,
            maximumBytes: iosConnectionProfilesMaximumBytes
        )
    }

    private static func cleanName(_ value: String) throws -> String {
        let clean = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !clean.isEmpty, clean.count <= 64, clean.unicodeScalars.allSatisfy({ $0.value >= 0x20 && $0.value != 0x7f }) else { throw issue("Connection profile name must be 1–64 printable characters.") }
        return clean
    }

    private static func normalizeMode(_ value: String) -> String {
        let clean = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let allowed = clean.count <= 80 && !clean.isEmpty && clean.unicodeScalars.allSatisfy { scalar in
            CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789._:-").contains(scalar)
        }
        return allowed ? clean : "smart-auto"
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
                    Text("A connection profile stores the selected node ID plus non-secret Mode/CUSTOM layers, home-LAN policy, DNS, kill switch, IPv6, WG/AWG base/fallback, AUTO encryption/obfuscation requirements, MTU, and startup/autoconnect choices. Router keys, API tokens, SOCKS credentials and external protocol secrets stay only in the linked node bundle/store.")
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
                    Text("Current iOS does not execute full desktop multihop, so an imported Router node carrying desktop-style multihop choices is rejected at Add/Update time rather than creating an iOS profile that cannot be loaded. Connect remains a separate action so PacketTunnel still has to establish and prove the real path.")
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

// iOS connection-profile contract: Add / Load / Update / Delete complete non-secret choices supported by the current iOS dataplane, including visible AUTO encryption/obfuscation requirements.
// Unsupported desktop multihop is rejected before save; load validates everything and applies one bundle update before selection changes.
// Profile mutation is blocked while connected or while NetworkExtension is connecting/reasserting/disconnecting.
// No RouterProfile/API token/private key/external secret payload is encoded into this store.
