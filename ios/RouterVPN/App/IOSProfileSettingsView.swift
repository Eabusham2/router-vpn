import SwiftUI

struct IOSProfileSettingsView: View {
    @EnvironmentObject var model: RouterVPNModel
    @Environment(\.dismiss) private var dismiss

    @State private var homeLANAccess = true
    @State private var killSwitchPolicy = "off"
    @State private var ipv6Mode = "on"
    @State private var baseTunnel = "auto"
    @State private var baseFallback = false
    @State private var autoRequireEncrypted = false
    @State private var autoRequireObfuscation = false
    @State private var mtuPolicy = "auto"
    @State private var manualMTU = ""
    @State private var startupMode = "smart-auto"
    @State private var autoConnect = false
    @State private var status = ""

    private let killValues = [("Off","off"),("On connect","on-connect"),("Always / strict","always")]
    private let ipv6Values = [("On — default","on"),("Auto","auto"),("Off","off")]
    private let baseValues = [("Auto","auto"),("WireGuard","wg"),("AmneziaWG","awg")]
    private let mtuValues = [("Auto measured — default","auto"),("Fixed / manual","manual"),("Runtime default","default")]
    private let startupValues = [("SMART AUTO — recommended","smart-auto"),("AUTO","auto"),("Last proven mode","last"),("Manual / stay disconnected","manual")]

    var body: some View {
        NavigationStack {
            Form {
                Section("Selected Router VPN node") {
                    Text("Disconnect before saving. These values persist in the private node profile and apply only where the iOS PacketTunnel/runtime actually supports them. A saved preference is not runtime proof.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Toggle("Allow home LAN access", isOn: $homeLANAccess)
                    Picker("Kill switch policy", selection: $killSwitchPolicy) { ForEach(killValues, id: \.1) { Text($0.0).tag($0.1) } }
                    Picker("IPv6 policy", selection: $ipv6Mode) { ForEach(ipv6Values, id: \.1) { Text($0.0).tag($0.1) } }
                }
                Section("Tunnel base") {
                    Picker("WG/AWG base", selection: $baseTunnel) { ForEach(baseValues, id: \.1) { Text($0.0).tag($0.1) } }
                    Toggle("Allow WG/AWG base fallback", isOn: $baseFallback)
                    if baseTunnel == "awg" {
                        Text("AmneziaWG stays unavailable on iOS until the native PacketTunnel engine exists; saving this preference does not make it runnable.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                Section("AUTO / SMART AUTO requirements") {
                    Toggle("Require encrypted AUTO candidates", isOn: $autoRequireEncrypted)
                    Toggle("Require obfuscation for AUTO candidates", isOn: $autoRequireObfuscation)
                    Text("Both are off by default. When enabled they filter AUTO and SMART AUTO before a candidate is attempted; manual modes and CUSTOM stay explicit user choices. If no iOS-runnable candidate satisfies the requested requirements, AUTO fails closed instead of silently relaxing them.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section("MTU") {
                    Picker("MTU policy", selection: $mtuPolicy) { ForEach(mtuValues, id: \.1) { Text($0.0).tag($0.1) } }
                    if mtuPolicy == "manual" {
                        TextField("Fixed MTU 576–9000", text: $manualMTU).keyboardType(.numberPad)
                    }
                    if let p = selectedProfile(), let value = p.effectiveMTU, value > 0 {
                        Text("Current effective MTU: \(value) • \(p.effectiveMTUSource ?? "measured")")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Text("Auto measured MTU is the default and is path/config specific. Jumbo TUN is intentionally not exposed here because current iOS support is path-specific/incomplete; unsupported settings are not faked green.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section("Startup") {
                    Picker("Startup behavior", selection: $startupMode) { ForEach(startupValues, id: \.1) { Text($0.0).tag($0.1) } }
                    Toggle("Auto-connect when Router VPN starts", isOn: $autoConnect)
                    Text("SMART AUTO is the unified default. Startup/autoconnect is stored as node policy; iOS may still require system VPN/Network Extension permission and background restrictions can limit automatic execution.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section {
                    Button("Save for next supported connection") { save() }
                        .disabled(model.connected)
                    if model.connected { Text("Disconnect before editing persistent tunnel policy.").font(.caption).foregroundStyle(.orange) }
                    if !status.isEmpty { Text(status).font(.caption) }
                }
            }
            .navigationTitle("Advanced Settings")
            .onAppear { load() }
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
        }
    }

    private func selectedProfile() -> RouterProfile? {
        guard let bundle = model.bundle else { return nil }
        return bundle.routerProfiles.first(where: { $0.id == bundle.selectedRouterID }) ?? bundle.routerProfiles.first
    }

    private func load() {
        guard let p = selectedProfile() else { status = "Pair/import and select a Router VPN node first."; return }
        guard p.normalizedNodeKind == "router-vpn" else { status = "External exits own their protocol settings."; return }
        homeLANAccess = p.homeLANAccess ?? true
        killSwitchPolicy = (p.killSwitchPolicy ?? (p.killSwitch == true ? "always" : "off")).lowercased()
        ipv6Mode = (p.ipv6Mode ?? "on").lowercased()
        baseTunnel = (p.baseTunnel ?? "auto").lowercased()
        baseFallback = p.baseFallback ?? false
        autoRequireEncrypted = p.autoRequireEncrypted ?? false
        autoRequireObfuscation = p.autoRequireObfuscation ?? false
        mtuPolicy = (p.mtuPolicy ?? "auto").lowercased()
        manualMTU = (p.manualMTU ?? 0) > 0 ? String(p.manualMTU!) : ""
        startupMode = (p.startupMode ?? "smart-auto").lowercased()
        autoConnect = p.autoConnect ?? false
    }

    private func save() {
        guard !model.connected else { status = "Disconnect before changing profile settings."; return }
        guard var bundle = model.bundle,
              let index = bundle.routerProfiles.firstIndex(where: { $0.id == bundle.selectedRouterID }) ?? bundle.routerProfiles.indices.first else {
            status = "Pair/import and select a Router VPN node first."; return
        }
        guard bundle.routerProfiles[index].normalizedNodeKind == "router-vpn" else { status = "External exits own their protocol settings."; return }
        let manual = Int(manualMTU.trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
        if mtuPolicy == "manual" && !(576...9000).contains(manual) { status = "Fixed MTU must be 576–9000."; return }

        var p = bundle.routerProfiles[index]
        p.homeLANAccess = homeLANAccess
        p.killSwitchPolicy = killSwitchPolicy
        p.killSwitch = killSwitchPolicy != "off"
        p.ipv6Mode = ipv6Mode
        p.baseTunnel = baseTunnel
        p.baseFallback = baseFallback
        p.autoRequireEncrypted = autoRequireEncrypted
        p.autoRequireObfuscation = autoRequireObfuscation
        p.mtuPolicy = mtuPolicy
        p.manualMTU = mtuPolicy == "manual" ? manual : 0
        p.startupMode = startupMode
        p.autoConnect = autoConnect
        bundle.profileSchemaVersion = max(bundle.profileSchemaVersion, 4)
        bundle.routerProfiles[index] = p
        do {
            try model.importBundle(JSONEncoder().encode(bundle))
            status = "Settings saved for the next supported PacketTunnel connection; saved values are not runtime proof."
        } catch {
            status = "Settings save failed: \(error.localizedDescription)"
        }
    }
}

// iOS settings contract: LAN Off / kill switch / IPv6 On default / WG-AWG base+fallback /
// Require encrypted + Require obfuscation AUTO filters / Auto measured-fixed-runtime MTU /
// SMART AUTO startup default. Jumbo/DAITA/SOCKS are omitted when the current Apple runtime
// cannot truthfully claim their support.
