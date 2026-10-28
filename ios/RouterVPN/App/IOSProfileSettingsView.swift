import SwiftUI

struct IOSProfileSettingsView: View {
    @EnvironmentObject var model: RouterVPNModel
    @Environment(\.dismiss) private var dismiss

    @State private var homeLANAccess = true
    @State private var killSwitchPolicy = "off"
    @State private var ipv6Mode = "on"
    @State private var baseTunnel = "auto"
    @State private var baseFallback = false
    @State private var startLayer = "off"
    @State private var autoRequireEncrypted = false
    @State private var autoRequireObfuscation = false
    @State private var mtuPolicy = "auto"
    @State private var manualMTU = ""
    @State private var daitaEnabled = false
    @State private var torPaddingRate = "192"
    @State private var jumboTUN = false
    @State private var startupMode = "smart-auto"
    @State private var autoConnect = false
    @State private var loadedProfile: RouterProfile?
    @State private var loadedTorEntry: Data?
    @State private var status = ""
    @State private var showingConnectionProfiles = false

    private let killValues = [("Off","off"),("On connect","on-connect"),("Always / strict","always")]
    private let ipv6Values = [("On — default","on"),("Auto","auto"),("Off","off")]
    private let baseValues = [("Auto","auto"),("WireGuard","wg"),("AmneziaWG","awg")]
    private let startLayerValues = [("Off — default","off"),("AES-256-GCM — authenticated Libbox modes","aes-256-gcm"),("AES-256-GCM + XOR whitening — native","aes-256-gcm+xor-whitening")]
    private let mtuValues = [("Auto — default","auto"),("Fixed / manual","manual"),("Runtime default","default")]
    private let startupValues = [("SMART AUTO — recommended","smart-auto"),("AUTO","auto"),("Last proven mode","last"),("Manual / stay disconnected","manual")]
    private var externalNode: Bool { selectedProfile()?.normalizedNodeKind == "external" }
    private var torNode: Bool { ["tor", "tor-bridge"].contains(selectedProfile()?.external?.protocolName.lowercased() ?? "") }

    var body: some View {
        NavigationStack {
            Form {
                if externalNode {
                    Section("Selected external node") {
                        Text("Startup reconnects this node's saved protocol and path, including its entry, exit and execution choice. Every new connection must prove that path again.")
                            .font(.caption).foregroundStyle(.secondary)
                        Text("Edit the node and its DNS or Multihop settings to change the saved path.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Section("Device policy") {
                        Toggle("Allow home LAN access", isOn: $homeLANAccess)
                        Picker("Kill switch policy", selection: $killSwitchPolicy) { ForEach(killValues, id: \.1) { Text($0.0).tag($0.1) } }
                        Picker("IPv6 policy", selection: $ipv6Mode) { ForEach(ipv6Values, id: \.1) { Text($0.0).tag($0.1) } }
                        Picker("MTU policy", selection: $mtuPolicy) { ForEach(mtuValues, id: \.1) { Text($0.0).tag($0.1) } }
                        if mtuPolicy == "manual" {
                            TextField("Fixed MTU 1280–9000", text: $manualMTU).keyboardType(.numberPad)
                        }
                        if torNode {
                            Toggle("Jumbo virtual interface (9000)", isOn: $jumboTUN)
                            Text("Tor carries TCP streams through this virtual interface; 9000 is not a measured Internet packet limit. Jumbo disables Auto MTU and Retest. Fixed MTU must also be 9000, and the captured entry must be compatible.")
                                .font(.caption).foregroundStyle(.secondary)
                            Toggle("Bounded outgoing Tor padding", isOn: $daitaEnabled)
                            if daitaEnabled {
                                TextField("Padding rate 32–192 kbps", text: $torPaddingRate).keyboardType(.numberPad)
                            }
                            Text("Local sends padding from this device; Server sends it from the selected entry server. The captured circuit must have fresh path and selected-DNS proof before padding starts. Off preserves the saved rate. The rate describes outgoing Tor link cells, not delivered traffic or both directions.")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Button("Save device policy for next connection") { saveExternalDevicePolicy() }
                            .disabled(model.profileMutationBlocked)
                        Text("These settings belong to this node. Its entry keeps its own policy, and the connection enforces both. Fixed MTU remains subject to the captured transport and entry limits; a saved value is not a path measurement. Use Live MTU below for Retest or Cancel.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                } else {
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
                        Text("AmneziaWG uses Router VPN's pinned native Apple AmneziaWG PacketTunnel for the generated Fast/Strong profiles. PQ/MAX composites still require every additional layer to be owned by the Apple dataplane.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                Section("Start encryption / obfuscation layer") {
                    Picker("Start Layer", selection: $startLayer) {
                        ForEach(startLayerValues, id: \.1) { item in
                            Text(item.0).tag(item.1)
                        }
                    }
                    Text("AES uses Shadowsocks 2022 BLAKE3 AES-256-GCM. Compatible native WG/AWG, PQ, proxy, Xray and complete MAX paths preserve the selected Start Layer, including entry and exit layers in multihop. AES+XOR uses an owned native outbound in the same VPN interface. XOR adds obfuscation and always accompanies authenticated AES.")
                        .font(.caption).foregroundStyle(.secondary)
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
                        TextField("Fixed MTU 1280–9000", text: $manualMTU).keyboardType(.numberPad)
                    }
                    if let p = selectedProfile(), let value = p.effectiveMTU, value > 0 {
                        Text("Saved MTU: \(value) • not a fresh measurement of this session")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Toggle("Jumbo TUN — compatible proxy paths", isOn: $jumboTUN)
                    Toggle("DAITA-like bounded traffic padding", isOn: $daitaEnabled)
                    Text("Padding uses the private endpoint inside the selected encrypted path, up to 192 kbps each direction. It is not Mullvad DAITA. Jumbo sets a compatible proxy TUN to 9000 bytes, not the Internet link or raw WG/AWG endpoint.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                }
                Section("Live MTU") {
                    // The live native owner supports Router, external and Tor
                    // paths independently of this form's saved Router fields.
                    IOSMTUCard()
                }
                Section("Startup") {
                    Picker("Startup behavior", selection: $startupMode) { ForEach(startupValues, id: \.1) { Text($0.0).tag($0.1) } }
                    Toggle("Auto-connect when Router VPN starts", isOn: $autoConnect)
                    Text(externalNode
                         ? "AUTO and SMART AUTO reconnect the saved external path. Last reuses its previous proved Local or Server choice when the complete saved path still matches; otherwise it runs the saved selection again. Every launch repeats the path proof. Auto-connect runs once when the app opens, not at device boot or whenever a view reappears."
                         : "SMART AUTO is the unified default. Auto-connect runs once when the app opens; it does not promise execution after device boot or while the app is closed.")
                        .font(.caption).foregroundStyle(.secondary)
                    Text("iOS may ask for VPN permission. An existing VPN or an unfinished operation keeps startup disconnected.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section("Connection profiles") {
                    Button("Add / Load / Update / Delete connection profiles") { showingConnectionProfiles = true }
                        .disabled(model.profileMutationBlocked)
                    Text("Profiles reference linked Router/Custom nodes and save only non-secret Mode/CUSTOM, DNS, kill-switch, IPv6, Start Layer, AUTO encryption/obfuscation requirements and MTU choices. Node keys, API tokens and external credentials stay in the private node store.")
                        .font(.caption).foregroundStyle(.secondary)
                    if model.profileMutationBlocked { Text("Disconnect or let the active VPN transition finish before changing saved connection-profile choices.").font(.caption).foregroundStyle(.orange) }
                }
                Section {
                    Button(externalNode ? "Save startup settings" : "Save for next supported connection") { save() }
                        .disabled(model.profileMutationBlocked)
                    if model.profileMutationBlocked { Text("Disconnect or let the active VPN transition finish before editing persistent tunnel policy.").font(.caption).foregroundStyle(.orange) }
                    if !status.isEmpty { Text(status).font(.caption) }
                }
            }
            .navigationTitle("Advanced Settings")
            .onAppear { load() }
            .sheet(isPresented: $showingConnectionProfiles) { IOSConnectionProfilesView().environmentObject(model) }
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
        }
    }

    private func selectedProfile() -> RouterProfile? {
        guard let bundle = model.bundle else { return nil }
        return IOSDNSRuntimePolicy.selectedProfile(in: bundle)
    }

    private func load() {
        loadedProfile = nil
        loadedTorEntry = nil
        guard let p = selectedProfile() else { status = "Pair/import and select a Router VPN node first. Connection profiles remain available above."; return }
        guard ["router-vpn", "external"].contains(p.normalizedNodeKind) else { status = "This node has no supported settings."; return }
        do { startupMode = try IOSStartupPolicy.mode(p.startupMode) }
        catch {
            startupMode = p.startupMode ?? "manual"
            status = error.localizedDescription
        }
        autoConnect = p.autoConnect ?? false
        loadedProfile = p
        if p.normalizedNodeKind == "external" {
            let policy = IOSDevicePolicySettings(profile: p)
            homeLANAccess = policy.homeLANAccess; killSwitchPolicy = policy.killSwitchPolicy
            ipv6Mode = policy.ipv6Mode; mtuPolicy = policy.mtuPolicy; manualMTU = policy.manualMTU
            jumboTUN = policy.jumboTUN
            daitaEnabled = policy.torPaddingEnabled; torPaddingRate = policy.torPaddingRate
            if ["tor", "tor-bridge"].contains(p.external?.protocolName ?? ""), p.multihopEnabled == true {
                // The entry may live in its own private node bundle. Capture
                // the same complete source used by startup, including assets.
                if let bundle = model.bundle { loadedTorEntry = try? model.externalTorEntryData(source: bundle) }
            }
            return
        }
        homeLANAccess = p.homeLANAccess ?? true
        killSwitchPolicy = (p.killSwitchPolicy ?? (p.killSwitch == true ? "always" : "off")).lowercased()
        ipv6Mode = (p.ipv6Mode ?? "on").lowercased()
        baseTunnel = (p.baseTunnel ?? "auto").lowercased()
        baseFallback = p.baseFallback ?? false
        startLayer = (p.startLayer ?? "off").lowercased()
        autoRequireEncrypted = p.autoRequireEncrypted ?? false
        autoRequireObfuscation = p.autoRequireObfuscation ?? false
        mtuPolicy = (p.mtuPolicy ?? "auto").lowercased()
        manualMTU = (p.manualMTU ?? 0) > 0 ? String(p.manualMTU!) : ""
        daitaEnabled = p.daitaEnabled ?? false
        jumboTUN = p.jumboTUN ?? false
    }

    private func saveExternalDevicePolicy() {
        guard !model.profileMutationBlocked else { status = "Disconnect or let the active VPN transition finish before changing device policy."; return }
        guard var bundle = model.bundle,
              let selected = IOSDNSRuntimePolicy.selectedProfile(in: bundle), selected.normalizedNodeKind == "external",
              selected == loadedProfile,
              let index = bundle.routerProfiles.firstIndex(where: { $0.id == selected.id }),
              bundle.routerProfiles.filter({ $0.id == selected.id }).count == 1 else {
            status = "The selected node changed. Reopen Settings before saving device policy."; return
        }
        if ["tor", "tor-bridge"].contains(selected.external?.protocolName ?? ""), selected.multihopEnabled == true {
            guard let loadedTorEntry, let currentEntry = try? model.externalTorEntryData(source: bundle), currentEntry == loadedTorEntry else {
                status = "The Tor entry changed. Reopen Settings before saving device policy."; return
            }
        }
        var draft = IOSDevicePolicySettings(profile: selected)
        draft.homeLANAccess = homeLANAccess; draft.killSwitchPolicy = killSwitchPolicy
        draft.ipv6Mode = ipv6Mode; draft.mtuPolicy = mtuPolicy; draft.manualMTU = manualMTU
        draft.jumboTUN = jumboTUN
        draft.torPaddingEnabled = daitaEnabled; draft.torPaddingRate = torPaddingRate
        do {
            let prepared = try draft.applying(to: selected)
            try IOSExternalExecution.validateDeviceDraft(prepared)
            bundle.routerProfiles[index] = prepared
            try model.importBundle(JSONEncoder().encode(bundle))
            // A private entry bundle can also contain this exit. Refresh the
            // accepted transaction's full capture so a second Save remains
            // valid without adopting later edits made outside this form.
            load()
            status = "Device policy saved for the next connection. The native path must still prove its DNS, entry and exit."
        } catch { status = "Device policy rejected: \(error.localizedDescription)" }
    }

    private func save() {
        guard !model.profileMutationBlocked else { status = "Disconnect or let the active VPN transition finish before changing profile settings."; return }
        guard var bundle = model.bundle,
              let selected = IOSDNSRuntimePolicy.selectedProfile(in: bundle),
              let index = bundle.routerProfiles.firstIndex(where: { $0.id == selected.id }) else {
            status = "Pair/import and select a Router VPN node first."; return
        }
        guard let loadedProfile, selected == loadedProfile,
              bundle.routerProfiles.filter({ $0.id == selected.id }).count == 1 else {
            status = "The selected node changed. Reopen Settings before saving."; return
        }
        let startup: RouterProfile
        do { startup = try IOSStartupPolicy.applying(mode: startupMode, enabled: autoConnect, to: selected) }
        catch { status = error.localizedDescription; return }
        if selected.normalizedNodeKind == "external" {
            // Only these two startup fields change. Hidden Router controls may
            // never replace an imported node's DNS, keys, protection or graph.
            bundle.routerProfiles[index] = startup
            do {
                try model.importBundle(JSONEncoder().encode(bundle))
                self.loadedProfile = selectedProfile()
                status = "Startup saved for this external node. Its saved protocol and path are unchanged."
            } catch { status = "Settings save failed: \(error.localizedDescription)" }
            return
        }
        guard selected.normalizedNodeKind == "router-vpn" else { status = "This node has no supported settings."; return }
        let manual = Int(manualMTU.trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
        if mtuPolicy == "manual" && !(1280...9000).contains(manual) { status = "Fixed MTU must be 1280–9000."; return }

        var p = startup
        p.homeLANAccess = homeLANAccess
        p.killSwitchPolicy = killSwitchPolicy
        p.killSwitch = killSwitchPolicy != "off"
        p.ipv6Mode = ipv6Mode
        p.baseTunnel = baseTunnel
        p.baseFallback = baseFallback
        p.startLayer = startLayer
        p.autoRequireEncrypted = autoRequireEncrypted
        p.autoRequireObfuscation = autoRequireObfuscation
        p.mtuPolicy = mtuPolicy
        p.manualMTU = mtuPolicy == "manual" ? manual : 0
        p.daitaEnabled = daitaEnabled
        p.jumboTUN = jumboTUN
        bundle.profileSchemaVersion = max(bundle.profileSchemaVersion, 4)
        bundle.routerProfiles[index] = p
        do {
            try model.importBundle(JSONEncoder().encode(bundle))
            self.loadedProfile = selectedProfile()
            status = "Settings saved for the next supported PacketTunnel connection; saved values are not runtime proof."
        } catch {
            status = "Settings save failed: \(error.localizedDescription)"
        }
    }
}

// iOS settings contract: LAN Off / kill switch / IPv6 On default / WG-AWG base+fallback /
// Start Layer Off, authenticated AES-256-GCM, or native AES+XOR whitening /
// Require encrypted + Require obfuscation AUTO filters / Auto measured-fixed-runtime MTU /
// SMART AUTO startup default / secret-free connection-profile Add-Load-Update-Delete including AUTO requirements.
// Persistent settings/profile mutation stays disabled through connected/connecting/reasserting/disconnecting state.
// Native padding and compatible proxy Jumbo are applied by the performance compiler.
