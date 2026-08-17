import MapKit
import SwiftUI

private let iosUnifiedModeKey = "routervpn.unified.mode.v1"
private let iosUnifiedPresetsKey = "routervpn.unified.custom-presets.v1"
private let iosRequireEncryptedPrefix = "routervpn.unified.require-encrypted."
private let iosRequireObfuscationPrefix = "routervpn.unified.require-obfuscation."

private struct IOSUnifiedCustomPreset: Codable, Identifiable, Hashable {
    var id: String { name.lowercased() }
    var name: String
    var layers: [String]
}

private enum IOSUnifiedModeSelection {
    static let smart = "smart-auto"
    static let auto = "auto"
    static let customPrefix = "custom:"
}

@MainActor
extension RouterVPNModel {
    var unifiedSelectedProfile: RouterProfile? {
        guard let bundle else { return nil }
        return bundle.routerProfiles.first(where: { $0.id == bundle.selectedRouterID }) ?? bundle.routerProfiles.first
    }

    var unifiedQuickKillSwitch: Bool {
        guard let p = unifiedSelectedProfile else { return false }
        if p.killSwitch == true { return true }
        return (p.killSwitchPolicy ?? "off").lowercased() != "off"
    }

    func setUnifiedQuickKillSwitch(_ enabled: Bool) {
        guard !connected else { message = "Disconnect before changing persistent kill-switch policy."; return }
        guard var current = bundle,
              let index = current.routerProfiles.firstIndex(where: { $0.id == current.selectedRouterID }) ?? current.routerProfiles.indices.first,
              current.routerProfiles[index].normalizedNodeKind == "router-vpn" else {
            message = "Select a Router VPN node before changing kill-switch policy."; return
        }
        current.routerProfiles[index].killSwitch = enabled
        current.routerProfiles[index].killSwitchPolicy = enabled ? "on-connect" : "off"
        do {
            try importBundle(JSONEncoder().encode(current))
            message = enabled ? "Kill switch enabled for the selected Router VPN node." : "Kill switch disabled for the selected Router VPN node."
        } catch { message = "Kill-switch update failed: \(error.localizedDescription)" }
    }

    func unifiedRequirement(_ kind: String) -> Bool {
        guard let id = unifiedSelectedProfile?.id else { return false }
        let prefix = kind == "obfuscation" ? iosRequireObfuscationPrefix : iosRequireEncryptedPrefix
        return UserDefaults.standard.bool(forKey: prefix + id)
    }

    func setUnifiedRequirement(_ kind: String, enabled: Bool) {
        guard let id = unifiedSelectedProfile?.id else { return }
        let prefix = kind == "obfuscation" ? iosRequireObfuscationPrefix : iosRequireEncryptedPrefix
        UserDefaults.standard.set(enabled, forKey: prefix + id)
    }

    func unifiedSetDNSMode(_ mode: String) {
        guard !connected else { message = "Disconnect before changing the selected DNS policy."; return }
        guard var current = bundle,
              let index = current.routerProfiles.firstIndex(where: { $0.id == current.selectedRouterID }) ?? current.routerProfiles.indices.first,
              current.routerProfiles[index].normalizedNodeKind == "router-vpn" else {
            message = "Select a Router VPN node before changing DNS."; return
        }
        current.routerProfiles[index].dnsMode = mode
        do {
            try importBundle(JSONEncoder().encode(current))
            message = "DNS set to \(mode). The next connection must still pass real tunnel DNS/path proof."
        } catch { message = "DNS update failed: \(error.localizedDescription)" }
    }

    private func unifiedRawModeMeetsAutoRequirements(_ rawID: String) -> Bool {
        let encrypted = unifiedRequirement("encrypted")
        let obfuscated = unifiedRequirement("obfuscation")
        if !encrypted && !obfuscated { return true }
        let raw = rawID.lowercased()
        let encryptedIDs: Set<String> = [
            "wg", "awg2-fast", "wg-pq", "shadowsocks", "awg2-strong", "awg2-pq",
            "reality-vision", "hysteria2", "reality-pq-vision", "ss-v2ray", "naive-h2",
            "naive-h3", "split", "reality-xhttp", "max", "max-quic-wg", "max-quic-awg",
            "max-tls-wg", "max-tls-awg", "all"
        ]
        let obfuscatedIDs: Set<String> = [
            "awg2-fast", "awg2-strong", "awg2-pq", "reality-vision", "hysteria2",
            "reality-pq-vision", "ss-v2ray", "naive-h2", "naive-h3", "split",
            "reality-xhttp", "max", "max-quic-wg", "max-quic-awg", "max-tls-wg",
            "max-tls-awg", "all"
        ]
        if encrypted && !encryptedIDs.contains(raw) { return false }
        if obfuscated && !obfuscatedIDs.contains(raw) { return false }
        return true
    }

    private func unifiedFilteredBundleForAuto() -> ClientBundle? {
        guard var current = bundle else { return nil }
        let encrypted = unifiedRequirement("encrypted"), obfuscated = unifiedRequirement("obfuscation")
        guard encrypted || obfuscated else { return current }
        current.modes = current.modes.filter { unifiedRawModeMeetsAutoRequirements($0.id) }
        current.logicalModes = current.logicalModes.filter { logical in
            guard let selection = try? IOSRuntimeSelector.select(bundle: current, logicalModeID: logical.id) else { return false }
            return unifiedRawModeMeetsAutoRequirements(selection.rawProfileID)
        }
        return current
    }

    private func unifiedRunWithFilteredBundle(_ operation: @escaping @MainActor () async -> Void) async {
        guard let original = bundle, let filtered = unifiedFilteredBundleForAuto() else { message = "Pair/import a Router VPN node first."; return }
        if filtered.modes.isEmpty || IOSRuntimeSelector.runnableModes(in: filtered).isEmpty {
            var requirements: [String] = []
            if unifiedRequirement("encrypted") { requirements.append("encrypted") }
            if unifiedRequirement("obfuscation") { requirements.append("obfuscated") }
            message = "AUTO found no iOS-runnable candidate satisfying Require \(requirements.joined(separator: " + "))."
            return
        }
        let filtering = filtered.modes.count != original.modes.count
        do { try importBundle(JSONEncoder().encode(filtered)) }
        catch { message = "AUTO requirement filtering failed closed: \(error.localizedDescription)"; return }
        await operation()
        let resultMessage = message
        let resultLogical = selectedLogicalMode
        let resultRaw = activeRawProfile
        do {
            try importBundle(JSONEncoder().encode(original))
            selectedLogicalMode = resultLogical
            selectedMode = resultRaw.isEmpty ? resultLogical : resultRaw
            message = filtering ? resultMessage + " • AUTO requirements enforced" : resultMessage
        } catch {
            message = resultMessage + " • warning: could not restore the complete local mode catalog after filtered attempt: \(error.localizedDescription)"
        }
    }

    func runUnifiedIOSAuto() async {
        await unifiedRunWithFilteredBundle {
            self.auto = true
            await self.connect()
            if self.connected { self.recordIOSLastRuntime() }
        }
    }

    func runUnifiedIOSSmartAuto() async {
        await unifiedRunWithFilteredBundle { await self.runIOSSmartAuto() }
    }
}

private final class IOSUnifiedMapAnnotation: MKPointAnnotation {
    let profileID: String
    let role: String
    init(profileID: String, role: String) { self.profileID = profileID; self.role = role; super.init() }
}

private struct IOSUnifiedMap: UIViewRepresentable {
    @EnvironmentObject var model: RouterVPNModel

    func makeCoordinator() -> Coordinator { Coordinator(self) }
    func makeUIView(context: Context) -> MKMapView {
        let map = MKMapView(frame: .zero)
        map.delegate = context.coordinator
        map.showsCompass = true
        map.showsScale = true
        map.pointOfInterestFilter = .excludingAll
        return map
    }

    func updateUIView(_ map: MKMapView, context: Context) {
        context.coordinator.parent = self
        map.removeAnnotations(map.annotations)
        map.removeOverlays(map.overlays)
        let profiles = model.allNodeProfiles
        let selectedID = model.bundle?.selectedRouterID ?? ""
        let selected = profiles.first(where: { $0.id == selectedID })
        let entryID = selected?.multihopEnabled == true ? selected?.multihopEntryID : nil
        let exitID = selected?.multihopEnabled == true ? selected?.multihopExitID : nil
        var coordinatesByID: [String: CLLocationCoordinate2D] = [:]
        for profile in profiles {
            guard let lat = profile.latitude, let lon = profile.longitude,
                  (-90...90).contains(lat), (-180...180).contains(lon), !(lat == 0 && lon == 0) else { continue }
            let role: String
            if profile.id == entryID { role = "entry" }
            else if profile.id == exitID { role = "exit" }
            else if profile.id == selectedID { role = "selected" }
            else if profile.normalizedNodeKind == "external" { role = "external" }
            else { role = "normal" }
            let annotation = IOSUnifiedMapAnnotation(profileID: profile.id, role: role)
            annotation.coordinate = CLLocationCoordinate2D(latitude: lat, longitude: lon)
            annotation.title = profile.name.isEmpty ? profile.id : profile.name
            annotation.subtitle = profile.normalizedNodeKind == "external" ? "Custom / external" : "Router node"
            map.addAnnotation(annotation)
            coordinatesByID[profile.id] = annotation.coordinate
        }
        if let entryID, let exitID, let a = coordinatesByID[entryID], let b = coordinatesByID[exitID] {
            var values = [a, b]
            map.addOverlay(MKPolyline(coordinates: &values, count: values.count))
        }
        if !map.annotations.isEmpty {
            map.showAnnotations(map.annotations, animated: context.transaction.animation != nil)
        }
    }

    final class Coordinator: NSObject, MKMapViewDelegate {
        var parent: IOSUnifiedMap
        init(_ parent: IOSUnifiedMap) { self.parent = parent }
        func mapView(_ mapView: MKMapView, viewFor annotation: MKAnnotation) -> MKAnnotationView? {
            guard let node = annotation as? IOSUnifiedMapAnnotation else { return nil }
            let view = (mapView.dequeueReusableAnnotationView(withIdentifier: "node") as? MKMarkerAnnotationView) ?? MKMarkerAnnotationView(annotation: annotation, reuseIdentifier: "node")
            view.annotation = annotation; view.canShowCallout = true
            switch node.role {
            case "entry": view.markerTintColor = .systemBlue
            case "exit": view.markerTintColor = .systemOrange
            case "selected": view.markerTintColor = .systemPurple
            case "external": view.markerTintColor = .systemPink
            default: view.markerTintColor = .systemTeal
            }
            return view
        }
        func mapView(_ mapView: MKMapView, didSelect view: MKAnnotationView) {
            guard let node = view.annotation as? IOSUnifiedMapAnnotation else { return }
            Task { @MainActor in parent.model.selectNode(node.profileID) }
        }
        func mapView(_ mapView: MKMapView, rendererFor overlay: MKOverlay) -> MKOverlayRenderer {
            guard let line = overlay as? MKPolyline else { return MKOverlayRenderer(overlay: overlay) }
            let renderer = MKPolylineRenderer(polyline: line); renderer.strokeColor = .systemBlue; renderer.lineWidth = 4; renderer.lineCap = .round; renderer.lineJoin = .round; return renderer
        }
    }
}

struct IOSUnifiedProductView: View {
    @EnvironmentObject var model: RouterVPNModel
    @AppStorage(iosUnifiedModeKey) private var selectedMode = IOSUnifiedModeSelection.smart
    @State private var expanded = false
    @State private var showingNodes = false
    @State private var showingModes = false
    @State private var showingDNS = false
    @State private var showingSettings = false
    @State private var showingOnboarding = false
    @State private var startupApplied = false

    var body: some View {
        GeometryReader { geo in
            ZStack(alignment: .bottom) {
                IOSUnifiedMap().environmentObject(model).ignoresSafeArea()

                VStack {
                    HStack(spacing: 8) {
                        Button { showingNodes = true } label: {
                            HStack(spacing: 7) {
                                Image(systemName: selectedProfile?.normalizedNodeKind == "external" ? "arrow.up.right.circle.fill" : "network")
                                VStack(alignment: .leading, spacing: 1) {
                                    Text(selectedProfile.map { $0.name.isEmpty ? $0.id : $0.name } ?? "Add a node").font(.subheadline.bold()).lineLimit(1)
                                    Text(selectedProfile?.normalizedNodeKind == "external" ? "Custom / external" : "Router node").font(.caption2).foregroundStyle(.secondary)
                                }
                            }
                        }
                        .buttonStyle(.borderedProminent)
                        Spacer()
                        VStack(alignment: .trailing, spacing: 1) {
                            Text(model.connected ? "Connected" : "Disconnected").font(.subheadline.bold())
                            Text(model.activeRawProfile.isEmpty ? selectedModeTitle : model.activeRawProfile).font(.caption2).foregroundStyle(.secondary)
                        }
                        .padding(.horizontal, 10).padding(.vertical, 7).background(.regularMaterial, in: Capsule())
                    }
                    .padding(.horizontal, 12).padding(.top, 8)
                    Spacer()
                }

                controlSheet(height: expanded ? min(max(420, geo.size.height * 0.68), 620) : min(330, geo.size.height * 0.46))
            }
        }
        .sheet(isPresented: $showingNodes) { RouterVPNNodeManagerSheet().environmentObject(model) }
        .sheet(isPresented: $showingModes) { IOSUnifiedModePicker(selectedMode: $selectedMode).environmentObject(model) }
        .sheet(isPresented: $showingDNS) { IOSDNSPolicyView().environmentObject(model) }
        .sheet(isPresented: $showingSettings) { IOSUnifiedSettingsView().environmentObject(model) }
        .sheet(isPresented: $showingOnboarding) { RouterVPNProductOnboardingView() }
        .onAppear { if !UserDefaults.standard.bool(forKey: "RouterVPNProductOnboardingDoneV2") { showingOnboarding = true } }
        .onChange(of: model.activeRawProfile) { value in if model.connected && !value.isEmpty { model.recordIOSLastRuntime() } }
        .task { guard !startupApplied else { return }; startupApplied = true; await model.applyIOSStartupPolicyIfNeeded() }
    }

    private var selectedProfile: RouterProfile? { model.unifiedSelectedProfile }
    private var selectedModeTitle: String {
        if selectedMode == IOSUnifiedModeSelection.smart { return "SMART AUTO" }
        if selectedMode == IOSUnifiedModeSelection.auto { return "AUTO" }
        if selectedMode.hasPrefix(IOSUnifiedModeSelection.customPrefix) { return "CUSTOM • " + String(selectedMode.dropFirst(IOSUnifiedModeSelection.customPrefix.count)) }
        return model.logicalModes.first(where: { $0.id == selectedMode })?.name ?? selectedMode
    }
    private var dnsTitle: String {
        switch (selectedProfile?.dnsMode ?? "home").lowercased() {
        case "fastest": return "Fastest measured"
        case "custom": return "Custom"
        case "dot": return "DoT"
        case "doh": return "DoH"
        case "doh3": return "DoH3"
        case "rescue": return "Rescue"
        default: return "Home AdGuard"
        }
    }

    @ViewBuilder
    private func controlSheet(height: CGFloat) -> some View {
        VStack(spacing: 10) {
            Capsule().fill(.secondary.opacity(0.45)).frame(width: 44, height: 5).padding(.top, 8)
                .gesture(DragGesture(minimumDistance: 8).onEnded { value in withAnimation(.spring(response: 0.32, dampingFraction: 0.82)) { expanded = value.translation.height < 0 } })
            ScrollView {
                VStack(spacing: 10) {
                    HStack(spacing: 8) {
                        Button { connectOrDisconnect() } label: { Text(model.connected ? "Disconnect" : "Connect").font(.headline).frame(maxWidth: .infinity).padding(.vertical, 7) }
                            .buttonStyle(.borderedProminent).tint(model.connected ? .red : .accentColor)
                        Toggle(isOn: Binding(get: { model.unifiedQuickKillSwitch }, set: { model.setUnifiedQuickKillSwitch($0) })) { Image(systemName: "lock.shield.fill") }
                            .toggleStyle(.button).buttonStyle(.bordered).accessibilityLabel("Kill switch")
                    }

                    unifiedRow(icon: "point.3.connected.trianglepath.dotted", title: "Multihop", value: "Unavailable on current iOS dataplane") { showingNodes = true }
                    unifiedRow(icon: "slider.horizontal.3", title: "Settings", value: settingsSummary) { showingSettings = true }
                    unifiedRow(icon: "wand.and.stars", title: "Mode", value: selectedModeTitle) { showingModes = true }

                    HStack {
                        Label("DNS", systemImage: "network").font(.subheadline.bold())
                        Spacer()
                        Menu(dnsTitle) {
                            Button("Home AdGuard") { model.unifiedSetDNSMode("home") }
                            Button("Fastest measured") { model.unifiedSetDNSMode("fastest") }
                            Button("Rescue") { model.unifiedSetDNSMode("rescue") }
                            Divider()
                            Button("Custom…") { showingDNS = true }
                            Button("DoT…") { showingDNS = true }
                            Button("DoH…") { showingDNS = true }
                            Button("DoH3…") { showingDNS = true }
                            Divider()
                            Button("DNS details / Retest…") { showingDNS = true }
                        }
                    }
                    .padding(11).background(.thinMaterial, in: RoundedRectangle(cornerRadius: 12))

                    if expanded {
                        IOSHomeSummaryView().environmentObject(model)
                        Button("Run setup guide again") { UserDefaults.standard.set(0, forKey: "RouterVPNProductOnboardingStepV2"); showingOnboarding = true }
                            .buttonStyle(.bordered)
                    }
                    Text(model.message).font(.caption).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled)
                }.padding(.horizontal, 14).padding(.bottom, 14)
            }
        }
        .frame(height: height)
        .background(.ultraThickMaterial, in: UnevenRoundedRectangle(topLeadingRadius: 24, bottomLeadingRadius: 0, bottomTrailingRadius: 0, topTrailingRadius: 24))
        .shadow(radius: 12, y: -3)
        .gesture(DragGesture(minimumDistance: 16).onEnded { value in
            if value.translation.height < -40 { withAnimation(.spring()) { expanded = true } }
            else if value.translation.height > 40 { withAnimation(.spring()) { expanded = false } }
        })
    }

    private var settingsSummary: String {
        let p = selectedProfile
        let mtu = (p?.mtuPolicy ?? "auto").lowercased() == "manual" ? "MTU \(p?.manualMTU ?? 0)" : "Auto MTU"
        let ipv6 = (p?.ipv6Mode ?? "on").lowercased() == "off" ? "IPv6 Off" : "IPv6 On"
        return "\(ipv6) • \(mtu)"
    }

    private func unifiedRow(icon: String, title: String, value: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack { Label(title, systemImage: icon).font(.subheadline.bold()); Spacer(); Text(value).font(.caption).foregroundStyle(.secondary).lineLimit(1); Image(systemName: "chevron.right").font(.caption).foregroundStyle(.tertiary) }
                .padding(11).background(.thinMaterial, in: RoundedRectangle(cornerRadius: 12))
        }.buttonStyle(.plain)
    }

    private func connectOrDisconnect() {
        if model.connected { model.disconnect(); return }
        guard let profile = selectedProfile else { showingNodes = true; return }
        if profile.normalizedNodeKind == "external" { Task { await model.connectSelectedExternal() }; return }
        if selectedMode == IOSUnifiedModeSelection.smart { Task { await model.runUnifiedIOSSmartAuto() }; return }
        if selectedMode == IOSUnifiedModeSelection.auto { Task { await model.runUnifiedIOSAuto() }; return }
        if selectedMode.hasPrefix(IOSUnifiedModeSelection.customPrefix) {
            let name = String(selectedMode.dropFirst(IOSUnifiedModeSelection.customPrefix.count))
            guard let preset = IOSUnifiedPresetStore.load().first(where: { $0.name == name }) else { showingModes = true; return }
            Task { await model.runIOSCustom(layers: preset.layers) }; return
        }
        model.auto = false; model.selectedLogicalMode = selectedMode; Task { await model.connect(); if model.connected { model.recordIOSLastRuntime() } }
    }
}

private struct IOSUnifiedModePicker: View {
    @EnvironmentObject var model: RouterVPNModel
    @Environment(\.dismiss) private var dismiss
    @Binding var selectedMode: String
    @State private var presets = IOSUnifiedPresetStore.load()
    @State private var editingPreset: IOSUnifiedCustomPreset?
    @State private var creatingPreset = false

    var body: some View {
        NavigationStack {
            List {
                Section("Automatic") {
                    choice("SMART AUTO", subtitle: "Recommended • connect, simplify, prove, restore last good on failure", id: IOSUnifiedModeSelection.smart, available: !model.iosStrategyStrictLockdown)
                    choice("AUTO", subtitle: "First iOS-runnable path that really passes PacketTunnel + selected-node proof", id: IOSUnifiedModeSelection.auto, available: true)
                }
                Section("Mode presets") {
                    ForEach(model.logicalModes) { mode in
                        let available = model.iosRunnableLogicalModes.contains(where: { $0.id == mode.id })
                        choice(mode.name, subtitle: available ? model.runtimeLabel(for: mode) : "Unavailable • \(model.runtimeReason(for: mode))", id: mode.id, available: available)
                    }
                }
                Section("CUSTOM presets") {
                    ForEach(presets) { preset in
                        Button { selectedMode = IOSUnifiedModeSelection.customPrefix + preset.name; dismiss() } label: {
                            VStack(alignment: .leading, spacing: 4) { HStack { Text(preset.name).font(.headline); if selectedMode == IOSUnifiedModeSelection.customPrefix + preset.name { Image(systemName: "checkmark.circle.fill") } }; Text(preset.layers.joined(separator: " • ")).font(.caption).foregroundStyle(.secondary).lineLimit(2) }
                        }
                        .swipeActions { Button(role: .destructive) { IOSUnifiedPresetStore.delete(preset.name); presets = IOSUnifiedPresetStore.load(); if selectedMode == IOSUnifiedModeSelection.customPrefix + preset.name { selectedMode = IOSUnifiedModeSelection.smart } } label: { Label("Delete", systemImage: "trash") } }
                        .contextMenu { Button("Edit") { editingPreset = preset }; Button("Delete", role: .destructive) { IOSUnifiedPresetStore.delete(preset.name); presets = IOSUnifiedPresetStore.load() } }
                    }
                    Button { creatingPreset = true } label: { Label("New CUSTOM preset…", systemImage: "plus.circle.fill") }
                }
            }
            .navigationTitle("Mode")
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
            .sheet(isPresented: $creatingPreset, onDismiss: { presets = IOSUnifiedPresetStore.load() }) { IOSUnifiedCustomBuilder().environmentObject(model) }
            .sheet(item: $editingPreset, onDismiss: { presets = IOSUnifiedPresetStore.load() }) { preset in IOSUnifiedCustomBuilder(editing: preset).environmentObject(model) }
        }
    }

    private func choice(_ title: String, subtitle: String, id: String, available: Bool) -> some View {
        Button { guard available else { return }; selectedMode = id; dismiss() } label: {
            HStack(alignment: .top) { VStack(alignment: .leading, spacing: 3) { Text(title).font(.headline); Text(subtitle).font(.caption).foregroundStyle(.secondary) }; Spacer(); if selectedMode == id { Image(systemName: "checkmark.circle.fill") } }
        }.disabled(!available)
    }
}

private enum IOSUnifiedPresetStore {
    static func load() -> [IOSUnifiedCustomPreset] {
        guard let data = UserDefaults.standard.data(forKey: iosUnifiedPresetsKey), let values = try? JSONDecoder().decode([IOSUnifiedCustomPreset].self, from: data) else { return [] }
        return values.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }
    static func save(_ preset: IOSUnifiedCustomPreset) {
        var values = load(); values.removeAll { $0.name.caseInsensitiveCompare(preset.name) == .orderedSame }; values.append(preset)
        if let data = try? JSONEncoder().encode(values) { UserDefaults.standard.set(data, forKey: iosUnifiedPresetsKey) }
    }
    static func delete(_ name: String) {
        let values = load().filter { $0.name.caseInsensitiveCompare(name) != .orderedSame }
        if let data = try? JSONEncoder().encode(values) { UserDefaults.standard.set(data, forKey: iosUnifiedPresetsKey) }
    }
}

private struct IOSUnifiedCustomBuilder: View {
    @EnvironmentObject var model: RouterVPNModel
    @Environment(\.dismiss) private var dismiss
    @State private var name: String
    @State private var selected: Set<String>

    init(editing: IOSUnifiedCustomPreset? = nil) {
        _name = State(initialValue: editing?.name ?? "")
        _selected = State(initialValue: Set(editing?.layers ?? []))
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Preset") { TextField("Preset name", text: $name); Text("Select exact required layers. Router VPN tries only iOS-runnable stacks containing every selected layer and fails closed when none pass proof.").font(.caption).foregroundStyle(.secondary) }
                Section("Required layers") {
                    let layers = model.iosAvailableCustomLayers()
                    if layers.isEmpty { Text("No iOS-runnable raw profile exposes CUSTOM layers for this node.").foregroundStyle(.secondary) }
                    ForEach(layers, id: \.self) { layer in Toggle(layer, isOn: Binding(get: { selected.contains(layer) }, set: { on in if on { selected.insert(layer) } else { selected.remove(layer) } })) }
                }
                Section { Button("Save preset") { save(connect: false) }.disabled(!valid); Button("Save & Connect") { save(connect: true) }.disabled(!valid) }
            }
            .navigationTitle("CUSTOM builder")
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } } }
        }
    }
    private var valid: Bool { !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !selected.isEmpty && name.count <= 64 }
    private func save(connect: Bool) {
        let preset = IOSUnifiedCustomPreset(name: name.trimmingCharacters(in: .whitespacesAndNewlines), layers: Array(selected).sorted()); IOSUnifiedPresetStore.save(preset)
        UserDefaults.standard.set(IOSUnifiedModeSelection.customPrefix + preset.name, forKey: iosUnifiedModeKey)
        if connect { Task { await model.runIOSCustom(layers: preset.layers) } }
        dismiss()
    }
}

private struct IOSUnifiedSettingsView: View {
    @EnvironmentObject var model: RouterVPNModel
    @Environment(\.dismiss) private var dismiss
    @State private var showingAdvanced = false
    @State private var requireEncrypted = false
    @State private var requireObfuscation = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Quick settings") {
                    Toggle("Kill switch", isOn: Binding(get: { model.unifiedQuickKillSwitch }, set: { model.setUnifiedQuickKillSwitch($0) }))
                    Toggle("AUTO / SMART: Require encrypted", isOn: $requireEncrypted)
                    Toggle("AUTO / SMART: Require obfuscation", isOn: $requireObfuscation)
                    Text("Both AUTO requirements are Off by default. They filter candidates before the proof attempt; SMART cannot simplify into a candidate that violates them.").font(.caption).foregroundStyle(.secondary)
                }
                Section("Defaults") {
                    LabeledContent("IPv6", value: (model.unifiedSelectedProfile?.ipv6Mode ?? "on").capitalized)
                    LabeledContent("MTU", value: (model.unifiedSelectedProfile?.mtuPolicy ?? "auto") == "manual" ? "Fixed \(model.unifiedSelectedProfile?.manualMTU ?? 0)" : "Auto measured")
                    Text("IPv6 On, SMART AUTO and Auto measured MTU are the unified defaults for newly normalized Router VPN profiles.").font(.caption).foregroundStyle(.secondary)
                    Button("Advanced node settings / MTU…") { showingAdvanced = true }
                }
                Section("Platform truth") {
                    Text("DAITA-like traffic padding, Jumbo TUN, arbitrary tunnel port forwarding and full multihop are shown only when this Apple PacketTunnel/runtime can actually enforce them. Current unsupported paths stay unavailable instead of becoming cosmetic toggles.").font(.caption).foregroundStyle(.secondary)
                    Button("DNS details / Retest…") { dismiss(); DispatchQueue.main.async { model.message = "Open DNS from the main control sheet for resolver policy and real DNS-query RTT." } }
                }
                Section { Button("Done") { saveRequirements(); dismiss() } }
            }
            .navigationTitle("Settings")
            .onAppear { requireEncrypted = model.unifiedRequirement("encrypted"); requireObfuscation = model.unifiedRequirement("obfuscation") }
            .onChange(of: requireEncrypted) { _ in saveRequirements() }
            .onChange(of: requireObfuscation) { _ in saveRequirements() }
            .sheet(isPresented: $showingAdvanced) { IOSProfileSettingsView().environmentObject(model) }
        }
    }
    private func saveRequirements() { model.setUnifiedRequirement("encrypted", enabled: requireEncrypted); model.setUnifiedRequirement("obfuscation", enabled: requireObfuscation) }
}

private let iosUnifiedUXContract = "map-first swipe-up Connect Disconnect quick kill switch Multihop Settings Mode DNS SMART AUTO default AUTO all presets CUSTOM builder saved delete Router node Custom external color-coded hops real coordinates IPv6 On Auto MTU Require encrypted Require obfuscation"
