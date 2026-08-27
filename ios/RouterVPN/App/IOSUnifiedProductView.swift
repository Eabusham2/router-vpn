import MapKit
import SwiftUI

private let iosUnifiedModeKey = "routervpn.unified.mode.v1"
private let iosUnifiedPresetsKey = "routervpn.unified.custom-presets.v1"

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
        guard !profileMutationBlocked else { message = "Disconnect or let the active VPN transition finish before changing persistent kill-switch policy."; return }
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
        guard let profile = unifiedSelectedProfile else { return false }
        return kind == "obfuscation" ? (profile.autoRequireObfuscation ?? false) : (profile.autoRequireEncrypted ?? false)
    }

    func setUnifiedRequirement(_ kind: String, enabled: Bool) {
        guard !profileMutationBlocked else { message = "Disconnect or let the active VPN transition finish before changing AUTO / SMART requirements."; return }
        guard var current = bundle,
              let index = current.routerProfiles.firstIndex(where: { $0.id == current.selectedRouterID }) ?? current.routerProfiles.indices.first,
              current.routerProfiles[index].normalizedNodeKind == "router-vpn" else {
            message = "Select a Router VPN node before changing AUTO / SMART requirements."; return
        }
        if kind == "obfuscation" { current.routerProfiles[index].autoRequireObfuscation = enabled }
        else { current.routerProfiles[index].autoRequireEncrypted = enabled }
        current.profileSchemaVersion = max(current.profileSchemaVersion, 4)
        do {
            try importBundle(JSONEncoder().encode(current))
            let label = kind == "obfuscation" ? "Require obfuscation" : "Require encrypted"
            message = "\(label) \(enabled ? "enabled" : "disabled") for AUTO / SMART on the selected Router VPN node."
        } catch { message = "AUTO requirement update failed: \(error.localizedDescription)" }
    }

    func unifiedSetDNSMode(_ mode: String) {
        guard !profileMutationBlocked else { message = "Disconnect or let the active VPN transition finish before changing the selected DNS policy."; return }
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
        guard let profile = unifiedSelectedProfile else { return false }
        return IOSStrategyCatalog.autoRequirementFailure(rawID: rawID, profile: profile) == nil
    }

    func runUnifiedIOSAuto() async {
        guard unifiedSelectedProfile != nil else { message = "Pair/import a Router VPN node first."; return }
        auto = true
        await connect()
        if connected { recordIOSLastRuntime() }
    }

    func runUnifiedIOSSmartAuto() async {
        guard unifiedSelectedProfile != nil else { message = "Pair/import a Router VPN node first."; return }
        await runIOSSmartAuto()
    }
}

private final class IOSUnifiedMapAnnotation: MKPointAnnotation {
    let profileID: String
    let role: String
    init(profileID: String, role: String) { self.profileID = profileID; self.role = role; super.init() }
}

private struct IOSUnifiedMap: UIViewRepresentable {
    @EnvironmentObject var model: RouterVPNModel
    var latencyByID: [String: Double]

    func makeCoordinator() -> Coordinator { Coordinator(self) }
    func makeUIView(context: Context) -> MKMapView {
        let map = MKMapView(frame: .zero)
        map.delegate = context.coordinator
        map.showsCompass = true
        map.showsScale = true
        map.pointOfInterestFilter = .excludingAll
        context.coordinator.startPacketAnimation(map)
        return map
    }

    static func dismantleUIView(_ uiView: MKMapView, coordinator: Coordinator) {
        // Swift 6 treats deinit as nonisolated, so Timer (a non-Sendable UI
        // object) must be stopped while SwiftUI still owns the coordinator on
        // the UI actor rather than from deinit.
        coordinator.stopPacketAnimation()
        uiView.delegate = nil
    }

    func updateUIView(_ map: MKMapView, context: Context) {
        context.coordinator.parent = self
        let packet = context.coordinator.packet
        map.removeAnnotations(map.annotations.filter { $0 !== packet })
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
            let kind = profile.normalizedNodeKind == "external" ? "Custom / external" : "Router node"
            let ms = latencyByID[profile.id] ?? profile.latencyMedianMs ?? 0
            annotation.subtitle = ms > 0 ? String(format: "%@ • %.1f ms", kind, ms) : kind
            map.addAnnotation(annotation)
            coordinatesByID[profile.id] = annotation.coordinate
        }
        if let entryID, let exitID, let a = coordinatesByID[entryID], let b = coordinatesByID[exitID] {
            var values = [a, b]
            map.addOverlay(MKPolyline(coordinates: &values, count: values.count))
            context.coordinator.entry = a; context.coordinator.exit = b; context.coordinator.ensurePacket(on: map)
        } else {
            context.coordinator.entry = nil; context.coordinator.exit = nil
            if let packet { map.removeAnnotation(packet); context.coordinator.packet = nil }
        }
        let regular = map.annotations.filter { $0 !== context.coordinator.packet }
        if !regular.isEmpty { map.showAnnotations(regular, animated: false) }
    }

    final class Coordinator: NSObject, MKMapViewDelegate {
        var parent: IOSUnifiedMap
        weak var map: MKMapView?
        var entry: CLLocationCoordinate2D?
        var exit: CLLocationCoordinate2D?
        var packet: IOSUnifiedMapAnnotation?
        private var timer: Timer?
        private var phase: Double = 0
        init(_ parent: IOSUnifiedMap) { self.parent = parent }

        func stopPacketAnimation() {
            timer?.invalidate()
            timer = nil
            map = nil
        }

        func startPacketAnimation(_ map: MKMapView) {
            self.map = map
            timer?.invalidate()
            timer = Timer.scheduledTimer(withTimeInterval: 0.08, repeats: true) { [weak self] _ in
                // Timer's callback is @Sendable under Swift 6. Re-enter the UI
                // actor before touching MapKit/coordinator state instead of
                // weakening concurrency checking for the whole target.
                Task { @MainActor [weak self] in
                    guard let self, let a = self.entry, let b = self.exit, let packet = self.packet else { return }
                    self.phase += 0.035; if self.phase >= 1 { self.phase -= 1 }
                    packet.coordinate = CLLocationCoordinate2D(latitude: a.latitude + (b.latitude-a.latitude)*self.phase, longitude: a.longitude + (b.longitude-a.longitude)*self.phase)
                }
            }
        }
        func ensurePacket(on map: MKMapView) {
            guard packet == nil, let a = entry else { return }
            let p = IOSUnifiedMapAnnotation(profileID: "__packet__", role: "packet"); p.coordinate = a; packet = p; map.addAnnotation(p)
        }
        func mapView(_ mapView: MKMapView, viewFor annotation: MKAnnotation) -> MKAnnotationView? {
            guard let node = annotation as? IOSUnifiedMapAnnotation else { return nil }
            if node.role == "packet" {
                let view = (mapView.dequeueReusableAnnotationView(withIdentifier: "packet") as? MKMarkerAnnotationView) ?? MKMarkerAnnotationView(annotation: annotation, reuseIdentifier: "packet")
                view.annotation = annotation; view.markerTintColor = .white; view.glyphText = "•"; view.canShowCallout = false; view.displayPriority = .required; return view
            }
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
            guard let node = view.annotation as? IOSUnifiedMapAnnotation, node.role != "packet" else { return }
            Task { @MainActor in
                guard !parent.model.profileMutationBlocked else { parent.model.message = "Disconnect or let the active VPN transition finish before selecting another node."; return }
                parent.model.selectNode(node.profileID)
            }
        }
        func mapView(_ mapView: MKMapView, rendererFor overlay: MKOverlay) -> MKOverlayRenderer {
            guard let line = overlay as? MKPolyline else { return MKOverlayRenderer(overlay: overlay) }
            let renderer = MKPolylineRenderer(polyline: line); renderer.strokeColor = .systemBlue; renderer.lineWidth = 4; renderer.lineCap = .round; renderer.lineJoin = .round; return renderer
        }
    }
}

struct IOSUnifiedProductView: View {
    @EnvironmentObject var model: RouterVPNModel
    @StateObject private var telemetry = IOSUnifiedTelemetry()
    @AppStorage(iosUnifiedModeKey) private var selectedMode = IOSUnifiedModeSelection.smart
    @State private var expanded = false
    @State private var showingNodes = false
    @State private var showingModes = false
    @State private var showingDNS = false
    @State private var showingSettings = false
    @State private var showingOnboarding = false
    @State private var showingForwardingInfo = false
    @State private var startupApplied = false

    var body: some View {
        GeometryReader { geo in
            ZStack(alignment: .bottom) {
                IOSUnifiedMap(latencyByID: telemetry.latencyByID).environmentObject(model).ignoresSafeArea()

                VStack {
                    HStack(spacing: 8) {
                        Button { showingNodes = true } label: {
                            HStack(spacing: 7) {
                                Image(systemName: selectedProfile?.normalizedNodeKind == "external" ? "arrow.up.right.circle.fill" : "network")
                                VStack(alignment: .leading, spacing: 1) {
                                    Text(selectedProfile.map { $0.name.isEmpty ? $0.id : $0.name } ?? "Add a node").font(.subheadline.bold()).lineLimit(1)
                                    Text(nodeSubtitle).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                                }
                            }
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(model.profileMutationBlocked)
                        Spacer()
                        VStack(alignment: .trailing, spacing: 1) {
                            Text(connectionStateTitle).font(.subheadline.bold())
                            HStack(spacing: 5) {
                                Text(model.activeRawProfile.isEmpty ? selectedModeTitle : model.activeRawProfile)
                                if let ms = telemetry.livePathMs, model.connected { Text(String(format: "• %.1f ms", ms)).monospacedDigit() }
                            }.font(.caption2).foregroundStyle(.secondary)
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
        .sheet(isPresented: $showingSettings) { IOSUnifiedSettingsView(telemetry: telemetry).environmentObject(model) }
        .sheet(isPresented: $showingOnboarding) { RouterVPNProductOnboardingView() }
        .alert("Master port forwarding", isPresented: $showingForwardingInfo) {
            Button("OK", role: .cancel) { }
        } message: {
            Text("Incoming forwarding is owned by the authenticated private Router VPN home node and only exists for routable tunnel modes. iOS PacketTunnel paths that cannot enforce arbitrary DNAT keep this unavailable rather than showing a fake switch. Configure the home-node rule in Setup Center/router-agent and validate it off-LAN.")
        }
        .onAppear { if !UserDefaults.standard.bool(forKey: "RouterVPNProductOnboardingDoneV2") { showingOnboarding = true } }
        .onChange(of: model.activeRawProfile) { value in if model.connected && !value.isEmpty { model.recordIOSLastRuntime() } }
        .task { guard !startupApplied else { return }; startupApplied = true; await model.applyIOSStartupPolicyIfNeeded(); _ = await telemetry.measureAll(model.allNodeProfiles, samples: 2) }
        .task(id: model.connected) {
            while !Task.isCancelled {
                await telemetry.refreshLivePath(profile: model.unifiedSelectedProfile, connected: model.connected)
                try? await Task.sleep(for: .seconds(2))
            }
        }
    }

    private var selectedProfile: RouterProfile? { model.unifiedSelectedProfile }
    private var routerProfiles: [RouterProfile] { model.allNodeProfiles.filter { $0.normalizedNodeKind == "router-vpn" } }
    private var nodeSubtitle: String {
        guard let p = selectedProfile else { return "Router / Custom node" }
        let kind = p.normalizedNodeKind == "external" ? "Custom / external" : "Router node"
        let ms = telemetry.cached(p.id) ?? p.latencyMedianMs ?? 0
        return ms > 0 ? String(format: "%@ • %.1f ms", kind, ms) : kind
    }
    private var connectionStateTitle: String {
        if model.connected { return "Connected" }
        if model.tunnelTransitioning { return model.message.lowercased().contains("disconnect") ? "Disconnecting…" : "Connecting…" }
        return "Disconnected"
    }
    private var connectionButtonTitle: String {
        if model.tunnelTransitioning { return model.message.lowercased().contains("disconnect") ? "Disconnecting…" : "Connecting…" }
        return model.connected ? "Disconnect" : "Connect"
    }
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
                    HStack(spacing: 7) {
                        Menu {
                            Button { Task { await connectFastest() } } label: { Label(telemetry.isTestingFastest ? "Testing…" : "Test & connect fastest", systemImage: "bolt.fill") }
                                .disabled(telemetry.isTestingFastest || model.profileMutationBlocked)
                            Divider()
                            ForEach(routerProfiles) { profile in
                                Button { connectSpecific(profile) } label: {
                                    let ms = telemetry.cached(profile.id) ?? profile.latencyMedianMs ?? 0
                                    Text(ms > 0 ? String(format: "%@ • %.1f ms", profile.name, ms) : profile.name)
                                }.disabled(model.profileMutationBlocked)
                            }
                        } label: { Image(systemName: "bolt.fill").frame(width: 24, height: 32) }
                        .buttonStyle(.bordered).accessibilityLabel("Fastest node or choose node")

                        Button { connectOrDisconnect() } label: { Text(connectionButtonTitle).font(.headline).frame(maxWidth: .infinity).padding(.vertical, 7) }
                            .buttonStyle(.borderedProminent).tint(model.connected ? .red : .accentColor)
                            .disabled(model.tunnelTransitioning)

                        if let ms = telemetry.livePathMs, model.connected { Text(String(format: "%.1f\nms", ms)).font(.caption2.bold()).monospacedDigit().multilineTextAlignment(.center) }
                        Toggle(isOn: Binding(get: { model.unifiedQuickKillSwitch }, set: { model.setUnifiedQuickKillSwitch($0) })) { Image(systemName: "lock.shield.fill") }
                            .toggleStyle(.button).buttonStyle(.bordered).accessibilityLabel("Kill switch")
                            .disabled(model.profileMutationBlocked)
                        Button { showingForwardingInfo = true } label: { Image(systemName: "arrow.triangle.branch") }
                            .buttonStyle(.bordered).accessibilityLabel("Master port forwarding")
                    }

                    unifiedRow(icon: "point.3.connected.trianglepath.dotted", title: "Multihop", value: iosMultihopSummary) { showingNodes = true }
                    unifiedRow(icon: "slider.horizontal.3", title: "Settings", value: settingsSummary) { showingSettings = true }
                    unifiedRow(icon: "wand.and.stars", title: "Mode", value: selectedModeTitle, disabled: model.profileMutationBlocked) { showingModes = true }

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
                        .disabled(model.profileMutationBlocked)
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

    private var iosMultihopSummary: String {
        if let p = selectedProfile, p.multihopEnabled == true, let entry = p.multihopEntryID, let exit = p.multihopExitID {
            let a = telemetry.cached(entry), b = telemetry.cached(exit)
            var text = "\(entry) → \(exit)"
            if let a, let b { text += String(format: " • %.1f / %.1f ms", a, b) }
            if let path = telemetry.livePathMs, model.connected { text += String(format: " • PATH %.1f", path) }
            return text
        }
        return "Unavailable on current iOS dataplane"
    }
    private var settingsSummary: String {
        let p = selectedProfile
        let mtu = (p?.mtuPolicy ?? "auto").lowercased() == "manual" ? "MTU \(p?.manualMTU ?? 0)" : "Auto MTU"
        let ipv6 = (p?.ipv6Mode ?? "on").lowercased() == "off" ? "IPv6 Off" : "IPv6 On"
        let encrypted = p?.autoRequireEncrypted ?? false
        let obfuscated = p?.autoRequireObfuscation ?? false
        let requirements = encrypted && obfuscated ? "AUTO Encrypted+Obfuscation" : encrypted ? "AUTO Encrypted" : obfuscated ? "AUTO Obfuscation" : "AUTO Off"
        return "\(ipv6) • \(mtu) • \(requirements)"
    }

    private func unifiedRow(icon: String, title: String, value: String, disabled: Bool = false, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack { Label(title, systemImage: icon).font(.subheadline.bold()); Spacer(); Text(value).font(.caption).foregroundStyle(.secondary).lineLimit(1); Image(systemName: "chevron.right").font(.caption).foregroundStyle(.tertiary) }
                .padding(11).background(.thinMaterial, in: RoundedRectangle(cornerRadius: 12))
        }.buttonStyle(.plain).disabled(disabled)
    }

    private func connectSpecific(_ profile: RouterProfile) {
        guard !model.profileMutationBlocked else { return }
        model.selectNode(profile.id)
        connectOrDisconnect()
    }
    private func connectFastest() async {
        guard !model.profileMutationBlocked else { return }
        let results = await telemetry.measureAll(routerProfiles, samples: 4)
        guard let winner = results.first else { model.message = telemetry.lastError; return }
        model.selectNode(winner.id)
        model.message = "Fastest live node: \(winner.name) • \(winner.shortLabel) • connecting with \(selectedModeTitle)…"
        connectOrDisconnect()
    }
    private func connectOrDisconnect() {
        guard !model.tunnelTransitioning else { return }
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
                        Button { guard !model.profileMutationBlocked else { return }; selectedMode = IOSUnifiedModeSelection.customPrefix + preset.name; dismiss() } label: {
                            VStack(alignment: .leading, spacing: 4) { HStack { Text(preset.name).font(.headline); if selectedMode == IOSUnifiedModeSelection.customPrefix + preset.name { Image(systemName: "checkmark.circle.fill") } }; Text(preset.layers.joined(separator: " • ")).font(.caption).foregroundStyle(.secondary).lineLimit(2) }
                        }
                        .disabled(model.profileMutationBlocked)
                        .swipeActions { Button(role: .destructive) { guard !model.profileMutationBlocked else { return }; IOSUnifiedPresetStore.delete(preset.name); presets = IOSUnifiedPresetStore.load(); if selectedMode == IOSUnifiedModeSelection.customPrefix + preset.name { selectedMode = IOSUnifiedModeSelection.smart } } label: { Label("Delete", systemImage: "trash") }.disabled(model.profileMutationBlocked) }
                        .contextMenu { Button("Edit") { guard !model.profileMutationBlocked else { return }; editingPreset = preset }.disabled(model.profileMutationBlocked); Button("Delete", role: .destructive) { guard !model.profileMutationBlocked else { return }; IOSUnifiedPresetStore.delete(preset.name); presets = IOSUnifiedPresetStore.load() }.disabled(model.profileMutationBlocked) }
                    }
                    Button { guard !model.profileMutationBlocked else { return }; creatingPreset = true } label: { Label("New CUSTOM preset…", systemImage: "plus.circle.fill") }
                        .disabled(model.profileMutationBlocked)
                    if model.profileMutationBlocked {
                        Text("Disconnect or let the active VPN transition finish before changing Mode or CUSTOM presets.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            .navigationTitle("Mode")
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
            .sheet(isPresented: $creatingPreset, onDismiss: { presets = IOSUnifiedPresetStore.load() }) { IOSUnifiedCustomBuilder().environmentObject(model) }
            .sheet(item: $editingPreset, onDismiss: { presets = IOSUnifiedPresetStore.load() }) { preset in IOSUnifiedCustomBuilder(editing: preset).environmentObject(model) }
        }
    }

    private func choice(_ title: String, subtitle: String, id: String, available: Bool) -> some View {
        Button { guard available, !model.profileMutationBlocked else { return }; selectedMode = id; dismiss() } label: {
            HStack(alignment: .top) { VStack(alignment: .leading, spacing: 3) { Text(title).font(.headline); Text(subtitle).font(.caption).foregroundStyle(.secondary) }; Spacer(); if selectedMode == id { Image(systemName: "checkmark.circle.fill") } }
        }.disabled(!available || model.profileMutationBlocked)
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
                Section { Button("Save preset") { save(connect: false) }.disabled(!valid || model.profileMutationBlocked); Button("Save & Connect") { save(connect: true) }.disabled(!valid || model.profileMutationBlocked)
                    if model.profileMutationBlocked { Text("Disconnect or let the active VPN transition finish before saving a CUSTOM preset.").font(.caption).foregroundStyle(.secondary) }
                }
            }
            .navigationTitle("CUSTOM builder")
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } } }
        }
    }
    private var valid: Bool { !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !selected.isEmpty && name.count <= 64 }
    private func save(connect: Bool) {
        guard !model.profileMutationBlocked else { model.message = "Disconnect or let the active VPN transition finish before saving a CUSTOM preset."; return }
        let preset = IOSUnifiedCustomPreset(name: name.trimmingCharacters(in: .whitespacesAndNewlines), layers: Array(selected).sorted()); IOSUnifiedPresetStore.save(preset)
        UserDefaults.standard.set(IOSUnifiedModeSelection.customPrefix + preset.name, forKey: iosUnifiedModeKey)
        if connect { Task { await model.runIOSCustom(layers: preset.layers) } }
        dismiss()
    }
}

private struct IOSUnifiedSettingsView: View {
    @EnvironmentObject var model: RouterVPNModel
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var telemetry: IOSUnifiedTelemetry
    @State private var showingAdvanced = false
    @State private var showingPerformance = false
    @State private var requireEncrypted = false
    @State private var requireObfuscation = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Quick settings") {
                    Toggle("Kill switch", isOn: Binding(get: { model.unifiedQuickKillSwitch }, set: { model.setUnifiedQuickKillSwitch($0) }))
                        .disabled(model.profileMutationBlocked)
                    Toggle("Require encrypted AUTO candidates", isOn: $requireEncrypted).disabled(model.profileMutationBlocked)
                    Toggle("Require obfuscation for AUTO candidates", isOn: $requireObfuscation).disabled(model.profileMutationBlocked)
                    Text("Both AUTO requirements are Off by default. They are stored in the selected schema-v4 Router VPN profile, shared with Advanced Settings, and filter candidates before the proof attempt; SMART cannot simplify into a candidate that violates them.").font(.caption).foregroundStyle(.secondary)
                }
                Section("Defaults") {
                    LabeledContent("IPv6", value: (model.unifiedSelectedProfile?.ipv6Mode ?? "on").capitalized)
                    LabeledContent("MTU", value: (model.unifiedSelectedProfile?.mtuPolicy ?? "auto") == "manual" ? "Fixed \(model.unifiedSelectedProfile?.manualMTU ?? 0)" : "Auto measured")
                    Text("IPv6 On, SMART AUTO and Auto measured MTU are the unified defaults for newly normalized Router VPN profiles.").font(.caption).foregroundStyle(.secondary)
                    Button("Advanced node settings / MTU…") { showingAdvanced = true }
                }
                Section("Performance") {
                    LabeledContent("Live path", value: telemetry.livePathMs.map { String(format: "%.1f ms", $0) } ?? "Not connected")
                    if let speed = telemetry.lastSpeedResult {
                        LabeledContent("Last real path speed", value: String(format: "↓ %.1f • ↑ %.1f Mbps", speed.downloadMbps, speed.uploadMbps))
                    }
                    Button("Latency / speed / node benchmarks…") { showingPerformance = true }
                    if let p = model.unifiedSelectedProfile, let mbps = p.effectiveMTUMbps, mbps > 0 {
                        LabeledContent("Last Auto-MTU path throughput", value: String(format: "%.1f Mbps", mbps))
                    }
                }
                Section("Platform truth") {
                    Text("DAITA-like traffic padding, Jumbo TUN, arbitrary tunnel port forwarding and full multihop are shown only when this Apple PacketTunnel/runtime can actually enforce them. Current unsupported paths stay unavailable instead of becoming cosmetic toggles.").font(.caption).foregroundStyle(.secondary)
                    Button("DNS details / Retest…") { dismiss(); DispatchQueue.main.async { model.message = "Open DNS from the main control sheet for resolver policy and real DNS-query RTT." } }
                }
                Section { Button("Done") { saveRequirements(); dismiss() } }
            }
            .navigationTitle("Settings")
            .onAppear { requireEncrypted = model.unifiedRequirement("encrypted"); requireObfuscation = model.unifiedRequirement("obfuscation") }
            .onChange(of: requireEncrypted) { value in model.setUnifiedRequirement("encrypted", enabled: value) }
            .onChange(of: requireObfuscation) { value in model.setUnifiedRequirement("obfuscation", enabled: value) }
            .sheet(isPresented: $showingAdvanced) { IOSProfileSettingsView().environmentObject(model) }
            .sheet(isPresented: $showingPerformance) { IOSUnifiedPerformanceView(telemetry: telemetry).environmentObject(model) }
        }
    }
    private func saveRequirements() { guard !model.profileMutationBlocked else { return }; model.setUnifiedRequirement("encrypted", enabled: requireEncrypted); model.setUnifiedRequirement("obfuscation", enabled: requireObfuscation) }
}

private struct IOSUnifiedPerformanceView: View {
    @EnvironmentObject var model: RouterVPNModel
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var telemetry: IOSUnifiedTelemetry
    @State private var output = "Choose a real measurement."
    @State private var busy = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Current path") {
                    LabeledContent("Live RTT", value: telemetry.livePathMs.map { String(format: "%.1f ms", $0) } ?? "Not connected")
                    Button("Measure current tunnel RTT") { runLive() }.disabled(!model.connected || busy)
                    Button(telemetry.isSpeedTesting ? "Testing real VPN path speed…" : "Run real current VPN path speed") { runSpeed() }
                        .disabled(!model.connected || model.unifiedSelectedProfile?.normalizedNodeKind != "router-vpn" || busy || telemetry.isSpeedTesting)
                    if let speed = telemetry.lastSpeedResult {
                        Text(speed.detail).font(.caption.monospaced()).textSelection(.enabled)
                    }
                    Text("Real speed transfers 8 MiB down and 8 MiB up against the selected Router VPN node's authenticated private router-agent through the active PacketTunnel route. It is not inferred from RTT.").font(.caption).foregroundStyle(.secondary)
                }
                Section("Nodes") {
                    Button("50-sample selected node") { runSelected() }.disabled(model.unifiedSelectedProfile == nil || busy)
                    Button("Benchmark all linked nodes") { runAll() }.disabled(busy)
                }
                Section("Auto MTU") {
                    if let p = model.unifiedSelectedProfile, let mbps = p.effectiveMTUMbps, mbps > 0 {
                        Text(String(format: "Last Auto-MTU optimizer result: %.1f Mbps • MTU %d • RTT %.1f ms", mbps, p.effectiveMTU ?? 0, p.effectiveMTUMedianRTTMs ?? 0))
                    } else { Text("No proven Auto-MTU optimizer result is stored for this path yet.").foregroundStyle(.secondary) }
                    Text("Auto-MTU throughput and the real 8 MiB down/up speed test are separate measurements. Hop-specific Mbps is shown only when that hop's private benchmark is actually reachable; Router VPN never derives it from latency arithmetic.").font(.caption).foregroundStyle(.secondary)
                }
                Section("Result") { Text(output).font(.caption.monospaced()).textSelection(.enabled) }
            }
            .navigationTitle("Performance")
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
        }
    }
    private func runLive() { busy = true; Task { await telemetry.refreshLivePath(profile: model.unifiedSelectedProfile, connected: model.connected); output = telemetry.livePathMs.map { String(format: "Current private tunnel median RTT: %.1f ms", $0) } ?? "Current tunnel RTT failed."; busy = false } }
    private func runSpeed() { busy = true; Task { do { output = try await telemetry.speedTest(profile: model.unifiedSelectedProfile, connected: model.connected, bytes: 8 << 20).detail } catch { output = error.localizedDescription }; busy = false } }
    private func runSelected() { guard let p = model.unifiedSelectedProfile else { return }; busy = true; Task { do { output = try await telemetry.measureOne(p, samples: 50).detail } catch { output = error.localizedDescription }; busy = false } }
    private func runAll() { busy = true; Task { let values = await telemetry.measureAll(model.allNodeProfiles, samples: 5); output = values.isEmpty ? telemetry.lastError : values.map(\.detail).joined(separator: "\n"); busy = false } }
}

private let iosUnifiedUXContract = "map-first swipe-up Connect Disconnect fastest-node live RTT real path Mbps quick kill switch forwarding shortcut Multihop Settings Performance Mode DNS SMART AUTO default AUTO all presets CUSTOM builder saved delete Router node Custom external color-coded hops real coordinates node ms animated packet path IPv6 On Auto MTU Require encrypted Require obfuscation schema-v4 profile-shared requirements"
