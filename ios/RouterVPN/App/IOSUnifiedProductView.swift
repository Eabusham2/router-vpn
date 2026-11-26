import MapKit
import SwiftUI

private let iosUnifiedModeKey = "routervpn.unified.mode.v1"
private let iosUnifiedPresetsKey = "routervpn.unified.custom-presets.v1"

private struct IOSUnifiedCustomPreset: Codable, Identifiable, Hashable {
    var id: Data { Data(name.utf8) }
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
        return IOSDNSRuntimePolicy.selectedProfile(in: bundle)
    }

    fileprivate func connectNamedCustom(_ preset: IOSUnifiedCustomPreset) {
        guard !profileMutationBlocked, unifiedSelectedProfile?.normalizedNodeKind == "router-vpn",
              let bundle, let source = try? iosStrategySource(bundle) else {
            message = "Select an idle Router VPN node before connecting this CUSTOM preset."
            return
        }
        let mode = IOSUnifiedModeSelection.customPrefix + preset.name
        let original = IOSNamedCustomSelection(source: source, generation: iosConnectGeneration) {
            guard UserDefaults.standard.string(forKey: iosUnifiedModeKey)?.utf8.elementsEqual(mode.utf8) == true,
                  let saved = try? IOSUnifiedPresetStore.selected(preset.name) else { return false }
            return saved.layers == preset.layers
        }
        Task { await runIOSCustom(layers: preset.layers, original: original) }
    }

    var unifiedQuickKillSwitch: Bool {
        guard let p = unifiedSelectedProfile else { return false }
        if p.killSwitch == true { return true }
        let policy = (p.killSwitchPolicy ?? "off").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return ["strict", "always", "enabled", "on", "lockdown"].contains(policy)
    }

    func setUnifiedQuickKillSwitch(_ enabled: Bool) {
        guard !profileMutationBlocked else { message = "Disconnect or let the active VPN transition finish before changing persistent kill-switch policy."; return }
        guard var current = bundle,
              !current.selectedRouterID.isEmpty,
              let selected = IOSDNSRuntimePolicy.selectedProfile(in: current),
              let index = current.routerProfiles.firstIndex(where: { $0.id == selected.id }),
              selected.normalizedNodeKind == "router-vpn" || selectedExternalSupportedOnIOS else {
            message = "Select one linked node with a native kill-switch runtime before changing its policy."; return
        }
        current.routerProfiles[index].killSwitch = enabled
        current.routerProfiles[index].killSwitchPolicy = enabled ? "on-connect" : "off"
        do {
            try importBundle(JSONEncoder().encode(current))
            message = enabled ? "Kill switch enabled for the selected node." : "Kill switch disabled for the selected node."
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
              !current.selectedRouterID.isEmpty,
              let selected = IOSDNSRuntimePolicy.selectedProfile(in: current),
              let index = current.routerProfiles.firstIndex(where: { $0.id == selected.id }) else {
            message = "Select one linked node before changing DNS."; return
        }
        do {
            let capturedEntry = selected.normalizedNodeKind == "external" && selected.multihopEnabled == true
                ? try iosMultihopEntryBundle(for: current) : nil
            current.routerProfiles[index] = try IOSDNSQuickSelection.applying(mode, to: selected,
                entry: capturedEntry.flatMap { IOSDNSRuntimePolicy.selectedProfile(in: $0) })
            try importBundle(JSONEncoder().encode(current))
            message = "DNS set to \(current.routerProfiles[index].dnsMode ?? mode). The next connection must still prove the selected DNS and path."
        } catch { message = "DNS update failed: \(error.localizedDescription)" }
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

struct IOSUnifiedMap: UIViewRepresentable {
    @EnvironmentObject var model: RouterVPNModel
    var latencyByID: [String: Double]
    var deviceLocation: CLLocationCoordinate2D?

    func makeCoordinator() -> Coordinator { Coordinator(self) }
    func makeUIView(context: Context) -> MKMapView {
        let map = MKMapView(frame: .zero)
        map.delegate = context.coordinator
        map.showsCompass = true
        map.showsScale = true
        map.pointOfInterestFilter = .excludingAll
        RouterVPNVectorMap.install(on: map)
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
        RouterVPNVectorMap.clearRoutes(on: map)
        let ordered = model.iosVisibleMapPath
        let profiles = model.iosMapNodePoints(path: ordered)
        let selectedID = ordered?.last?.id ?? model.bundle?.selectedRouterID ?? ""
        let selected = model.allNodeProfiles.first(where: { $0.id == selectedID })
        let hasOrderedSource = model.connected && !model.iosCandidateTesting || selected?.multihopNodes != nil || model.activeSessionIdentity?.nodeChainSource != nil
        let entryID = ordered?.first?.id ?? (!hasOrderedSource && selected?.multihopEnabled == true ? selected?.multihopEntryID : nil)
        let exitID = ordered?.last?.id ?? (!hasOrderedSource && selected?.multihopEnabled == true ? selected?.multihopExitID : nil)
        let middleIDs = Set(ordered?.dropFirst().dropLast().map(\.id) ?? [])
        let routeIDs = ordered?.map(\.id) ?? ([entryID, exitID].compactMap { $0 })
        var coordinatesByID: [String: CLLocationCoordinate2D] = [:]
        for profile in profiles {
            guard profile.hasCoordinates, let lat = profile.latitude, let lon = profile.longitude else { continue }
            let role: String
            if profile.id == entryID { role = "entry" }
            else if profile.id == exitID { role = "exit" }
            else if middleIDs.contains(profile.id) { role = "hop" }
            else if profile.id == selectedID { role = "selected" }
            else if profile.kind == "external" { role = "external" }
            else { role = "normal" }
            let annotation = IOSUnifiedMapAnnotation(profileID: profile.id, role: role)
            annotation.coordinate = CLLocationCoordinate2D(latitude: lat, longitude: lon)
            annotation.title = profile.name.isEmpty ? profile.id : profile.name
            let kind = profile.kind == "external" ? "Custom / external" : "Router node"
            let ms = latencyByID[profile.id] ?? profile.savedLatency ?? 0
            annotation.subtitle = ms > 0 ? String(format: "%@ • direct TCP %.1f ms", kind, ms) : kind
            if let phase = IOSNodeChainPresentation.candidateLabel(id: profile.id, path: ordered, testing: model.iosCandidateTestingNodeIDs) {
                annotation.subtitle = phase + " • " + (annotation.subtitle ?? kind)
            }
            map.addAnnotation(annotation)
            coordinatesByID[profile.id] = annotation.coordinate
        }
        for (position, edge) in zip(routeIDs, routeIDs.dropFirst()).enumerated() {
            guard let a = coordinatesByID[edge.0], let b = coordinatesByID[edge.1] else { continue }
            let segments = RouterVPNVectorMap.routes(from: a, to: b)
            for segment in segments { segment.title = position == routeIDs.count - 2 ? "exit" : position == 0 ? "entry" : "hop" }
            map.addOverlays(segments, level: .aboveLabels)
        }
        let owner = model.connected && !model.tunnelTransitioning && !model.iosCandidateTesting ? model.activeSessionIdentity : nil
        context.coordinator.updatePacket(on: map, owner: owner, coordinates: routeIDs.map { coordinatesByID[$0] })
        let regular = map.annotations.filter { $0 !== context.coordinator.packet }
        if let deviceLocation {
            let marker = IOSUnifiedMapAnnotation(profileID: "", role: "device")
            marker.coordinate = deviceLocation
            marker.title = "You • real device fix"
            map.addAnnotation(marker)
        }
        let geometryID = coordinatesByID.keys.sorted().map { id in
            let p = coordinatesByID[id]!
            return "\(id):\(p.latitude):\(p.longitude)"
        }.joined(separator: "|")
        if !regular.isEmpty && geometryID != context.coordinator.fittedGeometryID {
            map.showAnnotations(regular, animated: false)
            context.coordinator.fittedGeometryID = geometryID
        }
    }

    final class Coordinator: NSObject, MKMapViewDelegate {
        var parent: IOSUnifiedMap
        weak var map: MKMapView?
        var path: [CLLocationCoordinate2D?] = []
        private var packetOwner: IOSSessionIdentity?
        fileprivate var packet: IOSUnifiedMapAnnotation?
        var fittedGeometryID = ""
        private var timer: Timer?
        private var phase: Double = 0
        init(_ parent: IOSUnifiedMap) { self.parent = parent }

        func stopPacketAnimation() {
            timer?.invalidate()
            timer = nil
            if let map { updatePacket(on: map, owner: nil, coordinates: []) }
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
                    guard let self, let map = self.map else { return }
                    self.advancePacket(on: map)
                }
            }
        }

        func updatePacket(on map: MKMapView, owner: IOSSessionIdentity?, coordinates: [CLLocationCoordinate2D?]) {
            let active = coordinates.count >= 2 ? owner : nil
            if packetOwner != active { phase = 0 }
            packetOwner = active
            path = active == nil ? [] : coordinates
            renderPacket(on: map)
        }

        func advancePacket(on map: MKMapView) {
            guard let packetOwner else { return }
            guard packetOwner == parent.model.activeSessionIdentity,
                  parent.model.connected, !parent.model.tunnelTransitioning, !parent.model.iosCandidateTesting else {
                updatePacket(on: map, owner: nil, coordinates: [])
                return
            }
            // Keep the familiar short-route speed and draw at least four
            // positions per original leg when the route contains many hops.
            let increment = min(0.035, 0.25 / Double(path.count - 1))
            phase = (phase + increment).truncatingRemainder(dividingBy: 1)
            renderPacket(on: map)
        }

        private func renderPacket(on map: MKMapView) {
            let step = phase * Double(max(0, path.count - 1))
            let index = Int(step)
            guard index + 1 < path.count, let from = path[index], let to = path[index + 1],
                  let coordinate = RouterVPNVectorMap.packetCoordinate(from: from, to: to, fraction: step - Double(index)) else {
                if let packet { map.removeAnnotation(packet); self.packet = nil }
                return
            }
            if let packet {
                packet.coordinate = coordinate
            } else {
                let marker = IOSUnifiedMapAnnotation(profileID: "__packet__", role: "packet")
                marker.coordinate = coordinate
                packet = marker
                map.addAnnotation(marker)
            }
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
            case "device": view.markerTintColor = .systemGreen
            case "entry": view.markerTintColor = .systemBlue
            case "hop": view.markerTintColor = .systemCyan
            case "exit": view.markerTintColor = .systemOrange
            case "selected": view.markerTintColor = .systemPurple
            case "external": view.markerTintColor = .systemPink
            default: view.markerTintColor = .systemTeal
            }
            return view
        }
        func mapView(_ mapView: MKMapView, didSelect view: MKAnnotationView) {
            guard let node = view.annotation as? IOSUnifiedMapAnnotation, node.role != "packet", node.role != "device" else { return }
            Task { @MainActor in
                guard !parent.model.profileMutationBlocked else { parent.model.message = "Disconnect or let the active VPN transition finish before selecting another node."; return }
                parent.model.selectNode(node.profileID)
            }
        }
        func mapView(_ mapView: MKMapView, rendererFor overlay: MKOverlay) -> MKOverlayRenderer {
            if let base = overlay as? RouterVPNVectorMapOverlay { return RouterVPNVectorMapRenderer(overlay: base) }
            guard let line = overlay as? MKPolyline else { return MKOverlayRenderer(overlay: overlay) }
            let renderer = MKPolylineRenderer(polyline: line); renderer.strokeColor = line.title == "exit" ? .systemOrange : line.title == "hop" ? .systemCyan : .systemBlue; renderer.lineWidth = 4; renderer.lineCap = .round; renderer.lineJoin = .round
            renderer.lineDashPattern = parent.model.connected && !parent.model.iosCandidateTesting ? nil : [6, 5]
            return renderer
        }
    }
}

struct IOSUnifiedProductView: View {
    @EnvironmentObject var model: RouterVPNModel
    @StateObject private var location = IOSUserLocationController()
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var telemetry = IOSUnifiedTelemetry.shared
    @ObservedObject private var externalComparison = IOSExternalNodeComparison.shared
    @ObservedObject private var externalBenchmark = IOSExternalNodeBenchmark.shared
    @ObservedObject private var externalLive = IOSExternalLiveTelemetry.shared
    @AppStorage(iosUnifiedModeKey) private var selectedMode = IOSUnifiedModeSelection.smart
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @State private var canRankExternal = false
    @State private var expanded = false
    @State private var showingNodes = false
    @State private var showingMultihop = false
    @State private var showingModes = false
    @State private var showingDNS = false
    @State private var dnsEditorMode: String?
    @State private var showingSettings = false
    @State private var showingPerformance = false
    @State private var showingOnboarding = false
    @State private var startupApplied = false

    var body: some View {
        GeometryReader { geo in
            ZStack(alignment: .bottom) {
                IOSUnifiedMap(latencyByID: telemetry.latencyByID, deviceLocation: location.coordinate).environmentObject(model).ignoresSafeArea()

                VStack {
                    let compactHeader = dynamicTypeSize.isAccessibilitySize && geo.size.width < 620
                    let header = compactHeader ? AnyLayout(VStackLayout(alignment: .leading, spacing: 4)) : AnyLayout(HStackLayout(spacing: 8))
                    header {
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
                            IOSUserLocationControl().environmentObject(location)
                        }
                        if !compactHeader { Spacer() }
                        VStack(alignment: compactHeader ? .leading : .trailing, spacing: 1) {
                            Text(connectionStateTitle).font(.subheadline.bold())
                            Text(IOSUnifiedSecureTransport.handshakeLabel(connected: model.connected && !model.iosCandidateTesting))
                                .font(.caption2).foregroundStyle(model.connected && !model.iosCandidateTesting ? .green : .secondary)
                                .fixedSize(horizontal: false, vertical: true)
                            HStack(spacing: 5) {
                                Text(model.activeRawProfile.isEmpty ? selectedModeTitle : model.activeRawProfile).lineLimit(compactHeader ? 2 : 1)
                                if let ms = livePathMilliseconds, model.connected && !model.iosCandidateTesting { Text(String(format: "• %.1f ms %@", ms, livePathLabel)).monospacedDigit() }
                            }.font(.caption2).foregroundStyle(.secondary)
                        }
                        .padding(.horizontal, 10).padding(.vertical, 7).background(.regularMaterial, in: Capsule())
                    }
                    .padding(.horizontal, 12).padding(.top, 8)
                    Spacer()
                }

                controlSheet(height: min(geo.size.height * (expanded ? 0.70 : 0.48), expanded ? 620 : 350),
                             stackControls: dynamicTypeSize.isAccessibilitySize || geo.size.width < 340)
            }
        }
        .sheet(isPresented: $showingNodes) { RouterVPNNodeManagerSheet().environmentObject(model) }
        .sheet(isPresented: $showingMultihop) { IOSMultihopView().environmentObject(model) }
        .sheet(isPresented: $showingModes) { IOSUnifiedModePicker(selectedMode: $selectedMode).environmentObject(model) }
        .sheet(isPresented: $showingDNS) { IOSDNSPolicyView(initialMode: dnsEditorMode).environmentObject(model) }
        .sheet(isPresented: $showingSettings) { IOSUnifiedSettingsView(telemetry: telemetry).environmentObject(model) }
        .sheet(isPresented: $showingPerformance) { IOSUnifiedPerformanceView(telemetry: telemetry).environmentObject(model) }
        .sheet(isPresented: $showingOnboarding) { RouterVPNProductOnboardingView().presentationDetents([.medium, .large]).presentationDragIndicator(.visible).interactiveDismissDisabled(false) }
        .onChange(of: model.profileMutationBlocked) { blocked in if !blocked { restoreDeletedCustomSelection() } }
        .onAppear { restoreDeletedCustomSelection(); if !UserDefaults.standard.bool(forKey: "RouterVPNProductOnboardingDoneV2") { model.message = "Setup is ready. Open Setup guide from the expanded control sheet when needed." } }
        .onChange(of: model.activeRawProfile) { value in if model.connected && !value.isEmpty { model.recordIOSLastRuntime() } }
        .task { guard !startupApplied else { return }; startupApplied = true; await model.applyIOSStartupPolicyIfNeeded(); _ = await telemetry.measureAll(model.allNodeProfiles, model: model, samples: 2) }
        .task {
            while !Task.isCancelled {
                await model.refreshIOSMultihopExecutionProgress()
                try? await Task.sleep(for: .milliseconds(600))
            }
        }
        .task(id: IOSNodeBundleStore.shared.revision) { canRankExternal = IOSExternalNodeComparison.hasMultipleEligible(model) }
        .task(id: showingMultihop) {
            if !showingMultihop { await refreshIOSVisiblePathResponses(model) }
        }
        .onChange(of: model.activeSessionIdentity) { _ in externalLive.cancel(); externalLive.invalidate(model: model) }
        .onChange(of: scenePhase) { phase in if phase == .background { location.hideRealLocation() } }
        .onDisappear { externalLive.cancel(); location.hideRealLocation() }
    }

    private var selectedProfile: RouterProfile? { model.unifiedSelectedProfile }
    private var livePathMilliseconds: Double? { selectedProfile?.normalizedNodeKind == "external" ? externalLive.currentMilliseconds(model: model) : telemetry.currentMilliseconds(model: model) }
    private var livePathLabel: String { selectedProfile?.normalizedNodeKind == "external" ? "HTTPS" : "HTTP" }
    private var linkedRouters: [RouterProfile] { model.allNodeProfiles.filter { $0.normalizedNodeKind == "router-vpn" } }
    private var routerProfiles: [RouterProfile] {
        linkedRouters.filter { !IOSViaEntryTCP.endpointHost($0.endpoint).isEmpty }
    }
    private var canRankRouters: Bool { routerProfiles.count > 1 }
    private var nodeSubtitle: String {
        guard let p = selectedProfile else { return "Router / Custom node" }
        let kind = p.normalizedNodeKind == "external" ? "Custom / external" : "Router node"
        let ms = telemetry.cached(p.id) ?? p.latencyMedianMs ?? 0
        return ms > 0 ? String(format: "%@ • %.1f ms", kind, ms) : kind
    }
    private var connectionStateTitle: String {
        if model.iosCandidateTesting { return "Testing" }
        if model.connected { return "Connected" }
        if model.iosStrategyStatus?.phase == .blocked { return "Protected • no proven path" }
        if model.tunnelTransitioning { return model.message.lowercased().contains("disconnect") ? "Disconnecting…" : "Connecting…" }
        return "Disconnected"
    }
    private var connectionButtonTitle: String {
        if model.iosCandidateTesting { return "Cancel test" }
        if model.tunnelTransitioning { return model.iosUserDisconnectInProgress ? "Disconnecting…" : "Cancel & disconnect" }
        return model.connected ? "Disconnect" : "Connect"
    }
    private func restoreDeletedCustomSelection() {
        guard !model.profileMutationBlocked, let name = IOSCustomPresetName.suffix(in: selectedMode) else { return }
        if let saved = try? IOSUnifiedPresetStore.read(), !saved.contains(where: { $0.name.utf8.elementsEqual(name.utf8) }) {
            selectedMode = IOSUnifiedModeSelection.smart
        }
    }

    private var selectedModeTitle: String {
        if let ordered = model.iosVisibleOrderedNodePath {
            let execution = IOSNodeChainPresentation.executionTitle(saved: selectedProfile?.multihopExecution,
                running: model.connected && !model.iosCandidateTesting, identity: model.activeSessionIdentity,
                observed: model.orderedExecutionObservation)
            return "Multihop • \(ordered.count) nodes • \(execution)"
        }
        if selectedProfile?.multihopEnabled == true && selectedProfile?.multihopNodes != nil { return "Ordered route • source unavailable" }
        if selectedProfile?.multihopEnabled == true { return "Multihop • " + (selectedProfile?.multihopExitMode ?? "choose exit") }
        if selectedMode == IOSUnifiedModeSelection.smart { return "SMART AUTO" }
        if selectedMode == IOSUnifiedModeSelection.auto { return "AUTO" }
        if let name = IOSCustomPresetName.suffix(in: selectedMode) { return "CUSTOM • " + name }
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
    private func controlSheet(height: CGFloat, stackControls: Bool) -> some View {
        VStack(spacing: 10) {
            Button { withAnimation(.spring()) { expanded.toggle() } } label: {
                Capsule().fill(.secondary.opacity(0.45)).frame(width: 44, height: 5)
                    .frame(maxWidth: .infinity, minHeight: 32).contentShape(Rectangle())
            }
                .buttonStyle(.plain)
                .accessibilityLabel(expanded ? "Collapse controls" : "Expand controls")
                .gesture(DragGesture(minimumDistance: 8).onEnded { value in withAnimation(.spring(response: 0.32, dampingFraction: 0.82)) { expanded = value.translation.height < 0 } })
            ScrollView {
                VStack(spacing: 10) {
                    let actions = stackControls ? AnyLayout(VStackLayout(spacing: 7)) : AnyLayout(HStackLayout(spacing: 7))
                    actions {
                        if canRankRouters || canRankExternal {
                            Menu {
                                if canRankRouters {
                                    Button { Task { await selectFastest() } } label: { Label(telemetry.isTestingFastest ? "Testing Router TCP…" : "Fastest Router · 50 TCP samples", systemImage: "bolt.fill") }
                                        .disabled(telemetry.isTestingFastest || model.profileMutationBlocked || externalComparison.running || externalBenchmark.running)
                                }
                                if canRankExternal {
                                    Button("Compare external paths · 50 HTTPS responses") { startExternalComparison(connectFastest: false) }
                                        .disabled(externalComparisonUnavailable)
                                    Button("Compare & connect fastest external · 50 HTTPS responses") { startExternalComparison(connectFastest: true) }
                                        .disabled(externalComparisonUnavailable)
                                }
                                Divider()
                                ForEach(linkedRouters) { profile in
                                    Button { selectSpecific(profile) } label: {
                                        let ms = telemetry.cached(profile.id) ?? profile.latencyMedianMs ?? 0
                                        Text(ms > 0 ? String(format: "%@ • %.1f ms", profile.name, ms) : profile.name)
                                    }.disabled(model.profileMutationBlocked || externalComparison.running || externalBenchmark.running)
                                }
                            } label: { Image(systemName: "bolt.fill").frame(minWidth: 28, minHeight: 32) }
                            .buttonStyle(.bordered).accessibilityLabel("Compare Router nodes by TCP or external paths by 50 routed HTTPS responses, or choose a Router node")
                        }
                        Toggle(isOn: Binding(get: { model.unifiedQuickKillSwitch }, set: { model.setUnifiedQuickKillSwitch($0) })) { Image(systemName: "lock.shield.fill") }
                            .toggleStyle(.button).buttonStyle(.bordered).accessibilityLabel("Kill switch")
                            .disabled(model.profileMutationBlocked)

                        Button { connectOrDisconnect() } label: { Text(connectionButtonTitle).font(.headline).frame(maxWidth: .infinity).padding(.vertical, 7) }
                            .buttonStyle(.borderedProminent).tint(model.connected ? .red : .accentColor)
                            .disabled(model.iosUserDisconnectInProgress)

                        if let ms = livePathMilliseconds, model.connected && !model.iosCandidateTesting { Text(String(format: "%.1f\nms %@", ms, livePathLabel)).font(.caption2.bold()).monospacedDigit().multilineTextAlignment(.center) }
                        IOSForwardingMasterButton().environmentObject(model)
                    }

                    unifiedRow(icon: "plus.circle.fill", title: "Add / manage nodes", value: "Router / Custom") { showingNodes = true }
                    unifiedRow(icon: "point.3.connected.trianglepath.dotted", title: "Multihop", value: iosMultihopSummary) { showingMultihop = true }
                    unifiedRow(icon: "person.crop.rectangle.stack", title: "Profiles & bridges", value: "Router / Custom / Tor") { showingNodes = true }
                    unifiedRow(icon: "slider.horizontal.3", title: "Settings", value: settingsSummary) { showingSettings = true }
                    unifiedRow(icon: "wand.and.stars", title: "Mode", value: selectedModeTitle, disabled: model.profileMutationBlocked || (selectedProfile?.multihopEnabled == true && selectedProfile?.multihopNodes != nil)) { showingModes = true }

                    HStack {
                        Label("DNS", systemImage: "network").font(.subheadline.bold())
                        Spacer()
                        Menu(dnsTitle) {
                            Button("Home AdGuard") { model.unifiedSetDNSMode("home") }.disabled(model.profileMutationBlocked)
                            Button("Fastest measured") { openDNS("fastest") }
                            Button("Rescue") { model.unifiedSetDNSMode("rescue") }.disabled(model.profileMutationBlocked)
                            Divider()
                            Button("Custom…") { openDNS("custom") }
                            Button("DoT…") { openDNS("dot") }
                            Button("DoH…") { openDNS("doh") }
                            Button("DoH3…") { openDNS("doh3") }
                                .disabled(["tor", "tor-bridge"].contains(model.selectedExternalProtocol))
                            Divider()
                            Button("DNS details / Retest…") { openDNS() }
                        }
                    }
                    .padding(11).background(.thinMaterial, in: RoundedRectangle(cornerRadius: 12))

                    if expanded {
                        IOSHomeSummaryView().environmentObject(model)
                        Button("Run setup guide again") { UserDefaults.standard.set(0, forKey: "RouterVPNProductOnboardingStepV2"); showingOnboarding = true }
                            .buttonStyle(.bordered)
                    }
                    if !model.multihopProgressText.isEmpty { Text(model.multihopProgressText).font(.caption).textSelection(.enabled) }
                    Text(model.message).font(.caption).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled)
                }.padding(.horizontal, 14).padding(.bottom, 14)
            }
        }
        .frame(height: height)
        .background(.ultraThickMaterial, in: UnevenRoundedRectangle(topLeadingRadius: 24, bottomLeadingRadius: 0, bottomTrailingRadius: 0, topTrailingRadius: 24))
        .shadow(radius: 12, y: -3)

    }

    private func openDNS(_ mode: String? = nil) {
        dnsEditorMode = mode
        showingDNS = true
    }

    private var iosMultihopSummary: String {
        if let ordered = model.iosVisibleOrderedNodePath {
            let route = ordered.map(\.name).joined(separator: " → ")
            guard model.connected, !model.iosCandidateTesting, let ms = livePathMilliseconds else { return route }
            return route + String(format: " • total %.1f ms (final node HTTP)", ms)
        }
        if selectedProfile?.multihopEnabled == true && selectedProfile?.multihopNodes != nil { return "Waiting for the complete ordered source" }
        if let p = selectedProfile, p.multihopEnabled == true, let entry = p.multihopEntryID, let exit = p.multihopExitID {
            // Direct node-cache RTT is not a routed per-hop measurement.
            var text = "\(entry) → \(exit)"
            if let path = livePathMilliseconds, model.connected && !model.iosCandidateTesting { text += String(format: " • %@ %.1f ms", livePathLabel, path) }
            return text
        }
        return "Choose native entry → encrypted exit"
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
            HStack {
                ViewThatFits(in: .horizontal) {
                    HStack {
                        Label(title, systemImage: icon).font(.subheadline.bold())
                        Spacer()
                        Text(value).font(.caption).foregroundStyle(.secondary)
                    }.fixedSize(horizontal: true, vertical: false)
                    VStack(alignment: .leading, spacing: 3) {
                        Label(title, systemImage: icon).font(.subheadline.bold())
                        Text(value).font(.caption).foregroundStyle(.secondary)
                    }
                }
                Spacer(minLength: 4)
                Image(systemName: "chevron.right").font(.caption).foregroundStyle(.tertiary)
            }
                .padding(11).background(.thinMaterial, in: RoundedRectangle(cornerRadius: 12))
        }.buttonStyle(.plain).disabled(disabled)
    }

    private func selectSpecific(_ profile: RouterProfile) {
        guard !model.profileMutationBlocked, !externalComparison.running, !externalBenchmark.running else { return }
        guard model.selectNode(profile.id) else { return }
        model.message = "Selected \(profile.name.isEmpty ? profile.id : profile.name). Press Connect when ready."
    }
    private var externalComparisonUnavailable: Bool {
        externalComparison.running || externalBenchmark.running || telemetry.measuring ||
            telemetry.isTestingFastest || !IOSExternalNodeComparison.available(model)
    }
    private func startExternalComparison(connectFastest: Bool) {
        guard !externalComparisonUnavailable else { return }
        externalComparison.start(model: model, connectFastest: connectFastest)
        showingPerformance = true
    }
    private func selectFastest() async {
        guard canRankRouters, !model.profileMutationBlocked, !externalComparison.running, !externalBenchmark.running else { return }
        showingPerformance = true
        let results = await telemetry.measureFastest(routerProfiles, model: model)
        guard !model.profileMutationBlocked, !externalComparison.running, !externalBenchmark.running else {
            model.message = "VPN state changed while Fastest was measuring; the result was not selected."
            return
        }
        guard let winner = results.first else { model.message = telemetry.lastError; return }
        do { try telemetry.requireDirectResultCurrent(model: model) }
        catch { model.message = "The selected source or network changed after Fastest measured; retest before selecting its result."; return }
        guard model.selectNode(winner.id) else { return }
        model.message = "Selected fastest Router: \(winner.name) • \(String(format: "%.1f", winner.trimmedMeanMs)) ms, 50 TCP samples, 10% trimmed mean. Press Connect when ready with \(selectedModeTitle)."
    }
    private func connectOrDisconnect() {
        if model.iosCandidateTesting { model.cancelCandidateTesting(); return }
        if model.tunnelTransitioning || model.connected { model.disconnect(); return }
        if !model.connected, selectedProfile?.multihopEnabled == true { Task { await model.connect() }; return }
        if model.connected { model.disconnect(); return }
        guard let profile = selectedProfile else { showingNodes = true; return }
        if profile.normalizedNodeKind == "external" { Task { await model.connectSelectedExternal(nodeID: profile.id) }; return }
        if selectedMode == IOSUnifiedModeSelection.smart { Task { await model.runUnifiedIOSSmartAuto() }; return }
        if selectedMode == IOSUnifiedModeSelection.auto { Task { await model.runUnifiedIOSAuto() }; return }
        if let name = IOSCustomPresetName.suffix(in: selectedMode) {
            guard let preset = try? IOSUnifiedPresetStore.selected(name) else {
                model.message = "The selected CUSTOM preset is unavailable. Restore it or choose another mode."
                showingModes = true; return
            }
            model.connectNamedCustom(preset); return
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
                    choice("SMART AUTO", subtitle: "Recommended • connect, simplify, prove, restore last good on failure", id: IOSUnifiedModeSelection.smart, available: true)
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
                            VStack(alignment: .leading, spacing: 4) { HStack { Text(preset.name).font(.headline); if selectedMode.utf8.elementsEqual((IOSUnifiedModeSelection.customPrefix + preset.name).utf8) { Image(systemName: "checkmark.circle.fill") } }; Text(preset.layers.joined(separator: " • ")).font(.caption).foregroundStyle(.secondary).lineLimit(2) }
                        }
                        .disabled(model.profileMutationBlocked)
                        .swipeActions { Button(role: .destructive) { deletePreset(preset) } label: { Label("Delete", systemImage: "trash") }.disabled(model.profileMutationBlocked) }
                        .contextMenu { Button("Edit") { guard !model.profileMutationBlocked else { return }; editingPreset = preset }.disabled(model.profileMutationBlocked); Button("Delete", role: .destructive) { deletePreset(preset) }.disabled(model.profileMutationBlocked) }
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

    private func deletePreset(_ preset: IOSUnifiedCustomPreset) {
        guard !model.profileMutationBlocked else { return }
        do { try IOSUnifiedPresetStore.delete(preset) }
        catch { model.message = error.localizedDescription; return }
        presets = IOSUnifiedPresetStore.load()
        if selectedMode.utf8.elementsEqual((IOSUnifiedModeSelection.customPrefix + preset.name).utf8) {
            selectedMode = IOSUnifiedModeSelection.smart
        }
    }

    private func choice(_ title: String, subtitle: String, id: String, available: Bool) -> some View {
        Button { guard available, !model.profileMutationBlocked else { return }; selectedMode = id; dismiss() } label: {
            HStack(alignment: .top) { VStack(alignment: .leading, spacing: 3) { Text(title).font(.headline); Text(subtitle).font(.caption).foregroundStyle(.secondary) }; Spacer(); if selectedMode == id { Image(systemName: "checkmark.circle.fill") } }
        }.disabled(!available || model.profileMutationBlocked)
    }
}

private enum IOSUnifiedPresetStore {
    static func read() throws -> [IOSUnifiedCustomPreset] {
        guard let data = UserDefaults.standard.data(forKey: iosUnifiedPresetsKey) else { return [] }
        return try JSONDecoder().decode([IOSUnifiedCustomPreset].self, from: data)
    }
    static func load() -> [IOSUnifiedCustomPreset] {
        ((try? read()) ?? []).sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }
    static func selected(_ name: String) throws -> IOSUnifiedCustomPreset? {
        let values = try read()
        return try IOSCustomPresetName.index(of: name, in: values.map(\.name)).map { values[$0] }
    }
    static func save(_ preset: IOSUnifiedCustomPreset, replacing original: IOSUnifiedCustomPreset? = nil) throws {
        var values = try read()
        let names = values.map(\.name)
        if let original {
            guard let i = try IOSCustomPresetName.index(of: original.name, in: names), values[i].layers == original.layers
            else { throw IOSCustomPresetName.issue("This CUSTOM preset changed. Reopen it before saving.") }
            if !preset.name.utf8.elementsEqual(original.name.utf8) { try IOSCustomPresetName.requireFreeName(preset.name, in: names, excluding: i) }
            values[i] = preset
        } else {
            try IOSCustomPresetName.requireFreeName(preset.name, in: names)
            values.append(preset)
        }
        UserDefaults.standard.set(try JSONEncoder().encode(values), forKey: iosUnifiedPresetsKey)
    }
    static func delete(_ original: IOSUnifiedCustomPreset) throws {
        var values = try read()
        guard let i = try IOSCustomPresetName.index(of: original.name, in: values.map(\.name)), values[i].layers == original.layers
        else { throw IOSCustomPresetName.issue("This CUSTOM preset changed. Reopen it before deleting.") }
        values.remove(at: i)
        UserDefaults.standard.set(try JSONEncoder().encode(values), forKey: iosUnifiedPresetsKey)
    }
}

private struct IOSUnifiedCustomBuilder: View {
    @EnvironmentObject var model: RouterVPNModel
    @Environment(\.dismiss) private var dismiss
    @State private var name: String
    @State private var selected: Set<String>
    @State private var saveError = ""
    private let original: IOSUnifiedCustomPreset?

    init(editing: IOSUnifiedCustomPreset? = nil) {
        _name = State(initialValue: editing?.name ?? "")
        _selected = State(initialValue: Set(editing?.layers ?? []))
        original = editing
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
                    if !saveError.isEmpty { Text(saveError).font(.caption).foregroundStyle(.orange) }
                    if model.profileMutationBlocked { Text("Disconnect or let the active VPN transition finish before saving a CUSTOM preset.").font(.caption).foregroundStyle(.secondary) }
                }
            }
            .navigationTitle("CUSTOM builder")
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } } }
        }
    }
    private var valid: Bool { !selected.isEmpty && IOSCustomPresetName.normalized(name) != nil }
    private func save(connect: Bool) {
        guard !model.profileMutationBlocked else { model.message = "Disconnect or let the active VPN transition finish before saving a CUSTOM preset."; return }
        guard !selected.isEmpty, let displayName = IOSCustomPresetName.normalized(name) else { return }
        let preset = IOSUnifiedCustomPreset(name: displayName, layers: Array(selected).sorted())
        do { try IOSUnifiedPresetStore.save(preset, replacing: original) }
        catch { saveError = error.localizedDescription; return }
        UserDefaults.standard.set(IOSUnifiedModeSelection.customPrefix + preset.name, forKey: iosUnifiedModeKey)
        if connect { model.connectNamedCustom(preset) }
        dismiss()
    }
}

private struct IOSUnifiedSettingsView: View {
    @EnvironmentObject var model: RouterVPNModel
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var telemetry: IOSUnifiedTelemetry
    @State private var showingAdvanced = false
    @State private var showingPerformance = false
    @State private var showingProfiles = false
    @State private var showingDNS = false
    @State private var requireEncrypted = false
    @State private var requireObfuscation = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Secure transport") {
                    LabeledContent("Selected transport", value: IOSUnifiedSecureTransport.protectionLabel(protocolName: model.selectedNodeIsExternal ? model.selectedExternalProtocol : "router-vpn"))
                    Text("WireGuard, AmneziaWG, OpenVPN, Shadowsocks and Hysteria2 provide authenticated encryption. Tor uses encrypted relay circuits and verifies its dynamic exit. Plain SOCKS5 and HTTP CONNECT do not encrypt traffic. AES+XOR whitening adds obfuscation to authenticated AES; XOR alone is not encryption.").font(.caption).foregroundStyle(.secondary)
                    LabeledContent("Available bridges", value: "SOCKS5 • HTTP(S) • Shadowsocks • Tor")
                }
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
                    LabeledContent("Live path", value: telemetry.currentMilliseconds(model: model).map { String(format: "%.1f ms", $0) } ?? "Not connected")
                    if let speed = telemetry.lastSpeedResult {
                        LabeledContent("Last real path speed", value: String(format: "↓ %.1f • ↑ %.1f Mbps", speed.downloadMbps, speed.uploadMbps))
                    }
                    Button("Latency / speed / node benchmarks…") { showingPerformance = true }
                    if let p = model.unifiedSelectedProfile, let mbps = p.effectiveMTUMbps, mbps > 0 {
                        LabeledContent("Last Auto-MTU path throughput", value: String(format: "%.1f Mbps", mbps))
                    }
                }
                Section("Connection Profiles") {
                    Button("Add / Load / Update / Delete…") { showingProfiles = true }
                        .disabled(model.profileMutationBlocked)
                    Text("Profiles save the selected node and supported non-secret Mode/CUSTOM, DNS, kill-switch, IPv6, LAN, base/fallback, AUTO-requirement, MTU and startup choices. Private keys, tokens and external credentials remain only in the linked node store.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section("Platform truth") {
                    Text("Padding and Jumbo settings apply to compatible native paths. Multihop preserves each selected node and layer; external and Tor exits use their own DNS and exit proofs. Incoming forwarding requires a routable Router VPN path and the authenticated node's forwarding API.").font(.caption).foregroundStyle(.secondary)
                    Button("DNS details / Retest…") { showingDNS = true }
                }
                Section { Button("Done") { saveRequirements(); dismiss() } }
            }
            .navigationTitle("Settings")
            .onAppear { requireEncrypted = model.unifiedRequirement("encrypted"); requireObfuscation = model.unifiedRequirement("obfuscation") }
            .onChange(of: requireEncrypted) { value in model.setUnifiedRequirement("encrypted", enabled: value) }
            .onChange(of: requireObfuscation) { value in model.setUnifiedRequirement("obfuscation", enabled: value) }
            .sheet(isPresented: $showingAdvanced) { IOSProfileSettingsView().environmentObject(model) }
            .sheet(isPresented: $showingPerformance) { IOSUnifiedPerformanceView(telemetry: telemetry).environmentObject(model) }
            .sheet(isPresented: $showingProfiles) { IOSConnectionProfilesView().environmentObject(model) }
            .sheet(isPresented: $showingDNS) { IOSDNSPolicyView().environmentObject(model) }
        }
    }
    private func saveRequirements() { guard !model.profileMutationBlocked else { return }; model.setUnifiedRequirement("encrypted", enabled: requireEncrypted); model.setUnifiedRequirement("obfuscation", enabled: requireObfuscation) }
}

private struct IOSUnifiedPerformanceView: View {
    @EnvironmentObject var model: RouterVPNModel
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var telemetry: IOSUnifiedTelemetry
    @ObservedObject private var externalBenchmark = IOSExternalNodeBenchmark.shared
    @ObservedObject private var externalComparison = IOSExternalNodeComparison.shared
    @ObservedObject private var externalLive = IOSExternalLiveTelemetry.shared
    @State private var output = "Choose a real measurement."
    @State private var canRankExternal = false
    @State private var busy = false
    @State private var operation: Task<Void, Never>?
    private var selectedExternalHistoryKey: String? { try? IOSExternalNodeStatistics.selectedKey(model) }

    var body: some View {
        NavigationStack {
            Form {
                Section("Current path") {
                    if model.unifiedSelectedProfile?.normalizedNodeKind == "external" {
                        LabeledContent("External path HTTPS response", value: externalLive.currentMilliseconds(model: model).map { String(format: "%.1f ms", $0) } ?? "No current measurement")
                        Button("Measure live external HTTPS response") { runExternalLive() }
                            .disabled(!IOSExternalLiveTelemetry.supported(model) || busy || externalLive.running || telemetry.measuring || externalBenchmark.running || externalComparison.running || model.iosSpeedLabOwnership.active || IOSMTUMeasurementGate.held)
                        Text("Median of three HTTPS responses from the Cloudflare speed endpoint through this proved external path and its selected DNS. Timing starts after DNS, TCP and TLS preparation. These live values expire and do not replace saved 50-sample statistics or direct TCP rankings.").font(.caption).foregroundStyle(.secondary)
                    } else {
                        LabeledContent("Private node response", value: telemetry.currentMilliseconds(model: model).map { String(format: "%.1f ms", $0) } ?? "No current measurement")
                        Button("Measure private node response") { runLive() }.disabled(!model.connected || busy || telemetry.measuring || externalBenchmark.running || externalComparison.running)
                    }
                    Button(telemetry.isSpeedTesting ? "Testing real VPN path speed…" : "Run real current VPN path speed") { runSpeed() }
                        .disabled(!model.connected || model.unifiedSelectedProfile?.normalizedNodeKind != "router-vpn" || busy || telemetry.measuring || externalBenchmark.running || externalComparison.running)
                    if let speed = telemetry.lastSpeedResult {
                        Text(speed.detail).font(.caption.monospaced()).textSelection(.enabled)
                    }
                    Text("Real speed transfers 8 MiB down and 8 MiB up through the captured PacketTunnel after its private Router VPN node proves its identity. Auto MTU is held until native sockets finish cleanup. Response time includes a new TCP connection and the complete private health response.").font(.caption).foregroundStyle(.secondary)
                }
                Section("Nodes") {
                    if model.unifiedSelectedProfile?.normalizedNodeKind == "external" {
                        Button(externalBenchmark.running ? "Cancel 50 routed responses" : "50-sample selected external path") {
                            if externalBenchmark.running { externalBenchmark.cancel() }
                            else { externalBenchmark.start(model: model) }
                        }.disabled(!externalBenchmark.running && (!IOSExternalNodeBenchmark.supported(model) || busy || telemetry.measuring || model.iosSpeedLabOwnership.active || IOSMTUMeasurementGate.held))
                        Text("Connect this external node to measure 50 HTTPS responses through its captured route and selected DNS. Each sample downloads one byte from the labelled Cloudflare speed endpoint. Timings start after DNS, TCP and TLS preparation; they are separate from direct TCP latency, ICMP RTT and throughput.").font(.caption).foregroundStyle(.secondary)
                        if !externalBenchmark.history(for: selectedExternalHistoryKey).isEmpty {
                            Text(externalBenchmark.history(for: selectedExternalHistoryKey)).font(.caption.monospacedDigit()).textSelection(.enabled)
                        }
                        if !externalBenchmark.progress.isEmpty { Text(externalBenchmark.progress).font(.caption).textSelection(.enabled) }
                    } else {
                        Button("50-sample selected node") { runSelected() }.disabled(model.unifiedSelectedProfile == nil || model.profileMutationBlocked || busy || telemetry.measuring || externalBenchmark.running || externalComparison.running)
                    }
                    Button("Compare linked Router nodes (50 TCP)") { runAll() }.disabled(model.profileMutationBlocked || busy || telemetry.measuring || externalBenchmark.running || externalComparison.running)
                    Text("Disconnect for direct Router node TCP measurements. A complete 50-sample test atomically saves min, median, average, 10% trimmed mean, p90, max, sample count and test time to that exact node. Router comparison also requires 50 complete samples per node and ranks by the 10% trimmed mean. It does not replace saved statistics or rank external paths.").font(.caption).foregroundStyle(.secondary)
                }
                Section("Compare external paths") {
                    Button("Compare all external nodes") { externalComparison.start(model: model, connectFastest: false) }
                        .disabled(externalComparison.running || busy || telemetry.measuring || externalBenchmark.running || !IOSExternalNodeComparison.available(model))
                    if canRankExternal {
                        Button("Compare & connect fastest external") { externalComparison.start(model: model, connectFastest: true) }
                            .disabled(externalComparison.running || busy || telemetry.measuring || externalBenchmark.running || !IOSExternalNodeComparison.available(model))
                    }
                    Text("Each saved external path uses its own saved entry, DNS and device policy. It connects temporarily and makes 50 HTTPS responses to the same Cloudflare endpoint. The lowest 10% trimmed mean wins; incomplete paths receive no score. Your original connection is restored between trials. Compare & connect re-proves the winner using its measured Local or Server execution.").font(.caption).foregroundStyle(.secondary)
                    if externalComparison.running { Button("Cancel external comparison") { externalComparison.cancel() } }
                    if !externalComparison.progress.isEmpty { Text(externalComparison.progress).font(.caption).textSelection(.enabled) }
                    if !externalComparison.error.isEmpty { Text(externalComparison.error).font(.caption).foregroundStyle(.orange).textSelection(.enabled) }
                    ForEach(externalComparison.rows) { row in Text(row.detail).font(.caption.monospacedDigit()).textSelection(.enabled) }
                }
                Section("Auto MTU") {
                    if let p = model.unifiedSelectedProfile, let mbps = p.effectiveMTUMbps, mbps > 0 {
                        Text(String(format: "Last Auto-MTU optimizer result: %.1f Mbps • MTU %d • RTT %.1f ms", mbps, p.effectiveMTU ?? 0, p.effectiveMTUMedianRTTMs ?? 0))
                    } else { Text("No proven Auto-MTU optimizer result is stored for this path yet.").foregroundStyle(.secondary) }
                    Text("Auto-MTU throughput and the real 8 MiB down/up speed test are separate measurements. Hop-specific Mbps is shown only when that hop's private benchmark is actually reachable; Router VPN never derives it from latency arithmetic.").font(.caption).foregroundStyle(.secondary)
                }
                if telemetry.measuring {
                    Section(telemetry.cleanupPending ? "Cleanup pending" : "Measurement") {
                        Text(telemetry.progress).font(.caption).textSelection(.enabled)
                        Button("Cancel measurement") { cancelMeasurement() }
                    }
                }
                Section("Result") { Text(output).font(.caption.monospaced()).textSelection(.enabled) }
            }
            .task(id: IOSNodeBundleStore.shared.revision) { canRankExternal = IOSExternalNodeComparison.hasMultipleEligible(model) }
            .navigationTitle("Performance")
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { cancelMeasurement(); dismiss() } } }
            .onAppear { telemetry.showPerformance(true); telemetry.invalidateResults(model: model); externalLive.showPerformance(true); externalLive.invalidate(model: model); externalBenchmark.refreshSaved(model: model) }
            .onDisappear { cancelMeasurement(); telemetry.showPerformance(false); externalLive.showPerformance(false) }
            .onChange(of: model.connected) { _ in telemetry.invalidateResults(model: model); externalLive.cancel(); externalLive.invalidate(model: model); externalBenchmark.cancel(); externalBenchmark.refreshSaved(model: model) }
            .onChange(of: model.activeSessionIdentity) { _ in externalLive.cancel(); externalLive.invalidate(model: model); externalBenchmark.cancel(); externalBenchmark.refreshSaved(model: model) }
            .onChange(of: selectedExternalHistoryKey) { _ in externalLive.cancel(); externalLive.invalidate(model: model); externalBenchmark.cancel(); externalBenchmark.refreshSaved(model: model) }
        }
    }
    private func cancelMeasurement() { operation?.cancel(); telemetry.cancel(); externalLive.cancel(); externalBenchmark.cancel(); externalComparison.cancel() }
    private func runExternalLive() { busy = true; operation = Task { do { output = String(format: "Current external path HTTPS response: %.1f ms (three samples).", try await externalLive.measure(model: model)) } catch { output = error.localizedDescription }; busy = false } }
    private func runLive() { busy = true; operation = Task { do { output = String(format: "Current private tunnel median response time: %.1f ms", try await telemetry.measureCurrentRTT(model: model)) } catch { output = error.localizedDescription }; busy = false } }
    private func runSpeed() { busy = true; operation = Task { do { output = try await telemetry.speedTest(model: model).detail } catch { output = error.localizedDescription }; busy = false } }
    private func runSelected() { guard let p = model.unifiedSelectedProfile else { return }; busy = true; operation = Task { do { output = try await telemetry.measureOne(p, model: model, samples: 50).detail + "\nSaved to this node." } catch { output = error.localizedDescription }; busy = false } }
    private func runAll() {
        busy = true
        operation = Task {
            defer { busy = false }
            let values = await telemetry.measureFastest(model.allNodeProfiles, model: model)
            guard !values.isEmpty else { output = telemetry.lastError; return }
            do {
                try telemetry.requireDirectResultCurrent(model: model)
                output = "50 complete TCP responses per ranked Router node; ordered by 10% trimmed mean. Selection and saved statistics are unchanged.\n\n" + values.map(\.detail).joined(separator: "\n")
            } catch { output = error.localizedDescription }
        }
    }
}

private let iosUnifiedUXContract = "map-first swipe-up Connect Disconnect fastest-node live RTT real path Mbps quick kill switch forwarding shortcut Multihop Settings Performance Mode DNS SMART AUTO default AUTO all presets CUSTOM builder saved delete Router node Custom external color-coded hops real coordinates node ms animated packet path IPv6 On Auto MTU Require encrypted Require obfuscation schema-v4 profile-shared requirements Connection Profiles Add Load Update Delete real opt-in user location"
