import SwiftUI

struct IOSSpeedLabView: View {
    @EnvironmentObject private var model: RouterVPNModel
    @Environment(\.dismiss) private var dismiss
    @StateObject private var runner = IOSSpeedLabRunner()

    @State private var scope = IOSSpeedLabRunRequest.Scope.current
    @State private var topology = IOSSpeedLabRunRequest.Topology.systemDirect
    @State private var nodeID = ""
    @State private var mode = "smart-auto"
    @State private var customLayers: Set<String> = []
    @State private var requireEncrypted = false
    @State private var requireObfuscation = false
    @State private var durationMode = IOSSpeedLabDuration.Mode.auto
    @State private var minSeconds = 4.0
    @State private var maxSeconds = 12.0

    private var routerNodes: [RouterProfile] { model.allNodeProfiles.filter { $0.normalizedNodeKind == "router-vpn" } }
    private var externalNodes: [RouterProfile] { model.allNodeProfiles.filter { $0.normalizedNodeKind == "external" } }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    hero
                    pathCard
                    durationCard
                    if let result = runner.lastResult { resultCards(result) }
                    if !runner.lastError.isEmpty { errorCard }
                    runCard
                }
                .padding(16)
            }
            .background(Color(uiColor: .systemGroupedBackground))
            .navigationTitle("Speed Lab")
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
        }
        .onAppear { initializeSelection() }
        .onChange(of: topology) { _ in initializeNodeForTopology() }
        .onChange(of: nodeID) { _ in loadAutoRequirementsFromNode() }
        .onChange(of: minSeconds) { value in if maxSeconds < value { maxSeconds = value } }
        .onChange(of: maxSeconds) { value in if minSeconds > value { minSeconds = value } }
    }

    private var hero: some View {
        VStack(spacing: 8) {
            Image(systemName: "speedometer")
                .font(.system(size: 40, weight: .semibold))
                .foregroundStyle(.blue)
            Text("Router VPN Speed Lab")
                .font(.title2.bold())
            Text("Real Internet throughput plus idle, download-loaded and upload-loaded latency through the path you choose.")
                .font(.subheadline)
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
            if let result = runner.lastResult {
                Text(result.measurement.compactSummary)
                    .font(.headline.monospacedDigit())
                    .multilineTextAlignment(.center)
                    .padding(.top, 4)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(18)
        .background(.background, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
    }

    private var pathCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Test path", systemImage: "point.3.connected.trianglepath.dotted")
                .font(.headline)
            Picker("Scope", selection: $scope) {
                Text("Current config").tag(IOSSpeedLabRunRequest.Scope.current)
                Text("Temporary config").tag(IOSSpeedLabRunRequest.Scope.temporary)
            }
            .pickerStyle(.segmented)

            if scope == .current {
                LabeledContent("Path", value: currentPathLabel)
                Text(model.connected ? "The test stays on the currently proven PacketTunnel. If the tunnel/node/runtime changes during the test, the result is discarded." : "Router VPN is disconnected, so Current config measures the raw system Internet path.")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                Picker("Topology", selection: $topology) {
                    Text("System direct").tag(IOSSpeedLabRunRequest.Topology.systemDirect)
                    Text("Router node").tag(IOSSpeedLabRunRequest.Topology.router)
                    Text("External direct").tag(IOSSpeedLabRunRequest.Topology.external)
                    Text("Multihop — unavailable on iOS").tag(IOSSpeedLabRunRequest.Topology.multihop)
                }

                if topology == .router {
                    nodePicker(nodes: routerNodes, title: "Router node")
                    Picker("Mode", selection: $mode) {
                        Text("SMART AUTO").tag("smart-auto")
                        Text("AUTO").tag("auto")
                        Text("CUSTOM").tag("custom")
                        ForEach(model.iosRunnableLogicalModes) { logical in
                            Text(logical.name).tag(logical.id)
                        }
                    }
                    if mode == "smart-auto" || mode == "auto" {
                        Toggle("Require encrypted AUTO candidates", isOn: $requireEncrypted)
                        Toggle("Require obfuscation for AUTO candidates", isOn: $requireObfuscation)
                        Text("These are temporary Speed Lab filters only. They do not change the saved node profile.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    if mode == "custom" { customLayerPicker }
                } else if topology == .external {
                    nodePicker(nodes: externalNodes, title: "External exit")
                    if let selected = externalNodes.first(where: { $0.id == nodeID }) {
                        LabeledContent("Transport", value: selected.external?.protocolName ?? "Unknown")
                        Text(model.nodeRuntimeSummary(selected)).font(.caption).foregroundStyle(.secondary)
                    }
                } else if topology == .multihop {
                    Text("Desktop-style multihop is intentionally unavailable on iOS/iPadOS until an Apple PacketTunnel multihop dataplane can enforce and prove the whole chain. Speed Lab will not fake it.")
                        .font(.caption).foregroundStyle(.orange)
                }

                Text("Temporary tests require Router VPN to be disconnected. The chosen path is proven, measured, torn fully down, and your previous node/mode selection is restored afterward. A recovery journal restores the original saved state after an interrupted test.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .cardStyle()
    }

    private func nodePicker(nodes: [RouterProfile], title: String) -> some View {
        Picker(title, selection: $nodeID) {
            if nodes.isEmpty { Text("No compatible nodes").tag("") }
            ForEach(nodes, id: \.id) { node in
                Text(node.name.isEmpty ? node.id : node.name).tag(node.id)
            }
        }
    }

    private var customLayerPicker: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("CUSTOM required layers").font(.subheadline.bold())
            let layers = model.iosAvailableCustomLayers()
            if layers.isEmpty { Text("No iOS-runnable CUSTOM layers are available on this node.").font(.caption).foregroundStyle(.secondary) }
            ForEach(layers, id: \.self) { layer in
                Toggle(layer, isOn: Binding(
                    get: { customLayers.contains(layer) },
                    set: { enabled in if enabled { customLayers.insert(layer) } else { customLayers.remove(layer) } }
                ))
            }
        }
        .padding(.top, 4)
    }

    private var durationCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Test time", systemImage: "timer")
                .font(.headline)
            Picker("Timing", selection: $durationMode) {
                Text("Auto / default").tag(IOSSpeedLabDuration.Mode.auto)
                Text("Custom").tag(IOSSpeedLabDuration.Mode.custom)
            }
            .pickerStyle(.segmented)
            if durationMode == .auto {
                LabeledContent("Automatic range", value: "4–12 seconds / direction")
                Text("Speed Lab stops after the minimum once the last three throughput rounds stabilize within 4%, otherwise it continues to the maximum.")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                timeSlider(title: "Minimum", value: $minSeconds, range: 1...60)
                timeSlider(title: "Maximum", value: $maxSeconds, range: 1...60)
                Text("Custom range: \(Int(minSeconds))–\(Int(maxSeconds)) seconds per direction. Max can never be lower than Min.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .cardStyle()
    }

    private func timeSlider(title: String, value: Binding<Double>, range: ClosedRange<Double>) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack { Text(title); Spacer(); Text("\(Int(value.wrappedValue)) s").monospacedDigit().foregroundStyle(.secondary) }
            Slider(value: value, in: range, step: 1)
        }
    }

    @ViewBuilder
    private func resultCards(_ result: IOSSpeedLabRunResult) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(result.temporary ? "Temporary path result" : "Current path result", systemImage: "checkmark.seal.fill")
                .font(.headline).foregroundStyle(.green)
            Text(result.path).font(.caption).foregroundStyle(.secondary)
        }
        .cardStyle()

        HStack(spacing: 12) {
            metricCard(title: "Idle", value: String(format: "%.1f", result.measurement.idle.medianMs), unit: "ms", subtitle: String(format: "jitter %.1f", result.measurement.idle.jitterMs), tint: .blue)
            metricCard(title: "Download", value: String(format: "%.1f", result.measurement.download.mbps), unit: "Mbps", subtitle: String(format: "loaded %.1f ms", result.measurement.download.loadedLatency.medianMs), tint: .green)
        }
        HStack(spacing: 12) {
            metricCard(title: "Upload", value: String(format: "%.1f", result.measurement.upload.mbps), unit: "Mbps", subtitle: String(format: "loaded %.1f ms", result.measurement.upload.loadedLatency.medianMs), tint: .purple)
            metricCard(title: "Loaded Δ", value: String(format: "%.1f / %.1f", result.measurement.download.bufferbloatMs, result.measurement.upload.bufferbloatMs), unit: "ms", subtitle: "down / up", tint: .orange)
        }

        VStack(alignment: .leading, spacing: 8) {
            Text("Detailed latency").font(.headline)
            latencyRow("Idle", result.measurement.idle)
            latencyRow("Download loaded", result.measurement.download.loadedLatency)
            latencyRow("Upload loaded", result.measurement.upload.loadedLatency)
            Text(result.measurement.detailedSummary).font(.caption.monospaced()).textSelection(.enabled)
        }
        .cardStyle()
    }

    private func metricCard(title: String, value: String, unit: String, subtitle: String, tint: Color) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title).font(.caption.bold()).foregroundStyle(.secondary)
            Text(value).font(.title2.bold().monospacedDigit()).lineLimit(1).minimumScaleFactor(0.65)
            Text(unit).font(.caption).foregroundStyle(tint)
            Text(subtitle).font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14)
        .background(tint.opacity(0.09), in: RoundedRectangle(cornerRadius: 16, style: .continuous))
    }

    private func latencyRow(_ title: String, _ stats: IOSSpeedLabLatencyStats) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack { Text(title).font(.subheadline.bold()); Spacer(); Text(String(format: "%.1f ms", stats.medianMs)).monospacedDigit() }
            Text(String(format: "min %.1f • avg %.1f • p90 %.1f • max %.1f • jitter %.1f • %d samples", stats.minMs, stats.averageMs, stats.p90Ms, stats.maxMs, stats.jitterMs, stats.samples))
                .font(.caption2.monospaced()).foregroundStyle(.secondary)
        }
    }

    private var runCard: some View {
        VStack(spacing: 10) {
            if runner.running { ProgressView().controlSize(.large) }
            Button {
                Task { await runner.run(buildRequest(), model: model) }
            } label: {
                Label(runner.running ? runner.progress : "Run Speed Lab", systemImage: "bolt.horizontal.circle.fill")
                    .font(.headline).frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(runDisabled)
            Text(runner.running ? runner.progress : "Uses real public test transfers. Mbps is never derived from RTT; loaded latency is sampled concurrently with each direction's traffic.")
                .font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center)
        }
        .cardStyle()
    }

    private var errorCard: some View {
        Text(runner.lastError)
            .font(.caption)
            .foregroundStyle(.red)
            .frame(maxWidth: .infinity, alignment: .leading)
            .cardStyle()
    }

    private var currentPathLabel: String {
        if !model.connected { return "System direct" }
        let name = model.selectedNodeProfile?.name ?? "VPN"
        return "\(name) • \(model.selectedLogicalMode)"
    }

    private var runDisabled: Bool {
        if runner.running { return true }
        if durationMode == .custom && (minSeconds < 1 || maxSeconds > 60 || maxSeconds < minSeconds) { return true }
        if scope == .temporary {
            if model.connected || model.tunnelTransitioning || topology == .multihop { return true }
            if topology == .router && (nodeID.isEmpty || (mode == "custom" && customLayers.isEmpty)) { return true }
            if topology == .external && nodeID.isEmpty { return true }
        }
        return false
    }

    private func buildRequest() -> IOSSpeedLabRunRequest {
        let duration = (try? IOSSpeedLabDuration.normalized(mode: durationMode, minSeconds: minSeconds, maxSeconds: maxSeconds)) ?? .automatic
        return IOSSpeedLabRunRequest(
            scope: scope,
            topology: topology,
            nodeID: nodeID,
            mode: mode,
            customLayers: Array(customLayers).sorted(),
            requireEncrypted: requireEncrypted,
            requireObfuscation: requireObfuscation,
            duration: duration
        )
    }

    private func initializeSelection() {
        if nodeID.isEmpty { nodeID = model.selectedNodeProfile?.id ?? routerNodes.first?.id ?? externalNodes.first?.id ?? "" }
        loadAutoRequirementsFromNode()
    }

    private func initializeNodeForTopology() {
        switch topology {
        case .router: nodeID = routerNodes.first?.id ?? ""
        case .external: nodeID = externalNodes.first?.id ?? ""
        default: break
        }
        loadAutoRequirementsFromNode()
    }

    private func loadAutoRequirementsFromNode() {
        guard topology == .router, let profile = routerNodes.first(where: { $0.id == nodeID }) else {
            requireEncrypted = false
            requireObfuscation = false
            return
        }
        requireEncrypted = profile.autoRequireEncrypted ?? false
        requireObfuscation = profile.autoRequireObfuscation ?? false
    }
}

private extension View {
    func cardStyle() -> some View {
        self
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.background, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
    }
}
