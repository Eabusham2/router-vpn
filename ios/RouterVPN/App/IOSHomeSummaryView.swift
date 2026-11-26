import Foundation
@preconcurrency import NetworkExtension
import SwiftUI

struct IOSHomeSummaryView: View {
    @EnvironmentObject var model: RouterVPNModel
    @State private var actualExitIP: String?
    @State private var exitOwner: IOSExternalComparisonSelection?
    @State private var exitNetwork: UInt64?
    @State private var exitNodeRevision: UInt64 = 0
    @State private var exitRequest: UUID?
    @State private var exitError = ""
    @State private var showingSettings = false

    private var profile: RouterProfile? {
        guard let bundle = model.bundle else { return nil }
        return bundle.routerProfiles.first(where: { $0.id == bundle.selectedRouterID }) ?? bundle.routerProfiles.first
    }

    private var dnsMeasuredRTT: Double? {
        guard let p = profile else { return nil }
        let host = (p.dnsHost ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        if !host.isEmpty,
           let result = p.dnsResults?.first(where: { $0.working && $0.address == host }),
           let value = result.latencyMs {
            return value
        }
        if let value = p.fastestDNSLatencyMs, value > 0 { return value }
        return nil
    }

    private var actualBase: String {
        if !model.connected { return profile?.baseTunnel ?? model.basePreference }
        if model.activeEngine.lowercased().contains("wireguard") { return "wg / WireGuardKit" }
        if model.activeEngine.lowercased().contains("libbox") { return "libbox / raw profile \(model.activeRawProfile)" }
        return model.activeEngine.isEmpty ? "unproven" : model.activeEngine
    }

    private var fallbackText: String {
        guard profile?.baseFallback == true else { return "None configured" }
        return model.connected ? "Fallback allowed; actual engine/base shown above" : "Fallback allowed; no active runtime"
    }

    private var killSwitchText: String {
        if profile?.killSwitch == true { return "strict" }
        let value = (profile?.killSwitchPolicy ?? "off").trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty ? "off" : value
    }

    private var mtuText: String {
        guard let p = profile else { return "Default / not measured" }
        if let value = p.effectiveMTU, value > 0 { return "\(value) • \(p.effectiveMTUSource ?? "measured")" }
        if let value = p.manualMTU, value > 0 { return "manual \(value)" }
        return p.mtuPolicy ?? "default"
    }

    private var warnings: [String] {
        var values: [String] = []
        if let p = profile, (p.dnsMode ?? "").isEmpty == false {
            values.append("DNS RTT shown here is a home-node query measurement; active PacketTunnel DNS still needs runtime/device proof")
        }
        if profile?.baseFallback == true {
            values.append("Base fallback is enabled; actual engine/base is authoritative")
        }
        if !model.message.isEmpty && !model.message.lowercased().contains("connected") {
            values.append(model.message)
        }
        return values
    }

    private var locationText: String {
        guard let value = profile?.location, !value.isEmpty else { return "Location not labeled" }
        return value
    }

    private var actualExitText: String {
        if model.iosCandidateTesting { return "Testing temporary path" }
        if let actualExitIP, let exitOwner, exitIsCurrent(exitOwner) { return actualExitIP }
        return model.connected ? "Not checked for this connection" : "Not connected"
    }

    private var rawProfileText: String {
        model.activeRawProfile.isEmpty ? "—" : model.activeRawProfile
    }

    private var dnsText: String {
        let mode = profile?.dnsMode ?? "home"
        let host = profile?.dnsHost ?? profile?.adGuardIPv4 ?? "—"
        let rtt = dnsMeasuredRTT.map { String(format: " • home query RTT %.2f ms", $0) } ?? " • query RTT not measured"
        return "DNS: \(mode) • \(host)\(rtt)"
    }

    private var nodeLatencyText: String {
        guard let p = profile, (p.latencySamples ?? 0) > 0 else { return "Node latency: Not measured" }
        return String(format: "Node latency: %.2f ms / %d samples", p.latencyMedianMs ?? 0, p.latencySamples ?? 0)
    }

    private var warningsText: String {
        warnings.isEmpty ? "None" : warnings.joined(separator: " | ")
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            statusHeader
            summaryLines
            warningLines
            actionControls
        }
        .font(.caption)
        .padding(12)
        .frame(maxWidth: 760, alignment: .leading)
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 14))
        .sheet(isPresented: $showingSettings) {
            IOSProfileSettingsView().environmentObject(model)
        }
        .task(id: exitRequest) { [request = exitRequest] in
            if let request { await checkPublicIP(request) }
        }
        .onChange(of: model.activeSessionIdentity) { identity in
            if let owner = exitOwner, let identity, identity != owner.identity { clearExitObservation() }
        }
        .onChange(of: model.iosConnectGeneration) { _ in clearExitObservation() }
        .onChange(of: IOSNodeBundleStore.shared.revision) { _ in clearExitObservation() }
        .onChange(of: model.iosCandidateTesting) { _ in clearExitObservation() }
        .onReceive(NotificationCenter.default.publisher(for: .NEVPNStatusDidChange)) { _ in clearExitObservation() }
        .onReceive(NotificationCenter.default.publisher(for: IOSViaEntryNetwork.didChange).receive(on: DispatchQueue.main)) { _ in
            if let exitNetwork, exitNetwork != IOSViaEntryNetwork.shared.current { clearExitObservation() }
        }
        .onDisappear { clearExitObservation() }
    }

    private var statusHeader: some View {
        HStack {
            Text("Home / Connect state").font(.headline)
            Spacer()
            if model.iosCandidateTesting {
                Text("Testing").font(.caption.bold()).foregroundStyle(.secondary)
            } else if model.connected {
                Text("Connected").font(.caption.bold()).foregroundStyle(.green)
            } else {
                Text("Off").font(.caption.bold()).foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder private var summaryLines: some View {
        Text("Node: \(profile?.name ?? model.routerName) • \(locationText)")
        Text("Public endpoint: \(profile?.endpoint ?? model.endpoint)")
        Text("Public IP reported by ipify: \(actualExitText)")
        Text("Phase/path proof: \(model.iosCandidateTesting ? "Testing" : model.connected ? "connected • selected-node proof passed" : "off / not proven")")
        Text("Logical/runtime/base: \(model.selectedLogicalMode) • \(rawProfileText) • \(actualBase)")
        Text("Fallback: \(fallbackText)")
        Text(dnsText)
        Text(nodeLatencyText)
        Text("LAN access: \((profile?.homeLANAccess ?? model.homeLANAccess) ? "On" : "Off") • Kill switch: \(killSwitchText)")
        Text("Effective MTU: \(mtuText) • IPv6: \(profile?.ipv6Mode ?? "default")")
    }

    @ViewBuilder private var warningLines: some View {
        if warnings.isEmpty {
            Text("Warnings: None").foregroundStyle(.secondary)
        } else {
            Text("Warnings: \(warningsText)").foregroundStyle(.orange)
        }
        if !exitError.isEmpty {
            Text(exitError).foregroundStyle(.red)
        }
    }

    private var actionControls: some View {
        ViewThatFits(in: .horizontal) {
            HStack { actionButtons }
            VStack(alignment: .leading) { actionButtons }
        }
        .buttonStyle(.bordered)
    }

    @ViewBuilder private var actionButtons: some View {
        Button(exitRequest == nil ? "Check public IP" : "Checking…") {
            startExitCheck()
        }
        .disabled(!model.connected || model.activeSessionIdentity == nil || model.tunnelTransitioning || model.iosCandidateTesting || exitRequest != nil)

        Button("Advanced Settings") { showingSettings = true }
            .disabled(model.connected)

        Button("Emergency Disconnect") { disconnectEmergency() }
            .disabled(!model.connected)
    }

    private func disconnectEmergency() {
        clearExitObservation()
        model.disconnect()
    }

    private func startExitCheck() {
        clearExitObservation()
        // Capture the editor and native runtime independently. A linked route
        // can have a compiled provider bundle distinct from its editable input.
        guard let owner = try? IOSExternalComparisonSelection(model), owner.connected,
              owner.identity != nil, !model.iosCandidateTesting, !model.tunnelTransitioning,
              model.bundle != nil else {
            exitError = "Wait for the selected connection to finish starting, then check its public IP."
            return
        }
        exitOwner = owner
        exitNodeRevision = IOSNodeBundleStore.shared.revision
        exitNetwork = IOSViaEntryNetwork.shared.current
        exitRequest = UUID()
    }

    private func selectionIsCurrent(_ owner: IOSExternalComparisonSelection) -> Bool {
        !model.tunnelTransitioning && !model.iosUserDisconnectInProgress && !model.iosCandidateTesting &&
            IOSNodeBundleStore.shared.revision == exitNodeRevision && (try? IOSExternalComparisonSelection(model)) == owner
    }

    private func exitIsCurrent(_ owner: IOSExternalComparisonSelection) -> Bool {
        exitNetwork != nil && IOSViaEntryNetwork.shared.current == exitNetwork && selectionIsCurrent(owner)
    }

    @MainActor private func checkPublicIP(_ request: UUID) async {
        guard !Task.isCancelled, exitRequest == request, let owner = exitOwner else { return }
        defer { if exitRequest == request { exitRequest = nil } }
        do {
            if exitNetwork == nil {
                let snapshot = try await IOSViaEntryNetwork.shared.snapshot()
                try Task.checkCancellation()
                guard exitRequest == request, selectionIsCurrent(owner) else { return }
                exitNetwork = snapshot
            }
            func requireCurrent() throws {
                try Task.checkCancellation()
                guard exitRequest == request, exitIsCurrent(owner) else { throw CancellationError() }
            }
            try requireCurrent()
            let value = try await fetchPublicIP(requireCurrent: requireCurrent)
            try requireCurrent()
            await model.refreshTunnelStatus()
            try requireCurrent()
            actualExitIP = value
        } catch {
            guard exitRequest == request, !Task.isCancelled, !(error is CancellationError), selectionIsCurrent(owner) else { return }
            if let exitNetwork, exitNetwork != IOSViaEntryNetwork.shared.current { return }
            exitError = "Public IP check failed: \(error.localizedDescription)"
        }
    }

    @MainActor private func fetchPublicIP(requireCurrent: () throws -> Void) async throws -> String {
        let session = IOSSpeedLabHTTP.makeSession(timeout: 6, userAgent: "RouterVPN-Home/1")
        defer { session.invalidateAndCancel() }
        return try await withTaskCancellationHandler {
            for raw in ["https://api64.ipify.org/", "https://api.ipify.org/"] {
                try requireCurrent()
                guard let url = URL(string: raw) else { continue }
                if let value = try? await Self.readPublicIP(session, url: url) { return value }
            }
            throw URLError(.badServerResponse)
        } onCancel: {
            session.invalidateAndCancel()
        }
    }

    nonisolated private static func readPublicIP(_ session: URLSession, url: URL) async throws -> String? {
        let (bytes, response) = try await session.bytes(from: url)
        defer { bytes.task.cancel() }
        guard let http = response as? HTTPURLResponse, http.url == url,
              http.statusCode == 200, http.expectedContentLength <= 128 else { return nil }
        var body = Data()
        for try await byte in bytes {
            guard body.count < 128 else { return nil }
            body.append(byte)
        }
        let value = String(decoding: body, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        return IOSViaEntryTCP.publicHost(value) ? value : nil
    }

    private func clearExitObservation() {
        exitRequest = nil
        exitOwner = nil
        exitNetwork = nil
        actualExitIP = nil
        exitError = ""
    }
}
