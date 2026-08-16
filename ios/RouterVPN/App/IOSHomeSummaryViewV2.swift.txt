import Network
import SwiftUI

struct IOSHomeSummaryView: View {
    @EnvironmentObject var model: RouterVPNModel
    @State private var actualExitIP = ""
    @State private var actualExitStatus = "not-connected"
    @State private var provingExit = false
    @State private var exitError = ""
    @State private var showingSettings = false

    private var profile: RouterProfile? {
        guard let bundle = model.bundle else { return nil }
        return bundle.routerProfiles.first(where: { $0.id == bundle.selectedRouterID }) ?? bundle.routerProfiles.first
    }

    private var dnsMeasuredRTT: Double? {
        guard let p = profile else { return nil }
        let host = (p.dnsHost ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        if !host.isEmpty, let result = p.dnsResults?.first(where: { $0.working && $0.address == host }), let value = result.latencyMs { return value }
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
        if model.connected && actualExitStatus != "proved" { values.append("Actual public exit is not proven for this live PacketTunnel session") }
        if let p = profile, (p.dnsMode ?? "").isEmpty == false { values.append("DNS RTT shown here is a home-node query measurement; active PacketTunnel DNS still needs runtime/device proof") }
        if profile?.baseFallback == true { values.append("Base fallback is enabled; actual engine/base is authoritative") }
        if !model.message.isEmpty && !model.message.lowercased().contains("connected") { values.append(model.message) }
        return values
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("Home / Connect state").font(.headline)
                Spacer()
                Text(model.connected ? "Connected" : "Off").font(.caption.bold()).foregroundStyle(model.connected ? .green : .secondary)
            }
            Text("Node: \(profile?.name ?? model.routerName) • \((profile?.location?.isEmpty == false) ? profile!.location! : "Location not labeled")")
            Text("Public endpoint: \(profile?.endpoint ?? model.endpoint)")
            Text("Actual public VPN exit: \(actualExitStatus == "proved" ? actualExitIP : (model.connected ? "Unproven — tap Prove actual exit" : "Not connected"))")
            Text("Phase/path proof: \(model.connected ? "connected • selected-node proof passed" : "off / not proven")")
            Text("Logical/runtime/base: \(model.selectedLogicalMode) • \(model.activeRawProfile.isEmpty ? "—" : model.activeRawProfile) • \(actualBase)")
            Text("Fallback: \(fallbackText)")
            Text("DNS: \(profile?.dnsMode ?? "home") • \(profile?.dnsHost ?? profile?.adGuardIPv4 ?? "—")" + (dnsMeasuredRTT.map { String(format: " • home query RTT %.2f ms", $0) } ?? " • query RTT not measured"))
            Text("Node latency: \((profile?.latencySamples ?? 0) > 0 ? String(format: "%.2f ms / %d samples", profile?.latencyMedianMs ?? 0, profile?.latencySamples ?? 0) : "Not measured")")
            Text("LAN access: \((profile?.homeLANAccess ?? model.homeLANAccess) ? "On" : "Off") • Kill switch: \(killSwitchText)")
            Text("Effective MTU: \(mtuText) • IPv6: \(profile?.ipv6Mode ?? "default")")
            Text("Warnings: \(warnings.isEmpty ? "None" : warnings.joined(separator: " | "))").foregroundStyle(warnings.isEmpty ? .secondary : .orange)
            if !exitError.isEmpty { Text(exitError).foregroundStyle(.red) }
            ViewThatFits(in: .horizontal) {
                HStack {
                    Button(provingExit ? "Proving…" : "Prove actual exit") { Task { await proveActualExit() } }.disabled(!model.connected || provingExit)
                    Button("Advanced Settings") { showingSettings = true }.disabled(model.connected)
                    Button("Emergency Disconnect") { disconnectEmergency() }.disabled(!model.connected)
                }
                VStack(alignment: .leading) {
                    Button(provingExit ? "Proving…" : "Prove actual exit") { Task { await proveActualExit() } }.disabled(!model.connected || provingExit)
                    Button("Advanced Settings") { showingSettings = true }.disabled(model.connected)
                    Button("Emergency Disconnect") { disconnectEmergency() }.disabled(!model.connected)
                }
            }
            .buttonStyle(.bordered)
        }
        .font(.caption)
        .padding(12)
        .frame(maxWidth: 760, alignment: .leading)
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 14))
        .sheet(isPresented: $showingSettings) { IOSProfileSettingsView().environmentObject(model) }
        .onChange(of: model.connected) { _, connected in if !connected { actualExitIP = ""; actualExitStatus = "not-connected"; exitError = "" } }
        .onChange(of: model.activeRawProfile) { _, _ in clearExitProofForRuntimeChange() }
        .onChange(of: model.activeEngine) { _, _ in clearExitProofForRuntimeChange() }
    }

    private func disconnectEmergency() {
        actualExitIP = ""; actualExitStatus = "not-connected"; exitError = ""; model.disconnect()
    }

    @MainActor private func proveActualExit() async {
        guard model.connected, let bundle = model.bundle else { return }
        let selectedNode = bundle.selectedRouterID, engine = model.activeEngine, rawProfile = model.activeRawProfile
        provingExit = true; exitError = ""; actualExitStatus = "checking"; defer { provingExit = false }
        do {
            let value = try await fetchPublicIP()
            guard model.connected, model.bundle?.selectedRouterID == selectedNode, model.activeEngine == engine, model.activeRawProfile == rawProfile else {
                throw NSError(domain: "RouterVPN.Home", code: 2, userInfo: [NSLocalizedDescriptionKey: "VPN node/runtime changed while proving the public exit; result discarded."])
            }
            actualExitIP = value; actualExitStatus = "proved"
        } catch { actualExitIP = ""; actualExitStatus = model.connected ? "unproven" : "not-connected"; exitError = "Actual exit proof failed: \(error.localizedDescription)" }
    }

    private func fetchPublicIP() async throws -> String {
        for raw in ["https://api64.ipify.org", "https://api.ipify.org"] {
            guard let url = URL(string: raw) else { continue }
            do {
                var request = URLRequest(url: url); request.timeoutInterval = 6; request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
                let (data, response) = try await URLSession.shared.data(for: request)
                guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode), data.count <= 128 else { continue }
                let value = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                if IPv4Address(value) != nil || IPv6Address(value) != nil { return value }
            } catch { continue }
        }
        throw NSError(domain: "RouterVPN.Home", code: 1, userInfo: [NSLocalizedDescriptionKey: "Could not determine the public VPN exit through the current PacketTunnel."])
    }

    private func clearExitProofForRuntimeChange() { if actualExitStatus == "proved" { actualExitIP = ""; actualExitStatus = model.connected ? "unproven" : "not-connected" } }
}

// Apple Home contract: node/location/public endpoint/current-session actual exit,
// phase/logical/runtime/base/fallback/DNS RTT/node latency/LAN/kill/MTU/warnings,
// adaptive actions, editable supported settings, and Emergency Disconnect.
// Cached profile.publicIP is never used as live proof.
