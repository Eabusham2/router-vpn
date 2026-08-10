import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    @EnvironmentObject var model: RouterVPNModel
    @State private var importing = false
    @State private var showingOnboarding = false
    @AppStorage("routerVPNOnboardingDoneV1") private var onboardingDone = false
    @AppStorage("routerVPNOnboardingStepV1") private var onboardingStep = 0

    var body: some View {
        NavigationStack {
            Form {
                Section("Home router") {
                    TextField("Profile name", text: $model.routerName)
                    TextField("Public IPv4, IPv6, or hostname", text: $model.endpoint)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    TextField("Router API inside tunnel", text: $model.routerAPI)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    SecureField("Router API token", text: $model.apiToken)
                    DisclosureGroup("SOCKS5 settings") {
                        TextField("SOCKS5 host", text: $model.socksHost)
                        TextField("SOCKS5 port", text: $model.socksPort)
                            .keyboardType(.numberPad)
                        Text("No authentication. Reachable only through the tunnel or home LAN; never forward TCP 1080 from WAN.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Button("Save router profile") { model.saveRouter() }
                    Button("Import router-vpn-bundle.json") { importing = true }
                }

                Section("Connection") {
                    Toggle("AUTO", isOn: $model.auto)
                    Picker("Mode", selection: $model.selectedMode) {
                        ForEach(model.modes) { Text($0.name).tag($0.id) }
                    }
                    .disabled(model.auto)
                    Toggle("DAITA-like traffic shaping", isOn: $model.daita)
                    Toggle("Jumbo TUN", isOn: $model.jumbo)
                    Button(model.connected ? "Disconnect" : "Connect") {
                        if model.connected {
                            model.disconnect()
                        } else {
                            Task { await model.connect() }
                        }
                    }
                }

                Section("Native tunnel engine") {
                    Text("Build/signing is wired, but the Packet Tunnel adapter for WireGuard, AmneziaWG, Xray, and sing-box is not linked yet. The current extension reports this instead of pretending to connect.")
                        .font(.caption)
                }

                Section("SOCKS5 after VPN") {
                    Text(model.socksSummary).textSelection(.enabled)
                }

                Section("Port forwarding — WG/AWG") {
                    Picker("Protocol", selection: $model.forwardProtocol) {
                        Text("Both").tag("both")
                        Text("TCP").tag("tcp")
                        Text("UDP").tag("udp")
                    }
                    TextField("External start", text: $model.forwardFrom).keyboardType(.numberPad)
                    TextField("External end", text: $model.forwardTo).keyboardType(.numberPad)
                    TextField("Target port (0 preserves range)", text: $model.forwardTarget).keyboardType(.numberPad)
                    HStack {
                        Button("Apply") { Task { await model.applyForward(dmz: false) } }
                        Button("Protected DMZ") { Task { await model.applyForward(dmz: true) } }
                        Button("Clear") { Task { await model.clearForward() } }
                    }
                }

                Section("Help & setup") {
                    Button("Run onboarding again") {
                        onboardingDone = false
                        onboardingStep = 0
                        showingOnboarding = true
                    }
                    Button("Run setup check") {
                        model.message = setupCheckText()
                    }
                    Text("Finishing onboarding keeps it dismissed on this device. Reopening it does not erase your router profile.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Section("Status") { Text(model.message) }

                Section("Modes") {
                    ForEach(model.modes) { mode in
                        VStack(alignment: .leading) {
                            Text(mode.name).bold()
                            Text(mode.protection).font(.caption)
                            Text("+\(mode.pingMinMs, specifier: "%.1f")–\(mode.pingMaxMs, specifier: "%.1f") ms • +\(mode.trafficMinPct, specifier: "%.0f")–\(mode.trafficMaxPct, specifier: "%.0f")% traffic")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
            .navigationTitle("Router VPN")
            .fileImporter(isPresented: $importing, allowedContentTypes: [.json]) { result in
                importBundle(result)
            }
        }
        .onAppear {
            if !onboardingDone { showingOnboarding = true }
        }
        .sheet(isPresented: $showingOnboarding) {
            RouterVPNOnboardingView(
                model: model,
                done: $onboardingDone,
                step: $onboardingStep,
                isPresented: $showingOnboarding
            )
        }
    }

    private func importBundle(_ result: Result<URL, Error>) {
        guard case .success(let url) = result,
              url.startAccessingSecurityScopedResource() else { return }
        defer { url.stopAccessingSecurityScopedResource() }
        do {
            try model.importBundle(Data(contentsOf: url))
        } catch {
            model.message = error.localizedDescription
        }
    }

    private func setupCheckText() -> String {
        var checks: [String] = []
        checks.append(model.bundle == nil ? "✗ Router bundle/profile not ready" : "✓ Router bundle/profile ready")
        checks.append(model.endpoint.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "✗ Public endpoint is blank" : "✓ Public endpoint configured")
        checks.append(model.apiToken.isEmpty ? "✗ Router API token is blank" : "✓ Router API token configured")
        checks.append(model.routerAPI.isEmpty ? "✗ Internal router API is blank" : "✓ Internal router API configured")
        checks.append(model.socksHost.isEmpty || Int(model.socksPort) == nil ? "✗ SOCKS5 IP + port incomplete" : "✓ SOCKS5 IP + port configured")
        let ids = Set(model.modes.map(\.id))
        checks.append(ids.contains("all") && ids.contains("smart-auto") && ids.contains("custom") ? "✓ ALL / SMART AUTO / CUSTOM present" : "✗ Required modes missing")
        checks.append(model.modes.count >= 22 ? "✓ Full mode catalog present" : "! Mode catalog is incomplete")
        checks.append("ℹ Live all-mode tunnel handshakes are not claimed until the native Packet Tunnel adapters are linked.")
        return checks.joined(separator: "\n")
    }
}

private struct RouterVPNOnboardingView: View {
    @ObservedObject var model: RouterVPNModel
    @Binding var done: Bool
    @Binding var step: Int
    @Binding var isPresented: Bool
    @State private var importing = false
    @State private var checkResult = ""

    private let lastStep = 5

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("Step \(step + 1) of \(lastStep + 1)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    stepContent
                }

                Section {
                    HStack {
                        Button("Back") {
                            if step > 0 { step -= 1 }
                        }
                        .disabled(step == 0)
                        Spacer()
                        Button("Close") { isPresented = false }
                        Spacer()
                        Button(step == lastStep ? "Finish" : "Next") {
                            if step == lastStep {
                                done = true
                                step = 0
                                isPresented = false
                            } else {
                                step += 1
                            }
                        }
                        .bold()
                    }
                }
            }
            .navigationTitle("Router VPN setup")
            .fileImporter(isPresented: $importing, allowedContentTypes: [.json]) { result in
                guard case .success(let url) = result,
                      url.startAccessingSecurityScopedResource() else { return }
                defer { url.stopAccessingSecurityScopedResource() }
                do {
                    try model.importBundle(Data(contentsOf: url))
                    checkResult = "✓ Router bundle imported"
                } catch {
                    checkResult = "✗ \(error.localizedDescription)"
                }
            }
        }
    }

    @ViewBuilder
    private var stepContent: some View {
        switch step {
        case 0:
            VStack(alignment: .leading, spacing: 8) {
                Text("Welcome").font(.title2).bold()
                Text("This guide walks through your runtime home-router profile, DNS, connection modes, SOCKS5, forwarding, and optional checks. Your progress is saved until you finish.")
                Text("Nothing about your home endpoint is baked into the app.").font(.caption).foregroundStyle(.secondary)
            }
        case 1:
            VStack(alignment: .leading, spacing: 10) {
                Text("Add your home router").font(.title2).bold()
                TextField("Profile name", text: $model.routerName)
                TextField("Public IPv4, IPv6, or hostname", text: $model.endpoint)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                TextField("Router API inside tunnel", text: $model.routerAPI)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                SecureField("Router API token", text: $model.apiToken)
                Button("Import router-vpn-bundle.json") { importing = true }
                Button("Save router profile") { model.saveRouter() }
                if !checkResult.isEmpty { Text(checkResult).font(.caption) }
                Text("Importing the router-generated bundle is recommended because it carries generated profiles and runtime settings together.").font(.caption).foregroundStyle(.secondary)
            }
        case 2:
            VStack(alignment: .leading, spacing: 8) {
                Text("DNS and connection policy").font(.title2).bold()
                Text("The generated profile supports Home AdGuard, fastest DNS measured at the home exit, custom DNS, DoT, DoH, DoH3, and DNS Rescue where supported by the full client path.")
                Text("AUTO stops at the first healthy ordered mode. SMART AUTO takes longer, then tests removing/replacing layers and restores the last-good stack if simplification fails. CUSTOM chooses the lightest validated compatible stack containing your required layers.")
            }
        case 3:
            VStack(alignment: .leading, spacing: 8) {
                Text("Privacy and performance options").font(.title2).bold()
                Text("DAITA-like traffic shaping is bounded bidirectional cover traffic; it is not a claim of exact Mullvad DAITA. Jumbo TUN is for compatible modes and Internet traffic is still segmented to path-sized encrypted packets.")
                Text("IPv4 + IPv6 are part of the full router/client design; unsupported paths must not leak traffic outside the tunnel.").font(.caption).foregroundStyle(.secondary)
            }
        case 4:
            VStack(alignment: .leading, spacing: 8) {
                Text("SOCKS5 and forwarding").font(.title2).bold()
                Text("SOCKS5 is ordinary IP + port with no authentication and is LAN/tunnel-only. Never WAN-forward TCP 1080.")
                Text("Incoming forwarding supports TCP, UDP, both, ranges, target ports, and Protected DMZ, but it requires a WireGuard/AmneziaWG peer path. Proxy-only modes are outbound.")
                Button("Run setup check") { checkResult = onboardingCheckText() }
                if !checkResult.isEmpty { Text(checkResult).font(.caption).textSelection(.enabled) }
            }
        default:
            VStack(alignment: .leading, spacing: 8) {
                Text("Setup complete").font(.title2).bold()
                Text("Finish keeps onboarding dismissed on this device. You can reopen it anytime from Help & setup without erasing the imported router profile.")
                Text("This iOS build remains honest about its boundary: the native all-mode Packet Tunnel adapters are not linked yet, so optional checks do not fake a VPN handshake.").font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private func onboardingCheckText() -> String {
        var checks: [String] = []
        checks.append(model.bundle == nil ? "✗ Router bundle/profile not ready" : "✓ Router bundle/profile ready")
        checks.append(model.endpoint.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "✗ Public endpoint is blank" : "✓ Public endpoint configured")
        checks.append(model.apiToken.isEmpty ? "✗ Router API token is blank" : "✓ Router API token configured")
        checks.append(model.socksHost.isEmpty || Int(model.socksPort) == nil ? "✗ SOCKS5 IP + port incomplete" : "✓ SOCKS5 IP + port configured")
        let ids = Set(model.modes.map(\.id))
        checks.append(ids.contains("all") && ids.contains("smart-auto") && ids.contains("custom") ? "✓ ALL / SMART AUTO / CUSTOM present" : "✗ Required modes missing")
        checks.append(model.modes.count >= 22 ? "✓ Full mode catalog present" : "! Mode catalog is incomplete")
        checks.append("ℹ Safe configuration check only; no live all-mode tunnel handshake is claimed by this controller build.")
        return checks.joined(separator: "\n")
    }
}
