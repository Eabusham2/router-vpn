import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    @EnvironmentObject var model: RouterVPNModel
    @State private var importing = false
    @State private var showingOnboarding = false
    @AppStorage("routerVPNOnboardingDoneV2") private var onboardingDone = false
    @AppStorage("routerVPNOnboardingStepV2") private var onboardingStep = 0

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
                    Button("Run full onboarding again") {
                        onboardingDone = false
                        onboardingStep = 0
                        showingOnboarding = true
                    }
                    Button("Run setup check") {
                        model.message = setupCheckText()
                    }
                    Text("The full guide covers Portainer/AI Board, ASUS WAN forwarding, bundle/profile import, DNS/modes, SOCKS5, forwarding, and optional tests. Finishing keeps it dismissed; reopening does not erase the router profile.")
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
        checks.append("ℹ Server test: sudo bash server/scripts/doctor-current.sh")
        checks.append("ℹ ASUS test: /jffs/scripts/router-vpn-forward.sh status")
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

    private let lastStep = 9

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
                        Button("Close for now") { isPresented = false }
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
                Text("Complete first-run path: home node → ASUS router → client/profile → DNS/modes → optional tests. Progress is saved when you move steps. Closing does not mark setup complete; Finish does.")
            }
        case 1:
            VStack(alignment: .leading, spacing: 8) {
                Text("Deploy the home node").font(.title2).bold()
                Text("Portainer → Stacks → Add stack → Repository. Compose path: server/portainer-current.yaml.")
                Text("Normal environment values: WAN_INTERFACE=eth0, LAN_CIDR=192.168.50.0/24, ADGUARD4=192.168.50.133. ENDPOINT is optional and can stay blank for auto-detection.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        case 2:
            VStack(alignment: .leading, spacing: 8) {
                Text("Verify the home node").font(.title2).bold()
                Text("router-vpn-init and router-vpn-finalize should exit code 0; do not restart those one-shots. The long-running Router VPN containers should be running before WAN exposure.")
                Text("Optional: sudo bash server/scripts/doctor-current.sh")
                    .font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
            }
        case 3:
            VStack(alignment: .leading, spacing: 8) {
                Text("Download the private bundle").font(.title2).bold()
                Text("On the home LAN: http://192.168.50.133:8786/router-vpn-client-bundle.zip")
                    .textSelection(.enabled)
                Text("Keep it private. It includes router-vpn-bundle.json and router/asus-merlin-router-vpn-forwards.sh.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        case 4:
            VStack(alignment: .leading, spacing: 8) {
                Text("Add ASUS WAN forwards").font(.title2).bold()
                Text("Use the bundled Merlin helper over SSH. It preserves existing nat-start/firewall-start content and installs persistent JFFS hooks.")
                Text("External: TCP 80→18080; TCP 443; UDP 585; TCP+UDP 8388; UDP 8443; TCP 10443/11443/12443; TCP+UDP 13443; UDP 51820/51822. Never expose 1080, 8786, 8787, 9443, SSH, Portainer, or AdGuard admin.")
                    .font(.caption).foregroundStyle(.secondary)
                Text("ASUS TCP 8443 management does not conflict with Router VPN UDP 8443.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        case 5:
            VStack(alignment: .leading, spacing: 10) {
                Text("Import your router profile").font(.title2).bold()
                TextField("Profile name", text: $model.routerName)
                TextField("Public IPv4, IPv6, or hostname", text: $model.endpoint)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                TextField("Router API inside tunnel", text: $model.routerAPI)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                SecureField("Router API token", text: $model.apiToken)
                Button("Import router-vpn-bundle.json") { importing = true }
                Button("Save router profile") { model.saveRouter() }
                if !checkResult.isEmpty { Text(checkResult).font(.caption) }
                Text("Import is recommended because it keeps generated profiles, runtime endpoint/token, AdGuard and SOCKS settings together. Multiple runtime router profiles are supported.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        case 6:
            VStack(alignment: .leading, spacing: 8) {
                Text("DNS and connection policy").font(.title2).bold()
                Text("The full client supports Home AdGuard, fastest real DNS-query RTT measured at the home exit, custom UDP/TCP, DoT, DoH, DoH3, and DNS Rescue.")
                Text("AUTO stops at the first healthy ordered mode. SMART AUTO takes longer and preserves/restores a last-good stack while simplifying. CUSTOM chooses the lightest validated compatible stack containing every requested layer.")
            }
        case 7:
            VStack(alignment: .leading, spacing: 8) {
                Text("Privacy, SOCKS5, and forwarding").font(.title2).bold()
                Text("DAITA-like is bounded bidirectional cover traffic, not exact Mullvad DAITA/Maybenot. Jumbo TUN is only for compatible paths.")
                Text("SOCKS5 is ordinary IP + port, no authentication, LAN/tunnel-only. Incoming forwarding and Protected DMZ require a WireGuard/AmneziaWG peer path; proxy-only modes are outbound.")
            }
        case 8:
            VStack(alignment: .leading, spacing: 8) {
                Text("Optional tests").font(.title2).bold()
                Button("Run setup check") { checkResult = onboardingCheckText() }
                if !checkResult.isEmpty { Text(checkResult).font(.caption).textSelection(.enabled) }
                Text("Server: sudo bash server/scripts/doctor-current.sh\nASUS: /jffs/scripts/router-vpn-forward.sh status")
                    .font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                Text("A live VPN test only counts after an actual connection/handshake. Generic UDP port checkers cannot prove WireGuard/AWG success.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        default:
            VStack(alignment: .leading, spacing: 8) {
                Text("Setup complete").font(.title2).bold()
                Text("Finish keeps onboarding dismissed on this device. You can reopen it anytime from Help & setup without erasing the imported router profile.")
                Text("This iOS build remains honest about its boundary: native all-mode Packet Tunnel adapters are not linked yet, so optional checks do not fake a VPN handshake.")
                    .font(.caption).foregroundStyle(.secondary)
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
        checks.append("ℹ Server test: server/scripts/doctor-current.sh")
        checks.append("ℹ ASUS test: /jffs/scripts/router-vpn-forward.sh status")
        checks.append("ℹ Safe configuration check only; no live all-mode tunnel handshake is claimed by this controller build.")
        return checks.joined(separator: "\n")
    }
}
