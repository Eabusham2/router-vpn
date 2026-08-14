import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    @EnvironmentObject var model: RouterVPNModel
    @State private var importing = false
    @State private var showingOnboarding = false
    @AppStorage("routerVPNOnboardingDoneV4") private var onboardingDone = false
    @AppStorage("routerVPNOnboardingStepV4") private var onboardingStep = 0

    var body: some View {
        TabView {
            ConnectView()
                .tabItem { Label("Connect", systemImage: "shield.lefthalf.filled") }
            NodesView(importing: $importing)
                .tabItem { Label("Nodes", systemImage: "point.3.connected.trianglepath.dotted") }
            DNSView()
                .tabItem { Label("DNS", systemImage: "network") }
            MethodsView()
                .tabItem { Label("Modes", systemImage: "square.stack.3d.up") }
            SetupView(showingOnboarding: $showingOnboarding)
                .tabItem { Label("Setup", systemImage: "wrench.and.screwdriver") }
        }
        .fileImporter(isPresented: $importing, allowedContentTypes: [.json]) { result in
            importBundle(result)
        }
        .onAppear {
            if !onboardingDone { showingOnboarding = true }
        }
        .sheet(isPresented: $showingOnboarding) {
            NativeOnboardingView(
                done: $onboardingDone,
                step: $onboardingStep,
                isPresented: $showingOnboarding,
                importing: $importing
            )
            .environmentObject(model)
        }
    }

    private func importBundle(_ result: Result<URL, Error>) {
        guard case .success(let url) = result,
              url.startAccessingSecurityScopedResource() else { return }
        defer { url.stopAccessingSecurityScopedResource() }
        do { try model.importBundle(Data(contentsOf: url)) }
        catch { model.message = "Import failed: \(error.localizedDescription)" }
    }
}

private struct ConnectView: View {
    @EnvironmentObject var model: RouterVPNModel

    private var selectedMode: LogicalMode? {
        model.logicalModes.first(where: { $0.id == model.selectedLogicalMode })
    }

    private var selectedRuntimeLabel: String {
        guard let selectedMode else { return "No runnable mode" }
        return model.runtimeLabel(for: selectedMode)
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    NativeCard {
                        HStack(alignment: .top) {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(model.connected ? "Connected" : "Router VPN")
                                    .font(.title2.bold())
                                Text(model.endpoint.isEmpty ? "No node selected" : model.endpoint)
                                    .font(.caption).foregroundStyle(.secondary)
                                if model.connected {
                                    Text("Engine: \(model.activeEngine) • raw profile: \(model.activeRawProfile)")
                                        .font(.caption2).foregroundStyle(.secondary)
                                }
                            }
                            Spacer()
                            Image(systemName: model.connected ? "checkmark.shield.fill" : "shield")
                                .font(.system(size: 34))
                                .foregroundStyle(model.connected ? .green : .blue)
                        }
                    }

                    NativeCard {
                        Toggle("AUTO — try only real iOS WireGuardKit / Libbox modes", isOn: $model.auto)
                        if !model.auto {
                            Picker("Mode", selection: $model.selectedLogicalMode) {
                                ForEach(model.iosRunnableLogicalModes) { mode in
                                    Text("\(mode.name) — \(model.runtimeLabel(for: mode))").tag(mode.id)
                                }
                            }
                            .pickerStyle(.menu)

                            if let selectedMode {
                                Label(selectedRuntimeLabel, systemImage: "checkmark.circle.fill")
                                    .foregroundStyle(.green)
                                Text(model.runtimeReason(for: selectedMode))
                                    .font(.caption).foregroundStyle(.secondary)
                            } else {
                                Text("This imported node does not contain an iOS-runnable WireGuardKit or Libbox mode.")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                        } else {
                            Text("AUTO reports each attempt and tries only modes the imported bundle can actually run. WireGuardKit is preferred first. With strict Apple route lockdown, AUTO fails closed after a failed attempt instead of cycling through a transition that could create a leak gap.")
                                .font(.caption).foregroundStyle(.secondary)
                        }

                        Divider()
                        Text("AmneziaWG-only, Xray-only, ALL/MAX composites and iOS multihop remain unavailable until their real Apple dataplanes exist. They are never CSS-forced Ready.")
                            .font(.caption).foregroundStyle(.secondary)

                        Button {
                            if model.connected { model.disconnect() }
                            else { Task { await model.connect() } }
                        } label: {
                            Label(model.connected ? "Disconnect" : "Connect", systemImage: model.connected ? "stop.fill" : "play.fill")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.large)
                        .disabled(!model.auto && !model.iosManualModeSupported)
                    }

                    NativeCard {
                        Text("Connection truth").font(.headline)
                        if model.auto {
                            Text("AUTO readiness comes from the imported node's actual WG/sing-box profiles, not from a hard-coded iOS list.")
                                .font(.caption).foregroundStyle(.secondary)
                        } else if let selectedMode {
                            Text("Manual: \(selectedMode.name) • \(model.runtimeLabel(for: selectedMode))")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Text("Connected is reported only after NetworkExtension starts the selected engine and the exact selected-node private identity proof succeeds. Libbox proof is forced through its private in-engine proxy.")
                            .font(.caption).foregroundStyle(.secondary)
                    }

                    NativeCard {
                        Text("SOCKS5 after VPN").font(.headline)
                        Text(model.socksSummary).textSelection(.enabled)
                        Text("This remains an internal/LAN tunnel proxy, not a WAN-exposed service.")
                            .font(.caption).foregroundStyle(.secondary)
                    }

                    NativeCard {
                        Text(model.message)
                            .font(.caption)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                .padding()
            }
            .navigationTitle("Connect")
        }
    }
}

private struct NodesView: View {
    @EnvironmentObject var model: RouterVPNModel
    @Binding var importing: Bool

    var body: some View {
        NavigationStack {
            Form {
                Section("Fastest secure way to link this app") {
                    TextField("AI Board LAN IP / hostname", text: $model.lanImportHost)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                    SecureField("6-digit one-time pairing code", text: $model.lanPairingCode)
                        .keyboardType(.numberPad)
                    Button("Pair from home LAN") { Task { await model.importFromLAN() } }
                    Button("Import router-vpn-bundle.json from Files") { importing = true }
                    Text("Create the short-lived code in the authenticated home Setup Center. The code is redeemed once and is never stored by the app. Install once, then link node data separately; adding another router never reinstalls the app.")
                        .font(.caption).foregroundStyle(.secondary)
                }

                Section("Selected node") {
                    TextField("Name", text: $model.routerName)
                    TextField("Public IPv4 / IPv6 / hostname", text: $model.endpoint)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                    Button("Save node") { model.saveRouter() }
                }

                Section("Tunnel-only services") {
                    TextField("Router API", text: $model.routerAPI)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                    SecureField("Router API token", text: $model.apiToken)
                    TextField("SOCKS5 host", text: $model.socksHost)
                    TextField("SOCKS5 port", text: $model.socksPort).keyboardType(.numberPad)
                }

                Section("Incoming forwarding") {
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
                    Text("Forwarding is authenticated through a real peer path; proxy-only modes cannot fake DNAT semantics.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Nodes")
        }
    }
}

private struct DNSView: View {
    @EnvironmentObject var model: RouterVPNModel

    var body: some View {
        NavigationStack {
            Form {
                Section("Current iOS DNS behavior") {
                    Label("DNS is enforced inside the selected PacketTunnel engine", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                    Text("WireGuardKit uses the DNS embedded in the imported wg.conf. Libbox applies the selected raw profile's in-engine DNS and exposes that DNS address to NetworkExtension. A saved DNS choice is not counted as proof unless the active runtime enforces it.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section("Home resolver") {
                    Text(model.bundle?.adGuardIPv4 ?? "10.77.0.1")
                        .textSelection(.enabled)
                    Text("Home AdGuard remains the normal tunnel DNS where the selected profile carries it. Full per-resolver benchmark/sort UI parity remains part of the cross-platform visual/settings audit.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .navigationTitle("DNS")
        }
    }
}

private struct MethodsView: View {
    @EnvironmentObject var model: RouterVPNModel

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Text("This is the native Router VPN mode catalog, not Setup Center's simple third-party Methods list. A mode is iOS Ready only when the imported node contains a real WireGuardKit or Libbox runtime profile that this build can execute.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                ForEach(model.logicalModes) { mode in
                    let available = model.iosRunnableLogicalModes.contains(where: { $0.id == mode.id })
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            Text(mode.name).bold()
                            Spacer()
                            Text(available ? model.runtimeLabel(for: mode) : "Unavailable")
                                .font(.caption2)
                                .foregroundStyle(available ? .green : .secondary)
                        }
                        Text(mode.description).font(.caption).foregroundStyle(.secondary)
                        Text(model.runtimeReason(for: mode))
                            .font(.caption2).foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 3)
                }
            }
            .navigationTitle("Modes")
        }
    }
}

private struct SetupView: View {
    @EnvironmentObject var model: RouterVPNModel
    @Binding var showingOnboarding: Bool

    var body: some View {
        NavigationStack {
            Form {
                Section("Always available") {
                    Button("Run full onboarding") { showingOnboarding = true }
                    if let url = lanURL("") { Link("Open Full Guide / home Setup Center", destination: url) }
                    Text("The Full Guide remains independently accessible after onboarding is completed or dismissed.")
                        .font(.caption).foregroundStyle(.secondary)
                }

                Section("Small direct downloads") {
                    if let u = lanURL("router-vpn-bundle.json") { Link("Private router profile JSON — Setup Center sign-in required", destination: u) }
                    if let u = lanURL("asus-merlin-router-vpn-forwards.sh") { Link("ASUS Merlin forwarding helper", destination: u) }
                    if let u = lanURL("router-vpn-device-setup.html") { Link("Universal / native setup page", destination: u) }
                    if let u = lanURL("SHA256SUMS") { Link("Checksums", destination: u) }
                    Text("Normal app linking uses the one-time pairing flow above. The full ZIP is an advanced/offline fallback.")
                        .font(.caption).foregroundStyle(.secondary)
                }

                Section("Router-side simple Methods") {
                    Label("WireGuard / supported native configs", systemImage: "shield")
                    Label("Shadowsocks 2022", systemImage: "network")
                    Label("Hysteria2", systemImage: "bolt.horizontal.circle")
                    Label("SOCKS5 — internal/LAN only", systemImage: "arrow.left.arrow.right")
                    Label("SOCKS5 + TLS / OverTLS", systemImage: "lock.shield")
                    Text("Setup Center exposes only simple external-app Methods with truthful import/QR metadata. Complex Router VPN stacks stay in the Router VPN app.")
                        .font(.caption).foregroundStyle(.secondary)
                }

                Section("Apple distribution truth") {
                    Text("CI artifacts are unsigned/re-signable. Long-term iOS distribution still requires Apple signing/provisioning. Router VPN does not recommend globally disabling Apple platform security.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Setup")
        }
    }

    private func lanURL(_ path: String) -> URL? {
        let host = model.lanImportHost.trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "http://", with: "")
            .replacingOccurrences(of: "https://", with: "")
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let suffix = path.isEmpty ? "" : "/\(path)"
        return URL(string: "http://\(host):8786\(suffix)")
    }
}

private struct NativeOnboardingView: View {
    @EnvironmentObject var model: RouterVPNModel
    @Binding var done: Bool
    @Binding var step: Int
    @Binding var isPresented: Bool
    @Binding var importing: Bool

    private let lastStep = 7

    var body: some View {
        NavigationStack {
            VStack(spacing: 16) {
                ProgressView(value: Double(step + 1), total: Double(lastStep + 1))
                ScrollView {
                    onboardingContent
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.vertical)
                }
                HStack {
                    Button("Back") { if step > 0 { step -= 1 } }.disabled(step == 0)
                    Spacer()
                    Button("Close") { isPresented = false }
                    Spacer()
                    Button(step == lastStep ? "Finish" : "Next") {
                        if step == lastStep {
                            done = true
                            step = 0
                            isPresented = false
                        } else { step += 1 }
                    }
                    .buttonStyle(.borderedProminent)
                }
            }
            .padding()
            .navigationTitle("Setup \(step + 1)/\(lastStep + 1)")
        }
    }

    @ViewBuilder private var onboardingContent: some View {
        switch step {
        case 0:
            OnboardingPage(title: "Start simple", text: "If the home node is already deployed, stay on home Wi‑Fi and link this app with a one-time Setup Center pairing code or the private router profile file. Installing the app and adding a router are separate operations.")
        case 1:
            VStack(alignment: .leading, spacing: 12) {
                OnboardingPage(title: "Add your router", text: "In the authenticated Setup Center create a short-lived 6-digit pairing code. Enter the AI Board LAN IP/hostname and code below, or choose router-vpn-bundle.json from Files. Pairing is LAN-only, one-time, and the code is not saved on this device. iOS Local Network permission may be requested.")
                TextField("AI Board LAN IP / hostname", text: $model.lanImportHost)
                    .textFieldStyle(.roundedBorder)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                SecureField("6-digit one-time pairing code", text: $model.lanPairingCode)
                    .textFieldStyle(.roundedBorder)
                    .keyboardType(.numberPad)
                Button("Pair from LAN now") { Task { await model.importFromLAN() } }
                    .buttonStyle(.borderedProminent)
                Button("Choose router-vpn-bundle.json") { importing = true }
                Text(model.message).font(.caption).foregroundStyle(.secondary)
            }
        case 2:
            OnboardingPage(title: "Deploy the home node from zero", text: "On the ASUS AI Board open Portainer → Stacks → Add stack → Repository and use server/portainer-current.yaml. Normal values include WAN_INTERFACE=eth0, LAN_CIDR=192.168.50.0/24 and ADGUARD4=192.168.50.133. Leave ENDPOINT blank for auto-detection when appropriate. Verify one-shot init/finalize exit 0 and long-running services are healthy before router forwards.")
        case 3:
            OnboardingPage(title: "ASUS router forwarding", text: "Enable the required ASUS SSH/JFFS support, then use the current Setup Center forwarding helper. It preserves existing nat-start/firewall-start content and checks the firewall backend. Never WAN-expose SOCKS5 1080, Setup Center 8786, router API 8787, Portainer, AdGuard admin, SSH, or the OverTLS loopback backend.")
        case 4:
            OnboardingPage(title: "Connect on iPhone or iPad", text: "AUTO now evaluates the imported node and tries only modes this build can truly run through WireGuardKit or pinned Libbox 1.13.12. Manual mode lists the same real set. Each attempt remains Connecting until the PacketTunnel engine starts and the exact selected-node private proof passes through that engine. AWG-only, Xray-only, ALL/MAX and multihop stay unavailable until their Apple dataplanes are real.")
        case 5:
            OnboardingPage(title: "Simple external methods vs Router VPN modes", text: "Setup Center is for simple, proven external/native-compatible Methods and exact setup instructions. The Router VPN app owns complex layered modes. A Setup Center QR/config being available does not imply every third-party app supports it, and a Router VPN mode being listed does not make it iOS Ready without a real imported runtime profile.")
        case 6:
            OnboardingPage(title: "DNS, LAN, forwarding and safety", text: "WireGuardKit uses DNS/routes/MTU from wg.conf; Libbox applies the selected raw profile in-engine and gives NetworkExtension its tunnel DNS/routes. Strict policy configures includeAllNetworks + enforceRoutes, on-demand reconnect and LAN exclusion from the imported policy, then fails closed if PacketTunnel sees a mismatch. Physical Wi‑Fi/cellular/reconnect/sleep leak testing is still required before final release.")
        default:
            OnboardingPage(title: "Ready", text: "The Full Guide remains available in Setup. The PacketTunnel uses pinned WireGuardKit and pinned Libbox 1.13.12 where the imported mode provides a valid sing-box profile. Connected always requires exact selected-node private identity proof. Unsupported engines fail visibly rather than fake a successful VPN connection.")
        }
    }
}

private struct OnboardingPage: View {
    let title: String
    let text: String
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title).font(.title2.bold())
            Text(text)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct NativeCard<Content: View>: View {
    @ViewBuilder let content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 12) { content }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 18))
    }
}
