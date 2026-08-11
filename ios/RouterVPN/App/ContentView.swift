import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    @EnvironmentObject var model: RouterVPNModel
    @State private var importing = false
    @State private var showingOnboarding = false
    @AppStorage("routerVPNOnboardingDoneV3") private var onboardingDone = false
    @AppStorage("routerVPNOnboardingStepV3") private var onboardingStep = 0

    var body: some View {
        TabView {
            ConnectView()
                .tabItem { Label("Connect", systemImage: "shield.lefthalf.filled") }
            NodesView(importing: $importing)
                .tabItem { Label("Nodes", systemImage: "point.3.connected.trianglepath.dotted") }
            DNSView()
                .tabItem { Label("DNS", systemImage: "network") }
            MethodsView()
                .tabItem { Label("Methods", systemImage: "square.stack.3d.up") }
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
                            }
                            Spacer()
                            Image(systemName: model.connected ? "checkmark.shield.fill" : "shield")
                                .font(.system(size: 34))
                                .foregroundStyle(model.connected ? .green : .blue)
                        }
                    }

                    NativeCard {
                        Toggle("AUTO — choose the lightest healthy mode", isOn: $model.auto)
                        if !model.auto {
                            Picker("Mode", selection: $model.selectedLogicalMode) {
                                ForEach(model.logicalModes) { mode in Text(mode.name).tag(mode.id) }
                            }
                            .pickerStyle(.menu)

                            if model.baseSelectorEnabled {
                                Text("Tunnel base").font(.caption).foregroundStyle(.secondary)
                                Picker("Tunnel base", selection: $model.basePreference) {
                                    Text("Auto").tag("auto")
                                    Text("WireGuard").tag("wg")
                                    Text("AmneziaWG").tag("awg")
                                }
                                .pickerStyle(.segmented)
                                Toggle("Fall back to the other base if needed", isOn: $model.baseFallback)
                            }
                        }

                        Divider()
                        Toggle("Full access to my home LAN", isOn: $model.homeLANAccess)
                        if model.homeLANAccess {
                            TextField("Home LAN CIDR", text: Binding(
                                get: { model.homeLANCIDRs.first ?? "192.168.50.0/24" },
                                set: { model.homeLANCIDRs = [$0] }
                            ))
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        }

                        DisclosureGroup("Advanced") {
                            Toggle("DAITA-like cover traffic", isOn: $model.daita)
                            Toggle("Jumbo TUN", isOn: $model.jumbo)
                        }

                        Button {
                            if model.connected { model.disconnect() }
                            else { Task { await model.connect() } }
                        } label: {
                            Label(model.connected ? "Disconnect" : "Connect", systemImage: model.connected ? "stop.fill" : "play.fill")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.large)
                    }

                    NativeCard {
                        Text("Current selection").font(.headline)
                        if model.auto {
                            Text("AUTO will test validated modes in order and stop at the first healthy one.")
                                .font(.caption).foregroundStyle(.secondary)
                        } else if let logical = model.currentLogicalMode {
                            Text(logical.name).bold()
                            Text(logical.description).font(.caption).foregroundStyle(.secondary)
                            Text("Runtime candidates: \(model.modeCandidates().joined(separator: " → "))")
                                .font(.caption2).foregroundStyle(.secondary).textSelection(.enabled)
                        }
                    }

                    NativeCard {
                        Text("SOCKS5 after VPN").font(.headline)
                        Text(model.socksSummary).textSelection(.enabled)
                        Text("This is an internal/LAN app proxy, not a WAN-exposed service.")
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
                Section("Fastest way to link this app") {
                    TextField("AI Board LAN IP / hostname", text: $model.lanImportHost)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                    Button("Import directly from home LAN") { Task { await model.importFromLAN() } }
                    Button("Import router-vpn-bundle.json from Files") { importing = true }
                    Text("LAN import downloads only the small private router profile JSON, not the massive all-platform ZIP.")
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
                        Text("Both").tag("both"); Text("TCP").tag("tcp"); Text("UDP").tag("udp")
                    }
                    TextField("External start", text: $model.forwardFrom).keyboardType(.numberPad)
                    TextField("External end", text: $model.forwardTo).keyboardType(.numberPad)
                    TextField("Target port (0 preserves range)", text: $model.forwardTarget).keyboardType(.numberPad)
                    HStack {
                        Button("Apply") { Task { await model.applyForward(dmz: false) } }
                        Button("Protected DMZ") { Task { await model.applyForward(dmz: true) } }
                        Button("Clear") { Task { await model.clearForward() } }
                    }
                    Text("Forwarding is authenticated through the tunnel and requires a WireGuard/AmneziaWG peer path.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Nodes")
        }
    }
}

private struct DNSView: View {
    @EnvironmentObject var model: RouterVPNModel
    @AppStorage("routerVPN.dnsChoice") private var choice = "home"

    var body: some View {
        NavigationStack {
            Form {
                Section("DNS policy") {
                    Picker("Use", selection: $choice) {
                        Text("Home AdGuard").tag("home")
                        Text("Fastest measured public DNS").tag("fastest")
                        Text("DNS Rescue").tag("rescue")
                        Text("Custom / encrypted").tag("custom")
                    }
                    Text("Home AdGuard is the default. The server-side Setup Center benchmarks public resolvers from the home exit; the native app will consume those measured results from the bundle/API.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section("Common resolvers included in server benchmark") {
                    ResolverRow(name: "Cloudflare", values: "1.1.1.1 • 1.0.0.1 • IPv6")
                    ResolverRow(name: "Google", values: "8.8.8.8 • 8.8.4.4 • IPv6")
                    ResolverRow(name: "Quad9", values: "9.9.9.9 • 149.112.112.112 • IPv6")
                }
            }
            .navigationTitle("DNS")
        }
    }
}

private struct ResolverRow: View {
    let name: String
    let values: String
    var body: some View { VStack(alignment: .leading) { Text(name).bold(); Text(values).font(.caption).foregroundStyle(.secondary) } }
}

private struct MethodsView: View {
    @EnvironmentObject var model: RouterVPNModel

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Text("One logical mode is shown once. WireGuard/AmneziaWG is a base selector only where both variants really exist; fallback can try the other base automatically.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                ForEach(model.logicalModes) { mode in
                    VStack(alignment: .leading, spacing: 5) {
                        HStack {
                            Text(mode.name).bold()
                            Spacer()
                            if mode.baseSelector { Text("WG / AWG").font(.caption2).padding(5).background(.blue.opacity(0.15), in: Capsule()) }
                        }
                        Text(mode.description).font(.caption).foregroundStyle(.secondary)
                        if mode.baseSelector {
                            Text("WireGuard: \(mode.variants["wg"] ?? "—") • AmneziaWG: \(mode.variants["awg"] ?? "—")")
                                .font(.caption2).foregroundStyle(.secondary)
                        }
                    }
                    .padding(.vertical, 3)
                }
            }
            .navigationTitle("Methods")
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
                    if let url = lanURL("") { Link("Open home Setup Center", destination: url) }
                    Text("The Setup Center is the server/router guide and recovery surface. The Router VPN app is the daily-use VPN client.")
                        .font(.caption).foregroundStyle(.secondary)
                }

                Section("Small direct downloads") {
                    if let u = lanURL("router-vpn-bundle.json") { Link("Private router profile JSON", destination: u) }
                    if let u = lanURL("asus-merlin-router-vpn-forwards.sh") { Link("ASUS Merlin forwarding helper", destination: u) }
                    if let u = lanURL("router-vpn-device-setup.html") { Link("Universal / native setup page", destination: u) }
                    if let u = lanURL("SHA256SUMS") { Link("Checksums", destination: u) }
                    Text("The full ZIP stays available only as an offline/advanced fallback.")
                        .font(.caption).foregroundStyle(.secondary)
                }

                Section("Router-side methods") {
                    Label("SOCKS5 — internal/LAN only", systemImage: "arrow.left.arrow.right")
                    Label("SOCKS5 + TLS / OverTLS", systemImage: "lock.shield")
                    Label("Shadowsocks 2022", systemImage: "network")
                    Label("ShadowsocksR — legacy compatibility", systemImage: "clock.arrow.circlepath")
                    Label("WireGuard / AmneziaWG native configs", systemImage: "shield")
                    Label("Custom / universal protocol configs", systemImage: "doc.text")
                    Text("Exact QR/config/download details are generated by your home node because they contain node-specific keys and secrets.")
                        .font(.caption).foregroundStyle(.secondary)
                }

                Section("macOS security note") {
                    Text("If macOS blocks a locally-built Router VPN component, verify it came from your bundle/build, then use System Settings → Privacy & Security → Open Anyway. The Setup Center keeps the current exact steps.")
                        .font(.caption)
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
                ScrollView { onboardingContent.frame(maxWidth: .infinity, alignment: .leading).padding(.vertical) }
                HStack {
                    Button("Back") { if step > 0 { step -= 1 } }.disabled(step == 0)
                    Spacer()
                    Button("Close") { isPresented = false }
                    Spacer()
                    Button(step == lastStep ? "Finish" : "Next") {
                        if step == lastStep { done = true; step = 0; isPresented = false }
                        else { step += 1 }
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
            OnboardingPage(title: "Start simple", text: "If the home node is already deployed, you do not need the giant ZIP. Stay on home Wi‑Fi, enter the AI Board LAN IP, and tap Import directly from home LAN in Nodes. The app downloads the small private router profile and links itself.")
        case 1:
            VStack(alignment: .leading, spacing: 12) {
                OnboardingPage(title: "Link this app", text: "Default AI Board address is usually 192.168.50.133. LAN import and Files import are both supported.")
                TextField("AI Board LAN IP / hostname", text: $model.lanImportHost)
                    .textFieldStyle(.roundedBorder).textInputAutocapitalization(.never).autocorrectionDisabled()
                Button("Import from LAN now") { Task { await model.importFromLAN() } }.buttonStyle(.borderedProminent)
                Button("Choose router-vpn-bundle.json") { importing = true }
                Text(model.message).font(.caption).foregroundStyle(.secondary)
            }
        case 2:
            OnboardingPage(title: "If the server is not deployed yet", text: "On the ASUS AI Board open Portainer → Stacks → Add stack → Repository. Use server/portainer-current.yaml. Normal values: WAN_INTERFACE=eth0, LAN_CIDR=192.168.50.0/24, ADGUARD4=192.168.50.133. Leave ENDPOINT blank for auto-detection.")
        case 3:
            OnboardingPage(title: "ASUS router forwarding", text: "Enable SSH/JFFS scripts on the ASUS router, then use the Setup Center's current forwarding helper. It preserves existing nat-start/firewall-start content and checks the router firewall backend. Never WAN-expose SOCKS5 1080, Setup Center 8786, router API 8787, Portainer, AdGuard admin, or SSH.")
        case 4:
            OnboardingPage(title: "Choose how you connect", text: "AUTO is the simple default. Manual mode selection shows each logical mode once. Where both bases exist, choose Auto, WireGuard, or AmneziaWG and optionally allow automatic fallback to the other base. Full home-LAN access is enabled by default.")
        case 5:
            OnboardingPage(title: "Native / universal methods", text: "The home Setup Center exposes WireGuard, AmneziaWG, Shadowsocks 2022, Hysteria2, REALITY/Xray, SOCKS5, SOCKS5+TLS/OverTLS, ShadowsocksR legacy, and custom/universal configs with node-specific download/QR instructions. Use the Router VPN app when you want AUTO/SMART/CUSTOM and multi-mode behavior.")
        case 6:
            OnboardingPage(title: "DNS, forwarding, and safety", text: "Home AdGuard is the default. Public DNS candidates are benchmarked from the home exit, including secondary IPv4 resolvers. Incoming forwarding/Protected DMZ requires a WG/AWG peer path. The app will never claim a kill switch or remote peer kick until the platform/backend implementation is actually validated.")
        default:
            OnboardingPage(title: "Ready", text: "The full guide remains available in Setup at all times. Finishing only hides first-run onboarding; it never deletes your router profile. The native Packet Tunnel engine is linked separately from this UI and will fail visibly rather than fake a successful VPN connection if an engine is unavailable.")
        }
    }
}

private struct OnboardingPage: View {
    let title: String
    let text: String
    var body: some View { VStack(alignment: .leading, spacing: 10) { Text(title).font(.title2.bold()); Text(text); }.frame(maxWidth: .infinity, alignment: .leading) }
}

private struct NativeCard<Content: View>: View {
    @ViewBuilder let content: Content
    var body: some View { VStack(alignment: .leading, spacing: 12) { content }.padding(16).frame(maxWidth: .infinity, alignment: .leading).background(.thinMaterial, in: RoundedRectangle(cornerRadius: 18)) }
}
