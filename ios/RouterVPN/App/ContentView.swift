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
                        Toggle("AUTO — native WireGuard on this iOS build", isOn: $model.auto)
                        if !model.auto {
                            Picker("Mode", selection: $model.selectedLogicalMode) {
                                ForEach(model.iosRunnableLogicalModes) { mode in
                                    Text("\(mode.name) — WireGuard").tag(mode.id)
                                }
                            }
                            .pickerStyle(.menu)
                            Text("Manual iOS support is intentionally limited to Raw WireGuard until additional PacketTunnel engines are linked and proven.")
                                .font(.caption).foregroundStyle(.secondary)
                        }

                        Divider()
                        Label("Native engine: WireGuard", systemImage: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                        Text("LAN Off, DAITA-like cover traffic, Jumbo TUN override, AmneziaWG, layered modes, ALL/MAX, SMART/CUSTOM and multihop are not exposed as working controls on this iOS build. The imported WireGuard profile supplies routes, DNS and MTU.")
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
                    }

                    NativeCard {
                        Text("Connection truth").font(.headline)
                        Text(model.auto ? "AUTO currently resolves to the proven native WireGuard path on iOS." : "Manual mode: Raw WireGuard.")
                            .font(.caption).foregroundStyle(.secondary)
                        Text("Connected is reported only after the PacketTunnel starts and the selected node returns the exact private node-identity proof.")
                            .font(.caption).foregroundStyle(.secondary)
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
                    Text("Router linking is a small node-data operation; it does not reinstall the app or download the all-platform package.")
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
                    Text("Forwarding is authenticated through the tunnel and requires a real peer path; proxy-only modes cannot fake DNAT semantics.")
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
                    Label("DNS comes from the imported native WireGuard profile", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                    Text("The home Setup Center benchmarks and selects DNS from the home exit. This iOS PacketTunnel applies the DNS servers embedded in wg.conf. An in-app DNS override is not shown until it has a real runtime effect.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section("Home resolver") {
                    Text(model.bundle?.adGuardIPv4 ?? "10.77.0.1")
                        .textSelection(.enabled)
                    Text("Home AdGuard remains the normal tunnel DNS when that address is present in the imported profile.")
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
                    Text("The home node can generate all Router VPN methods. This iOS app currently executes only native WireGuard; the rest remain visible for capability truth and Setup Center use, not as fake connect buttons.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                ForEach(model.logicalModes) { mode in
                    let available = mode.id == "base-raw" && mode.variants["wg"] == "wg"
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            Text(mode.name).bold()
                            Spacer()
                            Text(available ? "Native WG available" : "Unavailable in this iOS build")
                                .font(.caption2)
                                .foregroundStyle(available ? .green : .secondary)
                        }
                        Text(mode.description).font(.caption).foregroundStyle(.secondary)
                        if !available {
                            Text("Use the home Setup Center for proven external/native configuration where supported, or another Router VPN platform build with the required engine.")
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
                    if let url = lanURL("") { Link("Open Full Guide / home Setup Center", destination: url) }
                    Text("The Full Guide remains independently accessible after onboarding is completed or dismissed.")
                        .font(.caption).foregroundStyle(.secondary)
                }

                Section("Small direct downloads") {
                    if let u = lanURL("router-vpn-bundle.json") { Link("Private router profile JSON", destination: u) }
                    if let u = lanURL("asus-merlin-router-vpn-forwards.sh") { Link("ASUS Merlin forwarding helper", destination: u) }
                    if let u = lanURL("router-vpn-device-setup.html") { Link("Universal / native setup page", destination: u) }
                    if let u = lanURL("SHA256SUMS") { Link("Checksums", destination: u) }
                    Text("The full ZIP is an advanced/offline fallback. Normal app setup links node data separately.")
                        .font(.caption).foregroundStyle(.secondary)
                }

                Section("Router-side methods") {
                    Label("SOCKS5 — internal/LAN only", systemImage: "arrow.left.arrow.right")
                    Label("SOCKS5 + TLS / OverTLS", systemImage: "lock.shield")
                    Label("Shadowsocks 2022", systemImage: "network")
                    Label("Hysteria2", systemImage: "bolt.horizontal.circle")
                    Label("WireGuard / AmneziaWG native configs", systemImage: "shield")
                    Label("Custom / universal protocol configs", systemImage: "doc.text")
                    Text("Exact QR/config/download instructions are generated by your home node because they contain node-specific values and must match the deployed server.")
                        .font(.caption).foregroundStyle(.secondary)
                }

                Section("Apple distribution truth") {
                    Text("The CI artifact is unsigned/re-signable. A normal long-term iOS distribution path still requires Apple signing/provisioning. Router VPN does not recommend disabling iOS or macOS platform security globally.")
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
                        } else {
                            step += 1
                        }
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
            OnboardingPage(title: "Start simple", text: "If the home node is already deployed, stay on home Wi‑Fi and link this app with the small private router profile. Installing the app and adding a router are separate operations.")
        case 1:
            VStack(alignment: .leading, spacing: 12) {
                OnboardingPage(title: "Add your router", text: "Default AI Board address is usually 192.168.50.133. Enter the LAN IP/hostname and import directly, or choose router-vpn-bundle.json from Files. iOS Local Network permission may be requested for LAN linking.")
                TextField("AI Board LAN IP / hostname", text: $model.lanImportHost)
                    .textFieldStyle(.roundedBorder)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                Button("Import from LAN now") { Task { await model.importFromLAN() } }
                    .buttonStyle(.borderedProminent)
                Button("Choose router-vpn-bundle.json") { importing = true }
                Text(model.message).font(.caption).foregroundStyle(.secondary)
            }
        case 2:
            OnboardingPage(title: "Deploy the home node from zero", text: "On the ASUS AI Board open Portainer → Stacks → Add stack → Repository and use server/portainer-current.yaml. Normal values include WAN_INTERFACE=eth0, LAN_CIDR=192.168.50.0/24 and ADGUARD4=192.168.50.133. Leave ENDPOINT blank for auto-detection when appropriate.")
        case 3:
            OnboardingPage(title: "ASUS router forwarding", text: "Enable the required ASUS SSH/JFFS support, then use the current Setup Center forwarding helper. It preserves existing nat-start/firewall-start content and checks the firewall backend. Never WAN-expose SOCKS5 1080, Setup Center 8786, router API 8787, Portainer, AdGuard admin, SSH, or the OverTLS loopback backend.")
        case 4:
            OnboardingPage(title: "Connect on iPhone or iPad", text: "AUTO currently uses the proven native WireGuard PacketTunnel. Manual mode currently offers Raw WireGuard only. The app does not present AmneziaWG, layered, SMART/CUSTOM, ALL/MAX or multihop as working iOS controls until those engines and lifecycles are implemented and validated.")
        case 5:
            OnboardingPage(title: "Other methods", text: "The home Setup Center can expose proven native/external instructions and QR/config downloads for WireGuard, AmneziaWG, Shadowsocks 2022, Hysteria2, REALITY/Xray, SOCKS5, SOCKS5+TLS/OverTLS and other supported methods. Availability there does not imply this iOS PacketTunnel embeds every engine.")
        case 6:
            OnboardingPage(title: "DNS, LAN, forwarding and safety", text: "The current iOS WireGuard path applies DNS, routes and MTU from the imported wg.conf. LAN Off, in-app DNS override, DAITA-like padding and Jumbo override are not shown as active controls yet. Strict Apple kill-switch requests fail closed until a true always-on/lockdown lifecycle can be proven. Forwarding requires an authenticated real peer path.")
        default:
            OnboardingPage(title: "Ready", text: "The Full Guide remains available in Setup at all times. The PacketTunnel uses pinned native WireGuard and requires exact selected-node private identity proof before reporting success. Unsupported engines fail visibly rather than fake a successful VPN connection.")
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
