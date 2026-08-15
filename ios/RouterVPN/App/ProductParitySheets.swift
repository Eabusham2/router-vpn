import Foundation
import SwiftUI

struct RouterVPNModePresentation: Identifiable {
    let id: String
    let name: String
    let description: String
    let layers: [String]
    let pingMinMs: Double
    let pingMaxMs: Double
    let trafficMinPct: Double
    let trafficMaxPct: Double
    let speedLossMinPct: Double
    let speedLossMaxPct: Double
    let available: Bool
    let runtime: String
    let reason: String
}

private struct RouterVPNDNSBenchmarkEnvelope: Codable {
    var winner: DNSBenchmarkResult
    var results: [DNSBenchmarkResult]
}

private struct RouterVPNDNSPreset: Identifiable {
    let id: String
    let name: String
    let host: String
    let serverName: String

    static let common: [RouterVPNDNSPreset] = [
        .init(id: "cf4", name: "Cloudflare IPv4", host: "1.1.1.1", serverName: "cloudflare-dns.com"),
        .init(id: "cf6", name: "Cloudflare IPv6", host: "2606:4700:4700::1111", serverName: "cloudflare-dns.com"),
        .init(id: "g4", name: "Google IPv4", host: "8.8.8.8", serverName: "dns.google"),
        .init(id: "g6", name: "Google IPv6", host: "2001:4860:4860::8888", serverName: "dns.google"),
        .init(id: "q4", name: "Quad9 IPv4", host: "9.9.9.9", serverName: "dns.quad9.net"),
        .init(id: "q6", name: "Quad9 IPv6", host: "2620:fe::fe", serverName: "dns.quad9.net")
    ]
}

extension RouterVPNModel {
    func productModePresentations() -> [RouterVPNModePresentation] {
        logicalModes.map { logical in
            let raw = logical.variants.values.compactMap { runtimeID in modes.first(where: { $0.id == runtimeID }) }
            let layers = Array(Set(raw.flatMap { mode in
                // The shipped raw mode description is protection text; the exact layer IDs live in
                // the bundle profile catalog on desktop. On Apple, preserve a truthful compact layer
                // summary from each raw protection string instead of inventing unavailable engines.
                mode.protection.split(separator: "+").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            })).sorted()
            let runnable = iosRunnableLogicalModes.contains(where: { $0.id == logical.id })
            return RouterVPNModePresentation(
                id: logical.id,
                name: logical.name,
                description: logical.description,
                layers: layers,
                pingMinMs: raw.map(\.pingMinMs).min() ?? 0,
                pingMaxMs: raw.map(\.pingMaxMs).max() ?? 0,
                trafficMinPct: raw.map(\.trafficMinPct).min() ?? 0,
                trafficMaxPct: raw.map(\.trafficMaxPct).max() ?? 0,
                speedLossMinPct: raw.map(\.speedLossMinPct).min() ?? 0,
                speedLossMaxPct: raw.map(\.speedLossMaxPct).max() ?? 0,
                available: runnable,
                runtime: runnable ? runtimeLabel(for: logical) : "Unavailable",
                reason: runtimeReason(for: logical)
            )
        }
    }

    func productDNSProfile() -> RouterProfile? {
        guard let bundle else { return nil }
        return bundle.routerProfiles.first(where: { $0.id == bundle.selectedRouterID }) ?? bundle.routerProfiles.first
    }

    func applyProductDNSPolicy(mode: String, protocolName: String, host: String, port: Int, serverName: String, path: String) throws {
        guard var current = bundle else { throw NSError(domain: "RouterVPN.DNS", code: 1, userInfo: [NSLocalizedDescriptionKey: "Import or pair a Router VPN node first."]) }
        guard let index = current.routerProfiles.firstIndex(where: { $0.id == current.selectedRouterID }) ?? current.routerProfiles.indices.first else {
            throw NSError(domain: "RouterVPN.DNS", code: 2, userInfo: [NSLocalizedDescriptionKey: "No selected Router VPN profile."])
        }
        guard current.routerProfiles[index].normalizedNodeKind == "router-vpn" else {
            throw NSError(domain: "RouterVPN.DNS", code: 3, userInfo: [NSLocalizedDescriptionKey: "External nodes own their DNS runtime; Router VPN DNS policy applies to home nodes only."])
        }
        guard !connected else {
            throw NSError(domain: "RouterVPN.DNS", code: 4, userInfo: [NSLocalizedDescriptionKey: "Disconnect before changing DNS policy so the next PacketTunnel starts coherently."])
        }
        var profile = current.routerProfiles[index]
        let value = mode.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let trimmedHost = host.trimmingCharacters(in: .whitespacesAndNewlines)
        var selectedProtocol = protocolName.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        var selectedHost = trimmedHost
        var selectedPort = port
        var selectedServerName = serverName.trimmingCharacters(in: .whitespacesAndNewlines)
        var selectedPath = path.trimmingCharacters(in: .whitespacesAndNewlines)
        switch value {
        case "home":
            selectedHost = profile.adGuardIPv4.isEmpty ? profile.adGuardIPv6 : profile.adGuardIPv4
            selectedProtocol = "udp"; selectedPort = 53; selectedServerName = ""; selectedPath = ""
        case "fastest":
            guard let fastest = profile.fastestDNSHost, !fastest.isEmpty else { throw NSError(domain: "RouterVPN.DNS", code: 5, userInfo: [NSLocalizedDescriptionKey: "Run DNS Retest while connected before selecting Fastest."]) }
            selectedHost = fastest; selectedProtocol = "udp"; selectedPort = 53; selectedServerName = ""; selectedPath = ""
        case "custom":
            guard selectedProtocol == "udp" || selectedProtocol == "tcp" else { throw NSError(domain: "RouterVPN.DNS", code: 6, userInfo: [NSLocalizedDescriptionKey: "Custom DNS must use UDP or TCP."]) }
            if selectedPort == 0 { selectedPort = 53 }
        case "dot":
            selectedProtocol = "tls"; if selectedPort == 0 { selectedPort = 853 }
        case "doh":
            selectedProtocol = "https"; if selectedPort == 0 { selectedPort = 443 }; if selectedPath.isEmpty { selectedPath = "/dns-query" }
        case "doh3":
            selectedProtocol = "h3"; if selectedPort == 0 { selectedPort = 443 }; if selectedPath.isEmpty { selectedPath = "/dns-query" }
        case "rescue":
            selectedProtocol = "rescue"; if selectedHost.isEmpty { selectedHost = profile.fastestDNSHost ?? "1.1.1.1" }; if selectedPort == 0 { selectedPort = 443 }; if selectedPath.isEmpty { selectedPath = "/dns-query" }
        default:
            throw NSError(domain: "RouterVPN.DNS", code: 7, userInfo: [NSLocalizedDescriptionKey: "Unsupported DNS mode."])
        }
        guard !selectedHost.isEmpty else { throw NSError(domain: "RouterVPN.DNS", code: 8, userInfo: [NSLocalizedDescriptionKey: "DNS host is required."]) }
        guard (1...65535).contains(selectedPort) else { throw NSError(domain: "RouterVPN.DNS", code: 9, userInfo: [NSLocalizedDescriptionKey: "DNS port must be 1–65535."]) }
        if ["dot", "doh", "doh3"].contains(value), selectedServerName.isEmpty {
            selectedServerName = RouterVPNDNSPreset.common.first(where: { $0.host == selectedHost })?.serverName ?? (selectedHost.contains(".") && selectedHost.rangeOfCharacter(from: .letters) != nil ? selectedHost : "")
            guard !selectedServerName.isEmpty else { throw NSError(domain: "RouterVPN.DNS", code: 10, userInfo: [NSLocalizedDescriptionKey: "Encrypted DNS to an IP address requires a TLS server name."]) }
        }
        if !selectedPath.isEmpty && !selectedPath.hasPrefix("/") { throw NSError(domain: "RouterVPN.DNS", code: 11, userInfo: [NSLocalizedDescriptionKey: "DNS HTTPS path must start with /."]) }
        profile.dnsMode = value
        profile.dnsProtocol = selectedProtocol
        profile.dnsHost = selectedHost
        profile.dnsPort = selectedPort
        profile.dnsServerName = selectedServerName
        profile.dnsPath = selectedPath
        current.routerProfiles[index] = profile
        try importBundle(JSONEncoder().encode(current))
        message = "DNS policy saved for the next connection: \(value.uppercased())"
    }

    func retestProductDNS() async {
        guard connected else { message = "Connect the selected Router VPN node before DNS Retest."; return }
        guard var current = bundle,
              let index = current.routerProfiles.firstIndex(where: { $0.id == current.selectedRouterID }) ?? current.routerProfiles.indices.first else { message = "No selected Router VPN node."; return }
        let profile = current.routerProfiles[index]
        guard profile.normalizedNodeKind == "router-vpn", !profile.routerAPI.isEmpty, !profile.apiToken.isEmpty else { message = "Selected node has no authenticated Router VPN DNS benchmark path."; return }
        guard let url = URL(string: profile.routerAPI.trimmingCharacters(in: CharacterSet(charactersIn: "/")) + "/api/dns/benchmark") else { message = "Selected router DNS benchmark URL is invalid."; return }
        do {
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.timeoutInterval = 45
            request.setValue("Bearer \(profile.apiToken)", forHTTPHeaderField: "Authorization")
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = Data("{}".utf8)
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else { throw URLError(.badServerResponse) }
            let result = try JSONDecoder().decode(RouterVPNDNSBenchmarkEnvelope.self, from: data)
            var updated = current.routerProfiles[index]
            updated.dnsResults = result.results
            if !result.winner.address.isEmpty {
                updated.fastestDNSHost = result.winner.address
                updated.fastestDNSName = result.winner.name
                updated.fastestDNSLatencyMs = result.winner.latencyMs
                if (updated.dnsMode ?? "").lowercased() == "fastest" { updated.dnsHost = result.winner.address }
            }
            current.routerProfiles[index] = updated
            try importBundle(JSONEncoder().encode(current))
            message = "DNS Retest complete from home node • \(result.winner.name) \(String(format: "%.2f", result.winner.latencyMs ?? 0)) ms"
        } catch { message = "DNS Retest failed: \(error.localizedDescription)" }
    }
}

struct RouterVPNModeMetricsSheet: View {
    @EnvironmentObject var model: RouterVPNModel
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        NavigationStack {
            List(model.productModePresentations()) { mode in
                VStack(alignment: .leading, spacing: 7) {
                    HStack { Text(mode.name).font(.headline); Spacer(); Text(mode.available ? mode.runtime : "Unavailable").foregroundStyle(mode.available ? .green : .secondary) }
                    Text(mode.description).font(.caption).foregroundStyle(.secondary)
                    Text("Layers: \(mode.layers.isEmpty ? "—" : mode.layers.joined(separator: " • "))").font(.caption)
                    Text(String(format: "Added latency %.1f–%.1f ms • traffic +%.1f–%.1f%% • speed loss %.1f–%.1f%%", mode.pingMinMs, mode.pingMaxMs, mode.trafficMinPct, mode.trafficMaxPct, mode.speedLossMinPct, mode.speedLossMaxPct)).font(.caption)
                    Text("Readiness: \(mode.available ? "Ready" : "Unavailable") • \(mode.reason)").font(.caption2).foregroundStyle(.secondary)
                }.padding(.vertical, 4)
            }
            .navigationTitle("Mode details")
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
        }
    }
}

struct RouterVPNDNSSettingsSheet: View {
    @EnvironmentObject var model: RouterVPNModel
    @Environment(\.dismiss) private var dismiss
    @State private var mode = "home"
    @State private var protocolName = "udp"
    @State private var host = ""
    @State private var port = "53"
    @State private var serverName = ""
    @State private var path = "/dns-query"
    @State private var preset = ""
    private let modes = [("Home AdGuard","home"),("Fastest measured","fastest"),("Custom UDP/TCP","custom"),("DNS-over-TLS","dot"),("DNS-over-HTTPS","doh"),("DNS-over-HTTP/3","doh3"),("DNS Rescue","rescue")]

    var body: some View {
        NavigationStack {
            Form {
                Section("Policy") {
                    Picker("DNS mode", selection: $mode) { ForEach(modes, id: \.1) { Text($0.0).tag($0.1) } }
                    Picker("Common resolver", selection: $preset) {
                        Text("Manual / current").tag("")
                        ForEach(RouterVPNDNSPreset.common) { Text($0.name).tag($0.id) }
                    }.onChange(of: preset) { _, value in if let item = RouterVPNDNSPreset.common.first(where: { $0.id == value }) { host = item.host; serverName = item.serverName } }
                    if mode == "custom" { Picker("Protocol", selection: $protocolName) { Text("UDP").tag("udp"); Text("TCP").tag("tcp") } }
                    if !["home","fastest"].contains(mode) {
                        TextField("Resolver host / IPv4 / IPv6", text: $host).textInputAutocapitalization(.never).autocorrectionDisabled()
                        TextField("Port", text: $port).keyboardType(.numberPad)
                    }
                    if ["dot","doh","doh3"].contains(mode) { TextField("TLS server name", text: $serverName).textInputAutocapitalization(.never).autocorrectionDisabled() }
                    if ["doh","doh3","rescue"].contains(mode) { TextField("HTTPS path", text: $path).textInputAutocapitalization(.never).autocorrectionDisabled() }
                    Button("Save DNS policy") {
                        do { try model.applyProductDNSPolicy(mode: mode, protocolName: protocolName, host: host, port: Int(port) ?? 0, serverName: serverName, path: path) }
                        catch { model.message = "DNS policy failed: \(error.localizedDescription)" }
                    }
                    .disabled(model.connected)
                    Text("Disconnect before changing policy. The selected policy is applied by the next PacketTunnel runtime; saving it is not counted as active-DNS proof.").font(.caption).foregroundStyle(.secondary)
                }
                Section("Home-node DNS RTT benchmark") {
                    Button("Retest resolvers from home node") { Task { await model.retestProductDNS() } }.disabled(!model.connected)
                    if let profile = model.productDNSProfile() {
                        if let fastest = profile.fastestDNSHost, !fastest.isEmpty { Text("Fastest: \(profile.fastestDNSName ?? fastest) • \(String(format: "%.2f", profile.fastestDNSLatencyMs ?? 0)) ms • \(fastest)") }
                        ForEach((profile.dnsResults ?? []).sorted { lhs, rhs in
                            if lhs.working != rhs.working { return lhs.working && !rhs.working }
                            return (lhs.latencyMs ?? .greatestFiniteMagnitude) < (rhs.latencyMs ?? .greatestFiniteMagnitude)
                        }, id: \.address) { result in
                            Button {
                                mode = "custom"; protocolName = "udp"; host = result.address; port = "53"; serverName = RouterVPNDNSPreset.common.first(where: { $0.host == result.address })?.serverName ?? ""
                            } label: {
                                HStack { VStack(alignment: .leading) { Text(result.name); Text("\(result.address) • \(result.family ?? "")").font(.caption2).foregroundStyle(.secondary) }; Spacer(); Text(result.working ? String(format: "%.2f ms", result.latencyMs ?? 0) : "failed") }
                            }.disabled(!result.working)
                        }
                    }
                    Text("Benchmark numbers are median A/AAAA DNS query RTTs measured by the selected home node—not ICMP ping.").font(.caption).foregroundStyle(.secondary)
                }
                Section { Text(model.message).font(.caption) }
            }
            .navigationTitle("DNS")
            .onAppear {
                if let profile = model.productDNSProfile() {
                    mode = profile.dnsMode ?? "home"; protocolName = profile.dnsProtocol ?? "udp"; host = profile.dnsHost ?? ""; port = String(profile.dnsPort ?? 0); serverName = profile.dnsServerName ?? ""; path = profile.dnsPath ?? "/dns-query"
                }
            }
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
        }
    }
}
