import Foundation
@preconcurrency import Network
import SwiftUI

private struct IOSDNSPreset: Identifiable, Hashable, Sendable {
    let id: String
    let name: String
    let address: String
    let serverName: String
    var family: String { address.contains(":") ? "IPv6" : "IPv4" }
}

struct IOSDNSPolicyView: View {
    @EnvironmentObject var model: RouterVPNModel
    @State private var mode = "home"
    @State private var protocolName = "udp"
    @State private var host = ""
    @State private var port = "53"
    @State private var serverName = ""
    @State private var path = "/dns-query"
    @State private var results: [DNSBenchmarkResult] = []
    @State private var status = ""
    @State private var benchmarking = false

    private let modeValues = [
        ("Home AdGuard", "home"), ("Fastest measured", "fastest"), ("Custom UDP/TCP", "custom"),
        ("DNS over TLS", "dot"), ("DNS over HTTPS", "doh"), ("DNS over HTTP/3", "doh3"), ("Rescue", "rescue")
    ]
    private let presets = [
        IOSDNSPreset(id: "cf4a", name: "Cloudflare Primary", address: "1.1.1.1", serverName: "cloudflare-dns.com"),
        IOSDNSPreset(id: "cf4b", name: "Cloudflare Secondary", address: "1.0.0.1", serverName: "cloudflare-dns.com"),
        IOSDNSPreset(id: "cf6a", name: "Cloudflare IPv6 Primary", address: "2606:4700:4700::1111", serverName: "cloudflare-dns.com"),
        IOSDNSPreset(id: "cf6b", name: "Cloudflare IPv6 Secondary", address: "2606:4700:4700::1001", serverName: "cloudflare-dns.com"),
        IOSDNSPreset(id: "g4a", name: "Google Primary", address: "8.8.8.8", serverName: "dns.google"),
        IOSDNSPreset(id: "g4b", name: "Google Secondary", address: "8.8.4.4", serverName: "dns.google"),
        IOSDNSPreset(id: "g6a", name: "Google IPv6 Primary", address: "2001:4860:4860::8888", serverName: "dns.google"),
        IOSDNSPreset(id: "g6b", name: "Google IPv6 Secondary", address: "2001:4860:4860::8844", serverName: "dns.google"),
        IOSDNSPreset(id: "q4a", name: "Quad9 Primary", address: "9.9.9.9", serverName: "dns.quad9.net"),
        IOSDNSPreset(id: "q4b", name: "Quad9 Secondary", address: "149.112.112.112", serverName: "dns.quad9.net"),
        IOSDNSPreset(id: "q6a", name: "Quad9 IPv6 Primary", address: "2620:fe::fe", serverName: "dns.quad9.net"),
        IOSDNSPreset(id: "q6b", name: "Quad9 IPv6 Secondary", address: "2620:fe::9", serverName: "dns.quad9.net")
    ]

    var body: some View {
        NavigationStack {
            Form {
                Section("Selected DNS policy") {
                    Picker("DNS", selection: $mode) {
                        ForEach(modeValues, id: \.1) { Text($0.0).tag($0.1) }
                    }
                    .onChange(of: mode) { value in applyModeDefaults(value) }
                    if mode == "custom" {
                        Picker("Transport", selection: $protocolName) { Text("UDP").tag("udp"); Text("TCP").tag("tcp") }
                    }
                    if ["custom", "dot", "doh", "doh3"].contains(mode) {
                        TextField("Resolver IP or hostname", text: $host)
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                        TextField("Port", text: $port).keyboardType(.numberPad)
                    }
                    if ["dot", "doh", "doh3"].contains(mode) {
                        TextField("TLS server name", text: $serverName)
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                    }
                    if ["doh", "doh3"].contains(mode) {
                        TextField("DNS HTTP path", text: $path)
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                    }
                    Button("Save DNS for next connection") { savePolicy() }
                        .disabled(model.profileMutationBlocked)
                    if model.profileMutationBlocked { Text("Disconnect or let the active VPN transition finish before changing the DNS policy.").font(.caption).foregroundStyle(.orange) }
                }

                Section("Runtime truth") {
                    Text("WireGuardKit can enforce Home/Fastest/Custom UDP when the selected resolver is an IP. Explicit TCP, DoT, DoH and DoH3 require a self-contained Libbox mode. Mode readiness changes with the selected DNS policy instead of pretending WireGuard can provide an encrypted DNS transport it does not own.")
                        .font(.caption).foregroundStyle(.secondary)
                    Text("Libbox receives the selected resolver as a typed sing-box DNS server, detoured through the selected non-direct outbound with DNS hijacking. A saved choice is still not counted as physical runtime proof until the live PacketTunnel test passes.")
                        .font(.caption).foregroundStyle(.secondary)
                }

                Section("Common resolvers") {
                    ForEach(presets) { preset in
                        Button {
                            usePreset(preset)
                        } label: {
                            HStack {
                                VStack(alignment: .leading) {
                                    Text(preset.name)
                                    Text("\(preset.address) • \(preset.family)").font(.caption2).foregroundStyle(.secondary)
                                }
                                Spacer()
                                if host == preset.address { Image(systemName: "checkmark") }
                            }
                        }
                        .buttonStyle(.plain)
                    }
                }

                Section("Measured DNS RTT") {
                    Button(benchmarking ? "Testing real DNS queries…" : "Retest over active VPN path") {
                        Task { await retest() }
                    }
                    .disabled(!model.connected || benchmarking)
                    Text(model.connected
                         ? "Retest sends real DNS A queries to each resolver over the device's current route. While Router VPN is connected, that route is the selected VPN path; this is DNS-query RTT, not ICMP ping."
                         : "Connect first so Retest measures from the selected VPN path instead of your unrelated direct network.")
                        .font(.caption).foregroundStyle(.secondary)
                    ForEach(Array(results.enumerated()), id: \.offset) { _, item in
                        HStack {
                            VStack(alignment: .leading) {
                                Text(item.name)
                                Text("\(item.address) • \(item.family ?? (item.address.contains(":") ? "IPv6" : "IPv4"))")
                                    .font(.caption2).foregroundStyle(.secondary)
                            }
                            Spacer()
                            if item.working, let value = item.latencyMs { Text(String(format: "%.2f ms", value)).monospacedDigit() }
                            else { Text("No reply").foregroundStyle(.secondary) }
                        }
                    }
                }

                if !status.isEmpty { Section("Status") { Text(status).font(.caption) } }
            }
            .navigationTitle("DNS")
            .onAppear { load() }
        }
    }

    private func selectedProfile() -> RouterProfile? {
        guard let bundle = model.bundle else { return nil }
        return bundle.routerProfiles.first(where: { $0.id == bundle.selectedRouterID }) ?? bundle.routerProfiles.first
    }

    private func load() {
        guard let p = selectedProfile(), p.normalizedNodeKind == "router-vpn" else { status = "Pair/import a Router VPN node first."; return }
        mode = (p.dnsMode ?? "home").lowercased()
        protocolName = (p.dnsProtocol ?? "udp").lowercased()
        host = p.dnsHost ?? ""
        port = String(p.dnsPort ?? defaultPort(mode))
        serverName = p.dnsServerName ?? ""
        path = p.dnsPath ?? "/dns-query"
        results = sorted(p.dnsResults ?? [])
    }

    private func savePolicy() {
        guard !model.profileMutationBlocked else { status = "Disconnect or let the active VPN transition finish before changing the DNS policy."; return }
        guard var bundle = model.bundle,
              let index = bundle.routerProfiles.firstIndex(where: { $0.id == bundle.selectedRouterID }) ?? bundle.routerProfiles.indices.first else {
            status = "Pair/import a Router VPN node first."; return
        }
        var p = bundle.routerProfiles[index]
        guard p.normalizedNodeKind == "router-vpn" else { status = "External exits own their DNS/runtime policy."; return }
        p.dnsMode = mode
        p.dnsProtocol = protocolName
        p.dnsHost = host.trimmingCharacters(in: .whitespacesAndNewlines)
        p.dnsPort = Int(port) ?? defaultPort(mode)
        p.dnsServerName = serverName.trimmingCharacters(in: .whitespacesAndNewlines)
        p.dnsPath = path.trimmingCharacters(in: .whitespacesAndNewlines)
        do {
            _ = try IOSDNSRuntimePolicy.resolve(p)
            bundle.routerProfiles[index] = p
            try model.importBundle(JSONEncoder().encode(bundle))
            status = "DNS policy saved and patched into compatible iOS runtimes for the next connection."
            load()
        } catch { status = "DNS policy rejected: \(error.localizedDescription)" }
    }

    private func retest() async {
        guard model.connected else { status = "Connect first so DNS RTT uses the selected VPN path."; return }
        guard var bundle = model.bundle,
              let index = bundle.routerProfiles.firstIndex(where: { $0.id == bundle.selectedRouterID }) ?? bundle.routerProfiles.indices.first else { return }
        benchmarking = true
        defer { benchmarking = false }
        var candidates = presets.map { ($0.name, $0.address, $0.family) }
        let profile = bundle.routerProfiles[index]
        for (name, address, family) in [
            ("Home AdGuard IPv4", profile.adGuardIPv4, "IPv4"),
            ("Home AdGuard IPv6", profile.adGuardIPv6, "IPv6")
        ] where !address.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            if !candidates.contains(where: { $0.1 == address }) { candidates.insert((name, address, family), at: 0) }
        }
        var measured: [DNSBenchmarkResult] = []
        for candidate in candidates {
            let value = await IOSDNSRTTProbe.query(address: candidate.1)
            measured.append(DNSBenchmarkResult(name: candidate.0, address: candidate.1, family: candidate.2, latencyMs: value, working: value != nil))
        }
        results = sorted(measured)
        var p = bundle.routerProfiles[index]
        p.dnsResults = results
        if let best = results.first(where: { $0.working && $0.latencyMs != nil }) {
            p.fastestDNSHost = best.address
            p.fastestDNSName = best.name
            p.fastestDNSLatencyMs = best.latencyMs
        } else {
            p.fastestDNSHost = nil; p.fastestDNSName = nil; p.fastestDNSLatencyMs = nil
        }
        bundle.routerProfiles[index] = p
        do {
            try model.importBundle(JSONEncoder().encode(bundle))
            status = p.fastestDNSHost == nil ? "Retest completed: no resolver returned a valid DNS answer." : "Retest saved the fastest real DNS-query RTT for this node/path."
            load()
        } catch { status = "DNS benchmark save failed: \(error.localizedDescription)" }
    }

    private func usePreset(_ preset: IOSDNSPreset) {
        host = preset.address
        serverName = preset.serverName
        if ["home", "fastest", "rescue"].contains(mode) { mode = "custom"; protocolName = "udp"; port = "53" }
    }

    private func applyModeDefaults(_ value: String) {
        switch value {
        case "custom": if port.isEmpty || port == "443" || port == "853" { port = "53" }
        case "dot": port = "853"
        case "doh", "doh3": port = "443"; if path.isEmpty { path = "/dns-query" }
        default: break
        }
    }
    private func defaultPort(_ value: String) -> Int { value == "dot" ? 853 : (["doh", "doh3"].contains(value) ? 443 : 53) }
    private func sorted(_ values: [DNSBenchmarkResult]) -> [DNSBenchmarkResult] {
        values.sorted {
            if $0.working != $1.working { return $0.working && !$1.working }
            let lhs = $0.latencyMs ?? .greatestFiniteMagnitude, rhs = $1.latencyMs ?? .greatestFiniteMagnitude
            if lhs != rhs { return lhs < rhs }
            return $0.name < $1.name
        }
    }
}

private enum IOSDNSRTTProbe {
    private final class ProbeState: @unchecked Sendable {
        let semaphore = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var connection: NWConnection?
        var result: Double?
        var finished = false
        var started: UInt64 = 0

        func markStarted() { lock.lock(); started = DispatchTime.now().uptimeNanoseconds; lock.unlock() }
        func finish(_ value: Double?) {
            lock.lock()
            guard !finished else { lock.unlock(); return }
            finished = true; result = value
            let connection = self.connection
            lock.unlock()
            connection?.cancel(); semaphore.signal()
        }
        func elapsedMilliseconds() -> Double? {
            lock.lock(); let start = started; lock.unlock()
            guard start > 0 else { return nil }
            return Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000.0
        }
    }

    static func query(address: String) async -> Double? {
        await Task.detached(priority: .utility) { querySync(address: address) }.value
    }

    private static func querySync(address: String) -> Double? {
        guard IPv4Address(address) != nil || IPv6Address(address) != nil,
              let port = NWEndpoint.Port(rawValue: 53) else { return nil }
        let state = ProbeState()
        let queue = DispatchQueue(label: "routervpn.dns-rtt.\(UUID().uuidString)")
        let connection = NWConnection(host: NWEndpoint.Host(address), port: port, using: .udp)
        state.connection = connection
        let id = UInt16.random(in: 1...UInt16.max)
        let query = packet(id: id)
        connection.stateUpdateHandler = { status in
            switch status {
            case .ready:
                state.markStarted()
                state.connection?.send(content: query, completion: .contentProcessed { error in
                    if error != nil { state.finish(nil); return }
                    state.connection?.receiveMessage { data, _, _, error in
                        guard error == nil, let data, validResponse(data, id: id), let elapsed = state.elapsedMilliseconds() else { state.finish(nil); return }
                        state.finish(elapsed)
                    }
                })
            case .failed, .cancelled: state.finish(nil)
            default: break
            }
        }
        connection.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 1.5) { state.finish(nil) }
        _ = state.semaphore.wait(timeout: .now() + 1.7)
        state.connection?.cancel()
        return state.result
    }

    private static func packet(id: UInt16) -> Data {
        var bytes: [UInt8] = [UInt8(id >> 8), UInt8(id & 0xff), 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        for label in ["example", "com"] {
            let utf8 = Array(label.utf8); bytes.append(UInt8(utf8.count)); bytes.append(contentsOf: utf8)
        }
        bytes.append(0); bytes.append(contentsOf: [0x00, 0x01, 0x00, 0x01])
        return Data(bytes)
    }

    private static func validResponse(_ data: Data, id: UInt16) -> Bool {
        let bytes = [UInt8](data)
        guard bytes.count >= 12,
              bytes[0] == UInt8(id >> 8), bytes[1] == UInt8(id & 0xff),
              (bytes[2] & 0x80) != 0, (bytes[3] & 0x0f) == 0 else { return false }
        return (Int(bytes[6]) << 8 | Int(bytes[7])) > 0
    }
}

// iOS DNS contract: Home/Fastest/Custom UDP/TCP/DoT/DoH/DoH3/Rescue; common
// IPv4+IPv6 primary/secondary resolvers; real DNS-query RTT over active tunnel;
// DNS-aware runtime readiness; saved policy != physical runtime proof.
