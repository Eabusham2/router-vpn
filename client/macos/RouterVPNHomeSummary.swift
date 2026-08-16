import AppKit
import Foundation

private struct RouterVPNDesktopHomeSummary: Decodable {
    var nodeName: String?
    var location: String?
    var publicEndpoint: String?
    var actualExitIP: String?
    var actualExitStatus: String
    var connectionPhase: String
    var connected: Bool
    var pathProof: String
    var logicalMode: String?
    var requestedBase: String?
    var actualRuntime: String?
    var actualBase: String?
    var fallback: String?
    var dnsMode: String?
    var dnsHost: String?
    var dnsLatencyMs: Double?
    var dnsStatus: String
    var nodeLatencyMs: Double?
    var nodeLatencySamples: Int?
    var lanAccess: Bool
    var killSwitch: String
    var effectiveMTU: Int?
    var effectiveMTUSource: String?
    var ipv6Mode: String?
    var autoConnect: Bool?
    var warnings: [String]

    enum CodingKeys: String, CodingKey {
        case connected, warnings, location
        case nodeName = "node_name"
        case publicEndpoint = "public_endpoint"
        case actualExitIP = "actual_exit_ip"
        case actualExitStatus = "actual_exit_status"
        case connectionPhase = "connection_phase"
        case pathProof = "path_proof"
        case logicalMode = "logical_mode"
        case requestedBase = "requested_base"
        case actualRuntime = "actual_runtime"
        case actualBase = "actual_base"
        case fallback
        case dnsMode = "dns_mode"
        case dnsHost = "dns_host"
        case dnsLatencyMs = "dns_latency_ms"
        case dnsStatus = "dns_status"
        case nodeLatencyMs = "node_latency_ms"
        case nodeLatencySamples = "node_latency_samples"
        case lanAccess = "lan_access"
        case killSwitch = "kill_switch"
        case effectiveMTU = "effective_mtu"
        case effectiveMTUSource = "effective_mtu_source"
        case ipv6Mode = "ipv6_mode"
        case autoConnect = "auto_connect"
    }
}

extension ProductWindowController {
    func refreshHomeSummary() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            do {
                let data = try self.api.request("/api/home-summary", timeout: 5)
                let summary = try JSONDecoder().decode(RouterVPNDesktopHomeSummary.self, from: data)
                let text = self.formatHomeSummary(summary)
                DispatchQueue.main.async { self.detailLabel.stringValue = text }
            } catch {
                DispatchQueue.main.async { self.detailLabel.stringValue = "Home state unavailable: \(error.localizedDescription)" }
            }
        }
    }

    @objc func proveActualHomeExit() {
        asyncAction {
            let data = try self.api.request("/api/home-summary/prove-exit", method: "POST", body: [:], timeout: 12)
            let summary = try JSONDecoder().decode(RouterVPNDesktopHomeSummary.self, from: data)
            guard summary.actualExitStatus == "proved", let ip = summary.actualExitIP, !ip.isEmpty else {
                throw NSError(domain: "RouterVPNMac.Home", code: 1, userInfo: [NSLocalizedDescriptionKey: "Public exit probe returned without current-session proof."])
            }
            DispatchQueue.main.async { self.detailLabel.stringValue = self.formatHomeSummary(summary) }
            return "Actual public VPN exit proved for this live session: \(ip)"
        }
    }

    @objc func emergencyDisconnectHome() {
        emergencyStop()
    }

    private func formatHomeSummary(_ s: RouterVPNDesktopHomeSummary) -> String {
        let exit: String
        if s.actualExitStatus == "proved", let value = s.actualExitIP, !value.isEmpty { exit = value }
        else if s.connected { exit = "Unproven — click Prove actual exit" }
        else { exit = "Not connected" }
        var dns = [s.dnsMode, s.dnsHost].compactMap { value -> String? in
            guard let value, !value.isEmpty else { return nil }; return value
        }.joined(separator: " • ")
        if let latency = s.dnsLatencyMs, latency > 0 { dns += String(format: " • %.2f ms", latency) }
        let nodeLatency: String
        if let samples = s.nodeLatencySamples, samples > 0, let latency = s.nodeLatencyMs {
            nodeLatency = String(format: "%.2f ms / %d samples", latency, samples)
        } else { nodeLatency = "Not measured" }
        let mtu = (s.effectiveMTU ?? 0) > 0 ? "\(s.effectiveMTU!) • \(s.effectiveMTUSource ?? "measured")" : "Default / not measured"
        let warnings = s.warnings.isEmpty ? "None" : s.warnings.joined(separator: " | ")
        return [
            "Node: \(s.nodeName ?? "—") • \(s.location ?? "Location not labeled")",
            "Public endpoint: \(s.publicEndpoint ?? "—")",
            "Actual public VPN exit: \(exit)",
            "Connection: \(s.connectionPhase) • path proof \(s.pathProof)",
            "Logical/runtime/base: \(s.logicalMode ?? "—") • \(s.actualRuntime ?? "—") • \(s.actualBase ?? "—")",
            "Fallback: \((s.fallback?.isEmpty == false) ? s.fallback! : "None")",
            "DNS: \(dns.isEmpty ? "—" : dns) • proof \(s.dnsStatus)",
            "Node latency: \(nodeLatency)",
            "LAN access: \(s.lanAccess ? "On" : "Off") • Kill switch: \(s.killSwitch)",
            "Effective MTU: \(mtu) • IPv6: \(s.ipv6Mode ?? "default") • Auto-connect: \((s.autoConnect ?? false) ? "On" : "Off")",
            "Warnings: \(warnings)"
        ].joined(separator: "\n")
    }
}

// Shipping Home contract: node location public endpoint actual public VPN exit
// connection phase logical mode actual runtime actual base fallback DNS latency
// node latency LAN access kill switch effective MTU warnings Connect
// Emergency Disconnect. Actual exit comes only from /api/home-summary/prove-exit.
