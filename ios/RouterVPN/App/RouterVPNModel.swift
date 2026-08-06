import Foundation
import NetworkExtension

@MainActor
final class RouterVPNModel: ObservableObject {
    @Published var modes: [VPNMode] = []
    @Published var selectedMode = "wg"
    @Published var auto = true
    @Published var daita = false
    @Published var jumbo = false
    @Published var connected = false
    @Published var message = "Import router-vpn-bundle.json"
    @Published var forwardProtocol = "both"
    @Published var forwardFrom = "25565"
    @Published var forwardTo = "25565"
    @Published var forwardTarget = "25565"
    private(set) var bundle: ClientBundle?

    var socksSummary: String {
        guard let b = bundle else { return "Import the bundle first" }
        return "\(b.socks5Host):\(b.socks5Port) • \(b.socks5Username) • \(b.socks5Password)"
    }

    func importBundle(_ data: Data) throws {
        let decoded = try JSONDecoder().decode(ClientBundle.self, from: data)
        bundle = decoded
        modes = decoded.modes
        if !modes.contains(where: { $0.id == selectedMode }) { selectedMode = modes.first?.id ?? "wg" }
        message = "Bundle imported"
    }

    func connect() async {
        guard let bundle else { message = "Import a bundle first"; return }
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            let manager = managers.first ?? NETunnelProviderManager()
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = "com.eabusham.routervpn.PacketTunnel"
            proto.serverAddress = bundle.endpoint
            proto.providerConfiguration = [
                "mode": auto ? "auto" : selectedMode,
                "daita": daita,
                "jumbo": jumbo,
                "bundle": try JSONEncoder().encode(bundle)
            ]
            manager.protocolConfiguration = proto
            manager.localizedDescription = "Router VPN"
            manager.isEnabled = true
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
            try manager.connection.startVPNTunnel()
            connected = true
            message = "Connecting"
        } catch { message = error.localizedDescription }
    }

    func disconnect() {
        Task {
            let managers = (try? await NETunnelProviderManager.loadAllFromPreferences()) ?? []
            managers.first?.connection.stopVPNTunnel()
            connected = false
            message = "Disconnected"
        }
    }

    func applyForward(dmz: Bool) async {
        guard let b = bundle, let url = URL(string: b.routerAPI + "/api/forward") else { message = "Import the bundle first"; return }
        guard let from = Int(forwardFrom), let to = Int(forwardTo), let target = Int(forwardTarget) else { message = "Enter valid ports"; return }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("Bearer \(b.apiToken)", forHTTPHeaderField: "Authorization")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try? JSONSerialization.data(withJSONObject: ["protocol": forwardProtocol, "from": from, "to": to, "target_port": target, "dmz": dmz])
        do {
            let (_, response) = try await URLSession.shared.data(for: req)
            guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw URLError(.badServerResponse) }
            message = dmz ? "Protected DMZ applied" : "Port forwarding applied"
        } catch { message = "Port forwarding requires a connected WireGuard/AWG tunnel: \(error.localizedDescription)" }
    }

    func clearForward() async {
        guard let b = bundle, let url = URL(string: b.routerAPI + "/api/forward/clear") else { return }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("Bearer \(b.apiToken)", forHTTPHeaderField: "Authorization")
        do { _ = try await URLSession.shared.data(for: req); message = "Port forwarding cleared" }
        catch { message = error.localizedDescription }
    }
}
