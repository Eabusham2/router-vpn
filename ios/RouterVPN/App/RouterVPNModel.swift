import Combine
import Foundation
@preconcurrency import NetworkExtension

@MainActor
final class RouterVPNModel: ObservableObject {
    @Published var modes: [VPNMode] = []
    @Published var selectedMode = "wg"
    @Published var auto = true
    @Published var daita = false
    @Published var jumbo = false
    @Published var connected = false
    @Published var message = "Import a router bundle or enter your home router settings"
    @Published var forwardProtocol = "both"
    @Published var forwardFrom = "25565"
    @Published var forwardTo = "25565"
    @Published var forwardTarget = "25565"
    @Published var routerName = "Home Router"
    @Published var endpoint = ""
    @Published var routerAPI = "http://10.77.0.1:8787"
    @Published var apiToken = ""
    @Published var socksHost = "10.77.0.1"
    @Published var socksPort = "1080"
    @Published var socksUsername = ""
    @Published var socksPassword = ""

    private(set) var bundle: ClientBundle?
    private let bundleKey = "router-vpn.bundle"

    init() {
        if let data = UserDefaults.standard.data(forKey: bundleKey),
           let saved = try? JSONDecoder().decode(ClientBundle.self, from: data) {
            apply(saved)
            message = "Saved router profile loaded"
        }
    }

    var socksSummary: String {
        guard !socksHost.isEmpty else { return "Configure your home router first" }
        return "\(socksHost):\(socksPort) • no authentication • tunnel/LAN only"
    }

    func importBundle(_ data: Data) throws {
        let decoded = try JSONDecoder().decode(ClientBundle.self, from: data)
        apply(decoded)
        saveRouter()
        message = "Router bundle imported"
    }

    func saveRouter() {
        guard !endpoint.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            message = "Enter the home router public IP or hostname"
            return
        }
        var current = bundle ?? ClientBundle.empty
        current.endpoint = endpoint.trimmingCharacters(in: .whitespacesAndNewlines)
        current.apiToken = apiToken
        current.routerAPI = routerAPI
        current.socks5Host = socksHost
        current.socks5Port = Int(socksPort) ?? 1080
        current.socks5Username = ""
        current.socks5Password = ""
        current.modes = modes
        bundle = current
        if let data = try? JSONEncoder().encode(current) {
            UserDefaults.standard.set(data, forKey: bundleKey)
        }
        message = "Router profile saved on this device"
    }

    private func apply(_ decoded: ClientBundle) {
        bundle = decoded
        modes = decoded.modes
        endpoint = decoded.endpoint
        routerAPI = decoded.routerAPI
        apiToken = decoded.apiToken
        socksHost = decoded.socks5Host
        socksPort = String(decoded.socks5Port)
        socksUsername = ""
        socksPassword = ""
        if !modes.contains(where: { $0.id == selectedMode }) { selectedMode = modes.first?.id ?? "wg" }
    }

    func connect() async {
        saveRouter()
        guard let bundle else { message = "Configure your home router first"; return }
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
            manager.localizedDescription = routerName
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
        saveRouter()
        guard let b = bundle, let url = URL(string: b.routerAPI + "/api/forward") else { message = "Configure your home router first"; return }
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
        saveRouter()
        guard let b = bundle, let url = URL(string: b.routerAPI + "/api/forward/clear") else { return }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("Bearer \(b.apiToken)", forHTTPHeaderField: "Authorization")
        do { _ = try await URLSession.shared.data(for: req); message = "Port forwarding cleared" }
        catch { message = error.localizedDescription }
    }
}
