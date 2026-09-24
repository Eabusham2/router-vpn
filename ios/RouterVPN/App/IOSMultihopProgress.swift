import Foundation
@preconcurrency import NetworkExtension

@MainActor
extension RouterVPNModel {
    func refreshIOSMultihopExecutionProgress() async {
        guard connected || tunnelTransitioning, selectedNodeProfile?.multihopEnabled == true else { return }
        if multihopProgressInFlight != nil {
            // An extension that never answers must not accumulate requests.
            if Date() < multihopProgressDeadline { return }
            multihopProgressInFlight = nil
        }
        let ticket = UUID()
        multihopProgressInFlight = ticket
        multihopProgressDeadline = Date().addingTimeInterval(3)
        let generation = multihopProgressGeneration
        let nodeID = selectedNodeProfile?.id
        guard let managers = try? await NETunnelProviderManager.loadAllFromPreferences(),
              let manager = managers.first(where: { ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == "com.eabusham.routervpn.PacketTunnel" }),
              let session = manager.connection as? NETunnelProviderSession,
              [.connecting, .connected, .reasserting].contains(session.status),
              let request = try? JSONSerialization.data(withJSONObject: ["operation": "multihop-progress"]) else {
            if multihopProgressInFlight == ticket { multihopProgressInFlight = nil }
            return
        }
        do { try session.sendProviderMessage(request) { [weak self] data in
            Task { @MainActor [weak self] in
                guard let self, self.multihopProgressInFlight == ticket else { return }
                self.multihopProgressInFlight = nil
                guard let data, data.count <= 16384, Date() <= self.multihopProgressDeadline,
                      self.multihopProgressGeneration == generation,
                      self.selectedNodeProfile?.id == nodeID, self.connected || self.tunnelTransitioning,
                      let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }
                var lines = ["Multihop: \(value["stage"] as? String ?? "pending") • \(value["execution"] as? String ?? "comparing")"]
                for item in value["measurements"] as? [[String: Any]] ?? [] {
                    let candidate = item["candidate"] as? [String: Any] ?? [:]
                    let name = candidate["execution"] as? String ?? "candidate"
                    if item["eligible"] as? Bool == true,
                       let last = item["last_node_ms"] as? Double, let external = item["external_ms"] as? Double,
                       let score = item["score_ms"] as? Double, last.isFinite, external.isFinite, score.isFinite,
                       last > 0, external > 0, score > 0 {
                        lines.append(String(format: "%@: (%.1f + %.1f) / 2 = %.1f ms", name, last, external, score))
                    } else { lines.append("\(name): rejected — \(item["failure"] as? String ?? "probe failed")") }
                }
                self.multihopProgressText = lines.joined(separator: "\n")
            }
        } } catch {
            if multihopProgressInFlight == ticket { multihopProgressInFlight = nil }
        }
    }
}
