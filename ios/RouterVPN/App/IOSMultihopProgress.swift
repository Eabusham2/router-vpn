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
        let connectionGeneration = iosConnectGeneration
        let identity = activeSessionIdentity
        let nodeID = selectedNodeProfile?.id
        guard let managers = try? await NETunnelProviderManager.loadAllFromPreferences(),
              multihopProgressGeneration == generation, iosConnectGeneration == connectionGeneration,
              activeSessionIdentity == identity, selectedNodeProfile?.id == nodeID,
              managers.filter({ ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == "com.eabusham.routervpn.PacketTunnel" }).count == 1,
              let manager = managers.first(where: { ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == "com.eabusham.routervpn.PacketTunnel" }),
              let configuration = (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration,
              let bundleData = configuration["bundle"] as? Data,
              let session = manager.connection as? NETunnelProviderSession,
              [.connecting, .connected, .reasserting].contains(session.status),
              let request = try? JSONSerialization.data(withJSONObject: ["operation": "multihop-progress"]) else {
            if multihopProgressInFlight == ticket { multihopProgressInFlight = nil }
            return
        }
        let connectedAt = session.connectedDate
        guard configuration["nodeChainSource"] == nil || configuration["nodeChainSOCKSSource"] == nil else {
            multihopProgressInFlight = nil; return
        }
        let chainKey = configuration["nodeChainSOCKSSource"] == nil ? "nodeChainSource" : "nodeChainSOCKSSource"
        let chainSource = configuration[chainKey] as? String
        if let identity {
            guard identity.connectedAt == connectedAt, identity.bundleData == bundleData,
                  identity.nodeChainSource == chainSource.map({ Data($0.utf8) }) else {
                if multihopProgressInFlight == ticket { multihopProgressInFlight = nil }
                return
            }
        }
        let orderedNodes = chainSource.flatMap { IOSNodeChainPresentation.captured(source: Data($0.utf8), bundleData: bundleData) }
        guard configuration[chainKey] == nil || orderedNodes != nil else {
            if multihopProgressInFlight == ticket { multihopProgressInFlight = nil }
            return
        }
        do { try session.sendProviderMessage(request) { [weak self] data in
            Task { @MainActor [weak self] in
                guard let self, self.multihopProgressInFlight == ticket else { return }
                self.multihopProgressInFlight = nil
                guard let data, data.count <= 16384, Date() <= self.multihopProgressDeadline,
                      self.multihopProgressGeneration == generation,
                      self.iosConnectGeneration == connectionGeneration, self.activeSessionIdentity == identity,
                      session.connectedDate == connectedAt, [.connecting, .connected, .reasserting].contains(session.status),
                      let current = (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration,
                      current["bundle"] as? Data == bundleData, current[chainKey] as? String == chainSource,
                      current[chainKey == "nodeChainSource" ? "nodeChainSOCKSSource" : "nodeChainSource"] == nil,
                      self.selectedNodeProfile?.id == nodeID, self.connected || self.tunnelTransitioning,
                      let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }
                if let orderedNodes {
                    guard let text = IOSNodeChainPresentation.progress(value, expected: orderedNodes.map(\.id)) else { return }
                    self.multihopProgressText = text
                    return
                }
                var lines = ["Multihop: \(value["stage"] as? String ?? "pending") • \(value["execution"] as? String ?? "comparing")"]
                let lastKind = value["last_node_measurement"] as? String
                let lastLabel = lastKind == "tor-relay-http-response-time" ? "last-relay HTTP response" : (lastKind == "https-response-time" ? "node HTTPS response" : "last-node response")
                let externalLabel = value["external_measurement"] as? String == "https-response-time" ? "external HTTPS response" : "external response"
                for item in value["measurements"] as? [[String: Any]] ?? [] {
                    let candidate = item["candidate"] as? [String: Any] ?? [:]
                    let name = candidate["execution"] as? String ?? "candidate"
                    if item["eligible"] as? Bool == true,
                       let last = item["last_node_ms"] as? Double, let external = item["external_ms"] as? Double,
                       let score = item["score_ms"] as? Double, last.isFinite, external.isFinite, score.isFinite,
                       last > 0, external > 0, score > 0 {
                        lines.append(String(format: "%@: (%@ %.1f + %@ %.1f) / 2 = %.1f ms", name, lastLabel, last, externalLabel, external, score))
                    } else { lines.append("\(name): rejected — \(item["failure"] as? String ?? "probe failed")") }
                }
                self.multihopProgressText = lines.joined(separator: "\n")
            }
        } } catch {
            if multihopProgressInFlight == ticket { multihopProgressInFlight = nil }
        }
    }
}
