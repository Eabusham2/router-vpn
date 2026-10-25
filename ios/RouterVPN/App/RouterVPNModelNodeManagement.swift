import Foundation

extension RouterVPNModel {
    func removeNode(_ id: String) {
        guard !profileMutationBlocked else { message = "Disconnect or let the active VPN transition finish before removing a linked node."; return }
        do {
            let replacement = try IOSNodeBundleStore.shared.remove(profileID: id, current: bundle)
            if let replacement {
                try importBundle(replacement)
            } else {
                let empty = try JSONEncoder().encode(ClientBundle.empty)
                try importBundle(empty)
            }
            message = "Removed linked node from this app. Router VPN itself remains installed."
        } catch {
            message = "Could not remove node: \(error.localizedDescription)"
        }
    }

    @discardableResult
    func updateNodeMetadata(
        id: String,
        name: String,
        location: String,
        latitudeText: String,
        longitudeText: String,
        expectedExternal: ExternalNodeConfig? = nil,
        responseProbeURL: String = "",
        responseProbeServerName: String = "",
        expectedStartLayer: String = "off",
        exitStartLayer: String? = nil,
        exitLayerAPI: String = "",
        exitLayerPort: Int = 0,
        exitLayerKey: String = "",
        serverPeerJSON: String? = nil,
        openVPNPairingJSON: String? = nil,
        openVPNResponseProbesJSON: String? = nil
    ) -> Bool {
        guard !profileMutationBlocked else { message = "Disconnect or let the active VPN transition finish before editing node metadata."; return false }
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedName.isEmpty, trimmedName.count <= 120 else {
            message = "Node name must be 1–120 characters"
            return false
        }
        let latRaw = latitudeText.trimmingCharacters(in: .whitespacesAndNewlines)
        let lonRaw = longitudeText.trimmingCharacters(in: .whitespacesAndNewlines)
        let latitude = latRaw.isEmpty ? nil : Double(latRaw)
        let longitude = lonRaw.isEmpty ? nil : Double(lonRaw)
        if (latitude == nil) != (longitude == nil) {
            message = "Enter both latitude and longitude, or leave both blank"
            return false
        }
        if let latitude, let longitude {
            guard (-90...90).contains(latitude), (-180...180).contains(longitude), !(latitude == 0 && longitude == 0) else {
                message = "Coordinates must be real latitude/longitude values; 0,0 is not accepted as a placeholder"
                return false
            }
        }
        let trimmedLocation = location.trimmingCharacters(in: .whitespacesAndNewlines)
        do {
            let probe: ExternalResponseProbe?
            let layerUpdate: ExternalStartLayerUpdate?
            let pairingUpdate: ExternalOpenVPNPairingUpdate?
            if let openVPNPairingJSON {
                guard let expectedExternal, expectedExternal.protocolName == "openvpn", let original = expectedExternal.openVPN else { throw IOSExternalExecution.issue() }
                pairingUpdate = ExternalOpenVPNPairingUpdate(pairing: try IOSExternalExecution.openVPNPairing(openVPNPairingJSON, profile: original))
            } else { pairingUpdate = nil }
            let probesUpdate: ExternalOpenVPNResponseProbesUpdate?
            if let openVPNResponseProbesJSON {
                guard let expectedExternal, expectedExternal.protocolName == "openvpn", let original = expectedExternal.openVPN else { throw IOSExternalExecution.issue() }
                probesUpdate = ExternalOpenVPNResponseProbesUpdate(probes: try IOSExternalExecution.openVPNResponseProbes(openVPNResponseProbesJSON, profile: original))
            } else { probesUpdate = nil }
            let peerUpdate: ExternalServerPeerUpdate?
            if let serverPeerJSON {
                guard let expectedExternal, ExternalNodeConfig.packetProtocols.contains(expectedExternal.protocolName) else { throw IOSExternalExecution.issue() }
                peerUpdate = ExternalServerPeerUpdate(peer: try IOSExternalExecution.serverPeer(serverPeerJSON))
            } else { peerUpdate = nil }
            if let expectedExternal {
                let host = try IOSExternalExecution.host(expectedExternal)
                probe = try IOSExternalExecution.responseProbe(host: host, url: responseProbeURL, serverName: responseProbeServerName)
            } else {
                guard responseProbeURL.isEmpty && responseProbeServerName.isEmpty else { throw IOSExternalExecution.issue() }
                probe = nil
            }
            if let exitStartLayer {
                guard let expectedExternal else { throw IOSExternalExecution.issue() }
                let host = try IOSExternalExecution.host(expectedExternal)
                let layer: ExternalStartLayer?
                if exitStartLayer == "off" {
                    guard exitLayerAPI.isEmpty, exitLayerPort == 0, exitLayerKey.isEmpty else { throw IOSExternalExecution.issue() }
                    layer = nil
                } else {
                    let raw: [String: Any] = ["mode": exitStartLayer, "api": exitLayerAPI,
                        "transport": ["type": "shadowsocks", "tag": expectedExternal.startLayer?.transport.tag ?? "provisioned-exit-layer",
                            "server": host, "server_port": exitLayerPort, "method": "2022-blake3-aes-256-gcm", "password": exitLayerKey]]
                    layer = try JSONDecoder().decode(ExternalStartLayer.self, from: JSONSerialization.data(withJSONObject: raw))
                }
                layerUpdate = ExternalStartLayerUpdate(expectedMode: expectedStartLayer, mode: exitStartLayer, layer: layer)
            } else {
                guard exitLayerAPI.isEmpty, exitLayerPort == 0, exitLayerKey.isEmpty else { throw IOSExternalExecution.issue() }
                layerUpdate = nil
            }
            let replacement = try IOSNodeBundleStore.shared.updateMetadata(
                profileID: id,
                current: bundle,
                name: trimmedName,
                location: trimmedLocation.isEmpty ? nil : trimmedLocation,
                latitude: latitude,
                longitude: longitude,
                expectedExternal: expectedExternal,
                responseProbe: probe,
                startLayerUpdate: layerUpdate,
                serverPeerUpdate: peerUpdate,
                openVPNPairingUpdate: pairingUpdate,
                openVPNResponseProbesUpdate: probesUpdate
            )
            if bundle?.routerProfiles.contains(where: { $0.id == id }) == true {
                try importBundle(replacement)
            }
            message = "Updated local node metadata"
            return true
        } catch {
            message = "Could not update node metadata: \(error.localizedDescription)"
            return false
        }
    }
}
