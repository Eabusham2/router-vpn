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
        responseProbeServerName: String = ""
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
            if let expectedExternal {
                guard expectedExternal.protocolName == "shadowsocks", let transport = expectedExternal.shadowsocks else { throw IOSExternalExecution.issue() }
                probe = try IOSExternalExecution.responseProbe(host: transport.server, url: responseProbeURL, serverName: responseProbeServerName)
            } else {
                guard responseProbeURL.isEmpty && responseProbeServerName.isEmpty else { throw IOSExternalExecution.issue() }
                probe = nil
            }
            let replacement = try IOSNodeBundleStore.shared.updateMetadata(
                profileID: id,
                current: bundle,
                name: trimmedName,
                location: trimmedLocation.isEmpty ? nil : trimmedLocation,
                latitude: latitude,
                longitude: longitude,
                expectedExternal: expectedExternal,
                responseProbe: probe
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
