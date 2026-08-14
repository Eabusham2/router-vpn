import Foundation

extension RouterVPNModel {
    func removeNode(_ id: String) {
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

    func updateNodeMetadata(
        id: String,
        name: String,
        location: String,
        latitudeText: String,
        longitudeText: String
    ) {
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedName.isEmpty, trimmedName.count <= 120 else {
            message = "Node name must be 1–120 characters"
            return
        }
        let latRaw = latitudeText.trimmingCharacters(in: .whitespacesAndNewlines)
        let lonRaw = longitudeText.trimmingCharacters(in: .whitespacesAndNewlines)
        let latitude = latRaw.isEmpty ? nil : Double(latRaw)
        let longitude = lonRaw.isEmpty ? nil : Double(lonRaw)
        if (latitude == nil) != (longitude == nil) {
            message = "Enter both latitude and longitude, or leave both blank"
            return
        }
        if let latitude, let longitude {
            guard (-90...90).contains(latitude), (-180...180).contains(longitude), !(latitude == 0 && longitude == 0) else {
                message = "Coordinates must be real latitude/longitude values; 0,0 is not accepted as a placeholder"
                return
            }
        }
        let trimmedLocation = location.trimmingCharacters(in: .whitespacesAndNewlines)
        do {
            let replacement = try IOSNodeBundleStore.shared.updateMetadata(
                profileID: id,
                current: bundle,
                name: trimmedName,
                location: trimmedLocation.isEmpty ? nil : trimmedLocation,
                latitude: latitude,
                longitude: longitude
            )
            if bundle?.routerProfiles.contains(where: { $0.id == id }) == true {
                try importBundle(replacement)
            }
            message = "Updated local node metadata"
        } catch {
            message = "Could not update node metadata: \(error.localizedDescription)"
        }
    }
}
