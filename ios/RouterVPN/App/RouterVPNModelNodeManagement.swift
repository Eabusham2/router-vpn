import Foundation

extension RouterVPNModel {
    func removeNode(_ id: String) {
        guard var value = bundle else { message = "No node bundle is loaded"; return }
        guard value.routerProfiles.contains(where: { $0.id == id }) else { message = "Node not found"; return }
        value.routerProfiles.removeAll(where: { $0.id == id })
        if value.selectedRouterID == id {
            value.selectedRouterID = value.routerProfiles.first?.id ?? ""
        }
        do {
            let data = try JSONEncoder().encode(value)
            try importBundle(data)
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
        guard var value = bundle,
              let index = value.routerProfiles.firstIndex(where: { $0.id == id })
        else { message = "Node not found"; return }
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
        value.routerProfiles[index].name = trimmedName
        let trimmedLocation = location.trimmingCharacters(in: .whitespacesAndNewlines)
        value.routerProfiles[index].location = trimmedLocation.isEmpty ? nil : trimmedLocation
        value.routerProfiles[index].latitude = latitude
        value.routerProfiles[index].longitude = longitude
        do {
            let data = try JSONEncoder().encode(value)
            try importBundle(data)
            message = "Updated local node metadata"
        } catch {
            message = "Could not update node metadata: \(error.localizedDescription)"
        }
    }
}
