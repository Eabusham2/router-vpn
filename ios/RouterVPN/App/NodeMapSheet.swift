import MapKit
import SwiftUI

struct RouterVPNNodeMapSheet: View {
    @EnvironmentObject var model: RouterVPNModel
    @Environment(\.dismiss) private var dismiss

    private var nodes: [RouterVPNMapPoint] {
        (model.bundle?.routerProfiles ?? []).compactMap { profile in
            guard let latitude = profile.latitude,
                  let longitude = profile.longitude,
                  (-90.0...90.0).contains(latitude),
                  (-180.0...180.0).contains(longitude),
                  !(latitude == 0 && longitude == 0) else { return nil }
            return RouterVPNMapPoint(
                id: profile.id,
                name: profile.name,
                location: profile.location ?? profile.endpoint,
                latitude: latitude,
                longitude: longitude,
                active: profile.id == model.bundle?.selectedRouterID
            )
        }
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                if nodes.isEmpty {
                    ContentUnavailableView(
                        "No real node coordinates",
                        systemImage: "map",
                        description: Text("Router VPN never invents map locations. Only stored latitude/longitude values are plotted.")
                    )
                } else {
                    RouterVPNMapPanel(nodes: nodes)
                    RouterVPNMapNodeList(nodes: nodes)
                }
            }
            .navigationTitle("Nodes & Map")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }
}

struct RouterVPNMapPoint: Identifiable {
    let id: String
    let name: String
    let location: String
    let latitude: Double
    let longitude: Double
    let active: Bool
    var coordinate: CLLocationCoordinate2D {
        CLLocationCoordinate2D(latitude: latitude, longitude: longitude)
    }
}

private struct RouterVPNMapPanel: View {
    let nodes: [RouterVPNMapPoint]
    var body: some View {
        Map {
            ForEach(nodes) { node in
                Marker(node.name, coordinate: node.coordinate)
                    .tint(node.active ? .blue : .teal)
            }
        }
        .mapStyle(.standard)
        .frame(minHeight: 360)
    }
}

private struct RouterVPNMapNodeList: View {
    let nodes: [RouterVPNMapPoint]
    var body: some View {
        List(nodes) { node in
            VStack(alignment: .leading, spacing: 3) {
                HStack {
                    Text(node.name).fontWeight(node.active ? .semibold : .regular)
                    if node.active { Image(systemName: "checkmark.circle.fill").foregroundStyle(.blue) }
                }
                Text(node.location).font(.caption).foregroundStyle(.secondary)
                Text(String(format: "%.5f, %.5f", node.latitude, node.longitude))
                    .font(.caption2.monospaced())
                    .textSelection(.enabled)
            }
        }
        .listStyle(.insetGrouped)
    }
}
