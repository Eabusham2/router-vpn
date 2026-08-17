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
                    VStack(spacing: 12) {
                        Image(systemName: "map")
                            .font(.system(size: 42))
                            .foregroundStyle(.secondary)
                        Text("No real node coordinates")
                            .font(.headline)
                        Text("Router VPN never invents map locations. Only stored latitude/longitude values are plotted.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                    }
                    .padding(24)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    RouterVPNMapPanel(nodes: nodes)
                    RouterVPNMapNodeList(nodes: nodes)
                }
            }
            .navigationTitle("Nodes & Map")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
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
    @State private var region = MKCoordinateRegion()

    var body: some View {
        Map(coordinateRegion: $region, annotationItems: nodes) { node in
            MapAnnotation(coordinate: node.coordinate) {
                VStack(spacing: 2) {
                    Image(systemName: node.active ? "location.circle.fill" : "mappin.circle.fill")
                        .font(.title2)
                        .foregroundStyle(node.active ? .blue : .teal)
                    Text(node.name)
                        .font(.caption2)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 2)
                        .background(.regularMaterial, in: Capsule())
                }
                .accessibilityLabel("\(node.name), \(node.location)")
            }
        }
        .frame(minHeight: 360)
        .onAppear { region = fittedRegion(nodes) }
    }

    private func fittedRegion(_ values: [RouterVPNMapPoint]) -> MKCoordinateRegion {
        guard let first = values.first else { return MKCoordinateRegion() }
        var minLat = first.latitude, maxLat = first.latitude, minLon = first.longitude, maxLon = first.longitude
        for item in values.dropFirst() {
            minLat = min(minLat, item.latitude); maxLat = max(maxLat, item.latitude)
            minLon = min(minLon, item.longitude); maxLon = max(maxLon, item.longitude)
        }
        let center = CLLocationCoordinate2D(latitude: (minLat + maxLat) / 2, longitude: (minLon + maxLon) / 2)
        let latDelta = max(0.05, (maxLat - minLat) * 1.5)
        let lonDelta = max(0.05, (maxLon - minLon) * 1.5)
        return MKCoordinateRegion(center: center, span: MKCoordinateSpan(latitudeDelta: min(180, latDelta), longitudeDelta: min(360, lonDelta)))
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
