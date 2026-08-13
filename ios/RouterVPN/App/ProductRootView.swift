import MapKit
import SwiftUI

struct ProductRootView: View {
    @EnvironmentObject var model: RouterVPNModel
    @State private var showingMap = false

    var body: some View {
        ContentView()
            .overlay(alignment: .bottomTrailing) {
                Button {
                    showingMap = true
                } label: {
                    Label("Nodes & Map", systemImage: "map.fill")
                        .labelStyle(.titleAndIcon)
                        .padding(.horizontal, 14)
                        .padding(.vertical, 10)
                }
                .buttonStyle(.borderedProminent)
                .clipShape(Capsule())
                .padding(.trailing, 14)
                .padding(.bottom, 58)
                .accessibilityHint("Shows only real coordinates stored in imported Router VPN node profiles")
            }
            .sheet(isPresented: $showingMap) {
                RouterVPNNodeMapView()
                    .environmentObject(model)
            }
    }
}

private struct RouterVPNMapNode: Identifiable, Hashable {
    let id: String
    let name: String
    let location: String
    let coordinate: CLLocationCoordinate2D
    let latencyMedianMs: Double?

    static func == (lhs: RouterVPNMapNode, rhs: RouterVPNMapNode) -> Bool {
        lhs.id == rhs.id && lhs.coordinate.latitude == rhs.coordinate.latitude && lhs.coordinate.longitude == rhs.coordinate.longitude
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(id)
        hasher.combine(coordinate.latitude)
        hasher.combine(coordinate.longitude)
    }
}

private struct RouterVPNNodeMapView: View {
    @EnvironmentObject var model: RouterVPNModel
    @Environment(\.dismiss) private var dismiss
    @State private var selectedID: String?
    @State private var position: MapCameraPosition = .automatic

    private var allProfiles: [RouterProfile] {
        model.bundle?.routerProfiles ?? []
    }

    private var nodes: [RouterVPNMapNode] {
        allProfiles.compactMap { profile in
            guard let latitude = profile.latitude,
                  let longitude = profile.longitude,
                  (-90.0...90.0).contains(latitude),
                  (-180.0...180.0).contains(longitude),
                  !(latitude == 0 && longitude == 0) else {
                return nil
            }
            return RouterVPNMapNode(
                id: profile.id,
                name: profile.name,
                location: profile.location ?? "",
                coordinate: CLLocationCoordinate2D(latitude: latitude, longitude: longitude),
                latencyMedianMs: profile.latencyMedianMs
            )
        }
    }

    private var selectedNode: RouterVPNMapNode? {
        guard let selectedID else { return nil }
        return nodes.first(where: { $0.id == selectedID })
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                if nodes.isEmpty {
                    ContentUnavailableView(
                        "No real node coordinates",
                        systemImage: "map",
                        description: Text("Router VPN never invents map locations. Add latitude/longitude to a node profile before it can appear here.")
                    )
                } else {
                    Map(position: $position, selection: $selectedID) {
                        ForEach(nodes) { node in
                            Marker(node.name, coordinate: node.coordinate)
                                .tint(node.id == model.bundle?.selectedRouterID ? .blue : .teal)
                                .tag(node.id)
                        }
                    }
                    .mapStyle(.standard(elevation: .realistic))
                    .mapControls {
                        MapCompass()
                        MapScaleView()
                        MapUserLocationButton()
                    }
                    .frame(minHeight: 360)

                    List {
                        if let selectedNode {
                            Section("Selected map pin") {
                                VStack(alignment: .leading, spacing: 5) {
                                    Text(selectedNode.name).font(.headline)
                                    if !selectedNode.location.isEmpty { Text(selectedNode.location).foregroundStyle(.secondary) }
                                    Text(String(format: "%.5f, %.5f", selectedNode.coordinate.latitude, selectedNode.coordinate.longitude))
                                        .font(.caption.monospaced())
                                        .textSelection(.enabled)
                                    if let latency = selectedNode.latencyMedianMs, latency > 0 {
                                        Text(String(format: "Median node latency %.1f ms", latency))
                                            .font(.caption).foregroundStyle(.secondary)
                                    }
                                    Text("Map selection is visual only on this iOS build; change the active Router VPN node from Nodes until multi-node switching is promoted into the native model.")
                                        .font(.caption2).foregroundStyle(.secondary)
                                }
                            }
                        }

                        Section("Stored nodes") {
                            ForEach(allProfiles) { profile in
                                let plotted = profile.latitude != nil && profile.longitude != nil && !((profile.latitude ?? 0) == 0 && (profile.longitude ?? 0) == 0)
                                Button {
                                    if let node = nodes.first(where: { $0.id == profile.id }) {
                                        selectedID = node.id
                                        position = .region(MKCoordinateRegion(
                                            center: node.coordinate,
                                            span: MKCoordinateSpan(latitudeDelta: 8, longitudeDelta: 8)
                                        ))
                                    }
                                } label: {
                                    VStack(alignment: .leading, spacing: 3) {
                                        HStack {
                                            Text(profile.name).fontWeight(profile.id == model.bundle?.selectedRouterID ? .semibold : .regular)
                                            Spacer()
                                            if profile.id == model.bundle?.selectedRouterID { Image(systemName: "checkmark.circle.fill").foregroundStyle(.blue) }
                                        }
                                        Text(profile.location ?? profile.endpoint).font(.caption).foregroundStyle(.secondary)
                                        Text(plotted ? "Real coordinates stored" : "Coordinates not stored — not plotted")
                                            .font(.caption2).foregroundStyle(plotted ? .secondary : .orange)
                                    }
                                }
                                .disabled(!plotted)
                            }
                        }
                    }
                    .listStyle(.insetGrouped)
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
