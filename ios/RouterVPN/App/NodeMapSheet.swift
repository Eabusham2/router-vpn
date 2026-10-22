import MapKit
import SwiftUI

enum RouterVPNMapRole: String {
    case selected = "Selected"
    case entry = "Entry"
    case exit = "Exit"
    case external = "Custom"
    case normal = "Node"

    var color: Color {
        switch self {
        case .selected: return .purple
        case .entry: return .blue
        case .exit: return .orange
        case .external: return .pink
        case .normal: return .teal
        }
    }

    var symbol: String {
        switch self {
        case .selected: return "location.circle.fill"
        case .entry: return "1.circle.fill"
        case .exit: return "2.circle.fill"
        case .external: return "plus.circle.fill"
        case .normal: return "mappin.circle.fill"
        }
    }
}

struct RouterVPNNodeMapSheet: View {
    @EnvironmentObject var model: RouterVPNModel
    @Environment(\.dismiss) private var dismiss

    private var nodes: [RouterVPNMapPoint] { routerVPNMapPoints(model: model) }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                if nodes.isEmpty {
                    RouterVPNEmptyMapView()
                } else {
                    RouterVPNMapPanel(nodes: nodes)
                    RouterVPNMapLegend()
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

@MainActor
func routerVPNMapPoints(model: RouterVPNModel) -> [RouterVPNMapPoint] {
    let profiles = model.bundle?.routerProfiles ?? []
    let selectedID = model.bundle?.selectedRouterID ?? ""

    // Planned roles use the selected saved graph. The shared native map draws
    // a dashed planned route and animates packets only while the VPN is proved.
    let selected = profiles.first { $0.id == selectedID }
    let entryID = selected?.multihopEnabled == true ? selected?.multihopEntryID : nil
    let exitID = selected?.multihopEnabled == true ? selected?.multihopExitID : nil
    return profiles.compactMap { profile in
        guard let latitude = profile.latitude,
              let longitude = profile.longitude,
              (-90.0...90.0).contains(latitude),
              (-180.0...180.0).contains(longitude),
              !(latitude == 0 && longitude == 0) else { return nil }
        let role: RouterVPNMapRole
        if profile.id == entryID { role = .entry }
        else if profile.id == exitID { role = .exit }
        else if profile.id == selectedID { role = .selected }
        else if profile.normalizedNodeKind == "external" { role = .external }
        else { role = .normal }
        return RouterVPNMapPoint(
            id: profile.id,
            name: profile.name,
            location: profile.location ?? profile.endpoint,
            latitude: latitude,
            longitude: longitude,
            role: role
        )
    }
}

struct RouterVPNMapPoint: Identifiable {
    let id: String
    let name: String
    let location: String
    let latitude: Double
    let longitude: Double
    let role: RouterVPNMapRole
    var active: Bool { role == .selected }
    var coordinate: CLLocationCoordinate2D {
        CLLocationCoordinate2D(latitude: latitude, longitude: longitude)
    }
}

struct RouterVPNMapPanel: View {
    @EnvironmentObject var model: RouterVPNModel
    let nodes: [RouterVPNMapPoint]

    var body: some View {
        IOSUnifiedMap(latencyByID: [:]).environmentObject(model).frame(minHeight: 260)
    }
}

struct RouterVPNMapLegend: View {
    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 12) {
                legend(.selected); legend(.entry); legend(.exit); legend(.external); legend(.normal)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 7)
        }
        .background(.thinMaterial)
    }

    @ViewBuilder private func legend(_ role: RouterVPNMapRole) -> some View {
        Label(role.rawValue, systemImage: role.symbol)
            .font(.caption2.weight(.semibold))
            .foregroundStyle(role.color)
    }
}

struct RouterVPNEmptyMapView: View {
    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "map")
                .font(.system(size: 42))
                .foregroundStyle(.secondary)
            Text("No real node coordinates")
                .font(.headline)
            Text("Router VPN never invents map locations. Link a Router VPN node or custom/external node with real coordinates to place it on the map.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

private struct RouterVPNMapNodeList: View {
    let nodes: [RouterVPNMapPoint]
    var body: some View {
        List(nodes) { node in
            VStack(alignment: .leading, spacing: 3) {
                HStack {
                    Label(node.name, systemImage: node.role.symbol)
                        .fontWeight(node.active ? .semibold : .regular)
                        .foregroundStyle(node.role.color)
                    Spacer()
                    Text(node.role.rawValue).font(.caption2).foregroundStyle(.secondary)
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
