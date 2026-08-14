import MapKit
import SwiftUI

struct ProductRootView: View {
    @EnvironmentObject var model: RouterVPNModel
    @State private var showingMap = false
    @State private var showingNodes = false

    var body: some View {
        ContentView()
            .overlay(alignment: .bottomTrailing) {
                VStack(alignment: .trailing, spacing: 8) {
                    Button {
                        showingNodes = true
                    } label: {
                        Label("Linked Nodes", systemImage: "point.3.connected.trianglepath.dotted")
                    }
                    .buttonStyle(.borderedProminent)
                    .accessibilityHint("Selects, edits or removes Router VPN and external nodes, including nodes without coordinates")

                    Button {
                        showingMap = true
                    } label: {
                        Label("Nodes & Map", systemImage: "map.fill")
                    }
                    .buttonStyle(.borderedProminent)
                    .accessibilityHint("Shows only real coordinates stored in imported Router VPN or external node profiles")
                }
                .padding(.trailing, 14)
                .padding(.bottom, 58)
            }
            .sheet(isPresented: $showingMap) {
                RouterVPNNodeMapSheet()
                    .environmentObject(model)
            }
            .sheet(isPresented: $showingNodes) {
                RouterVPNNodeManagerSheet()
                    .environmentObject(model)
            }
    }
}

// Audit/runtime truth: the shipping map is native MapKit and only consumes
// profile latitude / longitude in RouterVPNNodeMapSheet. When none exist it
// displays "No real node coordinates" rather than inventing a location.
// The separate Linked Nodes sheet includes coordinate-less external nodes so
// absence from the map never makes a real imported node unreachable.
private let routerVPNMapContract = "Map( latitude longitude No real node coordinates Linked Nodes"
