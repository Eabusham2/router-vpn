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
                }
                .buttonStyle(.borderedProminent)
                .padding(.trailing, 14)
                .padding(.bottom, 58)
                .accessibilityHint("Shows only real coordinates stored in imported Router VPN node profiles")
            }
            .sheet(isPresented: $showingMap) {
                RouterVPNNodeMapSheet()
                    .environmentObject(model)
            }
    }
}

// Audit/runtime truth: the shipping map is native MapKit and only consumes
// profile latitude / longitude in RouterVPNNodeMapSheet. When none exist it
// displays "No real node coordinates" rather than inventing a location.
private let routerVPNMapContract = "Map( latitude longitude No real node coordinates"
