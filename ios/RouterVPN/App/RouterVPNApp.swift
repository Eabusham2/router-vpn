import SwiftUI
import UIKit

@main
struct RouterVPNApp: App {
    @StateObject private var model = RouterVPNModel()
    @StateObject private var updates = IOSUpdateChecker()

    var body: some Scene {
        WindowGroup {
            ProductRootView()
                .environmentObject(model)
                .task { await updates.checkAutomatically() }
                .alert(
                    "Router VPN update available",
                    isPresented: Binding(
                        get: { updates.availableSHA != nil },
                        set: { if !$0 { updates.availableSHA = nil } }
                    )
                ) {
                    Button("Open exact release") {
                        if let url = updates.releaseURL { UIApplication.shared.open(url) }
                        updates.availableSHA = nil
                    }
                    Button("Later", role: .cancel) { updates.availableSHA = nil }
                } message: {
                    Text(updates.message + (updates.availableSHA.map { "\n\nExact SHA: " + String($0.prefix(12)) } ?? ""))
                }
        }
    }
}
