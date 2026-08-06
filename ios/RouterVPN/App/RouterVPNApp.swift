import SwiftUI

@main
struct RouterVPNApp: App {
    @StateObject private var model = RouterVPNModel()
    var body: some Scene { WindowGroup { ContentView().environmentObject(model) } }
}
