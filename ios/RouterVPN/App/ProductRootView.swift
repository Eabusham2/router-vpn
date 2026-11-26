import SwiftUI

struct ProductRootView: View {
    @EnvironmentObject var model: RouterVPNModel
    @State private var showingSpeedLab = false
    @State private var showingExternalNodeBuilder = false

    var body: some View {
        IOSUnifiedProductView(
            openSpeedLab: { showingSpeedLab = true },
            addExternalNode: { showingExternalNodeBuilder = true })
            .environmentObject(model)
        .sheet(isPresented: $showingSpeedLab) {
            IOSSpeedLabView().environmentObject(model)
        }
        .sheet(isPresented: $showingExternalNodeBuilder) {
            IOSExternalNodeBuilderView().environmentObject(model)
        }
        .task {
            // A temporary Speed Lab path can save NetworkExtension state before
            // the process is killed. The durable journal restores the original
            // bundle/last-good runtime and stops the temporary tunnel before the
            // normal product is allowed to continue from an interrupted test.
            await IOSSpeedLabPersistenceJournal.recoverIfNeeded(model: model)
        }
    }
}

private let routerVPNProductParityContract = "map-first swipe-up Connect Disconnect quick kill switch Multihop Settings Mode DNS Speed Lab idle loaded download upload latency Auto Custom min max time SMART AUTO default AUTO all logical presets CUSTOM preset builder saved delete Router node Custom external typed external node builder WireGuard SOCKS5 HTTP CONNECT HTTPS CONNECT Shadowsocks Hysteria2 color-coded hops real coordinates Home Fastest Custom DoT DoH DoH3 Rescue actual public VPN exit selected-node proof opt-in real user location no IP geolocation crash-recoverable temporary Speed Lab"
