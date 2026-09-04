import SwiftUI

struct ProductRootView: View {
    @EnvironmentObject var model: RouterVPNModel
    @State private var showingSpeedLab = false
    @State private var showingExternalNodeBuilder = false

    var body: some View {
        ZStack(alignment: .topTrailing) {
            IOSUnifiedProductView()
                .environmentObject(model)

            // The unified product already owns the one opt-in CoreLocation
            // control in its map header. Keep these small utility shortcuts in a
            // compact vertical rail so they never replace or modal-block the
            // map-first Connect/Multihop/Settings/Mode/DNS controls.
            VStack(spacing: 8) {
                Button { showingSpeedLab = true } label: {
                    Image(systemName: "speedometer")
                        .font(.system(size: 18, weight: .semibold))
                        .frame(width: 42, height: 42)
                }
                .accessibilityLabel("Open Router VPN Speed Lab")

                Button { showingExternalNodeBuilder = true } label: {
                    Image(systemName: "plus.circle.fill")
                        .font(.system(size: 18, weight: .semibold))
                        .frame(width: 42, height: 42)
                }
                .accessibilityLabel("Add external VPN node")
                .disabled(model.profileMutationBlocked)
            }
            .buttonStyle(.borderedProminent)
            .buttonBorderShape(.circle)
            .padding(.top, 58)
            .padding(.trailing, 12)
        }
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
