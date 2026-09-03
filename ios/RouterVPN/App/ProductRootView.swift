import SwiftUI

struct ProductRootView: View {
    @EnvironmentObject var model: RouterVPNModel
    @State private var showingSpeedLab = false

    var body: some View {
        ZStack(alignment: .topTrailing) {
            IOSUnifiedProductView()
                .environmentObject(model)

            // The unified product already owns the one opt-in CoreLocation
            // control in its map header. Keep this root overlay dedicated to
            // Speed Lab so no duplicate location button can cover map controls.
            Button { showingSpeedLab = true } label: {
                Image(systemName: "speedometer")
                    .font(.system(size: 18, weight: .semibold))
                    .frame(width: 42, height: 42)
            }
            .buttonStyle(.borderedProminent)
            .buttonBorderShape(.circle)
            .accessibilityLabel("Open Router VPN Speed Lab")
            .padding(.top, 58)
            .padding(.trailing, 12)
        }
        .sheet(isPresented: $showingSpeedLab) {
            IOSSpeedLabView().environmentObject(model)
        }
    }
}

private let routerVPNProductParityContract = "map-first swipe-up Connect Disconnect quick kill switch Multihop Settings Mode DNS Speed Lab idle loaded download upload latency Auto Custom min max time SMART AUTO default AUTO all logical presets CUSTOM preset builder saved delete Router node Custom external color-coded hops real coordinates Home Fastest Custom DoT DoH DoH3 Rescue actual public VPN exit selected-node proof opt-in real user location no IP geolocation"
