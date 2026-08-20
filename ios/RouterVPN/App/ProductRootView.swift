import SwiftUI

struct ProductRootView: View {
    @EnvironmentObject var model: RouterVPNModel

    var body: some View {
        ZStack(alignment: .topTrailing) {
            IOSUnifiedProductView()
                .environmentObject(model)

            // Location stays optional and outside the VPN connection contract.
            // The control itself requests When-In-Use permission only after a
            // user tap and never derives a coordinate from the public IP.
            IOSUserLocationControl()
                .padding(.top, 58)
                .padding(.trailing, 12)
        }
    }
}

private let routerVPNProductParityContract = "map-first swipe-up Connect Disconnect quick kill switch Multihop Settings Mode DNS SMART AUTO default AUTO all logical presets CUSTOM preset builder saved delete Router node Custom external color-coded hops real coordinates Home Fastest Custom DoT DoH DoH3 Rescue actual public VPN exit selected-node proof opt-in real user location no IP geolocation"
