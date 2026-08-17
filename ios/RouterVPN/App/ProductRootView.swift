import SwiftUI

struct ProductRootView: View {
    @EnvironmentObject var model: RouterVPNModel

    var body: some View {
        IOSUnifiedProductView()
            .environmentObject(model)
    }
}

private let routerVPNProductParityContract = "map-first swipe-up Connect Disconnect quick kill switch Multihop Settings Mode DNS SMART AUTO default AUTO all logical presets CUSTOM preset builder saved delete Router node Custom external color-coded hops real coordinates Home Fastest Custom DoT DoH DoH3 Rescue actual public VPN exit selected-node proof"
