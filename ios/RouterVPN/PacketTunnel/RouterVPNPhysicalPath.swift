import CryptoKit
import Foundation
import Libbox
@preconcurrency import Network

/// A settings-reapply callback must not be confused with a physical route
/// transition. Unavailable or ambiguous route information is never accepted.
enum RouterVPNPhysicalPath {
    static func snapshot(_ path: NWPath) -> (name: String, signature: String)? {
        guard path.status == .satisfied else { return nil }
        let eligible = path.availableInterfaces.filter {
            [.wifi, .cellular, .wiredEthernet].contains($0.type) && path.usesInterfaceType($0.type) &&
            !$0.name.hasPrefix("utun") && !$0.name.hasPrefix("tun") && !$0.name.hasPrefix("lo")
        }
        guard eligible.count == 1, let selected = eligible.first else { return nil }
        var failure: NSError?
        guard let native = LibboxRouterMTUPhysicalPath(selected.name, &failure), failure == nil, !native.isEmpty else { return nil }
        let fields = [selected.name, String(selected.index), native,
                      String(path.isExpensive), String(path.isConstrained), String(path.supportsIPv4),
                      String(path.supportsIPv6), String(path.supportsDNS)] + path.gateways.map { String(describing: $0) }.sorted()
        guard let data = try? JSONSerialization.data(withJSONObject: fields) else { return nil }
        return (selected.name, SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined())
    }
}
