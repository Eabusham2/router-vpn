import NetworkExtension

final class PacketTunnelProvider: NEPacketTunnelProvider {
    override func startTunnel(options: [String : NSObject]? = nil, completionHandler: @escaping (Error?) -> Void) {
        let error = NSError(
            domain: "RouterVPN.PacketTunnel",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: "Link AmneziaWGKit/Xray engine before signing this target. See ios/README.md."]
        )
        completionHandler(error)
    }
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) { completionHandler() }
}
