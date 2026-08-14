import Foundation
import Libbox
import Network
import NetworkExtension

/// Minimal Router VPN NetworkExtension bridge for the exact pinned Libbox 1.13.12 API.
/// It intentionally implements only Router VPN policy and does not inherit another app's UI/preferences model.
final class RouterVPNLibboxPlatform: NSObject, LibboxPlatformInterfaceProtocol, LibboxCommandServerHandlerProtocol {
    weak var tunnel: PacketTunnelProvider?
    var includeAllNetworksRequested = false
    var onStopService: (() throws -> Void)?
    var onReloadService: (() throws -> Void)?
    var onLog: ((String) -> Void)?

    private var networkSettings: NEPacketTunnelNetworkSettings?
    private var monitor: NWPathMonitor?

    init(tunnel: PacketTunnelProvider) {
        self.tunnel = tunnel
    }

    func openTun(_ options: LibboxTunOptionsProtocol?, ret0_: UnsafeMutablePointer<Int32>?) throws {
        guard let options, let ret0_, let tunnel else {
            throw error("Libbox requested TUN with missing options/provider/output pointer")
        }
        guard options.getAutoRoute() else {
            throw error("Router VPN iOS Libbox requires auto_route=true for a full-device PacketTunnel")
        }

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        let mtu = Int(options.getMTU())
        guard (1280...9000).contains(mtu) else { throw error("Libbox requested unsafe MTU \(mtu)") }
        settings.mtu = NSNumber(value: mtu)

        let dnsAddress = try options.getDNSServerAddress().value
        guard !dnsAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw error("Libbox did not provide an in-tunnel DNS server")
        }
        let dns = NEDNSSettings(servers: [dnsAddress])
        dns.matchDomains = [""]
        dns.matchDomainsNoSearch = true
        settings.dnsSettings = dns

        let ipv4AddressIterator = options.getInet4Address()!
        var ipv4Addresses: [String] = []
        var ipv4Masks: [String] = []
        while ipv4AddressIterator.hasNext() {
            let prefix = ipv4AddressIterator.next()!
            ipv4Addresses.append(prefix.address())
            ipv4Masks.append(prefix.mask())
        }
        if !ipv4Addresses.isEmpty {
            let ipv4 = NEIPv4Settings(addresses: ipv4Addresses, subnetMasks: ipv4Masks)
            var include: [NEIPv4Route] = []
            let routeIterator = options.getInet4RouteAddress()!
            while routeIterator.hasNext() {
                let prefix = routeIterator.next()!
                include.append(NEIPv4Route(destinationAddress: prefix.address(), subnetMask: prefix.mask()))
            }
            if include.isEmpty { include = [NEIPv4Route.default()] }
            var exclude: [NEIPv4Route] = []
            let excludeIterator = options.getInet4RouteExcludeAddress()!
            while excludeIterator.hasNext() {
                let prefix = excludeIterator.next()!
                exclude.append(NEIPv4Route(destinationAddress: prefix.address(), subnetMask: prefix.mask()))
            }
            ipv4.includedRoutes = include
            ipv4.excludedRoutes = exclude
            settings.ipv4Settings = ipv4
        }

        let ipv6AddressIterator = options.getInet6Address()!
        var ipv6Addresses: [String] = []
        var ipv6Prefixes: [NSNumber] = []
        while ipv6AddressIterator.hasNext() {
            let prefix = ipv6AddressIterator.next()!
            ipv6Addresses.append(prefix.address())
            ipv6Prefixes.append(NSNumber(value: prefix.prefix()))
        }
        if !ipv6Addresses.isEmpty {
            let ipv6 = NEIPv6Settings(addresses: ipv6Addresses, networkPrefixLengths: ipv6Prefixes)
            var include: [NEIPv6Route] = []
            let routeIterator = options.getInet6RouteAddress()!
            while routeIterator.hasNext() {
                let prefix = routeIterator.next()!
                include.append(NEIPv6Route(destinationAddress: prefix.address(), networkPrefixLength: NSNumber(value: prefix.prefix())))
            }
            if include.isEmpty { include = [NEIPv6Route.default()] }
            var exclude: [NEIPv6Route] = []
            let excludeIterator = options.getInet6RouteExcludeAddress()!
            while excludeIterator.hasNext() {
                let prefix = excludeIterator.next()!
                exclude.append(NEIPv6Route(destinationAddress: prefix.address(), networkPrefixLength: NSNumber(value: prefix.prefix())))
            }
            ipv6.includedRoutes = include
            ipv6.excludedRoutes = exclude
            settings.ipv6Settings = ipv6
        }

        if options.isHTTPProxyEnabled() {
            let proxy = NEProxySettings()
            let server = NEProxyServer(address: options.getHTTPProxyServer(), port: Int(options.getHTTPProxyServerPort()))
            proxy.httpServer = server
            proxy.httpsServer = server
            proxy.httpEnabled = true
            proxy.httpsEnabled = true
            var bypass: [String] = []
            let bypassIterator = options.getHTTPProxyBypassDomain()!
            while bypassIterator.hasNext() { if let value = bypassIterator.next() { bypass.append(value) } }
            if !bypass.isEmpty { proxy.exceptionList = bypass }
            var domains: [String] = []
            let matchIterator = options.getHTTPProxyMatchDomain()!
            while matchIterator.hasNext() { if let value = matchIterator.next() { domains.append(value) } }
            if !domains.isEmpty { proxy.matchDomains = domains }
            settings.proxySettings = proxy
        }

        try apply(settings, to: tunnel)
        networkSettings = settings

        if let fd = tunnel.packetFlow.value(forKeyPath: "socket.fileDescriptor") as? Int32 {
            ret0_.pointee = fd
            return
        }
        let fallbackFD = LibboxGetTunnelFileDescriptor()
        guard fallbackFD != -1 else { throw error("NetworkExtension TUN file descriptor is unavailable") }
        ret0_.pointee = fallbackFD
    }

    func usePlatformAutoDetectControl() -> Bool { false }
    func autoDetectControl(_: Int32) throws {}

    func findConnectionOwner(_ ipProtocol: Int32, sourceAddress: String?, sourcePort: Int32, destinationAddress: String?, destinationPort: Int32) throws -> LibboxConnectionOwner {
        throw error("Process-owner lookup is intentionally unavailable inside the Router VPN iOS extension")
    }

    func useProcFS() -> Bool { false }
    func writeLog(_ message: String?) { if let message { onLog?(message) } }
    func writeDebugMessage(_ message: String?) { if let message { onLog?(message) } }

    func startDefaultInterfaceMonitor(_ listener: LibboxInterfaceUpdateListenerProtocol?) throws {
        guard let listener else { return }
        monitor?.cancel()
        let next = NWPathMonitor()
        monitor = next
        let first = DispatchSemaphore(value: 0)
        var firstDelivery = true
        next.pathUpdateHandler = { path in
            self.update(listener, from: path)
            if firstDelivery { firstDelivery = false; first.signal() }
        }
        next.start(queue: DispatchQueue(label: "routervpn.libbox.path"))
        if first.wait(timeout: .now() + 5) == .timedOut {
            next.cancel(); monitor = nil
            throw error("Timed out while discovering the default iOS network interface")
        }
    }

    func closeDefaultInterfaceMonitor(_: LibboxInterfaceUpdateListenerProtocol?) throws {
        monitor?.cancel(); monitor = nil
    }

    func getInterfaces() throws -> LibboxNetworkInterfaceIteratorProtocol {
        guard let path = monitor?.currentPath else { throw error("Default-interface monitor has not started") }
        if path.status == .unsatisfied { return InterfaceIterator([]) }
        let values = path.availableInterfaces.map { item -> LibboxNetworkInterface in
            let result = LibboxNetworkInterface()
            result.name = item.name
            result.index = Int32(item.index)
            switch item.type {
            case .wifi: result.type = LibboxInterfaceTypeWIFI
            case .cellular: result.type = LibboxInterfaceTypeCellular
            case .wiredEthernet: result.type = LibboxInterfaceTypeEthernet
            default: result.type = LibboxInterfaceTypeOther
            }
            return result
        }
        return InterfaceIterator(values)
    }

    func underNetworkExtension() -> Bool { true }
    func includeAllNetworks() -> Bool { includeAllNetworksRequested }

    func clearDNSCache() {
        guard let tunnel, let settings = networkSettings else { return }
        tunnel.reasserting = true
        tunnel.setTunnelNetworkSettings(nil) { _ in
            tunnel.setTunnelNetworkSettings(settings) { _ in tunnel.reasserting = false }
        }
    }

    func readWIFIState() -> LibboxWIFIState? { nil }
    func readWIFISSID() -> String? { nil }
    func serviceStop() throws { try onStopService?() }
    func serviceReload() throws { try onReloadService?() }

    func getSystemProxyStatus() throws -> LibboxSystemProxyStatus {
        let status = LibboxSystemProxyStatus()
        guard let proxy = networkSettings?.proxySettings, proxy.httpServer != nil else { return status }
        status.available = true
        status.enabled = proxy.httpEnabled
        return status
    }

    func setSystemProxyEnabled(_ enabled: Bool) throws {
        guard let tunnel, let settings = networkSettings, let proxy = settings.proxySettings, proxy.httpServer != nil else { return }
        if proxy.httpEnabled == enabled { return }
        proxy.httpEnabled = enabled
        proxy.httpsEnabled = enabled
        settings.proxySettings = proxy
        try apply(settings, to: tunnel)
    }

    func send(_: LibboxNotification?) throws {}
    func localDNSTransport() -> (any LibboxLocalDNSTransportProtocol)? { nil }
    func systemCertificates() -> (any LibboxStringIteratorProtocol)? { nil }

    func reset() {
        networkSettings = nil
        monitor?.cancel(); monitor = nil
    }

    private func update(_ listener: LibboxInterfaceUpdateListenerProtocol, from path: NWPath) {
        guard path.status != .unsatisfied, let iface = path.availableInterfaces.first else {
            listener.updateDefaultInterface("", interfaceIndex: -1, isExpensive: false, isConstrained: false)
            return
        }
        listener.updateDefaultInterface(iface.name, interfaceIndex: Int32(iface.index), isExpensive: path.isExpensive, isConstrained: path.isConstrained)
    }

    private func apply(_ settings: NEPacketTunnelNetworkSettings?, to tunnel: PacketTunnelProvider) throws {
        let semaphore = DispatchSemaphore(value: 0)
        var failure: Error?
        tunnel.setTunnelNetworkSettings(settings) { error in failure = error; semaphore.signal() }
        if semaphore.wait(timeout: .now() + 10) == .timedOut { throw error("Timed out applying PacketTunnel network settings") }
        if let failure { throw failure }
    }

    private func error(_ message: String) -> NSError {
        NSError(domain: "RouterVPN.LibboxPlatform", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }

    final class InterfaceIterator: NSObject, LibboxNetworkInterfaceIteratorProtocol {
        private var iterator: IndexingIterator<[LibboxNetworkInterface]>
        private var pending: LibboxNetworkInterface?
        init(_ values: [LibboxNetworkInterface]) { iterator = values.makeIterator() }
        func hasNext() -> Bool { pending = iterator.next(); return pending != nil }
        func next() -> LibboxNetworkInterface? { pending }
    }
}
