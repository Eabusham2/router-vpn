import Foundation
import Libbox
@preconcurrency import Network
@preconcurrency import NetworkExtension

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

    init(tunnel: PacketTunnelProvider) { self.tunnel = tunnel }

    func openTun(_ options: LibboxTunOptionsProtocol?, ret0_: UnsafeMutablePointer<Int32>?) throws {
        guard let options, let ret0_, let tunnel else { throw error("Libbox requested TUN with missing options/provider/output pointer") }
        guard options.getAutoRoute() else { throw error("Router VPN iOS Libbox requires auto_route=true for a full-device PacketTunnel") }
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        let mtu = Int(options.getMTU())
        guard (1280...9000).contains(mtu) else { throw error("Libbox requested unsafe MTU \(mtu)") }
        settings.mtu = NSNumber(value: mtu)

        let dnsAddress = try options.getDNSServerAddress().value
        guard !dnsAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { throw error("Libbox did not provide an in-tunnel DNS server") }
        let dns = NEDNSSettings(servers: [dnsAddress])
        dns.matchDomains = [""]
        dns.matchDomainsNoSearch = true
        settings.dnsSettings = dns

        let ipv4AddressIterator = options.getInet4Address()!
        var ipv4Addresses: [String] = [], ipv4Masks: [String] = []
        while ipv4AddressIterator.hasNext() {
            let prefix = ipv4AddressIterator.next()!
            ipv4Addresses.append(prefix.address()); ipv4Masks.append(prefix.mask())
        }
        if !ipv4Addresses.isEmpty {
            let ipv4 = NEIPv4Settings(addresses: ipv4Addresses, subnetMasks: ipv4Masks)
            var include: [NEIPv4Route] = []
            let routes = options.getInet4RouteAddress()!
            while routes.hasNext() { let p = routes.next()!; include.append(NEIPv4Route(destinationAddress: p.address(), subnetMask: p.mask())) }
            if include.isEmpty { include = [NEIPv4Route.default()] }
            var exclude: [NEIPv4Route] = []
            let excluded = options.getInet4RouteExcludeAddress()!
            while excluded.hasNext() { let p = excluded.next()!; exclude.append(NEIPv4Route(destinationAddress: p.address(), subnetMask: p.mask())) }
            ipv4.includedRoutes = include; ipv4.excludedRoutes = exclude; settings.ipv4Settings = ipv4
        }

        let ipv6AddressIterator = options.getInet6Address()!
        var ipv6Addresses: [String] = [], ipv6Prefixes: [NSNumber] = []
        while ipv6AddressIterator.hasNext() {
            let prefix = ipv6AddressIterator.next()!
            ipv6Addresses.append(prefix.address()); ipv6Prefixes.append(NSNumber(value: prefix.prefix()))
        }
        if !ipv6Addresses.isEmpty {
            let ipv6 = NEIPv6Settings(addresses: ipv6Addresses, networkPrefixLengths: ipv6Prefixes)
            var include: [NEIPv6Route] = []
            let routes = options.getInet6RouteAddress()!
            while routes.hasNext() { let p = routes.next()!; include.append(NEIPv6Route(destinationAddress: p.address(), networkPrefixLength: NSNumber(value: p.prefix()))) }
            if include.isEmpty { include = [NEIPv6Route.default()] }
            var exclude: [NEIPv6Route] = []
            let excluded = options.getInet6RouteExcludeAddress()!
            while excluded.hasNext() { let p = excluded.next()!; exclude.append(NEIPv6Route(destinationAddress: p.address(), networkPrefixLength: NSNumber(value: p.prefix()))) }
            ipv6.includedRoutes = include; ipv6.excludedRoutes = exclude; settings.ipv6Settings = ipv6
        }

        if options.isHTTPProxyEnabled() {
            let proxy = NEProxySettings()
            let server = NEProxyServer(address: options.getHTTPProxyServer(), port: Int(options.getHTTPProxyServerPort()))
            proxy.httpServer = server; proxy.httpsServer = server; proxy.httpEnabled = true; proxy.httpsEnabled = true
            var bypass: [String] = []
            let bypassIterator = options.getHTTPProxyBypassDomain()!
            while bypassIterator.hasNext() { bypass.append(bypassIterator.next()) }
            if !bypass.isEmpty { proxy.exceptionList = bypass }
            var domains: [String] = []
            let matchIterator = options.getHTTPProxyMatchDomain()!
            while matchIterator.hasNext() { domains.append(matchIterator.next()) }
            if !domains.isEmpty { proxy.matchDomains = domains }
            settings.proxySettings = proxy
        }

        try apply(settings, to: tunnel)
        networkSettings = settings
        if let fd = tunnel.packetFlow.value(forKeyPath: "socket.fileDescriptor") as? Int32 { ret0_.pointee = fd; return }
        let fallbackFD = LibboxGetTunnelFileDescriptor()
        guard fallbackFD != -1 else { throw error("NetworkExtension TUN file descriptor is unavailable") }
        ret0_.pointee = fallbackFD
    }

    // Libbox renamed these callbacks across adjacent mobile-binding generations.
    // Keep both spellings so the pinned XCFramework and source contract remain compatible.
    func usePlatformAutoDetectControl() -> Bool { false }
    func usePlatformAutoDetectInterfaceControl() -> Bool { usePlatformAutoDetectControl() }
    func autoDetectControl(_: Int32) throws {}
    func autoDetectInterfaceControl(_ fd: Int32) throws { try autoDetectControl(fd) }

    func findConnectionOwner(_ ipProtocol: Int32, sourceAddress: String?, sourcePort: Int32, destinationAddress: String?, destinationPort: Int32) throws -> LibboxConnectionOwner { throw error("Process-owner lookup is intentionally unavailable inside the Router VPN iOS extension") }
    func useProcFS() -> Bool { false }
    func writeLog(_ message: String?) { if let message { onLog?(message) } }
    func writeDebugMessage(_ message: String?) { if let message { onLog?(message) } }

    func startDefaultInterfaceMonitor(_ listener: LibboxInterfaceUpdateListenerProtocol?) throws {
        guard let listener else { return }
        monitor?.cancel()
        let next = NWPathMonitor(); monitor = next
        let first = DispatchSemaphore(value: 0)
        let delivery = InterfaceMonitorDelivery(listener: listener, first: first)
        next.pathUpdateHandler = { path in delivery.deliver(path) }
        next.start(queue: DispatchQueue(label: "routervpn.libbox.path"))
        if first.wait(timeout: .now() + 5) == .timedOut { next.cancel(); monitor = nil; throw error("Timed out while discovering the default iOS network interface") }
    }
    func closeDefaultInterfaceMonitor(_: LibboxInterfaceUpdateListenerProtocol?) throws { monitor?.cancel(); monitor = nil }
    func getInterfaces() throws -> LibboxNetworkInterfaceIteratorProtocol {
        guard let path = monitor?.currentPath else { throw error("Default-interface monitor has not started") }
        if path.status == .unsatisfied { return InterfaceIterator([]) }
        let values = path.availableInterfaces.map { item -> LibboxNetworkInterface in
            let result = LibboxNetworkInterface()
            result.name = item.name
            result.index = Int32(item.index)
            result.mtu = 0
            result.flags = 0
            result.addresses = StringIterator([])
            result.dnsServer = StringIterator([])
            result.metered = path.isExpensive
            switch item.type { case .wifi: result.type = LibboxInterfaceTypeWIFI; case .cellular: result.type = LibboxInterfaceTypeCellular; case .wiredEthernet: result.type = LibboxInterfaceTypeEthernet; default: result.type = LibboxInterfaceTypeOther }
            return result
        }
        return InterfaceIterator(values)
    }
    func underNetworkExtension() -> Bool { true }
    func includeAllNetworks() -> Bool { includeAllNetworksRequested }
    func clearDNSCache() {
        guard let tunnel, let settings = networkSettings else { return }
        tunnel.reasserting = true
        tunnel.setTunnelNetworkSettings(nil) { _ in tunnel.setTunnelNetworkSettings(settings) { _ in tunnel.reasserting = false } }
    }
    func readWIFIState() -> LibboxWIFIState? { nil }
    func readWIFISSID() -> String? { nil }
    func serviceStop() throws { try onStopService?() }
    func serviceReload() throws { try onReloadService?() }
    func getSystemProxyStatus() throws -> LibboxSystemProxyStatus {
        let status = LibboxSystemProxyStatus()
        guard let proxy = networkSettings?.proxySettings, proxy.httpServer != nil else { return status }
        status.available = true; status.enabled = proxy.httpEnabled; return status
    }
    func setSystemProxyEnabled(_ enabled: Bool) throws {
        guard let tunnel, let settings = networkSettings, let proxy = settings.proxySettings, proxy.httpServer != nil else { return }
        if proxy.httpEnabled == enabled { return }
        proxy.httpEnabled = enabled; proxy.httpsEnabled = enabled; settings.proxySettings = proxy; try apply(settings, to: tunnel)
    }
    func send(_: LibboxNotification?) throws {}
    func sendNotification(_ notification: LibboxNotification?) throws { try send(notification) }
    func localDNSTransport() -> (any LibboxLocalDNSTransportProtocol)? { nil }
    func systemCertificates() -> (any LibboxStringIteratorProtocol)? { nil }
    func reset() { networkSettings = nil; monitor?.cancel(); monitor = nil }

    private static func update(_ listener: LibboxInterfaceUpdateListenerProtocol, from path: NWPath) {
        guard path.status != .unsatisfied, let iface = path.availableInterfaces.first else { listener.updateDefaultInterface("", interfaceIndex: -1, isExpensive: false, isConstrained: false); return }
        listener.updateDefaultInterface(iface.name, interfaceIndex: Int32(iface.index), isExpensive: path.isExpensive, isConstrained: path.isConstrained)
    }

    /// NWPathMonitor requires a @Sendable callback under Swift 6. The Libbox mobile
    /// listener protocol itself predates Sendable, so keep that foreign reference
    /// behind a serial-queue delivery box and protect the one-shot semaphore state.
    private final class InterfaceMonitorDelivery: @unchecked Sendable {
        private let listener: LibboxInterfaceUpdateListenerProtocol
        private let first: DispatchSemaphore
        private let lock = NSLock()
        private var deliveredFirst = false

        init(listener: LibboxInterfaceUpdateListenerProtocol, first: DispatchSemaphore) {
            self.listener = listener
            self.first = first
        }

        func deliver(_ path: NWPath) {
            RouterVPNLibboxPlatform.update(listener, from: path)
            lock.lock()
            let shouldSignal = !deliveredFirst
            deliveredFirst = true
            lock.unlock()
            if shouldSignal { first.signal() }
        }
    }

    private func apply(_ settings: NEPacketTunnelNetworkSettings?, to tunnel: PacketTunnelProvider) throws {
        let semaphore = DispatchSemaphore(value: 0); var failure: Error?
        tunnel.setTunnelNetworkSettings(settings) { error in failure = error; semaphore.signal() }
        if semaphore.wait(timeout: .now() + 10) == .timedOut { throw error("Timed out applying PacketTunnel network settings") }
        if let failure { throw failure }
    }
    private func error(_ message: String) -> NSError { NSError(domain: "RouterVPN.LibboxPlatform", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }

    final class InterfaceIterator: NSObject, LibboxNetworkInterfaceIteratorProtocol {
        private var iterator: IndexingIterator<[LibboxNetworkInterface]>; private var pending: LibboxNetworkInterface?
        init(_ values: [LibboxNetworkInterface]) { iterator = values.makeIterator() }
        func hasNext() -> Bool { pending = iterator.next(); return pending != nil }
        func next() -> LibboxNetworkInterface? { pending }
    }

    final class StringIterator: NSObject, LibboxStringIteratorProtocol {
        private let values: [String]
        private var index = 0
        init(_ values: [String]) { self.values = values }
        func len() -> Int32 { Int32(values.count) }
        func hasNext() -> Bool { index < values.count }
        func next() -> String {
            guard index < values.count else { return "" }
            let value = values[index]
            index += 1
            return value
        }
    }
}