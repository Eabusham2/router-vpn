import CFNetwork
import CryptoKit
import Foundation
@preconcurrency import Network
import NetworkExtension
import WireGuardKit

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private static let maxBundleBytes = 32 * 1024 * 1024
    private static let maxProfileBytes = 4 * 1024 * 1024
    private static let maxLayeredBytes = 12 * 1024 * 1024
    private static let maxProofBytes = 16 * 1024
    private static let proofKind = "router-vpn-private-agent-v1"
    private static let nodeProofDomain = "router-vpn-node-proof-v1\n"

    private final class NetworkProofGuard: @unchecked Sendable {
        private let lock = NSLock()
        private var sawInitialPath = false
        private var invalidated = false
        weak var owner: PacketTunnelProvider?

        init(owner: PacketTunnelProvider) { self.owner = owner }

        func handle(_ path: NWPath) {
            _ = path.status
            lock.lock()
            if !sawInitialPath {
                sawInitialPath = true
                lock.unlock()
                return
            }
            if invalidated {
                lock.unlock()
                return
            }
            invalidated = true
            lock.unlock()
            owner?.invalidateSelectedPathProof()
        }
    }

    private var wireGuardAdapter: WireGuardAdapter?
    private var libboxEngine: RouterVPNLibboxEngine?
    private var proofTask: URLSessionDataTask?
    private var proofSession: URLSession?
    private var pathMonitor: NWPathMonitor?
    private var pathProofGuard: NetworkProofGuard?
    private let pathMonitorQueue = DispatchQueue(label: "com.eabusham.routervpn.path-proof", qos: .utility)

    override func startTunnel(options: [String: NSObject]? = nil, completionHandler: @escaping (Error?) -> Void) {
        do {
            guard let tunnelProtocol = protocolConfiguration as? NETunnelProviderProtocol, let provider = tunnelProtocol.providerConfiguration else { throw tunnelError(1, "Router VPN PacketTunnel configuration is missing.") }
            guard let bundleData = provider["bundle"] as? Data, !bundleData.isEmpty, bundleData.count <= Self.maxBundleBytes else { throw tunnelError(2, "Router VPN private bundle is missing or exceeds the 32 MiB safety limit.") }
            guard let root = try JSONSerialization.jsonObject(with: bundleData) as? [String: Any] else { throw tunnelError(3, "Router VPN private bundle is invalid JSON.") }
            let selectedProfile = try selectedRouterProfile(root)
            let strict = strictKillSwitchRequested(selectedProfile)
            if strict {
                guard tunnelProtocol.includeAllNetworks, tunnelProtocol.enforceRoutes else { throw tunnelError(4, "strict Apple kill switch requested but NetworkExtension route lockdown is not enabled") }
                let allowLAN = selectedProfile["home_lan_access"] as? Bool ?? true
                guard tunnelProtocol.excludeLocalNetworks == !allowLAN else { throw tunnelError(5, "strict Apple kill switch LAN exclusion does not match the imported node policy") }
            }

            let engine = (provider["engine"] as? String ?? "wireguard").lowercased()
            switch engine {
            case "wireguard": try startWireGuard(provider: provider, root: root, selectedProfile: selectedProfile, completionHandler: completionHandler)
            case "libbox": try startLibbox(provider: provider, root: root, selectedProfile: selectedProfile, strict: strict, completionHandler: completionHandler)
            case "external-libbox": try startExternalLibbox(selectedProfile: selectedProfile, strict: strict, completionHandler: completionHandler)
            default: throw tunnelError(6, "Unsupported Router VPN iOS engine \(engine).")
            }
        } catch { completionHandler(error) }
    }

    private func startWireGuard(provider: [String: Any], root: [String: Any], selectedProfile: [String: Any], completionHandler: @escaping (Error?) -> Void) throws {
        let requestedMode = (provider["mode"] as? String ?? "wg").lowercased(), requestedCandidates = (provider["modeCandidates"] as? [String] ?? []).map { $0.lowercased() }
        if requestedMode != "auto" && requestedMode != "wg" && !requestedCandidates.contains("wg") { throw tunnelError(7, "WireGuard engine received a non-WireGuard mode request.") }
        let wgText = try wireGuardProfile(root), tunnelConfiguration = try RouterVPNWireGuardConfig.parse(wgText, name: "Router VPN")
        guard tunnelConfiguration.peers.count == 1 else { throw tunnelError(8, "Router VPN iOS node proof requires exactly one generated WireGuard server peer.") }
        let derivedNodeID = deriveNodeProof(from: tunnelConfiguration.peers[0].publicKey.base64Key), suppliedNodeID = try suppliedNodeProof(root: root, selectedProfile: selectedProfile)
        if !suppliedNodeID.isEmpty && suppliedNodeID != derivedNodeID { throw tunnelError(9, "Router bundle node identity does not match its WireGuard server public key.") }
        let expectedNodeID = suppliedNodeID.isEmpty ? derivedNodeID : suppliedNodeID
        guard expectedNodeID.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else { throw tunnelError(10, "Router VPN node proof id is invalid.") }
        let proofURL = try selectedProofURL(selectedProfile)
        let adapter = WireGuardAdapter(with: self) { level, message in if level == .error { NSLog("RouterVPN WireGuard: %@", message) } }
        wireGuardAdapter = adapter
        adapter.start(tunnelConfiguration: tunnelConfiguration) { [weak self] adapterError in
            guard let self else { completionHandler(NSError(domain: "RouterVPN.PacketTunnel", code: 11, userInfo: [NSLocalizedDescriptionKey: "Router VPN PacketTunnel was released during startup."])); return }
            if let adapterError { self.wireGuardAdapter = nil; completionHandler(self.tunnelError(12, "WireGuard engine failed to start: \(adapterError.localizedDescription)")); return }
            self.proveSelectedNode(url: proofURL, expectedNodeID: expectedNodeID, proxyPort: nil) { proofError in
                if let proofError { adapter.stop { _ in self.wireGuardAdapter = nil; completionHandler(proofError) }; return }
                self.armNetworkProofGuard()
                completionHandler(nil)
            }
        }
    }

    private func startLibbox(provider: [String: Any], root: [String: Any], selectedProfile: [String: Any], strict: Bool, completionHandler: @escaping (Error?) -> Void) throws {
        let rawProfileID = (provider["rawProfileID"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard rawProfileID.range(of: "^[A-Za-z0-9._-]{1,96}$", options: .regularExpression) != nil, !rawProfileID.contains("..") else { throw tunnelError(13, "iOS Libbox raw profile id is invalid.") }
        let files = try layeredProfile(root, rawProfileID: rawProfileID)
        let expectedNodeID = try suppliedNodeProof(root: root, selectedProfile: selectedProfile)
        guard expectedNodeID.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else { throw tunnelError(14, "Layered iOS modes require the imported node's exact node proof id.") }
        let proofURL = try selectedProofURL(selectedProfile)
        let engine = RouterVPNLibboxEngine(tunnel: self); libboxEngine = engine
        do { try engine.start(files: files, strict: strict) } catch { libboxEngine = nil; throw tunnelError(15, "Libbox engine failed to start: \(error.localizedDescription)") }
        proveSelectedNode(url: proofURL, expectedNodeID: expectedNodeID, proxyPort: RouterVPNLibboxEngine.proofProxyPort) { [weak self] proofError in
            guard let self else { completionHandler(NSError(domain: "RouterVPN.PacketTunnel", code: 16, userInfo: [NSLocalizedDescriptionKey: "Router VPN PacketTunnel was released during Libbox proof."])); return }
            if let proofError { engine.stop(); self.libboxEngine = nil; completionHandler(proofError); return }
            self.armNetworkProofGuard()
            completionHandler(nil)
        }
    }

    private func startExternalLibbox(selectedProfile: [String: Any], strict: Bool, completionHandler: @escaping (Error?) -> Void) throws {
        let runtime = try RouterVPNExternalExitBuilder.build(profile: selectedProfile)
        let engine = RouterVPNLibboxEngine(tunnel: self); libboxEngine = engine
        do { try engine.start(files: runtime.files, strict: strict) } catch { libboxEngine = nil; throw tunnelError(17, "External Libbox engine failed to start: \(error.localizedDescription)") }
        proveExternalExit(expectedPublicIP: runtime.expectedPublicIP, proxyPort: RouterVPNLibboxEngine.proofProxyPort) { [weak self] proofError in
            guard let self else { completionHandler(NSError(domain: "RouterVPN.PacketTunnel", code: 18, userInfo: [NSLocalizedDescriptionKey: "Router VPN PacketTunnel was released during external-exit proof."])); return }
            if let proofError { engine.stop(); self.libboxEngine = nil; completionHandler(proofError); return }
            self.armNetworkProofGuard()
            completionHandler(nil)
        }
    }

    private func armNetworkProofGuard() {
        pathMonitor?.cancel()
        let monitor = NWPathMonitor()
        let guardState = NetworkProofGuard(owner: self)
        pathProofGuard = guardState
        pathMonitor = monitor
        monitor.pathUpdateHandler = { path in guardState.handle(path) }
        monitor.start(queue: pathMonitorQueue)
    }

    private func invalidateSelectedPathProof() {
        pathMonitor?.cancel()
        pathMonitor = nil
        pathProofGuard = nil
        cancelTunnelWithError(tunnelError(19, "Underlying network changed; selected-node/public-exit proof was invalidated. Reconnect must establish and prove the selected path again."))
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        pathMonitor?.cancel(); pathMonitor = nil; pathProofGuard = nil
        proofTask?.cancel(); proofTask = nil; proofSession?.invalidateAndCancel(); proofSession = nil
        if let engine = libboxEngine { engine.stop(); libboxEngine = nil }
        guard let adapter = wireGuardAdapter else { completionHandler(); return }
        adapter.stop { [weak self] _ in self?.wireGuardAdapter = nil; completionHandler() }
    }

    override func sleep(completionHandler: @escaping () -> Void) { libboxEngine?.pause(); completionHandler() }
    override func wake() { libboxEngine?.wake() }
    func writeLibboxLog(_ message: String) { if !message.isEmpty { NSLog("RouterVPN Libbox: %@", message) } }

    private func proveSelectedNode(url: URL, expectedNodeID: String, proxyPort: Int?, completion: @escaping (Error?) -> Void) {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 5; configuration.timeoutIntervalForResource = 6; configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        if let proxyPort { configuration.connectionProxyDictionary = [kCFNetworkProxiesHTTPEnable as String: 1, kCFNetworkProxiesHTTPProxy as String: "127.0.0.1", kCFNetworkProxiesHTTPPort as String: proxyPort] }
        let session = URLSession(configuration: configuration); proofSession = session
        var request = URLRequest(url: url); request.timeoutInterval = 5; request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData; request.setValue("application/json", forHTTPHeaderField: "Accept")
        proofTask = session.dataTask(with: request) { [weak self] data, response, error in
            guard let self else { return }
            defer { self.proofTask = nil; self.proofSession?.finishTasksAndInvalidate(); self.proofSession = nil }
            if let error { completion(self.tunnelError(20, "Selected-node private path proof failed: \(error.localizedDescription)")); return }
            guard let http = response as? HTTPURLResponse, http.statusCode == 200, let data, !data.isEmpty, data.count <= Self.maxProofBytes else { completion(self.tunnelError(21, "Selected-node private path proof returned an invalid response.")); return }
            do {
                guard let body = try JSONSerialization.jsonObject(with: data) as? [String: Any], body["ok"] as? Bool == true, body["node_id"] as? String == expectedNodeID, body["proof"] as? String == Self.proofKind else { throw self.tunnelError(22, "Selected-node private path proof identity did not match the imported router bundle.") }
                completion(nil)
            } catch { completion(error) }
        }
        proofTask?.resume()
    }

    private func proveExternalExit(expectedPublicIP: String, proxyPort: Int, completion: @escaping (Error?) -> Void) {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 5; configuration.timeoutIntervalForResource = 6; configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.connectionProxyDictionary = [kCFNetworkProxiesHTTPEnable as String: 1, kCFNetworkProxiesHTTPProxy as String: "127.0.0.1", kCFNetworkProxiesHTTPPort as String: proxyPort]
        let session = URLSession(configuration: configuration); proofSession = session
        let endpoint = expectedPublicIP.contains(":") ? "https://api64.ipify.org" : "https://api.ipify.org"
        var request = URLRequest(url: URL(string: endpoint)!); request.timeoutInterval = 5; request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData; request.setValue("text/plain", forHTTPHeaderField: "Accept")
        proofTask = session.dataTask(with: request) { [weak self] data, response, error in
            guard let self else { return }
            defer { self.proofTask = nil; self.proofSession?.finishTasksAndInvalidate(); self.proofSession = nil }
            if let error { completion(self.tunnelError(23, "External public-exit proof failed: \(error.localizedDescription)")); return }
            guard let http = response as? HTTPURLResponse, http.statusCode == 200, let data, !data.isEmpty, data.count <= 256, let text = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) else { completion(self.tunnelError(24, "External public-exit proof returned an invalid response.")); return }
            let matches: Bool
            if let wanted = IPv4Address(expectedPublicIP), let seen = IPv4Address(text) { matches = wanted == seen }
            else if let wanted = IPv6Address(expectedPublicIP), let seen = IPv6Address(text) { matches = wanted == seen }
            else { matches = false }
            guard matches else { completion(self.tunnelError(25, "External exit reached \(text), expected \(expectedPublicIP).")); return }
            completion(nil)
        }
        proofTask?.resume()
    }

    private func selectedRouterProfile(_ root: [String: Any]) throws -> [String: Any] {
        guard let profiles = root["routerProfiles"] as? [[String: Any]], !profiles.isEmpty else { throw tunnelError(30, "Router VPN bundle has no routerProfiles.") }
        let selectedID = root["selectedRouterID"] as? String ?? ""
        if let selected = profiles.first(where: { ($0["id"] as? String ?? "") == selectedID }) { return selected }
        return profiles[0]
    }
    private func wireGuardProfile(_ root: [String: Any]) throws -> String {
        guard let profiles = root["profiles"] as? [String: Any], let wg = profiles["wg"] as? [String: Any], let encoded = wg["wg.conf"] as? String, !encoded.isEmpty, let data = Data(base64Encoded: encoded, options: .ignoreUnknownCharacters), !data.isEmpty, data.count <= Self.maxProfileBytes, let text = String(data: data, encoding: .utf8) else { throw tunnelError(31, "Router VPN bundle has no valid bounded native WireGuard profile.") }
        return text
    }
    private func layeredProfile(_ root: [String: Any], rawProfileID: String) throws -> [String: Data] {
        guard let profiles = root["profiles"] as? [String: Any], let raw = profiles[rawProfileID] as? [String: Any], raw["sing-box.json"] != nil else { throw tunnelError(32, "Selected iOS raw profile does not contain sing-box.json.") }
        var result: [String: Data] = [:], total = 0
        let assetPattern = try NSRegularExpression(pattern: "^[A-Za-z0-9._-]{1,128}$")
        for (name, value) in raw {
            guard let encoded = value as? String else { throw tunnelError(33, "Libbox asset \(name) is not an encoded string.") }
            let range = NSRange(name.startIndex..<name.endIndex, in: name)
            guard assetPattern.firstMatch(in: name, range: range)?.range == range, name != ".", name != "..", !name.contains("..") else { throw tunnelError(34, "Unsafe Libbox asset name \(name).") }
            guard let data = Data(base64Encoded: encoded, options: []), data.count <= Self.maxProfileBytes else { throw tunnelError(35, "Libbox asset \(name) is invalid or too large.") }
            total += data.count; guard total <= Self.maxLayeredBytes else { throw tunnelError(36, "Libbox raw profile exceeds the 12 MiB safety limit.") }
            result[name] = data
        }
        return result
    }
    private func strictKillSwitchRequested(_ profile: [String: Any]) -> Bool {
        if profile["kill_switch"] as? Bool == true { return true }
        let value = (profile["kill_switch_policy"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased(); return ["strict", "always", "enabled", "on", "lockdown"].contains(value)
    }
    private func suppliedNodeProof(root: [String: Any], selectedProfile: [String: Any]) throws -> String {
        let top = (root["nodeProofId"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines), nested = (selectedProfile["node_proof_id"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        for value in [top, nested] where !value.isEmpty { guard value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else { throw tunnelError(37, "Router bundle contains an invalid node proof id.") } }
        if !top.isEmpty && !nested.isEmpty && top != nested { throw tunnelError(38, "Router bundle node proof ids disagree.") }
        return top.isEmpty ? nested : top
    }
    private func deriveNodeProof(from serverPublicKey: String) -> String { SHA256.hash(data: Data((Self.nodeProofDomain + serverPublicKey).utf8)).map { String(format: "%02x", $0) }.joined() }
    private func selectedProofURL(_ profile: [String: Any]) throws -> URL {
        let raw = (profile["path_probe_url"] as? String ?? "http://10.77.0.1:8787/health").trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: raw), url.scheme?.lowercased() == "http", let host = url.host, privateLiteralHost(host) else { throw tunnelError(39, "Selected-node proof URL must use a literal private IPv4/IPv6 HTTP address.") }
        return url
    }
    private func privateLiteralHost(_ host: String) -> Bool {
        if let ipv4 = IPv4Address(host) { let b = [UInt8](ipv4.rawValue); guard b.count == 4 else { return false }; return b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254) }
        if let ipv6 = IPv6Address(host) { let b = [UInt8](ipv6.rawValue); guard b.count == 16 else { return false }; return (b[0] & 0xfe) == 0xfc || (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) }
        return false
    }
    private func tunnelError(_ code: Int, _ message: String) -> NSError { NSError(domain: "RouterVPN.PacketTunnel", code: code, userInfo: [NSLocalizedDescriptionKey: message]) }
}
