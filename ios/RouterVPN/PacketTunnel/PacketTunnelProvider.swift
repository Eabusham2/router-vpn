import CryptoKit
import Foundation
import Network
import NetworkExtension
import WireGuardKit

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private static let maxBundleBytes = 32 * 1024 * 1024
    private static let maxProfileBytes = 1024 * 1024
    private static let maxProofBytes = 16 * 1024
    private static let proofKind = "router-vpn-private-agent-v1"
    private static let nodeProofDomain = "router-vpn-node-proof-v1\n"

    private var wireGuardAdapter: WireGuardAdapter?
    private var proofTask: URLSessionDataTask?
    private var proofSession: URLSession?

    override func startTunnel(options: [String: NSObject]? = nil, completionHandler: @escaping (Error?) -> Void) {
        do {
            guard let tunnelProtocol = protocolConfiguration as? NETunnelProviderProtocol,
                  let provider = tunnelProtocol.providerConfiguration else {
                throw tunnelError(1, "Router VPN PacketTunnel configuration is missing.")
            }
            guard let bundleData = provider["bundle"] as? Data, !bundleData.isEmpty, bundleData.count <= Self.maxBundleBytes else {
                throw tunnelError(2, "Router VPN private bundle is missing or exceeds the 32 MiB safety limit.")
            }
            guard let root = try JSONSerialization.jsonObject(with: bundleData) as? [String: Any] else {
                throw tunnelError(3, "Router VPN private bundle is invalid JSON.")
            }
            let selectedProfile = try selectedRouterProfile(root)
            if strictKillSwitchRequested(selectedProfile) {
                // Fail closed if the host app did not actually request Apple's
                // route-lockdown controls. This prevents a decorative strict
                // policy from being accepted by the packet-tunnel engine.
                guard tunnelProtocol.includeAllNetworks, tunnelProtocol.enforceRoutes else {
                    throw tunnelError(4, "strict Apple kill switch requested but NetworkExtension route lockdown is not enabled")
                }
                let allowLAN = selectedProfile["home_lan_access"] as? Bool ?? true
                guard tunnelProtocol.excludeLocalNetworks == !allowLAN else {
                    throw tunnelError(5, "strict Apple kill switch LAN exclusion does not match the imported node policy")
                }
            }

            let requestedMode = (provider["mode"] as? String ?? "wg").lowercased()
            let requestedCandidates = (provider["modeCandidates"] as? [String] ?? []).map { $0.lowercased() }
            let mode: String
            if requestedMode == "auto" {
                mode = "wg"
            } else if requestedMode == "wg" || requestedCandidates.contains("wg") {
                mode = "wg"
            } else {
                throw tunnelError(6, "This iOS build currently has a real native WireGuard engine only. AmneziaWG, layered, ALL/MAX and multihop remain unavailable rather than reporting a fake Connected state.")
            }
            guard mode == "wg" else { throw tunnelError(7, "Unsupported iOS tunnel mode.") }

            let wgText = try wireGuardProfile(root)
            let tunnelConfiguration = try RouterVPNWireGuardConfig.parse(wgText, name: "Router VPN")
            guard tunnelConfiguration.peers.count == 1 else {
                throw tunnelError(8, "Router VPN iOS node proof requires exactly one generated WireGuard server peer.")
            }
            let derivedNodeID = deriveNodeProof(from: tunnelConfiguration.peers[0].publicKey.base64Key)
            let suppliedNodeID = try suppliedNodeProof(root: root, selectedProfile: selectedProfile)
            if !suppliedNodeID.isEmpty && suppliedNodeID != derivedNodeID {
                throw tunnelError(9, "Router bundle node identity does not match its WireGuard server public key.")
            }
            let expectedNodeID = suppliedNodeID.isEmpty ? derivedNodeID : suppliedNodeID
            guard expectedNodeID.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else {
                throw tunnelError(10, "Router VPN node proof id is invalid.")
            }
            let proofURL = try selectedProofURL(selectedProfile)

            let adapter = WireGuardAdapter(with: self) { level, message in
                if level == .error { NSLog("RouterVPN WireGuard: %@", message) }
            }
            wireGuardAdapter = adapter
            adapter.start(tunnelConfiguration: tunnelConfiguration) { [weak self] adapterError in
                guard let self else {
                    completionHandler(NSError(domain: "RouterVPN.PacketTunnel", code: 11, userInfo: [NSLocalizedDescriptionKey: "Router VPN PacketTunnel was released during startup."]))
                    return
                }
                if let adapterError {
                    self.wireGuardAdapter = nil
                    completionHandler(self.tunnelError(12, "WireGuard engine failed to start: \(adapterError.localizedDescription)"))
                    return
                }
                self.proveSelectedNode(url: proofURL, expectedNodeID: expectedNodeID) { proofError in
                    if let proofError {
                        adapter.stop { _ in
                            self.wireGuardAdapter = nil
                            completionHandler(proofError)
                        }
                        return
                    }
                    completionHandler(nil)
                }
            }
        } catch {
            completionHandler(error)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        proofTask?.cancel()
        proofTask = nil
        proofSession?.invalidateAndCancel()
        proofSession = nil
        guard let adapter = wireGuardAdapter else {
            completionHandler()
            return
        }
        adapter.stop { [weak self] _ in
            self?.wireGuardAdapter = nil
            completionHandler()
        }
    }

    private func proveSelectedNode(url: URL, expectedNodeID: String, completion: @escaping (Error?) -> Void) {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 5
        configuration.timeoutIntervalForResource = 6
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        let session = URLSession(configuration: configuration)
        proofSession = session
        var request = URLRequest(url: url)
        request.timeoutInterval = 5
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        proofTask = session.dataTask(with: request) { [weak self] data, response, error in
            guard let self else { return }
            defer {
                self.proofTask = nil
                self.proofSession?.finishTasksAndInvalidate()
                self.proofSession = nil
            }
            if let error {
                completion(self.tunnelError(20, "Selected-node private path proof failed: \(error.localizedDescription)"))
                return
            }
            guard let http = response as? HTTPURLResponse, http.statusCode == 200,
                  let data, !data.isEmpty, data.count <= Self.maxProofBytes else {
                completion(self.tunnelError(21, "Selected-node private path proof returned an invalid response."))
                return
            }
            do {
                guard let body = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                      body["ok"] as? Bool == true,
                      body["node_id"] as? String == expectedNodeID,
                      body["proof"] as? String == Self.proofKind else {
                    throw self.tunnelError(22, "Selected-node private path proof identity did not match the imported router bundle.")
                }
                completion(nil)
            } catch {
                completion(error)
            }
        }
        proofTask?.resume()
    }

    private func selectedRouterProfile(_ root: [String: Any]) throws -> [String: Any] {
        guard let profiles = root["routerProfiles"] as? [[String: Any]], !profiles.isEmpty else {
            throw tunnelError(30, "Router VPN bundle has no routerProfiles.")
        }
        let selectedID = root["selectedRouterID"] as? String ?? ""
        if let selected = profiles.first(where: { ($0["id"] as? String ?? "") == selectedID }) { return selected }
        return profiles[0]
    }

    private func wireGuardProfile(_ root: [String: Any]) throws -> String {
        guard let profiles = root["profiles"] as? [String: Any],
              let wg = profiles["wg"] as? [String: Any],
              let encoded = wg["wg.conf"] as? String,
              !encoded.isEmpty,
              let data = Data(base64Encoded: encoded, options: .ignoreUnknownCharacters),
              !data.isEmpty,
              data.count <= Self.maxProfileBytes,
              let text = String(data: data, encoding: .utf8) else {
            throw tunnelError(31, "Router VPN bundle has no valid bounded native WireGuard profile.")
        }
        return text
    }

    private func strictKillSwitchRequested(_ profile: [String: Any]) -> Bool {
        if profile["kill_switch"] as? Bool == true { return true }
        let value = (profile["kill_switch_policy"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return ["strict", "always", "enabled", "on", "lockdown"].contains(value)
    }

    private func suppliedNodeProof(root: [String: Any], selectedProfile: [String: Any]) throws -> String {
        let top = (root["nodeProofId"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let nested = (selectedProfile["node_proof_id"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        for value in [top, nested] where !value.isEmpty {
            guard value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else {
                throw tunnelError(32, "Router bundle contains an invalid node proof id.")
            }
        }
        if !top.isEmpty && !nested.isEmpty && top != nested {
            throw tunnelError(33, "Router bundle node proof ids disagree.")
        }
        return top.isEmpty ? nested : top
    }

    private func deriveNodeProof(from serverPublicKey: String) -> String {
        let digest = SHA256.hash(data: Data((Self.nodeProofDomain + serverPublicKey).utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private func selectedProofURL(_ profile: [String: Any]) throws -> URL {
        let raw = (profile["path_probe_url"] as? String ?? "http://10.77.0.1:8787/health").trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: raw), url.scheme?.lowercased() == "http", let host = url.host, privateLiteralHost(host) else {
            throw tunnelError(34, "Selected-node proof URL must use a literal private IPv4/IPv6 HTTP address.")
        }
        return url
    }

    private func privateLiteralHost(_ host: String) -> Bool {
        if let ipv4 = IPv4Address(host) {
            let b = [UInt8](ipv4.rawValue)
            guard b.count == 4 else { return false }
            return b[0] == 10
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 169 && b[1] == 254)
        }
        if let ipv6 = IPv6Address(host) {
            let b = [UInt8](ipv6.rawValue)
            guard b.count == 16 else { return false }
            return (b[0] & 0xfe) == 0xfc || (b[0] == 0xfe && (b[1] & 0xc0) == 0x80)
        }
        return false
    }

    private func tunnelError(_ code: Int, _ message: String) -> NSError {
        NSError(domain: "RouterVPN.PacketTunnel", code: code, userInfo: [NSLocalizedDescriptionKey: message])
    }
}