import Foundation
@preconcurrency import NetworkExtension
import SwiftUI

private enum IOSStrategyCatalog {
    static let layers: [String: Set<String>] = [
        "wg": ["wireguard"],
        "awg2-fast": ["amneziawg2", "light-obfuscation"],
        "wg-pq": ["wireguard", "rosenpass-pq"],
        "shadowsocks": ["shadowsocks2022"],
        "awg2-strong": ["amneziawg2", "strong-obfuscation"],
        "awg2-pq": ["amneziawg2", "strong-obfuscation", "rosenpass-pq"],
        "reality-vision": ["vless", "tcp", "reality", "xtls-vision", "utls-chrome"],
        "hysteria2": ["hysteria2", "quic", "salamander"],
        "reality-pq-vision": ["vless-pq", "reality", "xtls-vision", "tcp"],
        "ss-v2ray": ["shadowsocks2022", "v2ray-plugin", "websocket", "tls", "hysteria2", "quic-udp-fallback"],
        "naive-h2": ["naive", "https", "http2", "udp-over-tcp"],
        "naive-h3": ["naive", "https", "http3", "quic"],
        "split": ["vless", "reality", "xtls-vision", "utls-chrome", "tcp", "hysteria2", "quic", "protocol-split"],
        "reality-xhttp": ["vless-pq", "reality", "xhttp", "finalmask", "utls-chrome"],
        "max": ["vless-pq", "reality", "xtls-vision", "utls-chrome", "tcp", "hysteria2", "quic", "protocol-split"],
        "max-quic-wg": ["wireguard", "rosenpass-pq", "shadowsocks2022", "hysteria2", "quic"],
        "max-quic-awg": ["amneziawg2", "strong-obfuscation", "rosenpass-pq", "shadowsocks2022", "hysteria2", "quic"],
        "max-tls-wg": ["wireguard", "rosenpass-pq", "shadowsocks2022", "vless-pq", "reality", "xhttp", "finalmask", "utls-chrome"],
        "max-tls-awg": ["amneziawg2", "strong-obfuscation", "rosenpass-pq", "shadowsocks2022", "vless-pq", "reality", "xhttp", "finalmask", "utls-chrome"]
    ]

    static let simplify: [String: [String]] = [
        "wg": [],
        "awg2-fast": ["wg"],
        "wg-pq": ["wg"],
        "shadowsocks": ["wg", "awg2-fast"],
        "awg2-strong": ["awg2-fast", "wg"],
        "awg2-pq": ["wg-pq", "awg2-strong", "awg2-fast", "wg"],
        "reality-vision": ["wg", "awg2-fast", "shadowsocks"],
        "hysteria2": ["wg", "awg2-fast", "reality-vision"],
        "reality-pq-vision": ["wg-pq", "reality-vision", "awg2-pq"],
        "ss-v2ray": ["shadowsocks", "reality-vision", "hysteria2"],
        "naive-h2": ["reality-vision", "ss-v2ray"],
        "naive-h3": ["hysteria2", "naive-h2", "reality-vision"],
        "split": ["reality-vision", "hysteria2"],
        "reality-xhttp": ["reality-pq-vision", "reality-vision"],
        "max": ["split", "reality-pq-vision", "hysteria2"],
        "max-quic-wg": ["wg-pq", "hysteria2", "shadowsocks", "max"],
        "max-quic-awg": ["awg2-pq", "wg-pq", "hysteria2", "max-quic-wg"],
        "max-tls-wg": ["reality-xhttp", "reality-pq-vision", "wg-pq", "max-quic-wg"],
        "max-tls-awg": ["max-tls-wg", "reality-xhttp", "awg2-pq", "max-quic-awg"]
    ]
}

private struct IOSLastRuntime: Codable {
    let routerID: String
    let rawProfileID: String
    let logicalModeID: String
}

@MainActor
extension RouterVPNModel {
    private var iosStrategyProfile: RouterProfile? {
        guard let bundle else { return nil }
        return bundle.routerProfiles.first(where: { $0.id == bundle.selectedRouterID }) ?? bundle.routerProfiles.first
    }

    var iosStrategyStrictLockdown: Bool {
        guard let profile = iosStrategyProfile else { return false }
        if profile.killSwitch == true { return true }
        let policy = (profile.killSwitchPolicy ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return ["strict", "always", "enabled", "on", "lockdown"].contains(policy)
    }

    func iosAvailableCustomLayers() -> [String] {
        guard let bundle else { return [] }
        var values = Set<String>()
        for raw in bundle.modes.map(\.id) {
            guard IOSStrategyCatalog.layers[raw] != nil,
                  (try? IOSRuntimeSelector.selectRaw(bundle: bundle, rawProfileID: raw)) != nil else { continue }
            values.formUnion(IOSStrategyCatalog.layers[raw] ?? [])
        }
        return values.sorted()
    }

    func iosSavedCustomLayers() -> Set<String> {
        Set((iosStrategyProfile?.customLayers ?? []).map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }.filter { !$0.isEmpty })
    }

    private func stopIOSStrategyTunnel() async {
        let managers = (try? await NETunnelProviderManager.loadAllFromPreferences()) ?? []
        for manager in managers {
            manager.isOnDemandEnabled = false
            manager.onDemandRules = []
            try? await manager.saveToPreferences()
            manager.connection.stopVPNTunnel()
        }
        for _ in 0..<24 {
            if managers.allSatisfy({ $0.connection.status == .disconnected || $0.connection.status == .invalid }) { break }
            try? await Task.sleep(for: .milliseconds(150))
        }
        connected = false
        activeEngine = "none"
        activeRawProfile = ""
    }

    private func connectIOSRawCandidate(_ rawID: String) async -> Bool {
        guard let bundle,
              let selection = try? IOSRuntimeSelector.selectRaw(bundle: bundle, rawProfileID: rawID) else { return false }
        if connected { await stopIOSStrategyTunnel() }
        auto = false
        selectedLogicalMode = selection.logicalModeID
        selectedMode = rawID
        await connect()
        let exact = connected && activeRawProfile == rawID
        if connected && !exact { await stopIOSStrategyTunnel() }
        return exact
    }

    func runIOSSmartAuto() async {
        guard let profile = iosStrategyProfile, profile.normalizedNodeKind == "router-vpn" else {
            message = "SMART AUTO requires a selected Router VPN node; external exits use their own direct/hop path."
            return
        }
        guard !iosStrategyStrictLockdown else {
            message = "SMART AUTO is unavailable while iOS Always/strict route lockdown is enabled: changing PacketTunnel engines after a proven connection could create an unproven transition gap. Use strict AUTO or choose a mode manually."
            return
        }
        if connected { await stopIOSStrategyTunnel() }
        auto = true
        await connect()
        guard connected, !activeRawProfile.isEmpty else { return }

        var best = activeRawProfile
        var visited: Set<String> = [best]
        while true {
            var changed = false
            for candidate in IOSStrategyCatalog.simplify[best] ?? [] {
                if visited.contains(candidate) { continue }
                visited.insert(candidate)
                guard let bundle,
                      (try? IOSRuntimeSelector.selectRaw(bundle: bundle, rawProfileID: candidate)) != nil else { continue }
                let lastGood = best
                message = "SMART AUTO • testing simplification \(lastGood) → \(candidate)…"
                if await connectIOSRawCandidate(candidate) {
                    best = candidate
                    changed = true
                    break
                }
                message = "SMART AUTO • \(candidate) failed proof; restoring \(lastGood)…"
                guard await connectIOSRawCandidate(lastGood) else {
                    connected = false
                    message = "SMART AUTO failed closed: simplification \(candidate) failed and last-known-good \(lastGood) could not be restored."
                    return
                }
                best = lastGood
            }
            if !changed { break }
        }
        auto = false
        recordIOSLastRuntime()
        message = "SMART AUTO connected • \(best) • selected-node proof passed • no further iOS-runnable simplification preserved proof."
    }

    func runIOSCustom(layers requestedRaw: [String]) async {
        guard let profile = iosStrategyProfile, profile.normalizedNodeKind == "router-vpn", let bundle else {
            message = "CUSTOM requires a selected Router VPN node."
            return
        }
        let requested = Array(Set(requestedRaw.map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }.filter { !$0.isEmpty })).sorted()
        guard !requested.isEmpty else { message = "CUSTOM requires at least one exact layer."; return }

        var current = bundle
        if let index = current.routerProfiles.firstIndex(where: { $0.id == current.selectedRouterID }) ?? current.routerProfiles.indices.first {
            current.routerProfiles[index].customLayers = requested
            do { try importBundle(JSONEncoder().encode(current)) }
            catch { message = "CUSTOM could not save its private layer selection: \(error.localizedDescription)"; return }
        }

        struct Candidate {
            let raw: String
            let extra: Int
            let basePenalty: Int
            let traffic: Double
            let ping: Double
        }
        let preferred = (profile.baseTunnel ?? "wg").lowercased()
        var candidates: [Candidate] = []
        for mode in modes {
            guard let layers = IOSStrategyCatalog.layers[mode.id], requested.allSatisfy(layers.contains),
                  let refreshed = self.bundle,
                  (try? IOSRuntimeSelector.selectRaw(bundle: refreshed, rawProfileID: mode.id)) != nil else { continue }
            let hasWG = layers.contains("wireguard")
            let hasAWG = layers.contains("amneziawg2")
            let wantsAWG = preferred.hasPrefix("awg") || preferred.hasPrefix("amnezia")
            let penalty = wantsAWG ? (hasAWG ? 0 : (hasWG ? 1 : 0)) : (hasWG ? 0 : (hasAWG ? 1 : 0))
            candidates.append(Candidate(raw: mode.id, extra: layers.count - requested.count, basePenalty: penalty, traffic: mode.trafficMinPct, ping: mode.pingMinMs))
        }
        candidates.sort {
            if $0.extra != $1.extra { return $0.extra < $1.extra }
            if $0.basePenalty != $1.basePenalty { return $0.basePenalty < $1.basePenalty }
            if $0.traffic != $1.traffic { return $0.traffic < $1.traffic }
            if $0.ping != $1.ping { return $0.ping < $1.ping }
            return $0.raw < $1.raw
        }
        guard !candidates.isEmpty else {
            message = "CUSTOM found no iOS-runnable WireGuardKit/Libbox stack containing every requested layer: \(requested.joined(separator: ", "))."
            return
        }

        if connected { await stopIOSStrategyTunnel() }
        let attempts = iosStrategyStrictLockdown ? Array(candidates.prefix(1)) : candidates
        for (index, candidate) in attempts.enumerated() {
            message = "CUSTOM \(index + 1)/\(attempts.count) • trying \(candidate.raw) for \(requested.joined(separator: ", "))…"
            if await connectIOSRawCandidate(candidate.raw) {
                auto = false
                recordIOSLastRuntime()
                message = "CUSTOM connected • \(candidate.raw) • every requested layer present • selected-node proof passed."
                return
            }
            if iosStrategyStrictLockdown {
                message = "CUSTOM failed closed on \(candidate.raw) under iOS strict route lockdown; Router VPN will not cycle engines across an unproven transition."
                return
            }
        }
        message = "CUSTOM matching iOS stacks existed, but none passed the exact selected-node PacketTunnel proof."
    }

    func recordIOSLastRuntime() {
        guard connected, let profile = iosStrategyProfile, !activeRawProfile.isEmpty else { return }
        let value = IOSLastRuntime(routerID: profile.id, rawProfileID: activeRawProfile, logicalModeID: selectedLogicalMode)
        if let data = try? JSONEncoder().encode(value) { UserDefaults.standard.set(data, forKey: "router-vpn.ios.last-runtime-v1") }
    }

    func applyIOSStartupPolicyIfNeeded() async {
        guard let profile = iosStrategyProfile, profile.normalizedNodeKind == "router-vpn", profile.autoConnect == true else { return }
        let managers = (try? await NETunnelProviderManager.loadAllFromPreferences()) ?? []
        if managers.contains(where: { $0.connection.status == .connected || $0.connection.status == .connecting || $0.connection.status == .reasserting }) { return }
        switch (profile.startupMode ?? "manual").lowercased() {
        case "auto":
            auto = true
            await connect()
            if connected { recordIOSLastRuntime() }
        case "smart-auto":
            await runIOSSmartAuto()
        case "last":
            guard let data = UserDefaults.standard.data(forKey: "router-vpn.ios.last-runtime-v1"),
                  let last = try? JSONDecoder().decode(IOSLastRuntime.self, from: data),
                  last.routerID == profile.id,
                  await connectIOSRawCandidate(last.rawProfileID) else {
                message = "Last-mode auto-connect had no restorable proven iOS runtime; falling back to AUTO."
                auto = true
                await connect()
                if connected { recordIOSLastRuntime() }
                return
            }
            recordIOSLastRuntime()
            message = "Auto-connected last proven iOS runtime • \(last.rawProfileID) • selected-node proof passed."
        default:
            message = "Auto-connect is enabled but startup behavior is Manual/unsupported; iOS stayed disconnected."
        }
    }
}

struct IOSStrategySheet: View {
    @EnvironmentObject var model: RouterVPNModel
    @Environment(\.dismiss) private var dismiss
    @State private var selected = Set<String>()

    var body: some View {
        NavigationStack {
            Form {
                Section("Connection strategy") {
                    Button("AUTO — first proven iOS path") {
                        Task { model.auto = true; await model.connect(); if model.connected { model.recordIOSLastRuntime() } }
                    }
                    Button("SMART AUTO — connect, simplify, restore") { Task { await model.runIOSSmartAuto() } }
                        .disabled(model.iosStrategyStrictLockdown)
                    if model.iosStrategyStrictLockdown {
                        Text("SMART AUTO is disabled under iOS Always/strict lockdown because switching PacketTunnel engines after connection is not yet proven leak-free. Strict AUTO/manual still fail closed.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Text("AUTO/SMART/CUSTOM only use raw profiles this iOS build can really execute with WireGuardKit or pinned Libbox. AWG-only, Xray-only, unsupported MAX/ALL branches, OpenVPN and full desktop multihop stay unavailable.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section("CUSTOM — exact required layers") {
                    let layers = model.iosAvailableCustomLayers()
                    if layers.isEmpty {
                        Text("No iOS-runnable raw profile exposes a CUSTOM layer set in this linked node.")
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(layers, id: \.self) { layer in
                            Toggle(layer, isOn: Binding(
                                get: { selected.contains(layer) },
                                set: { enabled in if enabled { selected.insert(layer) } else { selected.remove(layer) } }
                            ))
                        }
                        Button("Connect CUSTOM") { Task { await model.runIOSCustom(layers: Array(selected)) } }
                            .disabled(selected.isEmpty)
                    }
                    Text("CUSTOM minimizes extra layers, then base mismatch, traffic overhead and latency; every requested layer must be present. Under strict lockdown only the top candidate is attempted to avoid an unproven engine-transition gap.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section("Live result") {
                    Text(model.message).font(.caption).textSelection(.enabled)
                }
            }
            .navigationTitle("AUTO / SMART / CUSTOM")
            .onAppear { selected = model.iosSavedCustomLayers() }
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
        }
    }
}
