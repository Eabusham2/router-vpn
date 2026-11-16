import Foundation

/// App-only sum of distinct private sources. Native owners remain typed in
/// PacketTunnel; this value grants neither ordinary nor temporary proof.
enum IOSOrderedRouteCapture {
    case ordinary(IOSNodeChainCapture)
    case socks(IOSNodeChainSOCKSCapture)
    case connect(IOSNodeChainCONNECTCapture)
    case execution(IOSNodeChainExecutionCapture)
    var members: [IOSNodeChainCapture.Member] { switch self { case .ordinary(let value): return value.members; case .socks(let value): return value.members; case .connect(let value): return value.members; case .execution(let value): return value.members } }
    var launchInput: String { switch self { case .ordinary(let value): return value.launchInput; case .socks(let value): return value.source; case .connect(let value): return value.source; case .execution(let value): return value.launchInput } }
    var strict: Bool { switch self { case .ordinary(let value): return value.strict; case .socks(let value): return value.strict; case .connect(let value): return value.strict; case .execution(let value): return value.strict } }
    var homeLANAccess: Bool { switch self { case .ordinary(let value): return value.homeLANAccess; case .socks(let value): return value.homeLANAccess; case .connect(let value): return value.homeLANAccess; case .execution(let value): return value.homeLANAccess } }
    var startupTimeout: TimeInterval { switch self { case .ordinary(let value): return value.startupTimeout; case .socks(let value): return value.startupTimeout; case .connect(let value): return value.startupTimeout; case .execution(let value): return value.startupTimeout } }
    var providerKey: String { switch self { case .ordinary: return IOSNodeChainProviderCapture.key; case .socks: return IOSNodeChainSOCKSCapture.providerKey; case .connect: return IOSNodeChainCONNECTCapture.providerKey; case .execution: return IOSNodeChainProviderCapture.executionKey } }
    func close() throws { switch self { case .ordinary(let value): try value.plan.close(); case .socks(let value): try value.plan.close(); case .connect(let value): try value.plan.close(); case .execution(let value): try value.close() } }
}

@MainActor
extension RouterVPNModel {
    func captureIOSOrderedRoute(_ selected: ClientBundle) throws -> IOSOrderedRouteCapture {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let sources = try iosNodeChainBundles(for: selected).map { try encoder.encode($0) }
        let control = selected.routerProfiles.first(where: { $0.id == selected.selectedRouterID })
        if let control, ["server", "auto"].contains(control.multihopExecution ?? "") {
            guard let nodes = control.multihopNodes, IOSMultihopNodeSelection.supportsServerExecution(nodes) else {
                throw IOSMultihopNodeSelection.issue("Choose a supported ordered Server or Compare path with its original paired nodes and a Shadowsocks or Hysteria2 final with its independent Off, AES or AES with XOR whitening layer. An imported middle requires a Shadowsocks final.")
            }
            return .execution(try IOSNodeChainExecutionCapture.compile(bundles: sources, requested: control.multihopExecution!))
        }
        if control?.multihopNodes?.contains(where: { ["http-connect", "https-connect"].contains($0.mode) }) == true {
            return .connect(try IOSNodeChainCONNECTCapture.compile(bundles: sources))
        }
        if control?.multihopNodes?.contains(where: { $0.mode == "socks5" }) == true {
            return .socks(try IOSNodeChainSOCKSCapture.compile(bundles: sources))
        }
        return .ordinary(try IOSNodeChainCapture.compile(bundles: sources))
    }
    /// Every selected record is read independently in its saved order. The
    /// caller closes this socket-free plan after staging its canonical input.
    func captureIOSNodeChain(_ selected: ClientBundle) throws -> IOSNodeChainCapture {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let sources = try iosNodeChainBundles(for: selected).map { try encoder.encode($0) }
        return try IOSNodeChainCapture.compile(bundles: sources)
    }

    /// Preference save/load can suspend while a middle node is edited or
    /// relinked. Compare the full compiled source again before native startup.
    func requireCurrentIOSNodeChain(_ input: String, selected: ClientBundle) throws {
        let current = try captureIOSOrderedRoute(selected)
        defer { try? current.close() }
        guard current.launchInput == input else { throw CancellationError() }
    }
}

extension IOSRuntimeSelector {
    static func selectNodeChain(_ capture: IOSOrderedRouteCapture) throws -> IOSRuntimeSelection {
        switch capture {
        case .execution(let original):
            return IOSRuntimeSelection(engine: .multihop, logicalModeID: "multihop", rawProfileID: original.members.last!.mode,
                                       files: [:], nodeChainInput: original.launchInput, nodeChainExecution: original.requested)
        case .ordinary(let original): return try selectNodeChain(original)
        case .socks(let original):
            return IOSRuntimeSelection(engine: .multihop, logicalModeID: "multihop", rawProfileID: original.members[original.members.count - 1].mode,
                                       files: [:], nodeChainInput: original.source)
        case .connect(let original):
            return IOSRuntimeSelection(engine: .multihop, logicalModeID: "multihop", rawProfileID: original.members[original.members.count - 1].mode,
                                       files: [:], nodeChainInput: original.source)
        }
    }
    /// Only a complete native compilation can make an ordered selection.
    /// The app retains this source across its first system-manager lookup.
    static func selectNodeChain(_ capture: IOSNodeChainCapture) throws -> IOSRuntimeSelection {
        guard capture.selectionExecution == "local",
              (2...IOSMultihopNodeSelection.maximumNodes).contains(capture.members.count),
              capture.members.dropLast().enumerated().allSatisfy({ position, member in
                  IOSMultihopNodeSelection.supportsNativePrefix(member.mode) && member.profile["node_kind"] as? String == "router-vpn" ||
                  IOSMultihopNodeSelection.supportsImportedMiddle(member.mode, position: position, count: capture.members.count) && ["shadowsocks", "openvpn"].contains(member.mode) && member.profile["node_kind"] as? String == "external"
              }),
              let final = capture.members.last, final.profile["node_kind"] as? String == "router-vpn",
              final.mode == "shadowsocks" || final.mode == "hysteria2" &&
                (final.profile["start_layer"] == nil ||
                 (final.profile["start_layer"] as? String).map({ ["", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"].contains($0) }) == true) &&
                capture.members.dropLast().allSatisfy({ IOSMultihopNodeSelection.supportsNativePrefix($0.mode) && $0.profile["node_kind"] as? String == "router-vpn" }) else {
            throw IOSMultihopNodeSelection.issue("This Local ordered path needs paired WireGuard or AWG2 nodes followed by Shadowsocks 2022 or Hysteria2 with its independent Off, AES or AES with XOR whitening layer. An imported middle requires a Shadowsocks 2022 final node.")
        }
        return IOSRuntimeSelection(engine: .multihop, logicalModeID: "multihop", rawProfileID: final.mode,
                                   files: [:], nodeChainInput: capture.launchInput)
    }
}
