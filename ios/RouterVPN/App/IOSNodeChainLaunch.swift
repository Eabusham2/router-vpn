import Foundation

@MainActor
extension RouterVPNModel {
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
        let current = try captureIOSNodeChain(selected)
        defer { try? current.plan.close() }
        guard current.launchInput == input else { throw CancellationError() }
    }
}

extension IOSRuntimeSelector {
    /// Only a complete native compilation can make an ordered selection.
    /// The app retains this source across its first system-manager lookup.
    static func selectNodeChain(_ capture: IOSNodeChainCapture) throws -> IOSRuntimeSelection {
        guard capture.selectionExecution == "local",
              (2...IOSMultihopNodeSelection.maximumNodes).contains(capture.members.count),
              capture.members.dropLast().enumerated().allSatisfy({ position, member in
                  IOSMultihopNodeSelection.supportsNativePrefix(member.mode) && member.profile["node_kind"] as? String == "router-vpn" ||
                  capture.members.count == 3 && position == 1 && member.mode == "shadowsocks" && member.profile["node_kind"] as? String == "external"
              }),
              let final = capture.members.last, final.profile["node_kind"] as? String == "router-vpn",
              final.mode == "shadowsocks" || final.mode == "hysteria2" &&
                ["", "off"].contains(final.profile["start_layer"] as? String ?? "") &&
                capture.members.dropLast().allSatisfy({ IOSMultihopNodeSelection.supportsNativePrefix($0.mode) && $0.profile["node_kind"] as? String == "router-vpn" }) else {
            throw IOSMultihopNodeSelection.issue("This Local ordered path needs paired WireGuard or AWG2 nodes followed by Shadowsocks 2022 or unlayered Hysteria2. An imported middle requires a Shadowsocks 2022 final node.")
        }
        return IOSRuntimeSelection(engine: .multihop, logicalModeID: "multihop", rawProfileID: final.mode,
                                   files: [:], nodeChainInput: capture.launchInput)
    }
}
