import Foundation
import CoreFoundation
import Libbox

/// Immutable source for an independent packet-prefix test. This capture has
/// no ordinary connection, DNS, application-ingress or measured-MTU authority.
/// The complete saved graph is retained only for original chooser/Save input.
struct IOSNodeCandidatePrefixCapture {
    struct Metadata: Decodable {
        struct Target: Decodable { let id: String, source_sha256: String }
        struct Prefix: Decodable {
            let position: Int
            let profile_id: String, node_id: String, mode: String, start_layer: String, source_sha256: String, tag: String
        }
        struct MTU: Decodable {
            struct Bound: Decodable { let position: Int; let tag: String; let ceiling: Int }
            let original: Int, ceiling: Int
            let tun_tag: String
            let prefixes: [Bound]
        }
        let schema: Int, prefix_position: Int
        let prefix_id: String, capture_sha256: String, source_sha256: String, config_sha256: String, original_source_sha256: String
        let targets: [Target]
        let prefixes: [Prefix]
        let application_open: Bool, dns_open: Bool, ready: Bool
        let stage: String, mtu_measurement: String
        let mtu: MTU
    }

    let native: LibboxRouterNodeChainCandidatePreparation
    let launchInput: String
    let originalLaunchInput: String
    let inventory: String
    let metadata: Metadata
    let strict: Bool
    let homeLANAccess: Bool
    var config: String { native.config() }
    var sourceSHA256: String { metadata.source_sha256 }
    var configSHA256: String { metadata.config_sha256 }
    var captureSHA256: String { metadata.capture_sha256 }
    var originalSourceSHA256: String { metadata.original_source_sha256 }

    static func compile(original: IOSNodeChainCapture, position: Int, inventory: String) throws -> Self {
        guard original.selectionExecution == "local", let source = original.originalSource,
              !source.isEmpty, source.utf8.count <= IOSNodeChainCapture.maximumInputBytes,
              position >= 0, position < original.members.count - 1,
              original.members.prefix(position + 1).allSatisfy({ ["wg", "awg2-fast", "awg2-strong"].contains($0.mode) }),
              !inventory.isEmpty, inventory.utf8.count <= IOSCandidateCatalogPublication.maximumInventoryBytes else { throw issue() }
        var failure: NSError?
        let created = LibboxNewRouterNodeChainCandidatePreparation(source, Int32(position), inventory, &failure)
        guard failure == nil, let created else { try? created?.close(); throw failure ?? issue() }
        do { return try Self(native: created, original: original, position: position, inventory: inventory) }
        catch { try? created.close(); throw error }
    }

    /// The provider uses the native strict reopener. No private launch field is
    /// dropped to turn an untrusted receipt back into a new constructor input.
    static func reopen(_ input: String, originalInput: String, selectedProfile: [String: Any],
                       position: Int, inventory: String) throws -> Self {
        guard !input.isEmpty, input.utf8.count <= IOSNodeChainCapture.maximumInputBytes,
              !inventory.isEmpty, inventory.utf8.count <= IOSCandidateCatalogPublication.maximumInventoryBytes else { throw issue() }
        let original = try IOSNodeChainCapture.reopen(originalInput, selectedProfile: selectedProfile)
        defer { try? original.plan.close() }
        var failure: NSError?
        let created = LibboxRouterNodeChainCandidatePreparationLaunch(input, &failure)
        guard failure == nil, let created else { try? created?.close(); throw failure ?? issue() }
        do {
            let value = try Self(native: created, original: original, position: position, inventory: inventory)
            guard value.launchInput == input else { throw issue() }
            return value
        } catch { try? created.close(); throw error }
    }

    private init(native: LibboxRouterNodeChainCandidatePreparation, original: IOSNodeChainCapture,
                 position: Int, inventory: String) throws {
        guard original.selectionExecution == "local", position >= 0, position < original.members.count - 1 else { throw Self.issue() }
        let launch = native.launchInput(), raw = native.metadata(), config = native.config()
        guard !launch.isEmpty, launch.utf8.count <= IOSNodeChainCapture.maximumInputBytes,
              !raw.isEmpty, raw.utf8.count <= 65536, !config.isEmpty, config.utf8.count <= 4 * 1024 * 1024,
              let source = try JSONSerialization.jsonObject(with: Data(launch.utf8)) as? [String: Any],
              source["kind"] as? String == "routervpn-node-chain-candidate-preparation",
              Self.integer(source["schema"]) == 1, Self.integer(source["prefix_position"]) == position,
              source["inventory"] as? String == inventory else { throw Self.issue() }
        let value = try JSONDecoder().decode(Metadata.self, from: Data(raw.utf8))
        guard value.schema == 1, value.prefix_position == position, value.prefix_id == original.members[position].id,
              value.source_sha256 == native.sourceSHA256(), value.config_sha256 == native.configSHA256(),
              value.capture_sha256 == native.captureSHA256(), value.original_source_sha256 == native.originalSourceSHA256(),
              value.original_source_sha256 == original.sourceSHA256,
              [value.source_sha256, value.config_sha256, value.capture_sha256, value.original_source_sha256].allSatisfy(Self.digest),
              !value.application_open, !value.dns_open, !value.ready, value.stage == "pending-prefix-proof",
              value.mtu_measurement == "configured-bounds-only", value.prefixes.count == position + 1,
              (1...64).contains(value.targets.count), Set(value.targets.map(\.id)).count == value.targets.count,
              value.targets.allSatisfy({ !$0.id.isEmpty && $0.id.utf8.count <= 128 && Self.digest($0.source_sha256) }) else { throw Self.issue() }
        for (index, prefix) in value.prefixes.enumerated() {
            let member = original.members[index]
            let layer = member.profile["start_layer"] as? String ?? "off"
            guard prefix.position == index, prefix.profile_id == member.id, prefix.mode == member.mode,
                  ["wg", "awg2-fast", "awg2-strong"].contains(prefix.mode),
                  prefix.node_id == member.profile["node_proof_id"] as? String,
                  prefix.start_layer == (layer.isEmpty ? "off" : layer), Self.digest(prefix.source_sha256),
                  !prefix.tag.isEmpty else { throw Self.issue() }
        }
        guard (1280...9000).contains(value.mtu.original), (1280...9000).contains(value.mtu.ceiling),
              value.mtu.original <= value.mtu.ceiling, !value.mtu.tun_tag.isEmpty,
              value.mtu.prefixes.count == value.prefixes.count,
              let graph = try JSONSerialization.jsonObject(with: Data(config.utf8)) as? [String: Any],
              let inbounds = graph["inbounds"] as? [[String: Any]], inbounds.count == 1,
              inbounds[0]["type"] as? String == "tun", inbounds[0]["tag"] as? String == value.mtu.tun_tag,
              Self.integer(inbounds[0]["mtu"]) == value.mtu.original else { throw Self.issue() }
        for (index, bound) in value.mtu.prefixes.enumerated() {
            guard bound.position == index, bound.tag == value.prefixes[index].tag,
                  (1280...9000).contains(bound.ceiling), value.mtu.original <= bound.ceiling else { throw Self.issue() }
        }
        guard value.mtu.ceiling == value.mtu.prefixes.map(\.ceiling).min() else { throw Self.issue() }
        self.native = native; launchInput = launch; originalLaunchInput = original.launchInput
        self.inventory = inventory; metadata = value; strict = original.strict; homeLANAccess = original.homeLANAccess
    }

    private static func integer(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              number.doubleValue.isFinite, number.doubleValue.rounded() == number.doubleValue,
              number.doubleValue >= 0, number.doubleValue <= 9000 else { return nil }
        return number.intValue
    }
    private static func digest(_ value: String) -> Bool { value.range(of: "\\A[0-9a-f]{64}\\z", options: .regularExpression) != nil }
    static func issue() -> NSError {
        NSError(domain: "RouterVPN.CandidatePrefixCapture", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "The original saved source, selected packet prefix or closed test policy could not be reproduced."])
    }
}
