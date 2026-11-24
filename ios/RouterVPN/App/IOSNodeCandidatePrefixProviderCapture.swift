import Foundation
import Libbox
import CoreFoundation

/// A private, explicitly temporary purpose. It cannot be reopened by the
/// ordinary ordered-chain or Last paths and cannot adopt another publication.
struct IOSNodeCandidatePrefixProviderCapture {
    static let key = "candidatePrefixSource"
    static let originalKey = "candidateOriginalSource"
    static let engine = "candidate-prefix-libbox"
    static let ownerKey = "routervpn_speed_lab_owner"
    static let epochKey = "candidatePrefixEpoch"
    static let requestKey = "candidatePrefixRequest"
    static let positionKey = "candidatePrefixPosition"
    static let fields: Set<String> = [key, originalKey, "engine", "bundle", ownerKey, epochKey, requestKey, positionKey]

    let capture: IOSNodeCandidatePrefixCapture
    let source: IOSCandidateCatalogPublication.Capture
    let owner: UUID
    let epoch: String
    private let publication: IOSCandidateCatalogPublication

    static func configuration(capture: IOSNodeCandidatePrefixCapture, bundle: Data,
                              owner: UUID, epoch: UUID, request: String) throws -> [String: Any] {
        guard IOSCandidateCatalogPublication.validRequest(request) else { throw IOSNodeCandidatePrefixCapture.issue() }
        return [key: capture.launchInput, originalKey: capture.originalLaunchInput,
                "engine": engine, "bundle": bundle, ownerKey: owner.uuidString,
                epochKey: epoch.uuidString, requestKey: request, positionKey: capture.metadata.prefix_position]
    }

    static func reopen(_ configuration: [String: Any], publication: IOSCandidateCatalogPublication = .shared) throws -> Self {
        guard Set(configuration.keys) == fields, configuration["engine"] as? String == engine,
              let ownerText = configuration[ownerKey] as? String, let owner = UUID(uuidString: ownerText),
              let epoch = configuration[epochKey] as? String, UUID(uuidString: epoch) != nil,
              let request = configuration[requestKey] as? String, IOSCandidateCatalogPublication.validRequest(request),
              !publication.closed(epoch: epoch, request: request),
              let number = configuration[positionKey] as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              number.doubleValue.isFinite, number.doubleValue.rounded() == number.doubleValue, (0..<IOSMultihopNodeSelection.physicalTraversalDepth).contains(number.intValue),
              let input = configuration[key] as? String, let originalInput = configuration[originalKey] as? String,
              let bundle = configuration["bundle"] as? Data, !bundle.isEmpty, bundle.count <= 32 * 1024 * 1024,
              let root = try JSONSerialization.jsonObject(with: bundle) as? [String: Any],
              let id = root["selectedRouterID"] as? String,
              let profiles = root["routerProfiles"] as? [[String: Any]],
              profiles.filter({ $0["id"] as? String == id }).count == 1,
              let selected = profiles.first(where: { $0["id"] as? String == id }) else { throw IOSNodeCandidatePrefixCapture.issue() }
        let original = try IOSNodeCandidateOriginalCapture.reopen(originalInput, selectedProfile: selected)
        defer { try? original.close() }
        guard number.intValue < original.members.count - 1 else { throw IOSNodeCandidatePrefixCapture.issue() }
        if number.intValue >= IOSMultihopNodeSelection.maximumNodes - 1 {
            guard case .ordinary(let source) = original, source.selectionExecution == "local",
                  Int(source.plan.extendedLocalNodeCount()) == source.members.count else { throw IOSNodeCandidatePrefixCapture.issue() }
            let modes = source.members.map(\.mode)
            let metric = LibboxRouterNodeChainCandidatePrefixMeasurement(source.plan, number.int32Value)
            let packets = Int(source.plan.extendedMixedLocalPacketCount())
            let mixed = packets > 0 && packets == IOSMultihopNodeSelection.extendedMixedPacketCount(modes, execution: "local") &&
                metric == (number.intValue < packets ? "routed-tcp-connect" : "routed-candidate-response")
            let packetCount = modes.prefix(while: IOSMultihopNodeSelection.supportsNativePrefix).count
            let privateStreams = source.members.dropFirst(packetCount).dropLast().contains {
                $0.mode == "shadowsocks" && $0.profile["node_kind"] as? String == "router-vpn"
            }
            let retained = privateStreams && packetCount > 0 && modes.dropFirst(packetCount).allSatisfy { $0 == "shadowsocks" } &&
                metric == (number.intValue < packetCount ? "routed-tcp-connect" : "routed-candidate-response")
            guard source.sourceSchema == 1 && IOSMultihopNodeSelection.extendedPairedModes(modes, execution: "local") && metric == "routed-tcp-connect" ||
                    source.sourceSchema == 6 && (retained || mixed || IOSMultihopNodeSelection.extendedLocalModes(modes, execution: "local") && metric == "routed-candidate-response") else { throw IOSNodeCandidatePrefixCapture.issue() }
        }
        guard let final = original.members.last, final.id == id,
              let assets = root["profiles"] as? [String: [String: String]],
              try final.matchesStartLayer(in: assets),
              let originalFiles = try JSONSerialization.jsonObject(with: Data(final.filesJSON.utf8)) as? [String: String],
              assets[final.mode] == originalFiles else { throw IOSNodeCandidatePrefixCapture.issue() }
        let source = try publication.reopen(request: request)
        let capture = try IOSNodeCandidatePrefixCapture.reopen(input, originalInput: originalInput,
            selectedProfile: selected, position: number.intValue, inventory: String(decoding: source.inventory.data, as: UTF8.self))
        do {
            let result = Self(capture: capture, source: source, owner: owner, epoch: epoch, publication: publication)
            try result.requireCurrent()
            return result
        } catch { try? capture.native.close(); throw error }
    }

    func storeCandidatesClosed() throws { try publication.storeClosed(epoch: epoch, request: source.request) }

    func requireCurrent() throws {
        guard !publication.closed(epoch: epoch, request: source.request), publication.current(source) else {
            throw IOSNodeCandidatePrefixCapture.issue()
        }
    }
}
