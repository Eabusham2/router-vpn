import Foundation
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
              number.doubleValue.isFinite, number.doubleValue.rounded() == number.doubleValue, (0..<7).contains(number.intValue),
              let input = configuration[key] as? String, let originalInput = configuration[originalKey] as? String,
              let bundle = configuration["bundle"] as? Data, !bundle.isEmpty, bundle.count <= 32 * 1024 * 1024,
              let root = try JSONSerialization.jsonObject(with: bundle) as? [String: Any],
              let id = root["selectedRouterID"] as? String,
              let profiles = root["routerProfiles"] as? [[String: Any]],
              profiles.filter({ $0["id"] as? String == id }).count == 1,
              let selected = profiles.first(where: { $0["id"] as? String == id }) else { throw IOSNodeCandidatePrefixCapture.issue() }
        let original = try IOSNodeChainCapture.reopen(originalInput, selectedProfile: selected)
        defer { try? original.plan.close() }
        guard let final = original.members.last, final.id == id,
              let assets = root["profiles"] as? [String: [String: String]],
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
