import Foundation
import CoreFoundation
import Libbox

/// Immutable source for an independent candidate prefix test. This capture has
/// no ordinary connection, DNS, application-ingress or measured-MTU authority.
/// The complete saved graph is retained only for original chooser/Save input.
struct IOSNodeCandidatePrefixCapture {
    struct Metadata: Decodable {
        struct Target: Decodable { let id: String, source_sha256: String }
        struct Prefix: Decodable, Equatable {
            let position: Int
            let node_kind: String?, kind: String?
            let profile_id: String, node_id: String, mode: String, start_layer: String, source_sha256: String, tag: String
        }
        struct MTU: Decodable {
            struct Bound: Decodable { let position: Int; let tag: String; let ceiling: Int }
            let original: Int, ceiling: Int
            let tun_tag: String
            let prefixes: [Bound]
        }
        let schema: Int, prefix_position: Int
        let measurement: String?
        let candidate_mode: String?, candidate_kind: String?
        let purpose: String?, append_source_metadata_sha256: String?
        let requested_execution: String?, execution_source_sha256: String?, execution_capture_sha256: String?
        let original_preparation_source_sha256: String?, original_preparation_capture_sha256: String?
        let prefix_id: String, capture_sha256: String, source_sha256: String, config_sha256: String, original_source_sha256: String
        let targets: [Target]
        let prefixes: [Prefix]
        let application_open: Bool, dns_open: Bool, ready: Bool
        let stage: String, mtu_measurement: String
        let mtu: MTU
    }

    /// Exactly one original native purpose is retained. The execution wrapper
    /// delegates the same CommandServer lifetime; it is never a complete route.
    final class Native {
        private let local: LibboxRouterNodeChainCandidatePreparation?
        private let execution: LibboxRouterNodeChainCandidateAppendExecutionPreparation?
        private let source: LibboxRouterNodeChainCandidateAppendExecutionSource?
        var isExecution: Bool { execution != nil }
        private init(local: LibboxRouterNodeChainCandidatePreparation) { self.local = local; execution = nil; source = nil }
        private init(execution: LibboxRouterNodeChainCandidateAppendExecutionPreparation, source: LibboxRouterNodeChainCandidateAppendExecutionSource) {
            local = nil; self.execution = execution; self.source = source
        }
        static func ordinary(_ value: LibboxRouterNodeChainCandidatePreparation) -> Native { Native(local: value) }
        static func appendExecution(_ input: String, reopening: Bool) throws -> Native {
            var failure: NSError?
            guard let source = LibboxNewRouterNodeChainCandidateAppendExecutionSource(input, &failure), failure == nil else { throw failure ?? IOSNodeCandidatePrefixCapture.issue() }
            let created: LibboxRouterNodeChainCandidateAppendExecutionPreparation?
            if reopening { created = LibboxRouterNodeChainCandidateAppendExecutionPreparationLaunch(input, &failure) }
            else { created = LibboxNewRouterNodeChainCandidateAppendExecutionPreparation(source.source(), &failure) }
            guard failure == nil, let created else { try? created?.close(); throw failure ?? IOSNodeCandidatePrefixCapture.issue() }
            return Native(execution: created, source: source)
        }
        func requireSource(_ original: IOSNodeCandidateAppendSource, inventory: String) throws {
            guard let execution, let source else { throw IOSNodeCandidatePrefixCapture.issue() }
            try original.requireExecution(execution.execution())
            let launch = execution.launchInput()
            guard launch == source.source(), source.localSource() == original.source,
                  let input = try JSONSerialization.jsonObject(with: Data(launch.utf8)) as? [String: Any],
                  Set(input.keys) == ["kind","schema","execution","local_source","inventory"],
                  input["kind"] as? String == "routervpn-node-chain-append-execution-source", IOSNodeCandidatePrefixCapture.integer(input["schema"]) == 1,
                  input["execution"] as? String == execution.execution(), input["local_source"] as? String == original.source,
                  input["inventory"] as? String == inventory, source.execution() == execution.execution(),
                  execution.sourceSHA256() == source.sourceSHA256(), execution.originalSourceSHA256() == original.sourceSHA256,
                  source.originalSourceSHA256() == original.sourceSHA256, execution.config() == source.config(),
                  execution.configSHA256() == source.configSHA256(), IOSCandidateCatalogPublication.digest(Data(execution.config().utf8)) == execution.configSHA256(),
                  execution.metadata() == source.metadata(), execution.appendSourceMetadata() == original.metadata,
                  source.appendSourceMetadata() == original.metadata, execution.candidateKind() == "router-vpn", source.candidateKind() == "router-vpn",
                  execution.candidateMode() == "shadowsocks", source.candidateMode() == "shadowsocks",
                  execution.candidateMeasurement() == "routed-candidate-response", source.candidateMeasurement() == "routed-candidate-response",
                  Int(execution.appendPosition()) == original.members.count, source.appendPosition() == execution.appendPosition() else { throw IOSNodeCandidatePrefixCapture.issue() }
        }
        func fitsExecutionSource(_ input: String) -> Bool {
            guard let source, execution != nil else { return false }
            return LibboxRouterNodeChainCandidateAppendExecutionInputFitsSource(source, input)
        }
        func config() -> String { execution?.config() ?? local!.config() }
        func launchInput() -> String { execution?.launchInput() ?? local!.launchInput() }
        func sourceSHA256() -> String { execution?.sourceSHA256() ?? local!.sourceSHA256() }
        func originalSourceSHA256() -> String { execution?.originalSourceSHA256() ?? local!.originalSourceSHA256() }
        func configSHA256() -> String { execution?.configSHA256() ?? local!.configSHA256() }
        func captureSHA256() -> String { execution?.captureSHA256() ?? local!.captureSHA256() }
        func metadata() -> String { execution?.metadata() ?? local!.metadata() }
        func metadataPage(_ offset: Int32) -> String { execution?.metadataPage(offset) ?? local!.metadataPage(offset) }
        func appendSourceMetadata() -> String { execution?.appendSourceMetadata() ?? local!.appendSourceMetadata() }
        func candidateMode() -> String { execution?.candidateMode() ?? local!.candidateMode() }
        func candidateKind() -> String { execution?.candidateKind() ?? local!.candidateKind() }
        func candidateMeasurement() -> String { execution?.candidateMeasurement() ?? local!.candidateMeasurement() }
        func appendPosition() -> Int32 { execution?.appendPosition() ?? local!.appendPosition() }
        func isAppend() -> Bool { isExecution || local!.isAppend() }
        func requestedExecution() -> String? { execution?.execution() }
        func bindNative(_ server: LibboxCommandServer) throws { if let execution { try execution.bindNative(server) } else { try local!.bindNative(server) } }
        func run(_ server: LibboxCommandServer, catalog: LibboxRouterNodeChainCandidateCatalogProtocol) throws {
            if let execution { try execution.run(server, catalog: catalog) } else { try local!.run(server, catalog: catalog) }
        }
        func healthy() -> Bool {
            guard let execution else { return local!.healthy() }
            return execution.healthy() && (try? requireProgress(prepared: true)) != nil
        }
        func progressJSON() -> String { execution?.progressJSON() ?? local!.progressJSON() }
        func requireProgress(prepared: Bool) throws {
            guard let execution,
                  let body = try JSONSerialization.jsonObject(with: Data(execution.progressJSON().utf8)) as? [String: Any],
                  Set(body.keys) == ["stage","purpose","requested_execution","prepared","prefixes","application_open","dns_open","execution_source_sha256","execution_capture_sha256"],
                  let stage = body["stage"] as? String,
                  ["pending-prefix-proof","pending-prefix-discovery","append-execution-prepared","append-execution-failed","append-execution-retired"].contains(stage),
                  let ready = body["prepared"] as? Bool, ready == (stage == "append-execution-prepared"), !prepared || ready,
                  body["purpose"] as? String == "draft-prefix-append-execution", body["requested_execution"] as? String == execution.execution(),
                  body["execution_source_sha256"] as? String == execution.sourceSHA256(),
                  let capture = body["execution_capture_sha256"] as? String, capture == execution.captureSHA256(),
                  capture.isEmpty || IOSCandidateCatalogPublication.isDigest(capture), !ready || IOSCandidateCatalogPublication.isDigest(capture),
                  body["application_open"] as? Bool == false, body["dns_open"] as? Bool == false,
                  let prefixes = body["prefixes"] as? [Any], prefixes.count <= Int(execution.appendPosition()) else { throw IOSNodeCandidatePrefixCapture.issue() }
        }
        func start(_ request: String, candidateID: String) throws { if let execution { try execution.start(request, candidateID: candidateID) } else { try local!.start(request, candidateID: candidateID) } }
        func cancel(_ request: String) { if let execution { execution.cancel(request) } else { local!.cancel(request) } }
        func drain(_ request: String) throws { if let execution { try execution.drain(request) } else { try local!.drain(request) } }
        func statusJSON() -> String { execution?.statusJSON() ?? local!.statusJSON() }
        func selectionJSON() -> String { execution?.selectionJSON() ?? "" }
        func networkChanged() { if let execution { execution.networkChanged() } else { local!.networkChanged() } }
        func close() throws { if let execution { try execution.close() } else { try local!.close() } }
        func nativeClosed() -> Bool { execution?.nativeClosed() ?? local!.nativeClosed() }
    }

    let native: Native
    let launchInput: String
    let originalLaunchInput: String
    let inventory: String
    let metadata: Metadata
    let responseSourceNodes: [IOSNodeCandidateResponseNode]?
    var responseMode: String? { metadata.candidate_mode }
    var responseKind: String? { metadata.candidate_kind }
    var appendSourceMetadataSHA256: String? { metadata.append_source_metadata_sha256 }
    var isAppend: Bool { ["draft-prefix-append", "draft-prefix-append-execution"].contains(metadata.purpose ?? "") }
    var isAppendExecution: Bool { metadata.purpose == "draft-prefix-append-execution" }
    var requestedExecution: String? { metadata.requested_execution }
    let immutableMetadata: String
    private let executionAppendSource: IOSNodeCandidateAppendSource?
    func requireAppendExecutionInput(_ input: String) throws {
        guard isAppendExecution, let executionAppendSource else { throw Self.issue() }
        try native.requireSource(executionAppendSource, inventory: inventory)
        guard native.metadata() == immutableMetadata, native.fitsExecutionSource(input) else { throw Self.issue() }
    }
    let strict: Bool
    let homeLANAccess: Bool
    let appendDeviceMTU: IOSDeviceMTUPreference?
    var config: String { native.config() }
    var sourceSHA256: String { metadata.source_sha256 }
    var configSHA256: String { metadata.config_sha256 }
    var captureSHA256: String { metadata.capture_sha256 }
    var originalSourceSHA256: String { metadata.original_source_sha256 }

    static func compile(original: IOSNodeChainCapture, position: Int, inventory: String) throws -> Self {
        try compile(original: .ordinary(original), position: position, inventory: inventory)
    }

    static func compile(original: IOSNodeCandidateOriginalCapture, position: Int, inventory: String, requestedExecution: String = "local") throws -> Self {
        guard original.selectionExecution == "local", let source = original.originalSource,
              !source.isEmpty, source.utf8.count <= IOSNodeChainCapture.maximumInputBytes,
              position >= 0, position < original.members.count - (original.isAppend ? 0 : 1),
              original.canPreparePrefix(at: position),
              !inventory.isEmpty, inventory.utf8.count <= IOSCandidateCatalogPublication.maximumInventoryBytes else { throw issue() }
        if requestedExecution != "local" {
            guard let append = original.appendSource else { throw issue() }
            try append.requireExecution(requestedExecution)
            let input = try JSONSerialization.data(withJSONObject: ["kind": "routervpn-node-chain-append-execution-source", "schema": 1,
                "execution": requestedExecution, "local_source": append.source, "inventory": inventory], options: [.sortedKeys])
            let created = try Native.appendExecution(String(decoding: input, as: UTF8.self), reopening: false)
            do { return try Self(native: created, original: original, position: position, inventory: inventory) }
            catch { try? created.close(); throw error }
        }
        var failure: NSError?
        let created: LibboxRouterNodeChainCandidatePreparation?
        switch original {
        case .ordinary: created = LibboxNewRouterNodeChainCandidatePreparation(source, Int32(position), inventory, &failure)
        case .socks: created = LibboxNewRouterNodeChainSOCKSCandidatePreparation(source, Int32(position), inventory, &failure)
        case .connect: created = LibboxNewRouterNodeChainCONNECTCandidatePreparation(source, Int32(position), inventory, &failure)
        case .append: created = LibboxNewRouterNodeChainCandidateAppendPreparation(source, inventory, &failure)
        }
        guard failure == nil, let created else { try? created?.close(); throw failure ?? issue() }
        do { return try Self(native: Native.ordinary(created), original: original, position: position, inventory: inventory) }
        catch { try? created.close(); throw error }
    }

    /// The provider uses the native strict reopener. No private launch field is
    /// dropped to turn an untrusted receipt back into a new constructor input.
    static func reopen(_ input: String, originalInput: String, selectedProfile: [String: Any],
                       position: Int, inventory: String) throws -> Self {
        guard !input.isEmpty, input.utf8.count <= IOSNodeChainCapture.maximumInputBytes,
              !inventory.isEmpty, inventory.utf8.count <= IOSCandidateCatalogPublication.maximumInventoryBytes else { throw issue() }
        let original = try IOSNodeCandidateOriginalCapture.reopen(originalInput, selectedProfile: selectedProfile)
        defer { try? original.close() }
        if let body = try JSONSerialization.jsonObject(with: Data(input.utf8)) as? [String: Any], body["kind"] as? String == "routervpn-node-chain-append-execution-source" {
            let created = try Native.appendExecution(input, reopening: true)
            do {
                let value = try Self(native: created, original: original, position: position, inventory: inventory)
                guard value.launchInput == input else { throw issue() }
                return value
            } catch { try? created.close(); throw error }
        }
        var failure: NSError?
        let created = LibboxRouterNodeChainCandidatePreparationLaunch(input, &failure)
        guard failure == nil, let created else { try? created?.close(); throw failure ?? issue() }
        do {
            let value = try Self(native: Native.ordinary(created), original: original, position: position, inventory: inventory)
            guard value.launchInput == input else { throw issue() }
            return value
        } catch { try? created.close(); throw error }
    }

    private init(native: Native, original: IOSNodeCandidateOriginalCapture,
                 position: Int, inventory: String) throws {
        guard original.selectionExecution == "local", position >= 0, position < original.members.count - (original.isAppend ? 0 : 1),
              let offered = try JSONSerialization.jsonObject(with: Data(inventory.utf8)) as? [String: Any] else { throw Self.issue() }
        let responseMode = offered["response_mode"] as? String
        guard offered["response_mode"] == nil || responseMode?.isEmpty == false else { throw Self.issue() }
        let prefixes = responseMode == nil ? original.candidatePrefixes : original.preparedCandidatePrefixes
        guard responseMode == prefixes[position].candidate_mode,
              responseMode == nil || prefixes[position].supported(in: prefixes),
              native.candidateMode() == (responseMode ?? "") else { throw Self.issue() }
        let launch = native.launchInput(), raw = native.metadata(), config = native.config()
        guard !launch.isEmpty, launch.utf8.count <= IOSNodeChainCapture.maximumInputBytes,
              !raw.isEmpty, raw.utf8.count <= 65536, !config.isEmpty, config.utf8.count <= 4 * 1024 * 1024,
              let source = try JSONSerialization.jsonObject(with: Data(launch.utf8)) as? [String: Any],
              Self.integer(source["schema"]) == 1, source["inventory"] as? String == inventory else { throw Self.issue() }
        if native.isExecution {
            guard let append = original.appendSource else { throw Self.issue() }
            try native.requireSource(append, inventory: inventory)
        } else {
            guard source["kind"] as? String == original.preparationKind, Self.integer(source["prefix_position"]) == position else { throw Self.issue() }
        }
        var pages = try IOSCandidateMetadataPages(raw, inventoryBytes: inventory.utf8.count, legacyLimit: 65536,
                                                  family: native.isExecution ? .appendExecutionPreparation : original.isAppend ? .appendPreparation : .preparation)
        while let offset = pages.nextOffset { try pages.append(native.metadataPage(offset)) }
        var metadataBytes = try pages.result()
        if let append = original.appendSource {
            let originalMetadata = native.appendSourceMetadata()
            guard native.isAppend(), Int(native.appendPosition()) == original.members.count,
                  native.candidateKind() == append.nextKind, native.candidateMeasurement() == append.measurement,
                  native.isExecution ? source["local_source"] as? String == append.source :
                    source["prefix_source"] as? String == append.source && Self.integer(source["append_position"]) == original.members.count,
                  originalMetadata == append.metadata,
                  let retained = try JSONSerialization.jsonObject(with: Data(originalMetadata.utf8)) as? [String: Any],
                  var body = try JSONSerialization.jsonObject(with: metadataBytes) as? [String: Any],
                  body["append_source_metadata_sha256"] as? String == append.metadataSHA256,
                  Self.integer(body["prefix_count"]) == original.members.count,
                  Self.integer(body["append_position"]) == original.members.count,
                  body["purpose"] as? String == (native.isExecution ? "draft-prefix-append-execution" : "draft-prefix-append"), body["measurement"] as? String == append.measurement,
                  append.nextKind == "external" ? body["candidate_kind"] as? String == "external" : body["candidate_kind"] == nil else { throw Self.issue() }
            for key in ["draft_revision","device_revision","device_source_sha256","device_mtu_revision","candidate_mode"] {
                guard let expected = retained[key] as? String, body[key] as? String == expected else { throw Self.issue() }
            }
            // The complete original proof/MTU description is independently
            // source-bound; native pages carry its exact digest, not repeated rows.
            body["prefixes"] = retained["prefixes"]; body["mtu"] = retained["mtu"]
            metadataBytes = try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])
        } else if native.isAppend() { throw Self.issue() }
        let value = try JSONDecoder().decode(Metadata.self, from: metadataBytes)
        guard (value.measurement ?? "routed-tcp-connect") == prefixes[position].metric,
              value.candidate_mode == responseMode, value.candidate_kind == prefixes[position].candidate_kind,
              value.purpose == (native.isExecution ? "draft-prefix-append-execution" : original.isAppend ? "draft-prefix-append" : nil),
              value.append_source_metadata_sha256 == original.appendSource?.metadataSHA256,
              value.schema == 1, value.prefix_position == position, value.prefix_id == original.members[position].id,
              value.source_sha256 == native.sourceSHA256(), value.config_sha256 == native.configSHA256(),
              value.capture_sha256 == native.captureSHA256(), value.original_source_sha256 == native.originalSourceSHA256(),
              value.original_source_sha256 == original.sourceSHA256,
              [value.source_sha256, value.config_sha256, value.original_source_sha256].allSatisfy(Self.digest),
              native.isExecution ? value.capture_sha256.isEmpty && value.execution_capture_sha256 == "" &&
                value.execution_source_sha256 == value.source_sha256 && value.requested_execution == native.requestedExecution() &&
                Self.digest(value.original_preparation_source_sha256 ?? "") && Self.digest(value.original_preparation_capture_sha256 ?? "") :
                Self.digest(value.capture_sha256) && value.execution_source_sha256 == nil && value.execution_capture_sha256 == nil &&
                value.requested_execution == nil && value.original_preparation_source_sha256 == nil && value.original_preparation_capture_sha256 == nil,
              !value.application_open, !value.dns_open, !value.ready, value.stage == "pending-prefix-proof",
              value.mtu_measurement == "configured-bounds-only", value.prefixes.count == position + 1,
              !value.targets.isEmpty, Set(value.targets.map(\.id)).count == value.targets.count,
              value.targets.allSatisfy({ !$0.id.isEmpty && $0.id.utf8.count <= 128 && Self.digest($0.source_sha256) }) else { throw Self.issue() }
        var appendProofs: [Metadata.Prefix] = [], appendOutbounds: [[String: Any]] = []
        var pairedProxyEntryAppend = false
        if let append = original.appendSource, append.members.contains(where: { ["shadowsocks", "hysteria2"].contains($0.mode) }) {
            guard let appendSource = try JSONSerialization.jsonObject(with: Data(append.source.utf8)) as? [String: Any],
                  let retained = try JSONSerialization.jsonObject(with: Data(append.metadata.utf8)) as? [String: Any],
                  let rows = retained["prefixes"] as? [[String: Any]], rows.count == value.prefixes.count,
                  let graph = try JSONSerialization.jsonObject(with: Data(append.config.utf8)) as? [String: Any],
                  let outbounds = graph["outbounds"] as? [[String: Any]] else { throw Self.issue() }
            appendProofs = try JSONDecoder().decode([Metadata.Prefix].self, from: JSONSerialization.data(withJSONObject: rows, options: [.sortedKeys]))
            appendOutbounds = outbounds
            pairedProxyEntryAppend = appendSource["schema"] as? Int == 3 &&
                IOSNodeCandidateAppendSource.proxyEntryMode(append.members.first?.mode ?? "") &&
                append.members.allSatisfy { $0.profile["node_kind"] as? String == "router-vpn" &&
                    ["", "off"].contains($0.profile["start_layer"] as? String ?? "off") }
        }
        for (index, prefix) in value.prefixes.enumerated() {
            let member = original.members[index]
            let layer = member.profile["start_layer"] as? String ?? "off"
            guard prefix.position == index, prefix.profile_id == member.id, prefix.mode == member.mode,
                  prefix.start_layer == (layer.isEmpty ? "off" : layer), Self.digest(prefix.source_sha256),
                  !prefix.tag.isEmpty else { throw Self.issue() }
            if original.isAppend && ["shadowsocks", "hysteria2"].contains(member.mode) {
                guard index > 0 || index == 0 && pairedProxyEntryAppend, prefix.start_layer == "off", value.measurement == original.appendSource?.measurement,
                      appendProofs.indices.contains(index), appendProofs[index] == prefix,
                      appendOutbounds.filter({ $0["tag"] as? String == prefix.tag && $0["type"] as? String == member.mode }).count == 1 else { throw Self.issue() }
                if member.profile["node_kind"] as? String == "external" {
                    guard member.mode == "shadowsocks", prefix.node_id.isEmpty, prefix.node_kind == "external", prefix.kind == "public-path" else { throw Self.issue() }
                } else {
                    guard member.profile["node_kind"] as? String == "router-vpn", member.profile["external"] == nil,
                          !prefix.node_id.isEmpty, prefix.node_id == member.profile["node_proof_id"] as? String,
                          prefix.node_kind == nil, prefix.kind == nil else { throw Self.issue() }
                }
            } else if member.mode == "shadowsocks" {
                guard index > 0, prefix.start_layer == "off", case .ordinary(let capture) = original else { throw Self.issue() }
                let retained: String? = LibboxRouterNodeChainCandidatePrefixProof(capture.plan, Int32(index))
                guard let retained, try JSONDecoder().decode(Metadata.Prefix.self, from: Data(retained.utf8)) == prefix,
                      let graph = try JSONSerialization.jsonObject(with: Data(capture.config.utf8)) as? [String: Any],
                      let outbounds = graph["outbounds"] as? [[String: Any]],
                      outbounds.filter({ $0["tag"] as? String == prefix.tag && $0["type"] as? String == "shadowsocks" }).count == 1 else { throw Self.issue() }
                if member.profile["node_kind"] as? String == "external" {
                    guard prefix.node_id.isEmpty, prefix.node_kind == "external", prefix.kind == "public-path" else { throw Self.issue() }
                } else {
                    guard value.measurement == "routed-candidate-response", capture.sourceSchema == 6, (4...IOSMultihopNodeSelection.physicalTraversalDepth).contains(capture.members.count),
                          member.profile["node_kind"] as? String == "router-vpn", member.profile["external"] == nil,
                          !prefix.node_id.isEmpty, prefix.node_id == member.profile["node_proof_id"] as? String,
                          prefix.node_kind == nil, prefix.kind == nil else { throw Self.issue() }
                }
            } else {
                guard ["wg", "awg2-fast", "awg2-strong"].contains(prefix.mode),
                      prefix.node_id == member.profile["node_proof_id"] as? String else { throw Self.issue() }
            }
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
        immutableMetadata = raw; executionAppendSource = native.isExecution ? original.appendSource : nil
        self.inventory = inventory; metadata = value; strict = original.strict; homeLANAccess = original.homeLANAccess
        appendDeviceMTU = original.appendSource?.deviceMTU
        responseSourceNodes = responseMode == nil ? nil : original.members.map {
            IOSNodeCandidateResponseNode(id: $0.id, mode: $0.mode, kind: $0.profile["node_kind"] as? String ?? "router-vpn")
        }
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
                userInfo: [NSLocalizedDescriptionKey: "The original saved source, selected prefix or closed test policy could not be reproduced."])
    }
}
