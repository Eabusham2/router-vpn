import Foundation
import CoreFoundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

// Both the display model and transport must recognize the same measured public
// hops. The controller verifies the private source seals against the live owner.
enum RouterVPNSelectedPublicInventory {
    static func localRoles(_ value: Any?, count: Int) -> [String]? {
        guard (9...96).contains(count), let text = value as? String, text.utf8.count <= 2048,
              let data = text.data(using: .utf8), let roles = try? JSONDecoder().decode([String].self, from: data),
              roles.count == count, roles.first == "private-node", roles.last == "private-node",
              roles.contains("public-path"), roles.dropFirst().dropLast().contains("private-node"),
              roles.allSatisfy({ $0 == "private-node" || $0 == "public-path" }),
              text == "[" + roles.map({ "\"" + $0 + "\"" }).joined(separator: ",") + "]" else { return nil }
        return roles
    }
    static func selectedPrivateRoles(_ roles: [String]) -> Bool {
        guard (9...96).contains(roles.count), roles.first == "private-node", roles.last == "private-node",
              roles[1] == "public-path" else { return false }
        let interior = roles.dropFirst().dropLast()
        return interior.contains("private-node") && interior.allSatisfy { $0 == "public-path" || $0 == "private-node" }
    }
    static let fields: Set<String> = ["schema", "source_sha256", "config_sha256", "generation_sha256", "selected_execution", "nodes"]
    static func externalFinal(_ capture: [String: Any], nodes: [[String: Any]]) -> Bool {
        func integer(_ value: Any?, _ expected: Int) -> Bool {
            guard let n = value as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID() else { return false }
            return n.doubleValue == Double(expected)
        }
        func digest(_ value: Any?) -> Bool {
            guard let s = value as? String else { return false }
            return s.utf8.count == 64 && s.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
        }
        let keys: Set<String> = ["schema", "original_source_sha256", "entry_source_sha256", "entry_start_layer", "dns_owner", "final_transport_sha256", "registered_final_source_sha256", "public", "source_authenticator"]
        guard Set(capture.keys) == fields.union(["external_final"]), (3...96).contains(nodes.count),
              let original = capture["external_final"] as? [String: Any], Set(original.keys) == keys,
              integer(original["schema"], 8),
              ["original_source_sha256", "entry_source_sha256", "final_transport_sha256", "registered_final_source_sha256", "source_authenticator"].allSatisfy({ digest(original[$0]) }),
              let layer = original["entry_start_layer"] as? String, ["off", "aes-256-gcm", "aes-256-gcm+xor-whitening"].contains(layer),
              let dns = original["dns_owner"] as? String, ["entry-home", "external-final"].contains(dns),
              let rows = original["public"] as? [[String: Any]], rows.count == nodes.count - 1,
              nodes.enumerated().allSatisfy({ $0.element["kind"] as? String == ($0.offset == 0 ? "private-node" : "public-path") }) else { return false }
        var tags = Set<String>()
        for (index, row) in rows.enumerated() {
            guard Set(row.keys) == Set(["position", "tag", "source_sha256"]), integer(row["position"], index + 1),
                  digest(row["source_sha256"]), let tag = row["tag"] as? String, !tag.isEmpty, tag.utf8.count <= 128,
                  tag.utf8.allSatisfy({ (33...126).contains($0) }), tags.insert(tag).inserted else { return false }
        }
        return capture["selected_execution"] as? String != "server" || rows.last?["source_sha256"] as? String == original["registered_final_source_sha256"] as? String
    }
    static func selectedSize(_ count: Int?, capture: [String: Any], nodes: [[String: Any]]) -> Bool {
        if capture.keys.contains("external_final") {
            return externalFinal(capture, nodes: nodes) && (nodes.count <= 8 ? count == nil : count == nodes.count)
        }
        guard let count else { return (2...8).contains(nodes.count) }
        guard (9...96).contains(count), count == nodes.count, capture["multiple_imported"] != nil else { return false }
        if selectedPrivateRoles(nodes.map { $0["kind"] as? String ?? "" }) { return true }
        return nodes.enumerated().allSatisfy { index, row in
            row["kind"] as? String == (index == 0 || index == count - 1 ? "private-node" : "public-path")
        }
    }

    static func valid(_ capture: [String: Any], nodes: [[String: Any]]) -> Bool {
        if capture.keys.contains("external_final") { return externalFinal(capture, nodes: nodes) }
        let positions = nodes.indices.filter { nodes[$0]["kind"] as? String == "public-path" }
        guard positions.allSatisfy({ $0 > 0 && $0 < nodes.count - 1 }) else { return false }
        guard capture.keys.contains("multiple_imported") else {
            return Set(capture.keys) == fields && positions.allSatisfy { $0 == nodes.count - 2 }
        }
        func integer(_ value: Any?, _ expected: Int) -> Bool {
            guard let n = value as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID() else { return false }
            return n.doubleValue == Double(expected)
        }
        func digest(_ value: Any?) -> Bool {
            guard let s = value as? String else { return false }
            return s.utf8.count == 64 && s.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
        }
        guard Set(capture.keys) == fields.union(["multiple_imported"]),
              let original = capture["multiple_imported"] as? [String: Any],
              Set(original.keys) == Set(["schema", "original_source_sha256", "public"]),
              integer(original["schema"], 6), digest(original["original_source_sha256"]),
              let rows = original["public"] as? [[String: Any]], rows.count == positions.count,
              positions.contains(where: { $0 < nodes.count - 2 }) else { return false }
        return zip(rows, positions).allSatisfy { row, position in
            guard Set(row.keys) == Set(["position", "tag", "source_sha256"]),
                  integer(row["position"], position), digest(row["source_sha256"]),
                  let tag = row["tag"] as? String, !tag.isEmpty, tag.utf8.count <= 128,
                  tag.utf8.allSatisfy({ (33...126).contains($0) }) else { return false }
            return true
        }
    }
}

// One object owns one loopback request. Close/Cancel never invalidate a newer
// dialog's session; the controller also checks its captured generation.
final class RouterVPNMacSpeedLabTransport: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var session: URLSession?
    private var task: URLSessionDataTask?
    private var data = Data()
    private var status = 0
    private var failure: Error?
    private var completion: ((Result<Data, Error>) -> Void)?
    private var finished = false
    private static let limit = 2 * 1024 * 1024

    init(url: URL, body: [String: Any]?, timeout: TimeInterval, completion: @escaping (Result<Data, Error>) -> Void) throws {
        let savedBase = "/api/multihop/saved-candidates"
        let draftBase = "/api/multihop/draft-candidates"
        let isDraft = url.path == draftBase || url.path.hasPrefix(draftBase + "/")
        let candidateBase = isDraft ? draftBase : (url.path == savedBase || url.path.hasPrefix(savedBase + "/") ? savedBase : "/api/multihop/prefix-candidates")
        let draftNamedSave = isDraft && url.path == draftBase + "/save-profile"
        let savePath = candidateBase + (isDraft && !draftNamedSave ? "/choose" : "/save-profile")
        // A catalog GET can select any physical slot. The controller resolves
        // its captured source before it can start a worker at that position.
        let query = url.query ?? ""
        var parts = query.components(separatedBy: "&")
        let serverResponse = parts.last == "server_response=true"
        if serverResponse { parts.removeLast() }
        let positionText = String((parts.first ?? "").dropFirst("prefix_position=".count))
        let selectedPosition = Int(positionText)
        let canonicalPosition = query.hasPrefix("prefix_position=") && selectedPosition.map { (0..<96).contains($0) && String($0) == positionText } == true
        let draftCatalog = isDraft && canonicalPosition && parts.count == 2 &&
            (parts[1] == "scope=saved-prefix-local" || parts[1] == "scope=draft-complete-selected" && (selectedPosition ?? 96) < 95)
        let appendCatalog = isDraft && canonicalPosition && (selectedPosition ?? 96) < 95 && !serverResponse &&
            parts.count == 2 && ["scope=draft-prefix-append","scope=draft-prefix-append-execution"].contains(parts[1])
        let prefixCatalog = candidateBase == savedBase && canonicalPosition && parts.count == 2 && parts[1] == "scope=saved-prefix-local"
        let serverQueryAllowed = !serverResponse || (candidateBase == "/api/multihop/prefix-candidates" && parts.count == 1) ||
            (isDraft && draftCatalog && parts.last == "scope=draft-complete-selected")
        let candidateCatalog = serverQueryAllowed && url.path == candidateBase + "/catalog" && (draftCatalog || appendCatalog || prefixCatalog || !isDraft && canonicalPosition && parts.count == 1)
        let candidateStatus = url.path == candidateBase && url.query?.range(of: "^request_id=[a-f0-9]{32}$", options: .regularExpression) != nil
        let orderedBase = "/api/speed-lab/ordered-latency"
        let orderedStatus = url.path == orderedBase && url.query?.range(of: "^request_id=[a-f0-9]{32}$", options: .regularExpression) != nil
        guard url.scheme == "http", url.host == "127.0.0.1", url.user == nil, url.password == nil,
              ["/api/speed-lab/options", "/api/speed-lab/run", "/api/profile/fastest",
               "/api/profiles", "/api/multihop/status", "/api/connection/live-latency",
               "/api/connection/speed-test", "/api/profile/latency", "/api/multihop/speed-test",
               candidateBase, candidateBase + "/catalog", candidateBase + "/cancel", savePath,
               orderedBase, orderedBase + "/cancel"].contains(url.path), (url.query == nil || candidateCatalog || candidateStatus || orderedStatus), url.fragment == nil else {
            throw NSError(domain: "RouterVPNSpeedLab", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid local Speed Lab endpoint."])
        }
        if url.path == "/api/profile/fastest" {
            guard timeout.isFinite, timeout > 0, timeout <= 185, let body,
                  Set(body.keys) == Set(["samples", "select"]),
                  (body["samples"] as? NSNumber)?.doubleValue == 50,
                  let selected = body["select"] as? NSNumber,
                  CFGetTypeID(selected) == CFBooleanGetTypeID(), selected.boolValue else {
                throw NSError(domain: "RouterVPNSpeedLab", code: 1, userInfo: [NSLocalizedDescriptionKey: "Fastest requires a bounded 50-sample selection request."])
            }
        }
        // Performance uses this same owned transport, with explicit bounded
        // schemas. Adding read/measurement endpoints does not grant mutation API access.
        func bounded(_ maximum: TimeInterval) -> Bool { timeout.isFinite && timeout > 0 && timeout <= maximum }
        func number(_ key: String, equals expected: Double) -> Bool {
            guard let value = body?[key] as? NSNumber, CFGetTypeID(value) != CFBooleanGetTypeID() else { return false }
            return value.doubleValue == expected
        }
        func identifier(_ key: String) -> String? {
            guard let value = body?[key] as? String, !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return nil }
            return value
        }
        func candidatePath(_ raw: Any?) -> [[String: String]]? {
            guard let nodes = raw as? [[String: String]], (2...96).contains(nodes.count),
                  Set(nodes.compactMap { $0["id"] }).count == nodes.count else { return nil }
            let modes = ["wg", "awg2-fast", "awg2-strong", "shadowsocks", "hysteria2", "socks5", "http-connect", "https-connect", "openvpn"]
            for node in nodes {
                guard Set(node.keys) == ["id", "mode"], let id = node["id"],
                      id.range(of: #"\A[A-Za-z0-9_-]{1,64}\z"#, options: .regularExpression) != nil,
                      modes.contains(node["mode"] ?? "") else { return nil }
            }
            if nodes.count > 8 {
                let imported = nodes.first?["mode"] == "wg" && nodes.dropFirst().allSatisfy { $0["mode"] == "shadowsocks" }
                let paired = nodes.last?["mode"] == "shadowsocks" && nodes.dropLast().allSatisfy { $0["mode"] == "wg" }
                let packets = nodes.prefix(while: { ["wg", "awg2-fast", "awg2-strong"].contains($0["mode"] ?? "") }).count
                let mixed = packets > 0 && packets < nodes.count - 1 && nodes.dropFirst(packets).allSatisfy { $0["mode"] == "shadowsocks" }
                guard imported || paired || mixed else { return nil }
            }
            return nodes
        }
        // An append request carries only real prefix rows, never a selected final.
        // Source kind, paired identity, layer and exact compiled MTU remain controller checks.
        func appendPath(_ raw: Any?, minimum: Int, maximum: Int) -> [[String: String]]? {
            guard let nodes = raw as? [[String: String]], (minimum...maximum).contains(nodes.count),
                  Set(nodes.compactMap { $0["id"] }).count == nodes.count else { return nil }
            for node in nodes {
                guard Set(node.keys) == ["id", "mode"], let id = node["id"],
                      id.range(of: #"\A[A-Za-z0-9_-]{1,64}\z"#, options: .regularExpression) != nil,
                      let mode = node["mode"], ["wg", "awg2-fast", "awg2-strong", "shadowsocks", "hysteria2"].contains(mode) else { return nil }
            }
            return nodes
        }
        func appendExecutionPath(_ nodes: [[String: String]], nextMode: String) -> Bool {
            guard ["wg", "awg2-fast", "awg2-strong", "shadowsocks", "hysteria2"].contains(nextMode),
                  ["wg", "awg2-fast", "awg2-strong"].contains(nodes.first?["mode"] ?? "") else { return false }
            var hysteriaTail=false
            for node in nodes {
                guard let mode=node["mode"], ["wg", "awg2-fast", "awg2-strong", "shadowsocks", "hysteria2"].contains(mode) else { return false }
                if hysteriaTail && ["wg", "awg2-fast", "awg2-strong"].contains(mode) { return false }
                if mode == "hysteria2" { hysteriaTail=true }
            }
            return !hysteriaTail || ["shadowsocks", "hysteria2"].contains(nextMode)
        }
        let performanceValid: Bool
        switch url.path {
        case orderedBase, orderedBase + "/cancel":
            if body == nil {
                performanceValid = url.path == orderedBase && (url.query == nil || orderedStatus) && bounded(6)
            } else {
                let capture = body?["capture"] as? [String: Any] ?? [:]
                let text: (Any?, Int) -> Bool = { value, limit in
                    guard let value = value as? String else { return false }
                    return !value.isEmpty && value.utf8.count <= limit && !value.unicodeScalars.contains { $0.value < 32 || $0.value == 127 }
                }
                let hex: (Any?, Int) -> Bool = { value, count in
                    guard let value = value as? String else { return false }
                    return value.utf8.count == count && value.range(of: "^[a-f0-9]+$", options: .regularExpression) != nil
                }
                let session = capture["session_id"] as? String ?? ""
                let position = body?["position"] as? NSNumber
                let ordinaryKeys = Set(["session_id", "profile_id", "profile_token", "source_sha256", "config_sha256", "generation_sha256"])
                let extendedCount = (capture["extended_local_nodes"] ?? capture["extended_original_nodes"]) as? NSNumber
                func selectedCaptureValid() -> Bool {
                    if capture.keys.contains("external_final_node_id") {
                        guard let exit = capture["external_final_node_id"] as? String,
                              exit.range(of: #"\A[A-Za-z0-9_-]{1,64}\z"#, options:.regularExpression) != nil,
                              let control = capture["profile_id"] as? String, exit != control,
                              let node = body?["node_id"] as? String, let index = position?.intValue,
                              (index == 0) == (node == control) else { return false }
                        var keys = ordinaryKeys.union(["external_final_node_id"])
                        if capture.keys.contains("extended_local_nodes") {
                            guard let count = extendedCount, CFGetTypeID(count) != CFBooleanGetTypeID(), let n = Int(count.stringValue),
                                  (9...96).contains(n), (index == n-1) == (node == exit) else { return false }
                            keys.insert("extended_local_nodes")
                        }
                        return Set(capture.keys) == keys && (node != exit || index >= 2)
                    }
                    if capture.keys.contains("extended_local_nodes") {
                        guard let count = extendedCount, CFGetTypeID(count) != CFBooleanGetTypeID(),
                              count.doubleValue == Double(count.intValue), (9...96).contains(count.intValue) else { return false }
                        let required = ordinaryKeys.union(["extended_local_nodes"])
                        if capture.keys.contains("local_roles_json") {
                            return Set(capture.keys) == required.union(["local_roles_json"]) &&
                                RouterVPNSelectedPublicInventory.localRoles(capture["local_roles_json"], count: count.intValue) != nil
                        }
                        guard let raw = capture["paired_prefix_nodes"] else { return Set(capture.keys) == required }
                        guard let packets = raw as? NSNumber, CFGetTypeID(packets) != CFBooleanGetTypeID(),
                              let prefixCount = Int(packets.stringValue), (1..<count.intValue-1).contains(prefixCount) else { return false }
                        return Set(capture.keys) == required.union(["paired_prefix_nodes"])
                    }
                    if !capture.keys.contains("selected_capture") { return Set(capture.keys) == ordinaryKeys }
                    let selectedCount = capture["extended_original_nodes"] as? NSNumber
                    if capture.keys.contains("extended_original_nodes") {
                        guard let selectedCount, CFGetTypeID(selectedCount) != CFBooleanGetTypeID(),
                              selectedCount.doubleValue == Double(selectedCount.intValue), (9...96).contains(selectedCount.intValue) else { return false }
                    }
                    let fields = selectedCount == nil ? ["selected_capture"] : ["selected_capture", "extended_original_nodes"]
                    let captureLimit = selectedCount.map { max(16384, 512 + 1536 * $0.intValue) } ?? 8192
                    guard Set(capture.keys) == ordinaryKeys.union(fields),
                          let raw = capture["selected_capture"] as? String, !raw.isEmpty, raw.utf8.count <= max(65536, captureLimit),
                          let data = raw.data(using: .utf8),
                          let selected = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                          raw.utf8.count <= (selected.keys.contains("external_final") ? 65536 : captureLimit),
                          let schema = selected["schema"] as? NSNumber, CFGetTypeID(schema) != CFBooleanGetTypeID(), schema.doubleValue == 1,
                          ["source_sha256", "config_sha256", "generation_sha256"].allSatisfy({ selected[$0] as? String == capture[$0] as? String }),
                          let execution = selected["selected_execution"] as? String, ["local", "server"].contains(execution),
                          let nodes = selected["nodes"] as? [[String: Any]], RouterVPNSelectedPublicInventory.selectedSize(selectedCount?.intValue, capture: selected, nodes: nodes),
                          RouterVPNSelectedPublicInventory.valid(selected, nodes: nodes),
                          !selected.keys.contains("external_final") || nodes.first?["node_id"] as? String == capture["profile_id"] as? String, let position,
                          CFGetTypeID(position) != CFBooleanGetTypeID(), position.doubleValue.rounded() == position.doubleValue,
                          nodes.indices.contains(position.intValue), nodes[position.intValue]["node_id"] as? String == body?["node_id"] as? String else { return false }
                    var ids = Set<String>()
                    for (index, node) in nodes.enumerated() {
                        let role = index == 0 ? "entry" : index == nodes.count-1 ? "exit" : "intermediate"
                        guard Set(node.keys) == Set(["node_id", "position", "role", "kind"]), text(node["node_id"], 128),
                              let id = node["node_id"] as? String, ids.insert(id).inserted,
                              let capturedPosition = node["position"] as? NSNumber, CFGetTypeID(capturedPosition) != CFBooleanGetTypeID(),
                              capturedPosition.doubleValue == Double(index), node["role"] as? String == role,
                              let kind = node["kind"] as? String,
                              kind == "private-node" || kind == "public-path" else { return false }
                    }
                    return true
                }
                performanceValid = url.query == nil && bounded(6) && Set(body!.keys) == Set(["capture", "node_id", "position", "request_id"]) &&
                    selectedCaptureValid() &&
                    session.utf8.count <= 64 && session.range(of: "^session-[0-9]+-[0-9]+$", options: .regularExpression) != nil &&
                    text(capture["profile_id"], 128) && ["profile_token", "source_sha256", "config_sha256", "generation_sha256"].allSatisfy({ hex(capture[$0], 64) }) &&
                    text(body?["node_id"], 128) && hex(body?["request_id"], 32) && position != nil && CFGetTypeID(position!) != CFBooleanGetTypeID() &&
                    position!.doubleValue.rounded() == position!.doubleValue && (0..<(extendedCount?.intValue ?? 8)).contains(position!.intValue)
            }
        case candidateBase + "/catalog":
            if appendCatalog {
                let external = body?["next_kind"] as? String == "external"
                let executionAppend = parts.last == "scope=draft-prefix-append-execution"
                let fields: Set<String> = ["schema", "purpose", "execution", "draft_revision", "append_position", "next_mode",
                                           "nodes", "expected_selected_node_id", "expected_profile_tokens"]
                guard let body, Set(body.keys) == (executionAppend ? fields.union(["requested_execution"]):external ? fields.union(["next_kind"]):fields), number("schema", equals: 1),
                      body["next_kind"] == nil || external && body["next_mode"] as? String == "shadowsocks",
                      body["purpose"] as? String == (executionAppend ? "draft-prefix-append-execution":"draft-prefix-append"), body["execution"] as? String == "local",
                       !executionAppend || !external && body["next_kind"] == nil && ["server","auto"].contains(body["requested_execution"] as? String ?? "") && ["wg","awg2-fast","awg2-strong","shadowsocks","hysteria2"].contains(body["next_mode"] as? String ?? ""),
                      let revision = body["draft_revision"] as? String,
                      revision.range(of: #"\A[0-9a-f]{32}\z"#, options: .regularExpression) != nil,
                      let nodes = appendPath(body["nodes"], minimum: 1, maximum: 95),
                      !external || !["shadowsocks", "hysteria2"].contains(nodes[0]["mode"] ?? ""),
                       !executionAppend || appendExecutionPath(nodes, nextMode: body["next_mode"] as? String ?? ""),
                      number("append_position", equals: Double(nodes.count)), selectedPosition == nodes.count - 1,
                      let mode = body["next_mode"] as? String, ["wg", "awg2-fast", "awg2-strong", "shadowsocks", "hysteria2"].contains(mode),
                      let device = body["expected_selected_node_id"] as? String,
                      device.range(of: #"\A[A-Za-z0-9_-]{1,64}\z"#, options: .regularExpression) != nil,
                      let tokens = body["expected_profile_tokens"] as? [String: String],
                      Set(tokens.keys) == Set(nodes.compactMap { $0["id"] } + [device]),
                      tokens.values.allSatisfy({ $0.range(of: #"\A[0-9a-f]{64}\z"#, options: .regularExpression) != nil }),
                      bounded(25) else { throw URLError(.badURL) }
                performanceValid = true
            } else if isDraft {
                guard draftCatalog, let body,
                      let nodes = candidatePath(body["nodes"]), let execution = body["execution"] as? String,
                      let prefix = selectedPosition,
                      nodes.indices.contains(prefix), prefix < nodes.count - 1,
                      let tokens = body["expected_profile_tokens"] as? [String: String] else { throw URLError(.badURL) }
                let ordinaryKeys: Set<String> = ["nodes", "execution", "expected_selected_node_id", "expected_profile_tokens"]
                let packetEntryWithStreams = nodes.count >= 3 && ["wg", "awg2-fast", "awg2-strong"].contains(nodes.first?["mode"] ?? "") &&
                    nodes.dropFirst().allSatisfy { $0["mode"] == "shadowsocks" }
                let externalFinal = body.keys.contains("external_final")
                if externalFinal {
                    guard Set(body.keys) == ordinaryKeys.union(["external_final"]),
                          let flag = body["external_final"] as? NSNumber, CFGetTypeID(flag) == CFBooleanGetTypeID(), flag.boolValue,
                          ["local","server","auto"].contains(execution), serverResponse == (execution != "local"),
                          execution == "local" || prefix > 0, packetEntryWithStreams else { throw URLError(.badURL) }
                } else if Set(body.keys) != ordinaryKeys { throw URLError(.badURL) }
                guard nodes.count <= 8 || packetEntryWithStreams || execution == "local" else { throw URLError(.badURL) }
                let packet = ["wg", "awg2-fast", "awg2-strong"].contains(nodes[prefix]["mode"] ?? "")
                let packets = nodes.prefix(prefix + 1).prefix(while: { ["wg", "awg2-fast", "awg2-strong"].contains($0["mode"] ?? "") }).count
                let stream = execution == "local" && packets > 0 && packets <= prefix &&
                    nodes.last?["mode"] == "shadowsocks" && nodes[packets...prefix].allSatisfy { $0["mode"] == "shadowsocks" }
                // This envelope exposes only public references. The controller checks
                // every original source, the selected winner and its selection epoch.
                let compareStream = (execution == "auto" || serverResponse && execution == "server") && nodes.count >= 3 && prefix > 0 &&
                    (nodes.first?["mode"] == "wg" || serverResponse && ["awg2-fast","awg2-strong"].contains(nodes.first?["mode"] ?? "")) && nodes.dropFirst().allSatisfy { $0["mode"] == "shadowsocks" } &&
                    (externalFinal || prefix == nodes.count - 2 || nodes.count < 96)
                guard packet && (prefix < 7 || execution == "local") || stream || compareStream else { throw URLError(.badURL) }
                let scope = execution == "local" ? "saved-prefix-local" : "draft-complete-selected"
                performanceValid = ["local", "server", "auto"].contains(execution) && parts.last == "scope=" + scope && serverQueryAllowed &&
                    Set(tokens.keys) == Set(nodes.compactMap { $0["id"] }) && tokens.values.allSatisfy { $0.range(of: #"\A[a-f0-9]{64}\z"#, options: .regularExpression) != nil } &&
                    body["expected_selected_node_id"] as? String == (externalFinal ? nodes.first?["id"] : nodes.last?["id"]) && bounded(25)
            } else { performanceValid = candidateCatalog && body == nil && bounded(25) }
        case candidateBase, candidateBase + "/cancel", savePath:
            func token(_ key: String, _ count: Int) -> Bool { guard let id = identifier(key) else {return false};return id.utf8.count == count && id.range(of:"^[a-f0-9]+$",options:.regularExpression) != nil }
            let suppliedKeys = Set(body?.keys.map { $0 } ?? [])
            let appendRequest = isDraft && ["draft-prefix-append","draft-prefix-append-execution"].contains(body?["scope"] as? String ?? "")
            let executionAppend = isDraft && body?["scope"] as? String == "draft-prefix-append-execution"
            if suppliedKeys.contains("scope") || isDraft && body != nil {
                let scopes = isDraft ? ["saved-prefix-local","draft-complete-selected"] : ["saved-prefix-local","saved-complete-local"]
                guard (candidateBase == savedBase || isDraft), let scope=body?["scope"] as? String,
                      scopes.contains(scope) || appendRequest && !draftNamedSave else {
                    throw NSError(domain:"RouterVPNSpeedLab",code:1,userInfo:[NSLocalizedDescriptionKey:"Invalid saved candidate purpose."])
                }
            }
            let keys = suppliedKeys.subtracting(["scope"])
            let original = token("request_id",32)
            if appendRequest {
                guard url.query == nil, !draftNamedSave else { throw URLError(.badURL) }
                if url.path == candidateBase + "/cancel" {
                    performanceValid = original && token("view_token",64) && keys == Set(["request_id","view_token"]) && bounded(25)
                } else if url.path == candidateBase {
                    let ids = body?["candidate_ids"] as? [String] ?? []
                    let position = body?["prefix_position"] as? NSNumber
                    let requestBytes = (try? JSONSerialization.data(withJSONObject: body ?? [:]))?.count ?? Int.max
                    performanceValid = original && token("view_token",64) && keys == Set(["request_id","view_token","prefix_position","candidate_ids","samples"]) &&
                        number("samples",equals:50) && bounded(180) && position != nil && CFGetTypeID(position!) != CFBooleanGetTypeID() &&
                        position!.doubleValue.rounded() == position!.doubleValue && (0..<95).contains(position!.intValue) &&
                        requestBytes <= 16384 && !ids.isEmpty && Set(ids).count == ids.count &&
                        ids.allSatisfy({ $0.range(of: #"\A[A-Za-z0-9_-]{1,64}\z"#, options: .regularExpression) != nil })
                } else if url.path == draftBase + "/choose" {
                    let proposed = appendPath(body?["proposed_path"], minimum: 2, maximum: 96)
                    let executionPrefix = proposed.map { appendExecutionPath(Array($0.dropLast()), nextMode: $0.last?["mode"] ?? "") } ?? false
                    performanceValid = original && token("view_token",64) && keys == Set(["request_id","view_token","candidate_id","proposed_path"]) &&
                        bounded(25) && proposed != nil && proposed?.last?["id"] == identifier("candidate_id") &&
                        (!executionAppend || executionPrefix)
                } else { performanceValid = false }
            } else if url.path == candidateBase + "/cancel" {
                let bound = candidateBase == savedBase || isDraft || keys.contains("view_token")
                performanceValid = original && (!bound || token("view_token",64)) && keys == (bound ? Set(["request_id","view_token"]) : Set(["request_id"])) && bounded(25)
            } else if url.path == candidateBase && body == nil {
                performanceValid = candidateStatus && bounded(25)
            } else if url.path == candidateBase {
                let ids = body?["candidate_ids"] as? [String] ?? []
                let position = body?["prefix_position"] as? NSNumber
                let requestBytes = (try? JSONSerialization.data(withJSONObject: body ?? [:]))?.count ?? Int.max
                performanceValid = url.query == nil && original && token("view_token",64) && keys == Set(["request_id","view_token","prefix_position","candidate_ids","samples"]) && number("samples",equals:50) && bounded(180) &&
                    position != nil && CFGetTypeID(position!) != CFBooleanGetTypeID() && position!.doubleValue.rounded() == position!.doubleValue && (0..<(body?["scope"] as? String == "draft-complete-selected" ? 95 : 96)).contains(position!.intValue) &&
                    requestBytes <= 16384 && !ids.isEmpty && Set(ids).count == ids.count && ids.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 128 })
            } else {
                let expected: Set<String> = isDraft && !draftNamedSave ? ["request_id","view_token","candidate_id","proposed_path"] : ["request_id","view_token","candidate_id","name","proposed_path"]
                let name = identifier("name") ?? ""
                let proposed = candidatePath(body?["proposed_path"])
                let selectedSave = draftNamedSave && body?["scope"] as? String == "draft-complete-selected"
                let selectedPath = proposed.map { nodes in
                    nodes.count >= 3 && nodes.first?["mode"] == "wg" && nodes.dropFirst().allSatisfy { $0["mode"] == "shadowsocks" } &&
                        nodes.dropFirst(2).contains { $0["id"] == identifier("candidate_id") }
                } ?? false
                let draftChoice = isDraft && !draftNamedSave
                let includesChosenHop = proposed?.dropFirst().dropLast().contains { $0["id"] == identifier("candidate_id") } == true
                performanceValid = original && token("view_token",64) && identifier("candidate_id") != nil && keys == expected && bounded(25) &&
                    (!draftChoice || includesChosenHop) && (!selectedSave || selectedPath) && (isDraft && !draftNamedSave || !name.isEmpty && name.utf8.count <= 64) && proposed != nil
            }
        case "/api/profiles", "/api/multihop/status": performanceValid = body == nil && bounded(5)
        case "/api/connection/live-latency": performanceValid = Set(body?.keys.map { $0 } ?? []) == Set(["samples"]) && number("samples", equals: 5) && bounded(12)
        case "/api/connection/speed-test": performanceValid = Set(body?.keys.map { $0 } ?? []) == Set(["bytes"]) && number("bytes", equals: 8388608) && bounded(45)
        case "/api/profile/latency": performanceValid = Set(body?.keys.map { $0 } ?? []) == Set(["id", "samples"]) && identifier("id") != nil && number("samples", equals: 50) && bounded(180)
        case "/api/multihop/speed-test":
            let keys = Set(body?.keys.map { $0 } ?? [])
            let pair = keys == Set(["entry_id", "exit_id", "bytes"]) && number("bytes", equals: 4194304) && bounded(70)
            let ordered = keys == Set(["entry_id", "exit_id", "bytes", "ordered_capture"]) &&
                identifier("ordered_capture")?.utf8.count == 64 && identifier("ordered_capture")?.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil && number("bytes", equals: 8388608) && bounded(100)
            performanceValid = identifier("entry_id") != nil && identifier("exit_id") != nil && identifier("entry_id") != identifier("exit_id") && (pair || ordered)
        default: performanceValid = true
        }
        guard performanceValid else {
            throw NSError(domain: "RouterVPNSpeedLab", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid bounded Performance request."])
        }
        var request = URLRequest(url: url)
        request.httpMethod = body == nil ? "GET" : "POST"
        request.timeoutInterval = timeout
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let body { request.httpBody = try JSONSerialization.data(withJSONObject: body); request.setValue("application/json", forHTTPHeaderField: "Content-Type") }
        try RouterVPNMacLocalAuthorization.shared.authorize(&request)
        self.completion = completion
        super.init()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.connectionProxyDictionary = [:]
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.timeoutIntervalForRequest = timeout
        configuration.timeoutIntervalForResource = timeout
        let queue = OperationQueue(); queue.maxConcurrentOperationCount = 1
        let session = URLSession(configuration: configuration, delegate: self, delegateQueue: queue)
        self.session = session
        task = session.dataTask(with: request)
    }

    func start() { lock.lock(); let owned = finished ? nil : task; lock.unlock(); owned?.resume() }

    func cancel() {
        lock.lock(); let owned = finished ? nil : task; lock.unlock()
        owned?.cancel()
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        lock.lock()
        guard !finished else { lock.unlock(); completionHandler(.cancel); return }
        status = (response as? HTTPURLResponse)?.statusCode ?? 0
        let oversized = response.expectedContentLength > Int64(Self.limit)
        if oversized { failure = NSError(domain: "RouterVPNSpeedLab", code: 2, userInfo: [NSLocalizedDescriptionKey: "Speed Lab response exceeded its size limit."]) }
        lock.unlock()
        completionHandler(oversized ? .cancel : .allow)
        // A rejected response already has a terminal result. Complete the
        // captured owner once even if Foundation defers its cancellation event.
        if oversized { finish(nil, cancelOwnedTask: true) }
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive bytes: Data) {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        let oversized = data.count > Self.limit - bytes.count
        if oversized { failure = NSError(domain: "RouterVPNSpeedLab", code: 2, userInfo: [NSLocalizedDescriptionKey: "Speed Lab response exceeded its size limit."]) }
        else { data.append(bytes) }
        lock.unlock()
        if oversized { finish(nil, cancelOwnedTask: true) }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        finish(error, cancelOwnedTask: false)
    }

    private func finish(_ error: Error?, cancelOwnedTask: Bool) {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        finished = true
        let callback = completion; completion = nil
        let response = data; data.removeAll(keepingCapacity: false)
        let explicitError = failure ?? error
        let code = status
        let ownedTask = task; let ownedSession = session
        self.task = nil; self.session = nil
        lock.unlock()
        if cancelOwnedTask { ownedTask?.cancel(); ownedSession?.invalidateAndCancel() }
        else { ownedSession?.finishTasksAndInvalidate() }
        let result: Result<Data, Error>
        if let explicitError { result = .failure(explicitError) }
        else if !(200..<300).contains(code) {
            let message = String(data: response.prefix(4096), encoding: .utf8) ?? "Local controller request failed."
            result = .failure(NSError(domain: "RouterVPNSpeedLab", code: code, userInfo: [NSLocalizedDescriptionKey: message]))
        } else { result = .success(response) }
        callback?(result)
    }
}
