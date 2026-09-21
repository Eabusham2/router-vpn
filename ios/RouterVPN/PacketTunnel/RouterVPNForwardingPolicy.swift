import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

// Pure policy/HTTP boundary shared by the real extension and executable tests.
// IPC accepts a boolean, never a URL, port, credential, or arbitrary admin route.
enum RouterVPNForwardingPolicy {
    static let maxMessage = 4096
    static let maxResponse = 64 * 1024
    static let route = "/api/forwarding/master"

    struct Command: Decodable, Sendable {
        let version: Int
        let action: String
        let nodeID: String
        let sessionID: String?
        let enabled: Bool?
        enum CodingKeys: String, CodingKey {
            case version, action, enabled
            case nodeID = "node_id", sessionID = "session_id"
        }
    }

    struct Endpoint: Sendable {
        let nodeID: String
        let proofID: String
        let host: String
        let port: Int
        let token: String
        var authority: String { host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)" }

        init(profile: [String: Any], proofID: String) throws {
            guard (profile["node_kind"] as? String ?? "router-vpn") == "router-vpn",
                  profile["external"] == nil || profile["external"] is NSNull,
                  let nodeID = profile["id"] as? String,
                  nodeID.range(of: "^[A-Za-z0-9._-]{1,128}$", options: .regularExpression) != nil,
                  proofID.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
                  let raw = profile["router_api"] as? String,
                  raw.utf8.count <= 512, !raw.contains("%"),
                  raw.rangeOfCharacter(from: .whitespacesAndNewlines.union(.controlCharacters)) == nil,
                  let url = URLComponents(string: raw), url.scheme == "http",
                  url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
                  url.path.isEmpty || url.path == "/", let rawHost = url.host else {
                throw issue("Forwarding requires a proved Router VPN node with a private HTTP agent.")
            }
            let host = rawHost.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
            let port = url.port ?? 80
            // Zone/scoped IPv6 literals are interface-dependent local addresses. They must
            // never be accepted as a persisted Router API identity because a later network
            // transition could retarget the same textual endpoint to another interface.
            guard !host.contains("%"), privateIP(host), (1...65535).contains(port),
                  let token = profile["api_token"] as? String,
                  token.range(of: "^[A-Za-z0-9._~+/=-]{16,512}$", options: .regularExpression) != nil else {
                throw issue("Forwarding agent must be a literal private address with a valid node token.")
            }
            self.nodeID = nodeID; self.proofID = proofID
            self.host = host; self.port = port; self.token = token
        }
    }

    static func decode(_ data: Data) throws -> Command {
        guard !data.isEmpty, data.count <= maxMessage,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys).isSubset(of: ["version", "action", "node_id", "session_id", "enabled"]) else {
            throw issue("Invalid forwarding message; only the master control is permitted.")
        }
        let command = try JSONDecoder().decode(Command.self, from: data)
        guard command.version == 1, ["get", "set"].contains(command.action), !command.nodeID.isEmpty else {
            throw issue("Unsupported forwarding command.")
        }
        if command.action == "set" {
            guard command.enabled != nil, let session = command.sessionID, UUID(uuidString: session) != nil else {
                throw issue("Refresh forwarding state before changing the master.")
            }
        } else if object["enabled"] != nil {
            throw issue("A read cannot change forwarding state.")
        }
        return command
    }

    static func authorize(_ command: Command, endpoint: Endpoint, sessionID: String) throws {
        guard command.nodeID == endpoint.nodeID else { throw issue("The active tunnel belongs to a different node.") }
        if command.action == "set" || command.sessionID != nil {
            guard command.sessionID == sessionID else { throw issue("Tunnel changed; refresh forwarding state before retrying.") }
        }
    }

    static func request(endpoint: Endpoint, proof: Bool = false, enabled: Bool? = nil) -> Data {
        let body = enabled.map { Data("{\"enabled\":\($0 ? "true" : "false")}".utf8) } ?? Data()
        let method = enabled == nil ? "GET" : "PUT"
        let path = proof ? "/health" : route
        var headers = "\(method) \(path) HTTP/1.1\r\nHost: \(endpoint.authority)\r\nConnection: close\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nCache-Control: no-store\r\n"
        // The public identity proof does not require a credential.
        if !proof { headers += "Authorization: Bearer \(endpoint.token)\r\n" }
        if enabled != nil { headers += "Content-Type: application/json\r\nContent-Length: \(body.count)\r\n" }
        return Data((headers + "\r\n").utf8) + body
    }

    static func response(_ wire: Data) throws -> [String: Any] {
        let separator = Data("\r\n\r\n".utf8)
        guard wire.count <= maxResponse, let range = wire.range(of: separator), range.lowerBound <= 8192,
              let head = String(data: wire[..<range.lowerBound], encoding: .utf8) else {
            throw issue("Invalid or oversized forwarding response.")
        }
        let lines = head.components(separatedBy: "\r\n")
        let status = (lines.first ?? "").split(separator: " ")
        guard status.count >= 2, ["HTTP/1.0", "HTTP/1.1"].contains(String(status[0])), status[1] == "200" else {
            throw issue("Private forwarding agent refused the request. State is unknown; refresh before retrying.")
        }
        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":"), !line.hasPrefix(" "), !line.hasPrefix("\t") else {
                throw issue("Malformed HTTP header.")
            }
            let key = line[..<colon].lowercased()
            guard headers[key] == nil else { throw issue("Duplicate HTTP header.") }
            headers[key] = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
        }
        // Agent replies are small Content-Length JSON messages. Never follow a
        // redirect or interpret ambiguous/chunked framing as successful mutation.
        let body = Data(wire[range.upperBound...])
        guard headers["transfer-encoding"] == nil,
              headers["content-encoding"] == nil || headers["content-encoding"] == "identity",
              let length = headers["content-length"].flatMap(Int.init), length == body.count,
              (headers["content-type"] ?? "").lowercased().hasPrefix("application/json"),
              let object = try JSONSerialization.jsonObject(with: body) as? [String: Any] else {
            throw issue("Unverifiable forwarding response framing.")
        }
        return object
    }

    static func verifyProof(_ object: [String: Any], endpoint: Endpoint) throws {
        struct Proof: Decodable { let ok: Bool; let node_id: String; let proof: String }
        let p = try JSONDecoder().decode(Proof.self, from: JSONSerialization.data(withJSONObject: object))
        guard p.ok, p.node_id == endpoint.proofID, p.proof == "router-vpn-private-agent-v1" else {
            throw issue("Forwarding agent identity does not match the running tunnel.")
        }
    }

    static func master(_ object: [String: Any], expected: Bool? = nil) throws -> Bool {
        struct Master: Decodable { let ok: Bool; let enabled: Bool }
        let value = try JSONDecoder().decode(Master.self, from: JSONSerialization.data(withJSONObject: object))
        guard value.ok, expected == nil || value.enabled == expected else {
            throw issue("Server did not verify the requested forwarding state.")
        }
        return value.enabled
    }

    static func reply(sessionID: String, nodeID: String, enabled: Bool) -> Data {
        (try? JSONSerialization.data(withJSONObject: ["version": 1, "ok": true, "session_id": sessionID, "node_id": nodeID, "enabled": enabled])) ?? Data()
    }
    static func failure(_ message: String) -> Data {
        (try? JSONSerialization.data(withJSONObject: ["version": 1, "ok": false, "error": message])) ?? Data()
    }
    static func issue(_ message: String) -> NSError { NSError(domain: "RouterVPN.Forwarding", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }

    private static func privateIP(_ host: String) -> Bool {
        // Darwin and Linux differ when parsing scoped addresses. Reject every
        // non-literal character before Foundation/C parsing can normalize it.
        guard !host.isEmpty, host.utf8.allSatisfy({
            (48...57).contains($0) || (65...70).contains($0) ||
            (97...102).contains($0) || $0 == 46 || $0 == 58
        }) else { return false }
        var v4 = in_addr(), v6 = in6_addr()
        if inet_pton(AF_INET, host, &v4) == 1 {
            let bytes = withUnsafeBytes(of: v4) { Array($0) }
            return bytes[0] == 10 || (bytes[0] == 172 && (16...31).contains(bytes[1])) || (bytes[0] == 192 && bytes[1] == 168)
        }
        if inet_pton(AF_INET6, host, &v6) == 1 {
            return withUnsafeBytes(of: v6) { ($0[0] & 0xfe) == 0xfc }
        }
        return false
    }
}
