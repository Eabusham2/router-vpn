import Foundation
import CoreFoundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(CryptoKit)
import CryptoKit
#endif

// Darwin ACLs can grant mutation without changing Unix mode bits. The kernel
// ATTR_CMN_EXTENDED_SECURITY payload contains bounded kauth_filesec/kauth_ace
// records; keep read and deny-only system ACLs, reject other permit authority.
// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/kauth.h
struct RouterVPNMacPathACL {
    static func accepts(_ data: Data, privateAuthority: Bool = false) -> Bool {
        guard data.count >= 12, data.count <= 4096 else { return false }
        let bytes = Array(data)
        func word(_ position: Int) -> UInt32 {
            UInt32(bytes[position]) | UInt32(bytes[position + 1]) << 8 |
            UInt32(bytes[position + 2]) << 16 | UInt32(bytes[position + 3]) << 24
        }
        let total = Int64(word(0)), start = Int64(4) + Int64(Int32(bitPattern: word(4))), length = Int64(word(8))
        guard total >= 12, total <= Int64(data.count), start >= 12, start <= total, length <= total - start else { return false }
        if length == 0 { return true }
        let offset = Int(start)
        guard length >= 44, word(offset) == 0x012cc16d else { return false }
        let count = word(offset + 36)
        if count == 0xffffffff { return length == 44 }
        guard count <= 128, length == 44 + 24 * Int64(count) else { return false }
        let readOnly: UInt32 = privateAuthority ? 0 : 1 << 1 | 1 << 3 | 1 << 7 | 1 << 9 | 1 << 11 | 1 << 20 | 1 << 22 | 1 << 24
        for index in 0..<Int(count) {
            let entry = offset + 44 + index * 24
            switch word(entry + 16) & 0xf {
            case 1: if word(entry + 20) & ~readOnly != 0 { return false }
            case 2: break
            default: return false
            }
        }
        return true
    }
}

struct RouterVPNMacControllerCredentials: Equatable, Sendable {
    let accessToken: String
    let ownerToken: String

    static func hexadecimal(_ value: String, count: Int) -> Bool {
        value.utf8.count == count && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    var valid: Bool { Self.hexadecimal(accessToken, count: 64) && Self.hexadecimal(ownerToken, count: 32) }
    var frame: Data {
        Data(("{\"schema\":1,\"access_token\":\"" + accessToken + "\",\"owner_token\":\"" + ownerToken + "\"}\n").utf8)
    }
    func mac(_ message: String) throws -> String {
        guard valid else { throw RouterVPNMacLocalAuthorization.failure("The captured controller launch identity is invalid.") }
        #if canImport(CryptoKit)
        let value = HMAC<SHA256>.authenticationCode(for: Data(message.utf8), using: SymmetricKey(data: Data(accessToken.utf8)))
        return value.map { String(format: "%02x", $0) }.joined()
        #else
        throw RouterVPNMacLocalAuthorization.failure("Native controller authentication requires CryptoKit.")
        #endif
    }
    func acceptsIdentity(_ data: Data, pid: Int32, challenge: String) -> Bool {
        guard pid > 0, Self.hexadecimal(challenge, count: 32),
              let fields = Self.exactObject(data, keys: ["schema", "process_id", "challenge", "proof"]),
              Self.integer(fields["schema"]) == 1, Self.integer(fields["process_id"]) == Int(pid),
              fields["challenge"] as? String == challenge, let proof = fields["proof"] as? String,
              Self.hexadecimal(proof, count: 64),
              let expected = try? mac("routervpn-controller-identity-response\n\(pid)\n\(challenge)") else { return false }
        return Self.equalProof(proof, expected)
    }
    func acceptsSupervisor(_ data: Data, phase: String, pid: Int32? = nil) -> (pid: Int32, exitCode: Int)? {
        guard ["started", "joined"].contains(phase),
              let fields = Self.exactObject(data, keys: ["schema", "phase", "process_id", "exit_code", "proof"]),
              Self.integer(fields["schema"]) == 1, fields["phase"] as? String == phase,
              let number = Self.integer(fields["process_id"]), number > 0, number <= Int(Int32.max),
              pid == nil || Int(pid!) == number, let code = Self.integer(fields["exit_code"]), (-1...255).contains(code),
              phase != "started" || code == 0, let proof = fields["proof"] as? String,
              Self.hexadecimal(proof, count: 64),
              let expected = try? mac("routervpn-controller-supervisor\n\(phase)\n\(number)\n\(ownerToken)\n\(code)"),
              Self.equalProof(proof, expected) else { return nil }
        return (Int32(number), code)
    }
    private static func equalProof(_ left: String, _ right: String) -> Bool {
        let a = Array(left.utf8), b = Array(right.utf8)
        guard a.count == 64, b.count == 64 else { return false }
        return zip(a, b).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
    }
    private static func integer(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              let integer = Int(number.stringValue), number.stringValue == String(integer) else { return nil }
        return integer
    }
    private static func exactObject(_ data: Data, keys: Set<String>) -> [String: Any]? {
        guard !data.isEmpty, data.count <= 4096, let text = String(data: data, encoding: .utf8), !text.contains("\\"),
              let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any], Set(value.keys) == keys else { return nil }
        for name in keys where text.components(separatedBy: "\"" + name + "\"").count != 2 { return nil }
        return value
    }
}

// One installed app owns one controller capability for its entire lifetime.
// Retiring it never makes a different localhost listener or a replacement PID
// eligible. The ordinary developer/package-folder path has no such capability.
final class RouterVPNMacLocalAuthorization: @unchecked Sendable {
    static let shared = RouterVPNMacLocalAuthorization(required: installedBundle())
    private let lock = NSLock()
    private let required: Bool
    private var credentials: RouterVPNMacControllerCredentials?
    private var processID: Int32 = 0
    private var live: (() -> Bool)?
    private var proved = false
    private var retired = false

    init(required: Bool) { self.required = required }
    static func installedBundle(_ bundle: URL = Bundle.main.bundleURL) -> Bool {
        bundle.resolvingSymlinksInPath().deletingLastPathComponent().path == "/opt/router-vpn-client"
    }
    static func failure(_ message: String) -> NSError {
        NSError(domain: "RouterVPN.ControllerOwner", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
    func capture(_ value: RouterVPNMacControllerCredentials, processID pid: Int32, live: @escaping () -> Bool) throws {
        lock.lock(); defer { lock.unlock() }
        guard value.valid, pid > 0, credentials == nil, !retired else { throw Self.failure("The app already captured a different controller owner.") }
        credentials = value; processID = pid; self.live = live
    }
    func retire(processID pid: Int32, owner: String) {
        lock.lock(); defer { lock.unlock() }
        if processID == pid, credentials?.ownerToken == owner { retired = true; proved = false }
    }
    func authorize(_ request: inout URLRequest) throws {
        lock.lock(); defer { lock.unlock() }
        guard let credentials else {
            if required { throw Self.failure("Open the installed app through its authenticated controller supervisor.") }
            return
        }
        guard proved, !retired, live?() == true, let url = request.url,
              url.scheme == "http", url.host == "127.0.0.1", url.port == 8788,
              url.user == nil, url.password == nil, url.fragment == nil,
              request.value(forHTTPHeaderField: "Authorization") == nil else {
            throw Self.failure("This request no longer owns the authenticated local controller.")
        }
        request.setValue("Bearer " + credentials.accessToken, forHTTPHeaderField: "Authorization")
    }
    func verifyIdentity() throws {
        lock.lock()
        guard let captured = credentials, !retired, live?() == true else {
            lock.unlock(); throw Self.failure("The captured controller is no longer available.")
        }
        let pid = processID
        lock.unlock()
        let challenge = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        let url = URL(string: "http://127.0.0.1:8788/api/controller/identity")!
        var request = URLRequest(url: url)
        request.httpMethod = "GET"; request.timeoutInterval = 1
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        request.setValue(challenge, forHTTPHeaderField: "X-RouterVPN-Challenge")
        request.setValue("RouterVPN-Identity " + (try captured.mac("routervpn-controller-identity-request\n" + challenge)), forHTTPHeaderField: "Authorization")
        let response = try RouterVPNMacIdentityRequest.run(request)
        guard captured.acceptsIdentity(response, pid: pid, challenge: challenge) else {
            throw Self.failure("The localhost response did not prove this app's captured controller.")
        }
        lock.lock(); defer { lock.unlock() }
        guard !retired, credentials == captured, processID == pid, live?() == true else {
            throw Self.failure("The controller owner changed during authentication.")
        }
        proved = true
    }
}

// This unauthenticated discovery phase sends only a fresh HMAC challenge.
// It has no bearer secret, no redirects, no proxy and a bounded response.
private final class RouterVPNMacIdentityRequest: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private let done = DispatchSemaphore(value: 0)
    private var data = Data()
    private var failure: Error?
    private var finished = false
    private var validResponse = false
    private var session: URLSession?
    private var task: URLSessionDataTask?

    static func run(_ request: URLRequest) throws -> Data {
        let owner = RouterVPNMacIdentityRequest()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.connectionProxyDictionary = [:]; configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false; configuration.urlCache = nil
        configuration.timeoutIntervalForRequest = 1; configuration.timeoutIntervalForResource = 1
        let session = URLSession(configuration: configuration, delegate: owner, delegateQueue: nil)
        owner.session = session; owner.task = session.dataTask(with: request)
        owner.task?.resume()
        if owner.done.wait(timeout: .now() + 1.5) == .timedOut {
            owner.finish(RouterVPNMacLocalAuthorization.failure("The captured controller identity check timed out."))
        }
        owner.lock.lock(); let data = owner.data, failure = owner.failure; owner.lock.unlock()
        session.invalidateAndCancel()
        if let failure { throw failure }
        return data
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        lock.lock()
        let valid = !finished && !validResponse && (response as? HTTPURLResponse)?.statusCode == 200 &&
            response.url == dataTask.originalRequest?.url && response.expectedContentLength <= 4096
        validResponse = valid
        lock.unlock()
        completionHandler(valid ? .allow : .cancel)
        if !valid { finish(RouterVPNMacLocalAuthorization.failure("The local controller identity response was rejected.")) }
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive bytes: Data) {
        lock.lock()
        let oversized = bytes.count > 4096 - data.count
        if !finished && !oversized { data.append(bytes) }
        lock.unlock()
        if oversized { finish(RouterVPNMacLocalAuthorization.failure("The local controller identity response was oversized.")) }
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) { finish(error) }
    private func finish(_ error: Error?) {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        finished = true
        failure = error ?? (validResponse ? nil : RouterVPNMacLocalAuthorization.failure("The local controller identity was not proved."))
        let task = task
        lock.unlock()
        task?.cancel(); done.signal()
    }
}
