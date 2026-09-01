import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

private final class RouterVPNUpdateRedirectDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        guard let url = request.url, IOSUpdateChecker.trustedReleaseURL(url) else {
            completionHandler(nil)
            return
        }
        completionHandler(request)
    }
}

@MainActor
final class IOSUpdateChecker: ObservableObject {
    @Published var availableSHA: String?
    @Published var releaseURL: URL?
    @Published var message = ""

    private let repository = "Eabusham2/router-vpn"
    private let prefix = "router-vpn-sha-"
    private let manifestName = "RouterVPN-RELEASE.json"
    private let ipaName = "RouterVPN-native-unsigned-resignable.ipa"
    private let producer = "build-all.yml"
    private let maxMetadata = 1024 * 1024
    private let maxIPABytes: Int64 = 768 * 1024 * 1024

    func checkAutomatically() async {
        guard let current = Bundle.main.object(forInfoDictionaryKey: "RouterVPNSourceSHA") as? String,
              Self.validSHA(current) else { return }
        do {
            let session = makeSession()
            let release = try await newestExactRelease(session: session)
            guard let tag = (release["tag_name"] as? String)?.lowercased(),
                  tag.hasPrefix(prefix) else { return }
            let target = String(tag.dropFirst(prefix.count))
            guard Self.validSHA(target),
                  target != current.lowercased(),
                  (release["target_commitish"] as? String)?.lowercased() == target,
                  try await strictUpgrade(current: current.lowercased(), target: target, session: session),
                  let manifestAsset = uniqueReleaseAsset(release, name: manifestName, maximum: Int64(maxMetadata)),
                  let ipaAsset = uniqueReleaseAsset(release, name: ipaName, maximum: maxIPABytes),
                  let manifestURL = manifestAsset["browser_download_url"] as? String,
                  let manifestURLValue = URL(string: manifestURL),
                  Self.trustedReleaseURL(manifestURLValue) else { return }

            let manifestData = try await fetchReleaseAsset(manifestURLValue, maximum: maxMetadata, session: session)
            guard let manifest = try Self.exactObject(manifestData),
                  Set(manifest.keys) == Set(["schema_version", "repository", "source_sha", "tag", "producer_workflow", "assets"]),
                  (manifest["schema_version"] as? NSNumber)?.intValue == 1,
                  manifest["repository"] as? String == repository,
                  (manifest["source_sha"] as? String)?.lowercased() == target,
                  (manifest["tag"] as? String)?.lowercased() == prefix + target,
                  manifest["producer_workflow"] as? String == producer,
                  let published = manifest["assets"] as? [[String: Any]] else { return }

            let ipaRows = published.filter { $0["name"] as? String == ipaName }
            guard ipaRows.count == 1,
                  let signedSize = (ipaRows[0]["size"] as? NSNumber)?.int64Value,
                  signedSize > 0, signedSize <= maxIPABytes,
                  let signedDigest = (ipaRows[0]["sha256"] as? String)?.lowercased(),
                  Self.validDigest(signedDigest),
                  let apiSize = (ipaAsset["size"] as? NSNumber)?.int64Value,
                  apiSize == signedSize else { return }

            availableSHA = target
            releaseURL = URL(string: "https://github.com/\(repository)/releases/tag/\(tag)")
            message = "A newer exact-SHA Router VPN release has verified published IPA size and SHA-256 metadata (\(signedDigest.prefix(12))…). Apple/TestFlight/sideload signing remains the installation authority; Router VPN never silently replaces its own app bundle."
        } catch {
            // Update discovery must never interfere with VPN startup.
        }
    }

    private func makeSession() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        config.connectionProxyDictionary = [:]
        config.timeoutIntervalForRequest = 8
        config.timeoutIntervalForResource = 15
        return URLSession(configuration: config, delegate: RouterVPNUpdateRedirectDelegate(), delegateQueue: nil)
    }

    private func newestExactRelease(session: URLSession) async throws -> [String: Any] {
        guard let url = URL(string: "https://api.github.com/repos/\(repository)/releases?per_page=50") else {
            throw URLError(.badURL)
        }
        let data = try await fetchAPI(url, session: session)
        guard let releases = try JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
            throw URLError(.cannotParseResponse)
        }
        for release in releases {
            // Build-all emits exact-SHA Apple artifacts as prereleases only after
            // the authoritative native matrix passes. Drafts remain forbidden.
            guard release["draft"] as? Bool != true,
                  let tag = (release["tag_name"] as? String)?.lowercased(),
                  tag.hasPrefix(prefix) else { continue }
            let target = String(tag.dropFirst(prefix.count))
            if Self.validSHA(target),
               (release["target_commitish"] as? String)?.lowercased() == target {
                return release
            }
        }
        throw URLError(.resourceUnavailable)
    }

    private func strictUpgrade(current: String, target: String, session: URLSession) async throws -> Bool {
        guard let url = URL(string: "https://api.github.com/repos/\(repository)/compare/\(current)...\(target)") else {
            return false
        }
        let data = try await fetchAPI(url, session: session)
        guard let comparison = try Self.exactObject(data),
              comparison["status"] as? String == "ahead",
              (comparison["ahead_by"] as? NSNumber)?.intValue ?? 0 > 0,
              (comparison["behind_by"] as? NSNumber)?.intValue == 0,
              let base = comparison["base_commit"] as? [String: Any],
              let mergeBase = comparison["merge_base_commit"] as? [String: Any],
              (base["sha"] as? String)?.lowercased() == current,
              (mergeBase["sha"] as? String)?.lowercased() == current else { return false }
        return true
    }

    private func uniqueReleaseAsset(_ release: [String: Any], name: String, maximum: Int64) -> [String: Any]? {
        guard let assets = release["assets"] as? [[String: Any]] else { return nil }
        let matches = assets.filter { $0["name"] as? String == name }
        guard matches.count == 1,
              let size = (matches[0]["size"] as? NSNumber)?.int64Value,
              size > 0, size <= maximum,
              let rawURL = matches[0]["browser_download_url"] as? String,
              let url = URL(string: rawURL), Self.trustedReleaseURL(url) else { return nil }
        return matches[0]
    }

    private func fetchAPI(_ url: URL, session: URLSession) async throws -> Data {
        guard url.scheme?.lowercased() == "https", url.host?.lowercased() == "api.github.com", url.user == nil else {
            throw URLError(.badURL)
        }
        var request = URLRequest(url: url)
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("router-vpn-ios-update/2", forHTTPHeaderField: "User-Agent")
        request.setValue("2022-11-28", forHTTPHeaderField: "X-GitHub-Api-Version")
        let (data, response) = try await session.data(for: request)
        guard data.count > 0, data.count <= maxMetadata,
              let http = response as? HTTPURLResponse,
              (200..<300).contains(http.statusCode),
              http.url?.scheme?.lowercased() == "https",
              http.url?.host?.lowercased() == "api.github.com" else {
            throw URLError(.badServerResponse)
        }
        return data
    }

    private func fetchReleaseAsset(_ url: URL, maximum: Int, session: URLSession) async throws -> Data {
        guard Self.trustedReleaseURL(url) else { throw URLError(.badURL) }
        var request = URLRequest(url: url)
        request.setValue("application/octet-stream", forHTTPHeaderField: "Accept")
        request.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
        request.setValue("router-vpn-ios-update/2", forHTTPHeaderField: "User-Agent")
        let (data, response) = try await session.data(for: request)
        guard data.count > 0, data.count <= maximum,
              let http = response as? HTTPURLResponse,
              (200..<300).contains(http.statusCode),
              let finalURL = http.url, Self.trustedReleaseURL(finalURL) else {
            throw URLError(.badServerResponse)
        }
        return data
    }

    nonisolated static func trustedReleaseURL(_ url: URL) -> Bool {
        guard url.scheme?.lowercased() == "https", url.user == nil,
              let host = url.host?.lowercased() else { return false }
        return host == "github.com" || host == "release-assets.githubusercontent.com" || host.hasSuffix(".githubusercontent.com")
    }

    nonisolated static func exactObject(_ data: Data) throws -> [String: Any]? {
        try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]
    }

    nonisolated static func validSHA(_ value: String) -> Bool {
        value.range(of: "^[0-9a-fA-F]{40}$", options: .regularExpression) != nil
    }

    nonisolated static func validDigest(_ value: String) -> Bool {
        value.range(of: "^[0-9a-fA-F]{64}$", options: .regularExpression) != nil
    }
}
