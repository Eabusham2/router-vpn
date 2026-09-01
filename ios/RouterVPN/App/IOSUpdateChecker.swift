import Foundation

@MainActor
final class IOSUpdateChecker: ObservableObject {
    @Published var availableSHA: String?
    @Published var releaseURL: URL?
    @Published var message = ""

    private let repository = "Eabusham2/router-vpn"
    private let prefix = "router-vpn-sha-"

    func checkAutomatically() async {
        guard let current = Bundle.main.object(forInfoDictionaryKey: "RouterVPNSourceSHA") as? String,
              Self.validSHA(current) else { return }
        do {
            let config = URLSessionConfiguration.ephemeral
            config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
            config.connectionProxyDictionary = [:]
            config.timeoutIntervalForRequest = 8
            config.timeoutIntervalForResource = 12
            let session = URLSession(configuration: config)
            guard let url = URL(string: "https://api.github.com/repos/\(repository)/releases?per_page=50") else { return }
            var request = URLRequest(url: url)
            request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
            request.setValue("router-vpn-ios-update/1", forHTTPHeaderField: "User-Agent")
            request.setValue("2022-11-28", forHTTPHeaderField: "X-GitHub-Api-Version")
            let (data, response) = try await session.data(for: request)
            guard data.count <= 1024 * 1024,
                  let http = response as? HTTPURLResponse,
                  (200..<300).contains(http.statusCode),
                  let releases = try JSONSerialization.jsonObject(with: data) as? [[String: Any]] else { return }
            for release in releases {
                guard release["draft"] as? Bool != true,
                      release["prerelease"] as? Bool != true,
                      let tag = (release["tag_name"] as? String)?.lowercased(),
                      tag.hasPrefix(prefix) else { continue }
                let target = String(tag.dropFirst(prefix.count))
                guard Self.validSHA(target),
                      (release["target_commitish"] as? String)?.lowercased() == target else { continue }
                if target == current.lowercased() { return }
                availableSHA = target
                releaseURL = URL(string: "https://github.com/\(repository)/releases/tag/\(tag)")
                message = "A newer verified Router VPN release is available. iOS keeps installation under Apple/TestFlight/sideload signing control; Router VPN never silently replaces its own app bundle."
                return
            }
        } catch {
            // Update discovery must never interfere with VPN startup.
        }
    }

    static func validSHA(_ value: String) -> Bool {
        value.range(of: "^[0-9a-fA-F]{40}$", options: .regularExpression) != nil
    }
}
