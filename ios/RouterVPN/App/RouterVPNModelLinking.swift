import Foundation

extension RouterVPNModel {
    func linkFromLAN(host rawHost: String, code rawCode: String) async {
        let raw = rawHost.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !raw.isEmpty else { message = "Enter the AI Board LAN IP or hostname"; return }
        let code = rawCode.trimmingCharacters(in: .whitespacesAndNewlines)
        guard code.count == 6, code.allSatisfy(\.isNumber) else {
            message = "Enter the 6-digit one-time pairing code shown by the authenticated Setup Center"
            return
        }
        let host = raw.replacingOccurrences(of: "http://", with: "")
            .replacingOccurrences(of: "https://", with: "")
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard !host.isEmpty, !host.contains("/"), !host.contains("?"), !host.contains("#"), !host.contains("@"),
              let url = URL(string: "http://\(host):8786/api/pairing/redeem") else {
            message = "Invalid LAN pairing host"
            return
        }
        do {
            var req = URLRequest(url: url)
            req.httpMethod = "POST"
            req.timeoutInterval = 12
            req.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.setValue("application/json", forHTTPHeaderField: "Accept")
            req.httpBody = try JSONSerialization.data(withJSONObject: ["code": code])
            let (data, response) = try await URLSession.shared.data(for: req)
            guard let http = response as? HTTPURLResponse else { throw URLError(.badServerResponse) }
            guard http.statusCode == 200 else {
                if http.statusCode == 401 || http.statusCode == 403 {
                    throw NSError(domain: "RouterVPN.Pairing", code: http.statusCode, userInfo: [NSLocalizedDescriptionKey: "Pairing code is invalid, expired, already used, or this request is not from the home LAN"])
                }
                throw NSError(domain: "RouterVPN.Pairing", code: http.statusCode, userInfo: [NSLocalizedDescriptionKey: "Setup Center returned HTTP \(http.statusCode)"])
            }
            guard data.count <= 32 * 1024 * 1024 else { throw URLError(.dataLengthExceedsMaximum) }
            try linkNodeBundle(data)
            UserDefaults.standard.set(raw, forKey: "router-vpn.lan-import-host")
            message = "Paired and linked \(host) • \(allNodeProfiles.count) node(s) now available without reinstalling"
        } catch {
            message = "LAN pairing failed: \(error.localizedDescription)"
        }
    }
}
