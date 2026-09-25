import Foundation
import Libbox

enum RouterVPNLibboxCompileProbe {
    static let expectedVersion = "1.14.1"

    static func verifyPinnedRuntime() throws {
        guard LibboxRouterXrayRevision() == "50231eaff98ccc31b5cbd247a721c16e97fe5ec1" else {
            throw NSError(domain: "RouterVPN.Libbox", code: 2, userInfo: [NSLocalizedDescriptionKey: "Pinned native Xray revision mismatch."])
        }
        let actual = LibboxVersion().trimmingCharacters(in: .whitespacesAndNewlines)
        guard actual == expectedVersion else {
            throw NSError(
                domain: "RouterVPN.Libbox",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Pinned Libbox runtime mismatch: \(actual)"]
            )
        }
    }
}
