import Foundation
import Libbox

enum RouterVPNLibboxCompileProbe {
    static let expectedVersion = "1.13.12"

    static func verifyPinnedRuntime() throws {
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
