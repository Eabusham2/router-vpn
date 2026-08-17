import Foundation

enum IOSRuntimeEngine: String, Codable, Hashable {
    case wireGuard = "wireguard"
    case libbox = "libbox"
}

struct IOSRuntimeSelection: Hashable {
    let engine: IOSRuntimeEngine
    let logicalModeID: String
    let rawProfileID: String
    let files: [String: Data]

    var configText: String? {
        guard let data = files["sing-box.json"] else { return nil }
        return String(data: data, encoding: .utf8)
    }
}

enum IOSRuntimeSelectionError: LocalizedError {
    case missingLogicalMode
    case unsupportedMode(String)
    case invalidProfileName(String)
    case invalidAssetName(String)
    case invalidAssetEncoding(String)
    case assetTooLarge(String)
    case profileTooLarge
    case invalidSingBoxConfig

    var errorDescription: String? {
        switch self {
        case .missingLogicalMode: return "The selected logical mode is not present in this node bundle."
        case .unsupportedMode(let reason): return reason
        case .invalidProfileName(let name): return "Unsafe raw profile id: \(name)"
        case .invalidAssetName(let name): return "Unsafe libbox asset name: \(name)"
        case .invalidAssetEncoding(let name): return "The libbox asset \(name) is not valid base64."
        case .assetTooLarge(let name): return "The libbox asset \(name) exceeds the iOS safety limit."
        case .profileTooLarge: return "The selected iOS libbox profile exceeds the total safety limit."
        case .invalidSingBoxConfig: return "The selected profile does not contain a valid sing-box JSON object."
        }
    }
}

enum IOSRuntimeSelector {
    static let maxAssetBytes = 4 * 1024 * 1024
    static let maxProfileBytes = 12 * 1024 * 1024
    static let rawProfilePattern = try! NSRegularExpression(pattern: "^[A-Za-z0-9._-]{1,96}$")
    static let assetPattern = try! NSRegularExpression(pattern: "^[A-Za-z0-9._-]{1,128}$")

    static func runnableModes(in bundle: ClientBundle) -> [LogicalMode] {
        bundle.logicalModes.filter { mode in
            (try? select(bundle: bundle, logicalModeID: mode.id)) != nil
        }
    }

    static func select(bundle: ClientBundle, logicalModeID: String) throws -> IOSRuntimeSelection {
        guard let logical = bundle.logicalModes.first(where: { $0.id == logicalModeID }) else {
            throw IOSRuntimeSelectionError.missingLogicalMode
        }

        // Preserve the known-good WireGuardKit path for raw WireGuard.
        if logical.id == "base-raw", logical.variants["wg"] == "wg" {
            return IOSRuntimeSelection(engine: .wireGuard, logicalModeID: logical.id, rawProfileID: "wg", files: [:])
        }

        // For layered iOS support, only advertise an imported raw variant that
        // actually ships a complete sing-box profile. This prevents UI parity
        // from turning into fake runtime parity for Xray/AWG-only modes.
        for rawID in orderedVariantIDs(logical) {
            if let selection = try? selectRaw(bundle: bundle, rawProfileID: rawID, logicalModeID: logical.id) {
                return selection
            }
        }

        throw IOSRuntimeSelectionError.unsupportedMode(
            "This iOS build cannot run \(logical.name) from the imported node: no validated WireGuardKit/sing-box variant is present. Xray-only, AmneziaWG-only, ALL/MAX and multihop combinations remain unavailable instead of faking Connected. Full desktop-equivalent Router VPN multihop and OpenVPN remain outside the iOS dataplane until a pinned native implementation exists."
        )
    }

    static func selectRaw(bundle: ClientBundle, rawProfileID: String) throws -> IOSRuntimeSelection {
        try selectRaw(bundle: bundle, rawProfileID: rawProfileID, logicalModeID: logicalModeID(for: rawProfileID, in: bundle))
    }

    static func logicalModeID(for rawProfileID: String, in bundle: ClientBundle) -> String {
        bundle.logicalModes.first(where: { $0.variants.values.contains(rawProfileID) })?.id ?? rawProfileID
    }

    private static func selectRaw(bundle: ClientBundle, rawProfileID: String, logicalModeID: String) throws -> IOSRuntimeSelection {
        guard isSafe(rawProfileID, pattern: rawProfilePattern) else {
            throw IOSRuntimeSelectionError.invalidProfileName(rawProfileID)
        }
        if rawProfileID == "wg" {
            return IOSRuntimeSelection(engine: .wireGuard, logicalModeID: logicalModeID, rawProfileID: rawProfileID, files: [:])
        }
        guard let encoded = bundle.profiles[rawProfileID], encoded["sing-box.json"] != nil else {
            throw IOSRuntimeSelectionError.unsupportedMode("Raw runtime \(rawProfileID) has no iOS-runnable sing-box profile.")
        }
        let files = try decodeProfile(encoded)
        guard let config = files["sing-box.json"],
              let object = try? JSONSerialization.jsonObject(with: config),
              object is [String: Any]
        else { throw IOSRuntimeSelectionError.invalidSingBoxConfig }
        return IOSRuntimeSelection(engine: .libbox, logicalModeID: logicalModeID, rawProfileID: rawProfileID, files: files)
    }

    private static func orderedVariantIDs(_ logical: LogicalMode) -> [String] {
        var result: [String] = []
        for key in ["wg", "default", "auto", "awg2"] {
            if let value = logical.variants[key], !value.isEmpty, !result.contains(value) { result.append(value) }
        }
        for key in logical.variants.keys.sorted() {
            if let value = logical.variants[key], !value.isEmpty, !result.contains(value) { result.append(value) }
        }
        return result
    }

    private static func decodeProfile(_ encoded: [String: String]) throws -> [String: Data] {
        var result: [String: Data] = [:]
        var total = 0
        for (name, value) in encoded {
            guard isSafe(name, pattern: assetPattern), name != ".", name != ".." else {
                throw IOSRuntimeSelectionError.invalidAssetName(name)
            }
            guard let data = Data(base64Encoded: value, options: []) else {
                throw IOSRuntimeSelectionError.invalidAssetEncoding(name)
            }
            guard data.count <= maxAssetBytes else { throw IOSRuntimeSelectionError.assetTooLarge(name) }
            total += data.count
            guard total <= maxProfileBytes else { throw IOSRuntimeSelectionError.profileTooLarge }
            result[name] = data
        }
        return result
    }

    private static func isSafe(_ value: String, pattern: NSRegularExpression) -> Bool {
        let range = NSRange(value.startIndex..<value.endIndex, in: value)
        return pattern.firstMatch(in: value, range: range)?.range == range && !value.contains("..")
    }
}
