#!/usr/bin/env python3
"""Exercise both native named CUSTOM callbacks and their production layer/strategy dispatch around asynchronous ownership changes."""
from pathlib import Path
import subprocess
import tempfile
from test_ios_startup_policy import member

APP = Path(__file__).resolve().parents[1] / "ios/RouterVPN/App"

SWIFT = r'''
import Foundation

enum Prefs {
    static let domain = "router-ios-custom-" + UUID().uuidString
    static var store: UserDefaults { UserDefaults(suiteName: domain)! }
}
struct RouterProfile: Codable {
    var id: String
    var normalizedNodeKind = "router-vpn", baseTunnel: String? = "wg", customLayers: [String]? = ["old"]
}
struct VPNMode { let id: String; let trafficMinPct = 1.0, pingMinMs = 1.0 }
struct ClientBundle: Codable {
    var selectedRouterID: String, routerProfiles: [RouterProfile]
    var transportAsset = "paired-asset"
}
struct IOSRuntimeSelection { let raw: String }
enum IOSRuntimeSelector {
    static func selectRaw(bundle: ClientBundle, rawProfileID: String) throws -> IOSRuntimeSelection {
        IOSRuntimeSelection(raw: rawProfileID)
    }
}
enum IOSStrategyPlan { enum Kind { case custom } }
@MainActor final class Admission {
    var change: (() -> Void)?, second: (() -> Void)?
    func admitConnection() async -> Bool {
        let callback = change; change = second; second = nil; callback?(); return true
    }
}
@MainActor enum IOSMTUControl {
    static var beforeOperation: (() -> Void)?
    static func withHold<T>(model: RouterVPNModel, operation: @MainActor () async throws -> T) async throws -> T {
        let callback = beforeOperation; beforeOperation = nil; callback?()
        return try await operation()
    }
}
@MainActor final class RouterVPNModel {
    var bundle: ClientBundle? = ClientBundle(selectedRouterID: "A", routerProfiles: [.init(id: "A")])
    var iosConnectGeneration = UUID()
    var saves = [String](), attempts = [String](), auto = false, profileMutationBlocked = false
    var message = "", activeRawProfile = ""
    let iosSpeedLabOwnership = Admission()
    var modes = [VPNMode(id: "wg")]
    var iosStrategyProfile: RouterProfile? { bundle?.routerProfiles.first }
    var unifiedSelectedProfile: RouterProfile? { iosStrategyProfile }
    func iosSavedCustomLayers() -> Set<String> { Set(iosStrategyProfile?.customLayers ?? []) }
    func importBundle(_ data: Data) throws {
        bundle = try JSONDecoder().decode(ClientBundle.self, from: data)
        saves.append(bundle!.selectedRouterID)
    }
    func recordIOSLastRuntime() {}
    // STRATEGY_BOUNDARY
    // MODEL
}
@MainActor private final class Home {
    let model: RouterVPNModel
    var selectedMode: String { Prefs.store.string(forKey: iosUnifiedModeKey) ?? "" }
    var showingModes = false
    init(_ model: RouterVPNModel) { self.model = model }
    func click() {
        // HOME_CUSTOM
    }
}
@MainActor private final class Builder {
    let model: RouterVPNModel
    var selected = Set(["wireguard"]), name = "Grüße", saveError = ""
    var original: IOSUnifiedCustomPreset?
    init(_ model: RouterVPNModel) { self.model = model }
    func dismiss() {}
    // BUILDER
    func click() { save(connect: true) }
}
@main struct Tests {
    @MainActor static func main() async throws {
        func check(_ ok: Bool, _ why: String) {
            if !ok { print("Rejected: " + why); exit(1) }
        }
        defer { Prefs.store.removePersistentDomain(forName: Prefs.domain) }
        for builder in [false, true] {
            for fault in ["none", "before-task", "admission", "hold", "generation", "same-id-relink", "preset-change", "mode-change", "at-provider"] {
                let model = RouterVPNModel()
                Prefs.store.removeObject(forKey: iosUnifiedPresetsKey)
                let preset = IOSUnifiedCustomPreset(name: "Grüße", layers: ["wireguard"])
                if !builder { try IOSUnifiedPresetStore.save(preset, replacing: nil) }
                Prefs.store.set("custom:Grüße", forKey: iosUnifiedModeKey)
                let replace = { model.bundle = ClientBundle(selectedRouterID: "B", routerProfiles: [.init(id: "B")]) }
                if fault == "at-provider" { model.iosSpeedLabOwnership.second = replace }
                if fault == "admission" { model.iosSpeedLabOwnership.change = replace }
                if fault == "hold" { IOSMTUControl.beforeOperation = replace }
                if fault == "generation" { IOSMTUControl.beforeOperation = { model.iosConnectGeneration = UUID() } }
                if fault == "same-id-relink" { IOSMTUControl.beforeOperation = { model.bundle?.transportAsset = "new-pair" } }
                if fault == "preset-change" { IOSMTUControl.beforeOperation = { try! IOSUnifiedPresetStore.save(.init(name: preset.name, layers: ["other"]), replacing: preset) } }
                if fault == "mode-change" { IOSMTUControl.beforeOperation = { Prefs.store.set("custom:Else", forKey: iosUnifiedModeKey) } }
                if builder { Builder(model).click() } else { Home(model).click() }
                if fault == "before-task" { replace() }
                for _ in 0..<250 where model.attempts.isEmpty && model.message.isEmpty { await Task.yield() }
                let entry = builder ? "builder" : "home"
                if fault == "none" {
                    check(model.saves == ["A"] && model.attempts == ["A"] && model.bundle?.routerProfiles.first?.customLayers == ["wireguard"], entry + " did not apply the captured preset once")
                } else {
                    check(model.saves == (fault == "at-provider" ? ["A"] : []) && model.attempts.isEmpty && model.bundle?.routerProfiles.first?.customLayers == ["old"], entry + " mutated a stale named CUSTOM selection at " + fault)
                    check(!model.message.isEmpty, entry + " never completed a stale selection at " + fault)
                }
            }
        }
        print("Both iOS named CUSTOM actions kept their captured node, private source, generation and exact saved preset across asynchronous admission and MTU preparation")
    }
}
'''


def source():
    ui = (APP / 'IOSUnifiedProductView.swift').read_text()
    policy = (APP / 'IOSStrategySupport.swift').read_text()
    owned = (APP / 'IOSOwnedStrategy.swift').read_text()
    model = '\n'.join(member(policy, head) for head in ('func runIOSCustom(', 'private func runIOSCustomHeld('))
    model += '\n' + member(ui, 'fileprivate func connectNamedCustom(') + '\n' + member(owned,'func iosStrategySource(')
    ownedEntry = member(owned, 'func runIOSOwnedStrategy(').split('guard !iosStrategyTaskActive',1)[0]
    boundary = ownedEntry + '''
        attempts.append(bundle!.selectedRouterID); activeRawProfile = selections.first!.raw; return true
    }'''
    support = '\n'.join(member(ui, head) for head in ('private struct IOSUnifiedCustomPreset:', 'private enum IOSUnifiedModeSelection', 'private enum IOSUnifiedPresetStore'))
    support += '\n@MainActor ' + member(policy,'struct IOSNamedCustomSelection')
    support += '\n' + member((APP/'Models.swift').read_text(), 'enum IOSCustomPresetName')
    support += '\n' + member(policy, 'enum IOSStrategyCatalog').split('    static func autoRequirementFailure', 1)[0] + '}\n'
    keys = '\n'.join(line for line in ui.splitlines() if line.startswith(('private let iosUnifiedModeKey ', 'private let iosUnifiedPresetsKey ')))
    home = member(member(ui, 'private func connectOrDisconnect()'), 'if let name = IOSCustomPresetName.suffix')
    code = keys + '\n' + support + '\n' + SWIFT
    code = code.replace('// HOME_CUSTOM', home).replace('// BUILDER', member(ui,'private func save(connect:'))
    code = code.replace('// MODEL', model).replace('// STRATEGY_BOUNDARY', boundary)
    return code.replace('UserDefaults.standard', 'Prefs.store')


def main():
    with tempfile.TemporaryDirectory(prefix='ios-named-custom-') as temp:
        file = Path(temp)/'Test.swift'
        binary = file.with_suffix('')
        shipping = source()
        compile_command = ['swiftc', '-swift-version', '6', '-parse-as-library', str(file), '-o', str(binary)]
        file.write_text(shipping)
        subprocess.run(compile_command, check=True, timeout=90)
        subprocess.run([binary], check=True, timeout=20)
        for original, unsafe, expected in (
            ('Task { await runIOSCustom(layers: preset.layers, original: original) }',
             'Task { await runIOSCustom(layers: preset.layers) }', 'before-task'),
            ('guard originalCustom?.admits(self) != false else { return false }',
             '', 'at-provider'),
        ):
            assert shipping.count(original) == 1, original
            file.write_text(shipping.replace(original, unsafe))
            subprocess.run(compile_command, check=True, timeout=90)
            result = subprocess.run([binary], capture_output=True, text=True, timeout=20)
            assert result.returncode == 1 and ('Rejected: home mutated a stale named CUSTOM selection at ' + expected) in result.stdout, result
            print('Rejected stale CUSTOM dispatch at ' + expected)

if __name__=='__main__':
    main()
