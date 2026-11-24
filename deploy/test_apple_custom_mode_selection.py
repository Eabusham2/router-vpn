#!/usr/bin/env python3
"""Run the shipping iOS actions and transformed macOS handlers with isolated defaults and UI doubles."""
from pathlib import Path
import runpy
import subprocess
import tempfile
from test_ios_startup_policy import member

ROOT = Path(__file__).resolve().parents[1]
IOS = ROOT / 'ios/RouterVPN/App/IOSUnifiedProductView.swift'
MAC = ROOT / 'client/macos/RouterVPNMacUnifiedShell.swift'

BOUNDARIES = r'''
import Foundation

@MainActor enum Preference {
    static let domain = "routervpn-callback-test-" + UUID().uuidString
    static let store = UserDefaults(suiteName: domain)!
}
struct Failure: Error, CustomStringConvertible { let description: String }
func check(_ condition: Bool, _ witness: String) throws {
    if !condition { throw Failure(description: witness) }
}
@MainActor final class Item {
    var representedObject: Any?, isEnabled = true, toolTip: String?
    static func separator() -> Item { Item() }
}
@MainActor final class Menu { func addItem(_ item: Item) {} }
@MainActor final class NSPopUpButton {
    var itemArray = [Item](), selectedItem: Item?
    let menu: Menu? = Menu()
    var indexOfSelectedItem = 0
    var lastItem: Item? { itemArray.last }
    var id: String? { selectedItem?.representedObject as? String }
    func select(_ item: Item?) { selectedItem = item }
    func removeAllItems() { itemArray = []; selectedItem = nil }
    func addItem(withTitle: String) { itemArray.append(Item()) }
    func pick(_ id: String) { select(itemArray.first { $0.representedObject as? String == id }) }
}
@MainActor final class Field { var stringValue = "" }
@MainActor final class TestQueue {
    enum QoS { case utility }
    static let main = TestQueue(), background = TestQueue()
    static func global(qos: QoS) -> TestQueue { background }
    var pending: [() -> Void] = []
    func async(_ body: @escaping () -> Void) { pending.append(body) }
    func drain() { while !pending.isEmpty { pending.removeFirst()() } }
    static func complete() { background.drain(); main.drain() }
}
@MainActor final class NSAlert {
    enum Style { case warning }
    enum Answer { case alertFirstButtonReturn, cancel }
    static var answer = Answer.alertFirstButtonReturn, onConfirm: (() -> Void)?
    var alertStyle = Style.warning, messageText = ""
    func addButton(withTitle: String) {}
    func runModal() -> Answer { Self.onConfirm?(); return Self.answer }
}
@MainActor final class API {
    var modes: [[String: Any]] = [["id":"wg","available":true]]
    var dispatched = ""
    func json(_ path: String, timeout: Int) throws -> Any { modes }
    func request(_ path: String, method: String, body: [String:Any], timeout: Int) throws -> Data {
        dispatched = path + ":" + ((body["layers"] as? [String])?.joined(separator:",") ?? "")
        return Data()
    }
}
'''

def line(source, prefix):
    return next(value for value in source.splitlines() if value.startswith(prefix))


def code():
    ios = IOS.read_text()
    transform = runpy.run_path(str(MAC.with_name('macos-session-mutation-transform.py')))
    mac = transform['transform'](MAC.read_text(), 'unified')
    assert 'startUnifiedPopupMode(popup)' in member(mac,'private func startUnifiedSelectedMode()')
    assert 'restoreDeletedCustomSelection()' in member(ios,'.onAppear { restoreDeletedCustomSelection')
    assert 'restoreDeletedCustomSelection()' in member(ios,'.onChange(of: model.profileMutationBlocked)')
    # Decode the actual button closures. Swapping either callback has to change the verdict.
    swipe = member(ios, '.swipeActions { Button(role: .destructive) ')
    context = member(ios, 'Button("Delete", role: .destructive) ')
    swipe = member(swipe, 'Button(role: .destructive) ').split(') ', 1)[1]
    context = context.split(') ', 1)[1]
    result = BOUNDARIES + '\n'.join(line(ios, 'private let '+key+' =') for key in ('iosUnifiedModeKey','iosUnifiedPresetsKey'))+'\n'
    result += member(IOS.with_name('Models.swift').read_text(), 'enum IOSCustomPresetName') + '\n'
    result += '\n'.join(member(ios, marker) for marker in ('private struct IOSUnifiedCustomPreset:', 'private enum IOSUnifiedModeSelection', 'private enum IOSUnifiedPresetStore'))
    result += '''
@MainActor private final class IOSControls {
    final class Model { var profileMutationBlocked = false }
    let model = Model()
    var presets = IOSUnifiedPresetStore.load()
    var selectedMode: String {
        get { Preference.store.string(forKey: iosUnifiedModeKey) ?? IOSUnifiedModeSelection.smart }
        set { Preference.store.set(newValue, forKey: iosUnifiedModeKey) }
    }
'''
    result += member(ios,'private func deletePreset(') + '\n' + member(ios,'private func restoreDeletedCustomSelection()').replace('private func','func')
    result += '\nfunc swipe(_ preset: IOSUnifiedCustomPreset) ' + swipe + '\nfunc menuDelete(_ preset: IOSUnifiedCustomPreset) '+context+'\n}\n'
    result += '\n'.join(line(mac,'private let '+key+' =') for key in ('unifiedCreatePresetAction','unifiedSelectedModeKey','unifiedCustomPresetsKey'))+'\n'
    result += member(MAC.with_name('RouterVPNConnectionProfiles.swift').read_text(),'func macCustomPresetName(in mode:') + '\n'
    result += member(mac,'fileprivate struct MacCustomPreset:') + '''
@MainActor private final class ProductWindowController {
    let popup = NSPopUpButton(), api = API(), errorLabel = Field()
    var idle = true, builders = 0
    func ensureMutationIdle(_ reason: String) -> Bool { idle }
    func refreshUnifiedChrome() {}
    func findUnifiedView(_ id: String) -> AnyObject? { popup }
    func openUnifiedCustomBuilder() { builders += 1 }
    func asyncAction(_ f: () throws -> String) { _ = try! f() }
    func connectUnifiedCustomPreset(_ name: String, layers: [String]) {
        _ = try! api.request("/api/strategy/custom", method:"POST", body:["layers":layers],timeout:240)
    }
'''
    for marker in ('fileprivate static func loadUnifiedCustomPresets','fileprivate static func saveUnifiedCustomPresets',
                   '@objc func unifiedModeChanged','private func storedUnifiedModeID','private func restoreUnifiedModeSelection',
                   'func refreshUnifiedModeMenu','private func addUnifiedModeItem','private func startUnifiedPopupMode'):
        result += '\n' + member(mac,marker).replace('private func startUnifiedPopupMode','func startUnifiedPopupMode')
    result += '''
}
@MainActor private final class Builder {
    var productOwner: ProductWindowController?
    let presetPopup = NSPopUpButton(), nameField = Field(), status = Field()
    var presets = ProductWindowController.loadUnifiedCustomPresets()
    var chosen: [String] = ["one"]
    init(_ owner: ProductWindowController) { productOwner = owner }
    func selectedLayers() -> [String] { chosen }
    func preservedUnknownLayers() -> [String] { [] }
    func reloadPresets(select: String? = nil) { presets = ProductWindowController.loadUnifiedCustomPresets() }
    func close() {}
'''
    for marker in ('private func editingPreset()', '@objc private func deletePreset()', 'private func persist()', '@objc private func savePreset()', '@objc private func closeBuilder()'):
        result += '\n' + member(mac,marker).replace('@objc private func','func')
    result += '\n}\n'
    # The Foundation test suite is private to this execution, including mutation runs.
    return result.replace('UserDefaults.standard','Preference.store').replace('private enum IOSUnifiedPresetStore','@MainActor private enum IOSUnifiedPresetStore').replace('@objc ','').replace('DispatchQueue.','TestQueue.') + TESTS


TESTS = r'''
@main @MainActor struct Checks {
    static func main() {
        defer { Preference.store.removePersistentDomain(forName: Preference.domain) }
        do { try exercise(); print("Apple CUSTOM selection callbacks passed") }
        catch { print("Rejected: " + String(describing:error)); exit(1) }
    }
    private static func exercise() throws {
        let ios = IOSControls()
        let a = IOSUnifiedCustomPreset(name:"new",layers:["one"]), b = IOSUnifiedCustomPreset(name:"B",layers:["two"])
        for action in [ios.swipe, ios.menuDelete] {
            IOSUnifiedPresetStore.save(a); IOSUnifiedPresetStore.save(b); ios.selectedMode = "custom:new"
            ios.model.profileMutationBlocked = true; action(a)
            try check(IOSUnifiedPresetStore.load().count == 2 && ios.selectedMode == "custom:new", "iOS busy deletion")
            ios.model.profileMutationBlocked = false; action(b)
            try check(IOSUnifiedPresetStore.load() == [a] && ios.selectedMode == "custom:new", "iOS deleted a different selected mode")
            action(a)
            try check(ios.presets.isEmpty && ios.selectedMode == "smart-auto", "iOS active deletion left a stale mode")
        }
        ios.selectedMode = "custom:missing"; ios.model.profileMutationBlocked = true; ios.restoreDeletedCustomSelection()
        try check(ios.selectedMode == "custom:missing", "iOS busy legacy migration")
        ios.model.profileMutationBlocked = false; ios.restoreDeletedCustomSelection()
        try check(ios.selectedMode == "smart-auto", "iOS historical orphan")
        let owner = ProductWindowController(), popup = owner.popup
        let first = MacCustomPreset(name:"new",layers:["one"]), other = MacCustomPreset(name:"B",layers:["two"])
        ProductWindowController.saveUnifiedCustomPresets([first,other])
        func saved() -> String? { Preference.store.string(forKey:unifiedSelectedModeKey) }
        func choose(_ id: String) { popup.pick(id); owner.unifiedModeChanged(popup) }
        func update() { owner.refreshUnifiedModeMenu(); TestQueue.complete() }
        func connect() { owner.api.dispatched = ""; owner.startUnifiedPopupMode(popup) }
        update(); choose("auto")
        choose(unifiedCreatePresetAction); Builder(owner).closeBuilder()
        try check(owner.builders == 1 && popup.id == "auto" && saved() == "auto", "macOS builder Cancel changed the selected mode")
        popup.pick(unifiedCreatePresetAction); connect()
        try check(owner.builders == 1 && owner.api.dispatched == "/api/strategy/auto:" && saved() == "auto", "macOS Connect interpreted a builder action")
        owner.refreshUnifiedModeMenu(preferred:"auto"); choose("custom:new"); TestQueue.complete()
        try check(popup.id == "custom:new" && saved() == "custom:new", "macOS refresh lost a newer choice")
        connect(); try check(owner.api.dispatched == "/api/strategy/custom:one", "macOS reserved name shadowed saved preset")
        owner.idle = false; choose(unifiedCreatePresetAction)
        try check(owner.builders == 1 && popup.id == "custom:new", "macOS busy popup mutated")
        let builder = Builder(owner); builder.presetPopup.indexOfSelectedItem = 1; builder.deletePreset()
        try check(ProductWindowController.loadUnifiedCustomPresets().count == 2, "macOS busy deletion")
        owner.idle = true
        NSAlert.answer = .cancel; builder.deletePreset()
        try check(ProductWindowController.loadUnifiedCustomPresets().count == 2, "macOS cancelled deletion")
        NSAlert.answer = .alertFirstButtonReturn; NSAlert.onConfirm = { owner.idle = false }; builder.deletePreset()
        try check(ProductWindowController.loadUnifiedCustomPresets().count == 2, "macOS mutation started during confirmation")
        NSAlert.onConfirm = nil; owner.idle = true
        builder.presetPopup.indexOfSelectedItem = 2; builder.deletePreset(); TestQueue.complete()
        try check(ProductWindowController.loadUnifiedCustomPresets() == [first] && saved() == "custom:new" && popup.id == "custom:new", "macOS deleted a different selected mode")
        builder.presetPopup.indexOfSelectedItem = 1; builder.deletePreset(); TestQueue.complete()
        try check(ProductWindowController.loadUnifiedCustomPresets().isEmpty && saved() == "smart-auto" && popup.id == "smart-auto", "macOS active deletion left a stale mode")
        Preference.store.set("custom:new",forKey:unifiedSelectedModeKey); update(); connect()
        try check(popup.id == "smart-auto" && owner.api.dispatched == "/api/strategy/smart-auto:", "macOS legacy action survived without a named preset")
        builder.presetPopup.indexOfSelectedItem = 0; builder.nameField.stringValue = "Saved"; builder.savePreset()
        try check(saved() == "custom:Saved", "macOS save did not commit its selected mode")
        connect()
        try check(owner.api.dispatched == "/api/strategy/custom:one", "macOS saved mode failed to connect before menu refresh")
        TestQueue.complete()
        let mark = MacCustomPreset(name:"\u{0301}Leading", layers:["two"])
        ProductWindowController.saveUnifiedCustomPresets([mark]); update(); choose("custom:" + mark.name); connect()
        try check(owner.api.dispatched == "/api/strategy/custom:two", "macOS CUSTOM lost a leading Unicode scalar")
        update(); choose("wg"); owner.api.modes = []; update(); connect()
        try check(saved() == "wg" && owner.api.dispatched.isEmpty, "macOS catalog refresh changed durable mode or dispatched an unavailable mode")
    }
}
'''


def main():
    source = code()
    defects = (
        ('mode.utf8.starts(with: prefix)', 'mode.hasPrefix("custom:")', 'macOS CUSTOM lost a leading Unicode scalar'),
        ('func menuDelete(_ preset: IOSUnifiedCustomPreset) { deletePreset(preset) }',
         'func menuDelete(_ preset: IOSUnifiedCustomPreset) { IOSUnifiedPresetStore.delete(preset.name); presets = IOSUnifiedPresetStore.load() }', 'iOS busy deletion'),
        ('func menuDelete(_ preset: IOSUnifiedCustomPreset) { deletePreset(preset) }',
         'func menuDelete(_ preset: IOSUnifiedCustomPreset) { guard !model.profileMutationBlocked else { return }; IOSUnifiedPresetStore.delete(preset.name); presets = IOSUnifiedPresetStore.load() }', 'iOS active deletion left a stale mode'),
        ('restoreUnifiedModeSelection(in: sender); openUnifiedCustomBuilder()', 'openUnifiedCustomBuilder()', 'macOS builder Cancel changed the selected mode'),
        ('private let unifiedCreatePresetAction = "action:create-custom"', 'private let unifiedCreatePresetAction = "custom:new"', 'macOS refresh lost a newer choice'),
        ('if Preference.store.string(forKey: unifiedSelectedModeKey) == "custom:\\(target.name)" {', 'if true {', 'macOS deleted a different selected mode'),
        ('guard productOwner?.ensureMutationIdle("deleting a CUSTOM preset") == true else { return }', '', 'macOS mutation started during confirmation'),
        ('let id = storedUnifiedModeID()\n        switch id', 'let id = popup.id ?? "smart-auto"\n        switch id', 'macOS Connect interpreted a builder action'),
    )
    with tempfile.TemporaryDirectory(prefix='apple-custom-mode-') as temp:
        path = Path(temp)/'Callback.swift'; binary = path.with_suffix('')
        for before, after, witness in [(None,None,None), *defects]:
            if before and source.count(before) != 1:
                raise ValueError('CUSTOM callback control lost its source boundary: '+before)
            path.write_text(source.replace(before,after) if before else source)
            subprocess.run(['swiftc','-swift-version','6','-parse-as-library',str(path),'-o',str(binary)],check=True,timeout=90)
            result = subprocess.run([binary],capture_output=True,text=True,timeout=15)
            if witness:
                assert result.returncode == 1 and 'Rejected: '+witness in result.stdout, (witness,result)
                print('Rejected selection defect:',witness,flush=True)
            else:
                assert result.returncode == 0 and 'Apple CUSTOM selection callbacks passed' in result.stdout, result
                print(result.stdout.strip(),flush=True)


if __name__ == '__main__':
    main()
