#!/usr/bin/env python3
"""Compile actual selection/label sources and prove captured graph attribution."""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'
TEST = r'''
var checks = 0
@MainActor func check(_ condition: Bool, _ message: String) {
    precondition(condition, message); checks += 1
}
let model = LabelConsumer()
for entry in ["wg", "awg2-fast", "awg2-strong", "shadowsocks", "hysteria2"] {
    for exit in ["wg", "awg2-fast", "awg2-strong", "shadowsocks", "hysteria2"] {
        var savedEntry = entry
        let selected = IOSRuntimeSelection(engine:.multihop, logicalModeID:"multihop",
            rawProfileID:exit, files:[:], multihopEntryMode:savedEntry)
        savedEntry = "different-saved-selection"
        check(model.label(selected) == "\(entry) entry → \(exit) exit", "label lost captured entry/exit")
        check(selected.multihopEntryMode == entry && savedEntry != entry, "capture was not immutable")
    }
}
let old = IOSRuntimeSelection(engine:.multihop, logicalModeID:"multihop", rawProfileID:"hysteria2", files:[:])
check(model.label(old) == "Unspecified entry → hysteria2 exit", "missing identity was invented as WireGuard")
for (mode, expected) in [("wg", "WireGuardKit"), ("awg2-fast", "AmneziaWG native"), ("awg2-strong", "AmneziaWG native")] {
    check(model.label(IOSRuntimeSelection(engine:.wireGuard, logicalModeID:mode, rawProfileID:mode, files:[:])) == expected,
          "raw backend label regressed")
}
check(model.label(IOSRuntimeSelection(engine:.libbox, logicalModeID:"test", rawProfileID:"shadowsocks", files:[:])) == "Libbox 1.14.1", "Libbox label regressed")
check(model.label(IOSRuntimeSelection(engine:.libbox, logicalModeID:"test", rawProfileID:"reality-vision", files:["xray.json":Data("{}".utf8)])) == "Xray 26.7.11 + Libbox 1.14.1", "Xray label regressed")
let a = IOSRuntimeSelection(engine:.multihop, logicalModeID:"multihop",rawProfileID:"wg",files:[:],multihopEntryMode:"shadowsocks")
let b = IOSRuntimeSelection(engine:.multihop, logicalModeID:"multihop",rawProfileID:"wg",files:[:],multihopEntryMode:"hysteria2")
check(a != b && Set([a,b]).count == 2, "different captured entries collapsed into the same selection")
print("Shipping Apple runtime labels: PASS (\(checks) checks; no VPN or network started)")
'''

def main():
    swift = shutil.which('swiftc')
    if not swift:
        raise SystemExit('swiftc is required for executable label validation')
    selection = (APP / 'IOSRuntimeSelection.swift').read_text().split('enum IOSRuntimeSelectionError:', 1)[0]
    model = (APP / 'RouterVPNModel.swift').read_text()
    start = model.index('    private func engineName(')
    end = model.index('\n    func refreshTunnelStatus()', start)
    method = model[start:end]
    assert 'multihopEntryMode: profile.multihopEntryMode ?? "wg"' in model
    assert 'case .multihop: return "Multihop • \\(selection.displayName)"' in model
    source = selection + '\nstruct LabelConsumer {\n' + method + '\nfunc label(_ s: IOSRuntimeSelection) -> String { engineName(s) }\n}\n' + TEST
    with tempfile.TemporaryDirectory(prefix='routervpn-labels-') as name:
        tmp = Path(name); file = tmp / 'main.swift'; binary = tmp / 'labels'
        file.write_text(source)
        command = [swift, '-swift-version', '6', str(file), '-o', str(binary)]
        subprocess.run(command, check=True, timeout=90)
        subprocess.run([str(binary)], check=True, timeout=10)
        # Reproduce the real Xcode failure instead of supplying a parallel
        # selectedProfile fixture which would hide the out-of-scope reference.
        bad = source.replace('        selection.displayName\n', '        "\\(selectedProfile?.multihopEntryMode ?? "wg")"\n')
        assert bad != source
        file.write_text(bad)
        result = subprocess.run(command, capture_output=True, text=True, timeout=90)
        assert result.returncode != 0 and "cannot find 'selectedProfile' in scope" in result.stderr, result.stderr
        print('Negative control: original out-of-scope profile reference is rejected')

if __name__ == '__main__':
    main()
