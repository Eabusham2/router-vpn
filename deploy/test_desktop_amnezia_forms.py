#!/usr/bin/env python3
"""Run each native external-node form and consume its real payload in Go.

GTK uses actual widgets/JsonBuilder under Xvfb. Windows executes the shipping
Save callback with non-network controller doubles. Swift executes the shipping
peer-field block and parameter parser with value-only field doubles; the normal
macOS build separately compiles the complete AppKit window.
"""
from pathlib import Path
import argparse
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def block(source, marker):
    start = source.index(marker)
    brace = source.index('{', start)
    depth = 1
    end = brace + 1
    while depth and end < len(source):
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    if depth:
        raise AssertionError('Unclosed shipping form block: '+marker)
    return source[start:end]


def swift_form(directory):
    source = (ROOT/'client/macos/RouterVPNMacExternalNode.swift').read_text()
    helper = source[source.index('// Keep the provider'):source.index('extension ProductWindowController')]
    csv = block(source, 'private func externalCSV(')
    fields = block(source, 'if selected == "wireguard" || selected == "amneziawg"')
    test = r'''
import Foundation
HELPER
final class Field { var stringValue: String; init(_ value: String) { stringValue = value } }
final class Form {
    var selected = "amneziawg"
    var result: [String: Any]?
    var message = ""
    let wgPrivate = Field(Data(repeating: 112, count: 32).base64EncodedString())
    let wgPeer = Field(Data(repeating: 113, count: 32).base64EncodedString())
    let wgPSK = Field("")
    let wgAddresses = Field("10.66.0.2/32, fd66::2/128")
    let wgAllowed = Field("0.0.0.0/0, ::/0")
    let wgDNS = Field("9.9.9.9")
    let wgMTU = Field("1280")
    let wgKeepalive = Field("17")
    let awgParameters = Field("Jc=3; Jmin=40; Jmax=900; S1=56; S2=48; S3=24; S4=32; H1=10000000-19999999; H2=20000000-29999999; H3=30000000-39999999; H4=40000000-49999999")
    CSV
    func appendHelp(_ text: String) { message = text }
    func save() {
        result = nil
        var body: [String: Any] = ["protocol": selected, "name": "Imported AWG fixture", "server": "203.0.113.60", "port": 51820, "expected_public_ip": "203.0.113.60"]
        FIELDS
        result = body
    }
}
func check(_ value: Bool, _ message: String) { precondition(value, message) }
let form = Form()
let parameters = form.awgParameters.stringValue
form.save()
check(form.result != nil, form.message)
let first = form.result!
let awg = first["awg_parameters"] as! [String: String]
check(awg.count == 11 && awg["h4"] == "40000000-49999999" && awg["s4"] == "32", "Provider values changed")
check(first["wg_keepalive"] as? Int == 17 && first["wg_mtu"] as? Int == 1280, "Peer settings changed")
let output = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
try JSONSerialization.data(withJSONObject: first, options: [.sortedKeys]).write(to: output.appendingPathComponent("amneziawg.json"))
var count = 1
for bad in ["", parameters+";JC=3", parameters.replacingOccurrences(of: "S4=32; ", with: ""), parameters+";unknown=4", parameters.replacingOccurrences(of: "H1=10000000-19999999", with: "H1=1--9"), parameters.replacingOccurrences(of: "S4=32", with: "S4=bad"), String(repeating: "Jc=3;", count: 1000)] {
    form.awgParameters.stringValue = bad; form.save()
    check(form.result == nil, "Malformed AWG fields reached the controller"); count += 1
}
form.awgParameters.stringValue = parameters
for bad in ["-1", "65536", "bad"] {
    form.wgKeepalive.stringValue = bad; form.save()
    check(form.result == nil, "Invalid keepalive reached the controller"); count += 1
}
form.wgKeepalive.stringValue = "17"
for bad in ["1279", "9001", "bad"] {
    form.wgMTU.stringValue = bad; form.save()
    check(form.result == nil, "Invalid MTU reached the controller"); count += 1
}
form.wgMTU.stringValue = "1280"; form.selected = "wireguard"; form.save()
check(form.result != nil && form.result!["awg_parameters"] == nil && form.result!["wg_keepalive"] as? Int == 17, "Ordinary WG became AWG")
try JSONSerialization.data(withJSONObject: form.result!, options: [.sortedKeys]).write(to: output.appendingPathComponent("wireguard.json"))
count += 1
print("PASS shipping Swift external peer serialization: \(count) cases")
'''.replace('HELPER', helper).replace('CSV', csv).replace('FIELDS', fields)
    path = directory/'main.swift'
    path.write_text(test)
    binary = directory/'swift-form'
    subprocess.run(['swiftc', '-swift-version', '6', str(path), '-o', str(binary)], check=True, timeout=120)
    subprocess.run([str(binary), str(directory)], check=True, timeout=30)


def linux_form(directory):
    flags = subprocess.check_output(['pkg-config', '--cflags', '--libs', 'gtk+-3.0', 'json-glib-1.0'], text=True).split()
    binary = directory/'gtk-form'
    subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                    str(ROOT/'client/linux/test-external-amnezia.c'), '-o', str(binary), *flags], check=True, timeout=120)
    subprocess.run(['xvfb-run', '-a', str(binary), str(directory)], check=True, timeout=60)


def windows_form(directory, shell):
    subprocess.run([shell, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
                    str(ROOT/'client/test-windows-external-amnezia.ps1'), '-Root', str(ROOT),
                    '-Output', str(directory)], check=True, timeout=60)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', choices=['linux', 'darwin', 'windows'], default='windows' if sys.platform == 'win32' else sys.platform)
    args = parser.parse_args()
    shells = [None]
    if args.platform == 'windows':
        shells = [shell for shell in ('pwsh', 'powershell.exe') if shutil.which(shell)]
        if not shells:
            raise SystemExit('PowerShell is required to execute the actual Save callback')
    for shell in shells:
        with tempfile.TemporaryDirectory(prefix='router-vpn-amnezia-form-') as temporary:
            directory = Path(temporary)
            if args.platform == 'linux':
                linux_form(directory)
            elif args.platform == 'darwin':
                swift_form(directory)
            else:
                windows_form(directory, shell)
            env = dict(os.environ, ROUTERVPN_AWG_FORM_PAYLOADS=str(directory))
            subprocess.run(['go', 'test', '-race', '-count=1', './cmd/client', '-run', '^TestDesktopAmneziaFormPayload$'], cwd=ROOT, env=env, check=True, timeout=180)
    print('Verified native '+args.platform+' form to exact Go AWG/WG runtime profiles', flush=True)


if __name__ == '__main__':
    main()
