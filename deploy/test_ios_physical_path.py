#!/usr/bin/env python3
"""Compile the unchanged path owner and reject unproved/ambiguous native routes.

Default: executable platform-boundary tests (no VPN or network is started).
--framework: typecheck both complete MTU owners against the real generated
Libbox framework and iPhoneOS SDK. No hand-written bindings are used in that gate.
"""
from pathlib import Path
import argparse
import os
import platform
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PATH_SOURCE = ROOT / 'ios/RouterVPN/PacketTunnel/RouterVPNPhysicalPath.swift'
OWNER_SOURCE = ROOT / 'ios/RouterVPN/PacketTunnel/RouterVPNMTUSession.swift'

NETWORK = r'''
public struct NWInterface: Sendable {
    public enum InterfaceType: Hashable, Sendable { case wifi, cellular, wiredEthernet, loopback, other }
    public let name: String
    public let index: Int
    public let type: InterfaceType
    public init(_ name: String, _ index: Int, _ type: InterfaceType) {
        self.name = name; self.index = index; self.type = type
    }
}
public struct NWPath: Sendable {
    public enum Status: Sendable { case satisfied, unsatisfied, requiresConnection }
    public var status = Status.satisfied
    public var availableInterfaces: [NWInterface] = [NWInterface("en0", 4, .wifi)]
    public var used: Set<NWInterface.InterfaceType> = [.wifi]
    public var isExpensive = false, isConstrained = false
    public var supportsIPv4 = true, supportsIPv6 = true, supportsDNS = true
    public var gateways = ["gateway-b", "gateway-a"]
    public func usesInterfaceType(_ type: NWInterface.InterfaceType) -> Bool { used.contains(type) }
    public init() {}
}
'''
LIBBOX = r'''
import Foundation
public enum NativePathFixture {
    nonisolated(unsafe) public static var value = "native-address-hash"
    nonisolated(unsafe) public static var fail = false
    nonisolated(unsafe) public static var names: [String] = []
}
// Matches the real generated binding: the string is NOT Optional.
public func LibboxRouterMTUPhysicalPath(_ name: String?, _ error: UnsafeMutablePointer<NSError?>?) -> String {
    NativePathFixture.names.append(name ?? "")
    if NativePathFixture.fail { error?.pointee = NSError(domain: "Fixture", code: 1) }
    return NativePathFixture.value
}
'''
# Linux has no Apple CryptoKit. Use the system OpenSSL SHA-256 implementation
# solely for this platform-boundary harness; Apple uses actual CryptoKit.
LINUX_CRYPTO = r'''
import Foundation
@_silgen_name("SHA256") private func opensslSHA256(
    _ input: UnsafePointer<UInt8>?, _ size: Int, _ output: UnsafeMutablePointer<UInt8>?
) -> UnsafeMutablePointer<UInt8>?
public enum SHA256 {
    public static func hash(data: Data) -> [UInt8] {
        var digest = [UInt8](repeating: 0, count: 32)
        data.withUnsafeBytes { input in
            digest.withUnsafeMutableBufferPointer { output in
                precondition(opensslSHA256(input.bindMemory(to: UInt8.self).baseAddress, input.count, output.baseAddress) != nil)
            }
        }
        return digest
    }
}
'''
TESTS = r'''
import Foundation
import Network
import Libbox
var checks = 0
@MainActor func check(_ value: Bool, _ message: String) {
    checks += 1
    if !value { fatalError(message) }
}
let original = NWPath()
let baseline = RouterVPNPhysicalPath.snapshot(original)!
check(baseline.name == "en0" && baseline.signature.count == 64, "selected physical interface/hash missing")
check(baseline.signature.allSatisfy { "0123456789abcdef".contains($0) }, "invalid hash encoding")
check(NativePathFixture.names == ["en0"], "readback used a guessed or wrong interface")
check(RouterVPNPhysicalPath.snapshot(original)?.signature == baseline.signature, "duplicate callback changed the path")
var reordered = original; reordered.gateways.reverse()
check(RouterVPNPhysicalPath.snapshot(reordered)?.signature == baseline.signature, "gateway enumeration order changed the path")
for state in [NWPath.Status.unsatisfied, .requiresConnection] {
    var path = original; path.status = state
    let calls = NativePathFixture.names.count
    check(RouterVPNPhysicalPath.snapshot(path) == nil, "unusable route was accepted")
    check(calls == NativePathFixture.names.count, "unusable route read a native interface")
}
for interfaces in [[], [NWInterface("en0", 4, .wifi), NWInterface("en1", 5, .wifi)],
                   [NWInterface("utun8", 8, .wifi)], [NWInterface("tun1", 9, .wifi)],
                   [NWInterface("lo0", 1, .wifi)], [NWInterface("pdp_ip0", 3, .cellular)],
                   [NWInterface("other0", 10, .other)]] {
    var path = original; path.availableInterfaces = interfaces
    let calls = NativePathFixture.names.count
    check(RouterVPNPhysicalPath.snapshot(path) == nil, "ambiguous/tunnel/nonselected interface was accepted")
    check(calls == NativePathFixture.names.count, "invalid route reached native readback")
}
var extra = original; extra.availableInterfaces.append(NWInterface("utun3", 7, .other))
check(RouterVPNPhysicalPath.snapshot(extra)?.signature == baseline.signature, "irrelevant tunnel changed physical ownership")
NativePathFixture.fail = true
check(RouterVPNPhysicalPath.snapshot(original) == nil, "native error with nonempty result was accepted")
NativePathFixture.fail = false; NativePathFixture.value = ""
check(RouterVPNPhysicalPath.snapshot(original) == nil, "missing native address hash was accepted")
NativePathFixture.value = "changed-native-addresses"
check(RouterVPNPhysicalPath.snapshot(original)?.signature != baseline.signature, "native address transition was ignored")
NativePathFixture.value = "native-address-hash"
for field in 0..<8 {
    var path = original
    switch field {
    case 0: path.isExpensive.toggle()
    case 1: path.isConstrained.toggle()
    case 2: path.supportsIPv4.toggle()
    case 3: path.supportsIPv6.toggle()
    case 4: path.supportsDNS.toggle()
    case 5: path.gateways = ["new-gateway"]
    case 6: path.availableInterfaces = [NWInterface("en1", 5, .wifi)]
    default: path.availableInterfaces = [NWInterface("en0", 6, .wifi)]
    }
    check(RouterVPNPhysicalPath.snapshot(path)?.signature != baseline.signature, "route transition omitted from fingerprint")
}
for type in [NWInterface.InterfaceType.cellular, .wiredEthernet] {
    var path = original; path.used = [type]; path.availableInterfaces = [NWInterface("physical", 6, type)]
    check(RouterVPNPhysicalPath.snapshot(path)?.name == "physical", "selected cellular/wired route was rejected")
}
print("Production Swift physical-path validation: PASS (\(checks) checks; native/route boundaries doubled)")
'''


def actual_framework(framework: Path) -> None:
    if platform.system() != 'Darwin':
        raise SystemExit('The generated Apple binding gate requires macOS and the iPhoneOS SDK.')
    info = __import__('plistlib').loads((framework / 'Info.plist').read_bytes())
    slices = [entry for entry in info.get('AvailableLibraries', [])
              if entry.get('SupportedPlatform') == 'ios' and not entry.get('SupportedPlatformVariant')]
    if len(slices) != 1 or 'arm64' not in slices[0].get('SupportedArchitectures', []):
        raise SystemExit('Exactly one generated arm64 iOS framework slice is required.')
    sdk = subprocess.check_output(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], text=True).strip()
    directory = framework / slices[0]['LibraryIdentifier']
    subprocess.run(['xcrun', '--sdk', 'iphoneos', 'swiftc', '-typecheck', '-swift-version', '6',
                    '-target', 'arm64-apple-ios17.0', '-sdk', sdk, '-application-extension',
                    '-F', str(directory), str(PATH_SOURCE), str(OWNER_SOURCE)], check=True, timeout=120)
    print('Complete physical-path and MTU owner sources typecheck against the real iOS SDK/Libbox bindings.')


def behavior() -> None:
    swift = shutil.which('swiftc')
    if not swift:
        raise SystemExit('swiftc is required; marker checks are not a substitute.')
    with tempfile.TemporaryDirectory(prefix='routervpn-physical-path-') as temp:
        tmp = Path(temp)
        env = {**os.environ, 'LD_LIBRARY_PATH': temp, 'DYLD_LIBRARY_PATH': temp}
        suffix = 'dylib' if platform.system() == 'Darwin' else 'so'
        def run(args, **kw):
            return subprocess.run(args, env=env, cwd=tmp, timeout=120, **kw)
        for name, content in [('Network', NETWORK), ('Libbox', LIBBOX)]:
            source = tmp / (name + '.swift'); source.write_text(content)
            run([swift, '-swift-version', '6', '-emit-module', '-emit-library', '-module-name', name,
                 str(source), '-o', str(tmp / ('lib' + name + '.' + suffix))], check=True)
        libs = ['-lNetwork', '-lLibbox']
        if platform.system() != 'Darwin':
            source = tmp / 'CryptoKit.swift'; source.write_text(LINUX_CRYPTO)
            run([swift, '-swift-version', '6', '-emit-module', '-emit-library', '-module-name', 'CryptoKit',
                 str(source), '-lcrypto', '-o', str(tmp / 'libCryptoKit.so')], check=True)
            libs += ['-lCryptoKit']
        main = tmp / 'main.swift'; main.write_text(TESTS)
        base = [swift, '-swift-version', '6', '-I', temp, '-L', temp, *libs]
        run([*base, str(PATH_SOURCE), str(main), '-o', str(tmp / 'test')], check=True)
        run([str(tmp / 'test')], check=True)
        original = PATH_SOURCE.read_text()
        old = original.replace('let native = LibboxRouterMTUPhysicalPath(selected.name, &failure)',
                               'guard let native = LibboxRouterMTUPhysicalPath(selected.name, &failure) else { return nil }')
        assert old != original
        mutant = tmp / 'RouterVPNPhysicalPath.swift'; mutant.write_text(old)
        failed = run([*base, '-typecheck', str(mutant)], capture_output=True, text=True)
        assert failed.returncode != 0 and 'conditional binding must have Optional type' in failed.stderr, failed.stderr
        for needle, replacement in [('failure == nil, ', ''), ('eligible.count == 1', '!eligible.isEmpty')]:
            assert original.count(needle) == 1
            mutant.write_text(original.replace(needle, replacement))
            run([*base, str(mutant), str(main), '-o', str(tmp / 'mutant')], check=True)
            failed = run([str(tmp / 'mutant')], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            assert failed.returncode != 0, 'Unsafe path mutant was accepted: ' + needle
        print('Old optional binding, ignored native errors and ambiguous-route negative controls rejected.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--framework', type=Path)
    args = parser.parse_args()
    actual_framework(args.framework.resolve()) if args.framework else behavior()
