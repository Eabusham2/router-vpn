#!/usr/bin/env python3
from pathlib import Path
here=Path(__file__).resolve()
p=here.with_name('prepare-libbox.sh').read_text()
workflow=(here.parents[2]/'.github/workflows/ios-libbox-engine.yml').read_text()
required=[
 'VERSION=1.14.1',
 'COMMIT=1ac1a339cb1223e9c70eae14c44411c75033c02d',
 'GO_TOOLCHAIN=go1.26.3',
 'GOMOBILE_VERSION=0.1.12',
 'go run ./cmd/internal/build_libbox -target apple -platform ios,iossimulator',
 'Libbox.xcframework',
 'libbox-LICENSE.txt',
 "('ios','')",
 "('ios','simulator')",
 "grep -Fq 'with_openvpn'",
 'LibboxRouterOpenVPNEndpoint', 'BRIDGE_SHA', 'BRIDGE_STAMP',
]
for marker in required:
    assert marker in p, marker
assert 'latest' not in p.lower()
assert "grep -nE 'PlatformInterface|CommandServer|StartOrReloadService|OpenTun|openTun|LibboxVersion|SetupOptions' \"$HEADER\" | head" not in workflow
assert 'SIGNATURES="$RUNNER_TEMP/routervpn-libbox-signatures.txt"' in workflow
assert 'head -n 240 "$SIGNATURES"' in workflow
print('Pinned Apple Libbox build contract OK')

# Execute the shipping verification step against generated-header fixtures.
# The old umbrella-header lookup failed only after the expensive Apple build;
# source-marker tests alone did not expose that mismatch.
import os
import plistlib
import re
import subprocess
import tempfile
import textwrap
import unittest


# These declarations were generated with the pinned gomobile v0.1.12 from the
# actual Go function/method signatures. String/error results deliberately use
# NSError**; a marker or a no-error status getter cannot substitute for this ABI.
TOR_PADDING_HEADER = '''
@interface LibboxRouterTorProofRequest : NSObject <goSeqRefInterface> {
}
- (void)cancel;
- (BOOL)healthy;
- (NSString* _Nonnull)run:(NSError* _Nullable* _Nullable)error;
- (NSString* _Nonnull)paddingStatusJSON:(NSError* _Nullable* _Nullable)error;
@end
FOUNDATION_EXPORT NSString* _Nonnull LibboxRouterTorPaddingSource(NSString* _Nullable configJSON, NSString* _Nullable profileJSON, NSString* _Nullable sessionID, NSError* _Nullable* _Nullable error);
'''


def cached_tor_padding_verifier(source):
    block = source.split("<<'PYHEAD'\n", 1)[1].split('\nPYHEAD', 1)[0]
    start = block.index("    assert 'FOUNDATION_EXPORT NSString* _Nonnull LibboxRouterTorPaddingSource(")
    end = block.index("    assert 'LibboxRouterOpenVPNEndpoint'", start)
    # Execute the new checks verbatim inside the shipping per-slice header loop.
    # Other independently tested APIs are outside this focused boundary fixture.
    prefix = block[:block.index("    for symbol in ('LibboxRouterCompileExternalPolicy'")]
    return prefix + block[start:end]


class AppleCachedTorPaddingABI(unittest.TestCase):
    def check_headers(self, device=TOR_PADDING_HEADER, simulator=TOR_PADDING_HEADER, source=p):
        with tempfile.TemporaryDirectory(prefix='apple-padding-abi-') as temporary:
            root = Path(temporary)
            for name, content in (('ios-arm64', device), ('ios-arm64-simulator', simulator)):
                if content is not None:
                    header = root/name/'Libbox.framework/Headers/Libbox.objc.h'
                    header.parent.mkdir(parents=True)
                    header.write_text(content)
            return subprocess.run(['python3', '-c', cached_tor_padding_verifier(source), str(root)],
                                  text=True, capture_output=True, timeout=15)

    def test_pinned_generated_declarations_pass_in_each_slice(self):
        result = self.check_headers()
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)

    def test_old_or_changed_source_factory_is_rejected(self):
        signature = TOR_PADDING_HEADER.split('FOUNDATION_EXPORT ', 1)[1]
        for changed in ('', signature.replace('profileJSON', 'foreignJSON'),
                        signature.replace('NSError* _Nullable* _Nullable error', 'NSError* _Nullable error')):
            with self.subTest(changed=changed):
                header = TOR_PADDING_HEADER.replace('FOUNDATION_EXPORT '+signature, 'FOUNDATION_EXPORT '+changed)
                result = self.check_headers(device=header)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Tor padding captured-source API changed', result.stderr)

    def test_status_requires_exact_retained_request_and_error_protocol(self):
        signature = '- (NSString* _Nonnull)paddingStatusJSON:(NSError* _Nullable* _Nullable)error;'
        for changed in ('', '- (NSString* _Nonnull)paddingStatusJSON;',
                        signature.replace('NSString* _Nonnull', 'BOOL'),
                        signature.replace('NSError* _Nullable* _Nullable', 'NSError* _Nullable')):
            with self.subTest(changed=changed):
                header = TOR_PADDING_HEADER.replace(signature, changed)
                result = self.check_headers(simulator=header)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Tor proof ownership API changed', result.stderr)
        header = TOR_PADDING_HEADER.replace('@end', '@end\n@interface ForeignRequest : NSObject <goSeqRefInterface> {\n}\n'+signature+'\n@end')
        header = header.replace(signature+'\n@end', '@end', 1)
        self.assertNotEqual(self.check_headers(simulator=header).returncode, 0)

    def test_retained_proof_lifecycle_methods_remain_required(self):
        for signature in ('- (void)cancel;', '- (BOOL)healthy;', '- (NSString* _Nonnull)run:(NSError* _Nullable* _Nullable)error;'):
            with self.subTest(signature=signature):
                result = self.check_headers(device=TOR_PADDING_HEADER.replace(signature, ''))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Tor proof ownership API changed', result.stderr)

    def test_no_generated_header_cannot_pass(self):
        self.assertNotEqual(self.check_headers(device=None, simulator=None).returncode, 0)


TOR_COMPARE_HEADER = '''
@protocol LibboxRouterTorCompareCandidate <NSObject>
- (void)cancel;
- (BOOL)close:(NSError* _Nullable* _Nullable)error;
- (BOOL)current;
- (LibboxRouterTorProofRequest* _Nullable)proof;
- (LibboxCommandServer* _Nullable)server;
- (BOOL)start:(NSError* _Nullable* _Nullable)error;
@end
@protocol LibboxRouterTorCompareHost <NSObject>
- (BOOL)current;
- (id<LibboxRouterTorCompareCandidate> _Nullable)newCandidate:(NSString* _Nullable)execution target:(NSString* _Nullable)target;
- (void)progress:(NSString* _Nullable)stage execution:(NSString* _Nullable)execution;
@end
@interface LibboxRouterTorCompare : NSObject <goSeqRefInterface> {
}
- (void)cancel;
- (BOOL)close:(NSError* _Nullable* _Nullable)error;
- (NSString* _Nonnull)execution;
- (BOOL)keep:(NSError* _Nullable* _Nullable)error;
- (NSString* _Nonnull)resultJSON;
- (BOOL)run:(NSError* _Nullable* _Nullable)error;
@end
@interface LibboxRouterTorCompareCandidate : NSObject <goSeqRefInterface, LibboxRouterTorCompareCandidate> {
}
- (void)cancel;
- (BOOL)close:(NSError* _Nullable* _Nullable)error;
- (BOOL)current;
- (LibboxRouterTorProofRequest* _Nullable)proof;
- (LibboxCommandServer* _Nullable)server;
- (BOOL)start:(NSError* _Nullable* _Nullable)error;
@end
@interface LibboxRouterTorCompareHost : NSObject <goSeqRefInterface, LibboxRouterTorCompareHost> {
}
- (BOOL)current;
- (id<LibboxRouterTorCompareCandidate> _Nullable)newCandidate:(NSString* _Nullable)execution target:(NSString* _Nullable)target;
- (void)progress:(NSString* _Nullable)stage execution:(NSString* _Nullable)execution;
@end
FOUNDATION_EXPORT LibboxRouterTorCompare* _Nullable LibboxRouterTorNewCompare(id<LibboxRouterTorCompareHost> _Nullable host, NSString* _Nullable entryID, NSString* _Nullable exitID, NSString* _Nullable transport, NSString* _Nullable captureSHA256, NSError* _Nullable* _Nullable error);
'''


def cached_tor_compare_verifier(source):
    block = source.split("<<'PYHEAD'\n", 1)[1].split('\nPYHEAD', 1)[0]
    start = block.index("    assert content.count('FOUNDATION_EXPORT LibboxRouterTorCompare*")
    end = block.index("    assert 'LibboxNewRouterMultihop'", start)
    prefix = block[:block.index("    for symbol in ('LibboxRouterCompileExternalPolicy'")]
    return prefix + block[start:end]


class AppleCachedTorCompareABI(unittest.TestCase):
    def check_headers(self, device=TOR_COMPARE_HEADER, simulator=TOR_COMPARE_HEADER):
        with tempfile.TemporaryDirectory(prefix='apple-compare-abi-') as temporary:
            root = Path(temporary)
            for name, content in (('ios-arm64', device), ('ios-arm64-simulator', simulator)):
                if content is not None:
                    header = root/name/'Libbox.framework/Headers/Libbox.objc.h'
                    header.parent.mkdir(parents=True)
                    header.write_text(content)
            return subprocess.run(['python3', '-c', cached_tor_compare_verifier(p), str(root)],
                                  text=True, capture_output=True, timeout=15)

    def assert_rejected_in_each_slice(self, header, reason):
        for slice_name in ('device', 'simulator'):
            with self.subTest(slice=slice_name):
                result = self.check_headers(**{slice_name: header})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(reason, result.stderr)

    def test_pinned_generated_compare_owners_pass_in_each_slice(self):
        result = self.check_headers()
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)

    def test_factory_requires_capture_owner_and_error_protocol(self):
        signature = TOR_COMPARE_HEADER.split('FOUNDATION_EXPORT ', 1)[1]
        for changed in ('', signature.replace('captureSHA256', 'foreignSHA256'),
                        signature.replace('LibboxRouterTorCompareHost', 'LibboxRouterTorCompareCandidate'),
                        signature.replace('NSError* _Nullable* _Nullable error', 'NSError* _Nullable error')):
            with self.subTest(changed=changed):
                self.assert_rejected_in_each_slice(
                    TOR_COMPARE_HEADER.replace('FOUNDATION_EXPORT '+signature, 'FOUNDATION_EXPORT '+changed),
                    'Tor comparison captured-owner factory changed')

    def test_every_consumed_selector_is_required_on_its_exact_owner(self):
        owners = re.findall(r'^@(?:protocol|interface) LibboxRouterTorCompare[^\n]*\n.*?^@end',
                            TOR_COMPARE_HEADER, re.M|re.S)
        self.assertEqual(len(owners), 5)
        for owner in owners:
            for signature in (line for line in owner.splitlines() if line.startswith('- (')):
                with self.subTest(owner=owner.splitlines()[0], signature=signature):
                    changed = owner.replace(signature, '')
                    self.assert_rejected_in_each_slice(TOR_COMPARE_HEADER.replace(owner, changed),
                                                       'Tor comparison ownership selector changed')

    def test_methods_on_unrelated_owner_do_not_satisfy_callback_protocol(self):
        owners = re.findall(r'^@(?:protocol|interface) LibboxRouterTorCompare[^\n]*\n.*?^@end',
                            TOR_COMPARE_HEADER, re.M|re.S)
        for owner in owners:
            with self.subTest(owner=owner.splitlines()[0]):
                signature = next(line for line in owner.splitlines() if line.startswith('- ('))
                foreign = '\n@interface ForeignOwner : NSObject {\n}\n'+signature+'\n@end\n'
                changed = TOR_COMPARE_HEADER.replace(owner, owner.replace(signature, ''))+foreign
                self.assert_rejected_in_each_slice(changed, 'Tor comparison ownership selector changed')

    def test_missing_or_duplicate_owner_cannot_satisfy_generated_contract(self):
        owners = re.findall(r'^@(?:protocol|interface) LibboxRouterTorCompare[^\n]*\n.*?^@end',
                            TOR_COMPARE_HEADER, re.M|re.S)
        for owner in owners:
            for header in (TOR_COMPARE_HEADER.replace(owner, ''), TOR_COMPARE_HEADER+'\n'+owner+'\n'):
                with self.subTest(owner=owner.splitlines()[0], duplicate=header.count(owner)==2):
                    self.assert_rejected_in_each_slice(header, 'Tor comparison generated owner missing or ambiguous')

    def test_changed_native_error_or_target_selector_is_rejected(self):
        for before, after in (
                ('- (BOOL)keep:(NSError* _Nullable* _Nullable)error;', '- (void)keep;'),
                ('- (BOOL)close:(NSError* _Nullable* _Nullable)error;', '- (void)close;'),
                ('- (BOOL)start:(NSError* _Nullable* _Nullable)error;', '- (BOOL)start:(NSError* _Nullable)error;'),
                ('newCandidate:(NSString* _Nullable)execution target:(NSString* _Nullable)target;',
                 'newCandidate:(NSString* _Nullable)execution;'),
                ('- (NSString* _Nonnull)resultJSON;', '- (BOOL)resultJSON;')):
            with self.subTest(selector=before):
                self.assert_rejected_in_each_slice(TOR_COMPARE_HEADER.replace(before, after),
                                                   'Tor comparison ownership selector changed')

    def test_no_generated_header_cannot_pass(self):
        self.assertNotEqual(self.check_headers(device=None, simulator=None).returncode, 0)


def verification_script(source):
    name = '      - name: Verify exact pin slices and generated API\n'
    step = source.split(name, 1)[1].split('\n      - ', 1)[0]
    return textwrap.dedent(step.split('        run: |\n', 1)[1])


class AppleLibboxWorkflowVerification(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='routervpn-libbox-contract-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.deps = self.root / '.deps'
        self.framework = self.deps / 'Libbox.xcframework'
        self.header = self.framework / 'ios-arm64' / 'Libbox.framework' / 'Headers' / 'Libbox.objc.h'
        self.header.parent.mkdir(parents=True)
        self.header.write_text('\n'.join([
            'LibboxVersion', 'LibboxPlatformInterface', 'LibboxCommandServer',
            'LibboxRouterOpenVPNEndpoint',
        ]) + '\n')
        self.license = self.deps / 'libbox-LICENSE.txt'
        self.license.write_text('Generated fixture license\n')
        self.pin = self.deps / 'Libbox.xcframework.pin'
        self.pin.write_text('1.14.1+1ac1a339cb1223e9c70eae14c44411c75033c02d+go1.26.3+0.1.12+ios,iossimulator\n')
        self.libraries = [
            {'SupportedPlatform': 'ios'},
            {'SupportedPlatform': 'ios', 'SupportedPlatformVariant': 'simulator'},
        ]
        self.write_plist()

    def write_plist(self):
        with (self.framework / 'Info.plist').open('wb') as output:
            plistlib.dump({'AvailableLibraries': self.libraries}, output)

    def run_step(self, source=workflow):
        return subprocess.run(
            ['bash', '-e', '-o', 'pipefail', '-c', verification_script(source)],
            cwd=self.root, env={**os.environ, 'RUNNER_TEMP': str(self.root)},
            text=True, capture_output=True, timeout=15,
        )

    def test_generated_objc_header_passes(self):
        result = self.run_step()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('LibboxVersion', (self.root / 'routervpn-libbox-signatures.txt').read_text())

    def test_old_header_lookup_is_a_negative_control(self):
        old = workflow.replace('Headers/Libbox.objc.h', 'Headers/Libbox.h')
        self.assertNotEqual(self.run_step(old).returncode, 0)

    def test_umbrella_header_is_not_api_evidence(self):
        self.header.rename(self.header.with_name('Libbox.h'))
        self.assertNotEqual(self.run_step().returncode, 0)

    def test_missing_generated_header_fails(self):
        self.header.unlink()
        self.assertNotEqual(self.run_step().returncode, 0)

    def test_missing_required_api_fails(self):
        self.header.write_text('LibboxVersion\nLibboxPlatformInterface\n')
        self.assertNotEqual(self.run_step().returncode, 0)

    def test_wrong_pin_fails(self):
        self.pin.write_text('unverified-other-core\n')
        self.assertNotEqual(self.run_step().returncode, 0)

    def test_missing_license_fails(self):
        self.license.unlink()
        self.assertNotEqual(self.run_step().returncode, 0)

    def test_missing_simulator_slice_fails(self):
        self.libraries.pop()
        self.write_plist()
        self.assertNotEqual(self.run_step().returncode, 0)

    def test_missing_device_slice_fails(self):
        self.libraries.pop(0)
        self.write_plist()
        self.assertNotEqual(self.run_step().returncode, 0)

    def test_uploaded_evidence_uses_generated_header(self):
        self.assertIn('ios/RouterVPN/.deps/Libbox.xcframework/**/Headers/Libbox.objc.h', workflow)
        self.assertNotIn('Headers/Libbox.h', workflow)


if __name__ == '__main__':
    unittest.main()
