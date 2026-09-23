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
import subprocess
import tempfile
import textwrap
import unittest


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
