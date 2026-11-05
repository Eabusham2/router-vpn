#!/usr/bin/env python3
"""Require real staged source and reject changed private-copy boundaries."""
from pathlib import Path
import hashlib
import json
import tempfile
import types
import unittest
from unittest import mock
import linux_standard_service_bundle as B
import linux_standard_service_gate as G


class StandardServiceBundleTests(unittest.TestCase):
    def test_missing_and_relative_bundle_never_fall_back(self):
        for path in (None, Path('runtime/native'), Path('/definitely-missing-routervpn-native')):
            with self.subTest(path=path), self.assertRaises(ValueError):
                B.verify(path, {})

    def test_private_copy_preserves_exact_verified_bytes(self):
        # This explicit miniature catalog tests the copy boundary only. It is
        # never accepted by production verify()/the app native payload verifier.
        for scenario in ('complete', 'manifest', 'payload', 'extra', 'missing', 'symlink', 'hardlink'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);source=root/'source';source.mkdir()
                body=b'actual original copy boundary bytes'
                payload={'size':len(body),'sha256':hashlib.sha256(body).hexdigest()}
                raw=(json.dumps({'target':'linux/amd64','files':{'engine':payload}},sort_keys=True)+'\n').encode()
                (source/'engine').write_bytes(body);(source/'NATIVE-RUNTIME.json').write_bytes(raw)
                digest=hashlib.sha256(raw).hexdigest()
                if scenario=='manifest': (source/'NATIVE-RUNTIME.json').write_bytes(raw+b' ')
                if scenario=='payload': (source/'engine').write_bytes(b'foreign changed executable')
                if scenario=='extra': (source/'foreign').write_bytes(b'x')
                if scenario=='missing': (source/'engine').unlink()
                if scenario=='symlink':
                    (root/'foreign').write_bytes(body);(source/'engine').unlink();(source/'engine').symlink_to(root/'foreign')
                if scenario=='hardlink': (root/'foreign').hardlink_to(source/'engine')
                build=types.SimpleNamespace(unique_object=lambda pairs:dict(pairs),expected_names=lambda target:{'engine'},
                    payload_bound=lambda name,target:1024,binary_name=lambda target:'engine',
                    TOR=types.SimpleNamespace(VERIFY=types.SimpleNamespace(binary_name=lambda target:'tor')))
                with mock.patch.object(B,'builder',return_value=build):
                    if scenario=='complete':
                        result=B.copy_private(source,root/'private',digest)
                        self.assertEqual((result/'engine').read_bytes(),body)
                        self.assertEqual((result/'NATIVE-RUNTIME.json').read_bytes(),raw)
                        self.assertEqual((result/'engine').stat().st_mode&0o777,0o500)
                    else:
                        with self.assertRaises(ValueError):B.copy_private(source,root/'private',digest)

    def test_service_mtu_sources_bind_native_bundle_provenance(self):
        root=Path(__file__).resolve().parents[1]
        captured={path.relative_to(root).as_posix() for path in B.builder().inputs()}
        required={name for name in G.SOURCE if '/linux_standard_service_mtu_' in name}
        required.update(G.AUXILIARY_TESTS)
        required.update({'internal/desktopnetwork/routing_history_retirement_linux.go',
                         'internal/dnsmeasure/addresses.go',
                         'mobile/desktop/standard_mtu_linux.go.tmpl',
                         'mobile/desktop/standard_mtu_linux_test.go.tmpl',
                         'deploy/linux_standard_service_gate.py',
                         'deploy/test_linux_standard_service_runner.py',
                         'deploy/test_linux_controller_privilege.py'})
        self.assertTrue(required)
        self.assertEqual(sorted(required-captured),[],
                         'native reuse/provenance omitted service MTU implementation or required gate')

    def test_shipping_gate_follows_actual_bundle_and_binds_manifest(self):
        root=Path(__file__).resolve().parents[1]
        package=(root/'deploy/package-linux-native.sh').read_text()
        self.assertLess(package.index('"$ROOT/deploy/package-native-runtime.sh"'),package.index('"$ROOT/deploy/test_linux_controller_privilege.py"'))
        self.assertLess(package.index('"$ROOT/deploy/test_linux_controller_privilege.py"'),package.index('"$ROOT/server/scripts/source_provenance.py"'))
        self.assertIn('--runtime-bundle "$dir/runtime/native"',package)
        runner=(root/'deploy/test_linux_controller_privilege.py').read_text()
        self.assertIn('runtime_manifest = BUNDLE.verify(runtime_bundle, env)',runner)
        self.assertIn('BUNDLE.copy_private(runtime_bundle',runner)
        self.assertIn("'--runtime-manifest-sha256', runtime_manifest",runner)
        fixture=(root/'cmd/client/linux_standard_service_namespace_test.go').read_text()
        self.assertIn('linuxStandardInstallRuntimeFixture(t)',fixture)
        self.assertNotIn('legacyDNSEngineFixture',fixture)


if __name__=='__main__':unittest.main()
