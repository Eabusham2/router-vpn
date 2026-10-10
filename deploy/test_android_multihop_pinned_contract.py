#!/usr/bin/env python3
"""Regression checks for the mandatory native Android graph validation gate."""
from pathlib import Path
import importlib.util
import itertools
import hashlib
import io
import zipfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('android_native_graph', ROOT / 'deploy/test_android_multihop_pinned.py')
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class NativeGraphGate(unittest.TestCase):
    def populate(self, root):
        for entry, exit_mode, execution in itertools.product(
                ('shadowsocks', 'hysteria2', 'reality-vision', 'reality-pq-vision', 'reality-xhttp'),
                ('wg', 'awg2-fast', 'awg2-strong', 'shadowsocks', 'hysteria2'),
                ('local', 'server', 'auto')):
            folder = root / f'{entry}-{exit_mode}-{execution}'
            folder.mkdir()
            for name in ('sing-box.json', 'planned.json') + (('trust.pem',) if exit_mode == 'hysteria2' else ()):
                (folder / name).write_text('{}')

    def jar_bytes(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            for name in ('JSONObject', 'JSONArray', 'JSONTokener'):
                archive.writestr('org/json/' + name + '.class', b'test-fixture-not-executed')
        return buffer.getvalue()

    def response(self, data):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.geturl.return_value = GATE.ANDROID_JSON_URL
        response.read.return_value = data
        return response

    def test_missing_host_package_uses_only_hash_verified_temporary_dependency(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data = self.jar_bytes()
            response = self.response(data)
            env = {}
            with mock.patch.object(GATE, 'SYSTEM_JSON_JAR', root / 'missing'), mock.patch.object(GATE, 'ANDROID_JSON_SHA256', hashlib.sha256(data).hexdigest()), mock.patch.object(GATE.urllib.request, 'urlopen', return_value=response) as fetch:
                selected = GATE.android_json_dependency(root, env)
                self.assertEqual(selected.read_bytes(), data)
                self.assertEqual(selected.parent, root)
                self.assertEqual(env, {})
                fetch.assert_called_once_with(GATE.ANDROID_JSON_URL, timeout=30)
                response.read.assert_called_once_with(GATE.MAX_JSON_JAR + 1)
                response.__exit__.assert_called_once()

    def test_explicit_and_system_dependencies_never_download(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            jar = root / 'explicit.jar'
            jar.write_bytes(self.jar_bytes())
            with mock.patch.object(GATE.urllib.request, 'urlopen', side_effect=AssertionError('unexpected download')):
                self.assertEqual(GATE.android_json_dependency(root, {'ANDROID_JSON_JAR': str(jar)}), jar.resolve())
                with mock.patch.object(GATE, 'SYSTEM_JSON_JAR', jar):
                    self.assertEqual(GATE.android_json_dependency(root, {}), jar.resolve())
                for value in ('', str(root / 'missing'), str(root)):
                    with self.assertRaises((ValueError, FileNotFoundError)):
                        GATE.android_json_dependency(root, {'ANDROID_JSON_JAR': value})

    def test_corrupt_oversized_redirected_or_failed_download_is_not_published(self):
        for kind in ('hash', 'size', 'redirect', 'status', 'classes'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                data = b'x' * (GATE.MAX_JSON_JAR + 1) if kind == 'size' else self.jar_bytes()
                if kind == 'classes':
                    b = io.BytesIO()
                    with zipfile.ZipFile(b, 'w') as z:
                        z.writestr('not-json.class', b'no')
                    data = b.getvalue()
                response = self.response(data)
                if kind == 'redirect': response.geturl.return_value = 'https://unowned.invalid/file.jar'
                if kind == 'status': response.status = 503
                checksum = '0' * 64 if kind == 'hash' else hashlib.sha256(data).hexdigest()
                with mock.patch.object(GATE, 'SYSTEM_JSON_JAR', root / 'missing'), mock.patch.object(GATE, 'ANDROID_JSON_SHA256', checksum), mock.patch.object(GATE.urllib.request, 'urlopen', return_value=response):
                    with self.assertRaises(ValueError):
                        GATE.android_json_dependency(root, {})
                self.assertFalse((root / 'android-json.jar').exists())

    def test_jar_is_selected_before_host_graph_compilation(self):
        script = (ROOT / 'deploy/test_android_multihop_pinned.py').read_text()
        start = script.index('def run(')
        self.assertLess(script.index("env['ANDROID_JSON_JAR'] =", start), script.index("subprocess.run([sys.executable", start))

    def test_exact_complete_matrix_and_no_extra_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.populate(root)
            GATE.require_fixture_matrix(root)
            self.assertEqual(len(list(root.glob('*/*.json'))), 150)
            extra = root / 'shadowsocks-wg-local' / 'unexpected.txt'
            extra.write_text('unowned')
            with self.assertRaises(ValueError):
                GATE.require_fixture_matrix(root)

    def test_missing_empty_and_oversized_graphs_fail(self):
        for mutation in ('missing', 'empty', 'oversized'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                self.populate(root)
                path = root / 'hysteria2-awg2-fast-auto' / 'planned.json'
                if mutation == 'missing':
                    path.unlink()
                elif mutation == 'empty':
                    path.write_text('')
                else:
                    with path.open('wb') as stream:
                        stream.truncate(4 * 1024 * 1024 + 1)
                with self.assertRaises((ValueError, FileNotFoundError)):
                    GATE.require_fixture_matrix(root)

    def test_symlinks_and_extra_empty_directories_fail(self):
        for mutation in ('file-link', 'folder-link', 'extra-directory'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                self.populate(root)
                folder = root / 'shadowsocks-wg-local'
                if mutation == 'file-link':
                    (folder / 'planned.json').unlink()
                    (folder / 'planned.json').symlink_to(folder / 'sing-box.json')
                elif mutation == 'folder-link':
                    (folder / 'unowned').symlink_to(root / 'hysteria2-wg-local', target_is_directory=True)
                else:
                    (folder / 'extra-empty').mkdir()
                with self.assertRaises(ValueError):
                    GATE.require_fixture_matrix(root)

    def test_cached_native_build_binds_the_java_compiler_inputs(self):
        paths = GATE.inputs()
        self.assertEqual(len(paths), len(set(paths)))
        for name in GATE.JAVA_NAMES:
            self.assertTrue(any(path.name == name + '.java' for path in paths))
        before = GATE.digest()
        original_read = Path.read_bytes
        changed = ROOT / 'android/app/src/main/java/com/eabusham/routervpn/AndroidMultihopController.java'
        with mock.patch.object(Path, 'read_bytes', lambda p: original_read(p) + (b'\n// changed graph\n' if p == changed else b'')):
            self.assertNotEqual(before, GATE.digest())
        shell = (ROOT / 'android/build-sing-box-libbox.sh').read_text()
        self.assertIn('"$OPENVPN_SHA" "$ANDROID_GRAPH_SHA"', shell)
        self.assertLess(shell.index('ANDROID_GRAPH_SHA='), shell.index('if [[ -s "$AAR"'))
        self.assertLess(shell.index('test_android_multihop_pinned.py" "$VENDOR"'), shell.index('go_retry run ./cmd/internal/build_libbox -target android'))
        self.assertIn('routerCompileProxyEntry', shell)
        self.assertIn('routerMultihopMTUProfile', shell)
        gradle = (ROOT / 'android/app/build.gradle').read_text()
        self.assertIn("fileTree('src/main/java/com/eabusham/routervpn')", gradle)
        self.assertIn("rootProject.file('../deploy/test_android_multihop_pinned.py')", gradle)

    def test_gate_runs_exact_native_test_and_negative_controls(self):
        script = (ROOT / 'deploy/test_android_multihop_pinned.py').read_text()
        template = (ROOT / 'mobile/routervpn_multihop_native_test.go.tmpl').read_text()
        self.assertIn("env['ROUTERVPN_REQUIRE_ANDROID_GRAPH_FIXTURES'] = '1'", script)
        self.assertIn("'^TestRouterMultihopAndroidGeneratedGraphs$'", script)
        self.assertIn('require_fixture_matrix(fixtures)', script)
        self.assertIn('native_test.read_bytes()', script)
        self.assertIn('required Android fixture matrix is missing', template)
        self.assertIn('CheckConfig(string(raw))', template)
        self.assertIn('CheckConfig(string(bad))', template)
        self.assertIn('if checks != 150', template)
        self.assertNotIn('t.Parallel()', template)


if __name__ == '__main__':
    unittest.main()
