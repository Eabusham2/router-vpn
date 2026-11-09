#!/usr/bin/env python3
"""Execute the XHTTP CI wiring contract without simulating native evidence.

The build AST and focused shell are the shipping callers. Captured subprocesses
prove mandatory order, original deadlines and failure propagation only; the
separate native runner owns all source inventories and protocol verdicts.
"""
import ast
import copy
import contextlib
import fnmatch
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT/'deploy/build-native-runtime.py'
WORKFLOW = ROOT/'.github/workflows/imported-socks-reality-native.yml'
XHTTP_WORKFLOW = ROOT/'.github/workflows/imported-xhttp-native.yml'
GATE = 'test_mobile_imported_xhttp_xray.py'
CHECKS = ('test_imported_xhttp_workflow.py', 'test_mobile_imported_xhttp_xray_runner.py')
STAGES = (('parser', (), 1200), ('loopback', ('--loopback-only',), 1200),
          ('reference', ('--reference-only',), 3000))
ORDINARY = (
    ('test_mobile_imported_socks_xray.py', ('--reference-only',)),
    ('test_mobile_imported_proxy_xray.py', ('--reference-only',)),
    ('test_mobile_imported_connect_xray.py', ('--reference-only',)),
    ('test_native_imported_packet_xray.py', ()),
    ('test_native_xray_udp443.py', ()),
)
KINDS = ('socks5', 'shadowsocks', 'hysteria2', 'http-connect', 'https-connect',
         'wireguard', 'amneziawg', 'openvpn-tcp', 'openvpn-udp')


def section(source, marker, indentation):
    """Read one known workflow block; this is not a general YAML parser."""
    lines = source.splitlines(keepends=True)
    found = [i for i, line in enumerate(lines) if line.rstrip() == ' '*indentation+marker]
    if len(found) != 1:
        raise AssertionError('Workflow block is missing or duplicated: '+marker)
    start = found[0]
    end = next((i for i in range(start+1, len(lines)) if lines[i].strip()
                and len(lines[i])-len(lines[i].lstrip()) <= indentation), len(lines))
    return ''.join(lines[start:end])


def native_stage(source):
    tree = ast.parse(source)
    found = []
    def visit(node, conditions=()):
        if isinstance(node, ast.If):
            expression = ast.unparse(node.test)
            if expression == "target.startswith(('linux/', 'windows/'))":
                found.append((node, conditions))
            conditions += (expression,)
        for child in ast.iter_child_nodes(node):
            visit(child, conditions)
    visit(tree)
    if len(found) != 1 or 'target == host' not in found[0][1]:
        raise AssertionError('Native references lost their exact host execution boundary')
    return ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(found[0][0])], type_ignores=[]))


def capture_native(source, target, failure=None):
    calls = []
    def run(command, **options):
        command = [str(part) for part in command]
        calls.append((command, options))
        name = Path(command[1]).name
        stage = command[-1] if name == GATE and command[-1].startswith('--') else name
        if failure == stage:
            raise RuntimeError('modeled subprocess failure: '+stage)
    namespace = dict(ROOT=ROOT, sys=sys, target=target, source=Path('captured-core'),
                     pq=Path('captured-pq'), cache=None, env={'CAPTURED_ENV': '1'}, run=run)
    try:
        exec(compile(native_stage(source), str(BUILDER), 'exec'), namespace)
    except RuntimeError as error:
        if failure is None or not str(error).startswith('modeled subprocess failure: '):
            raise
        return calls, error
    return calls, None


class ImportedXHTTPWorkflow(unittest.TestCase):
    def check_native(self, source, *, mutation=False):
        for target in ('linux/amd64', 'linux/arm64', 'windows/amd64', 'windows/arm64',
                       'darwin/amd64', 'darwin/arm64'):
            with contextlib.nullcontext() if mutation else self.subTest(target=target):
                calls, error = capture_native(source, target)
                self.assertIsNone(error)
                indexed = [(i, command, options) for i, (command, options) in enumerate(calls)]
                pq = [(i, command, options) for i, command, options in indexed
                      if Path(command[1]).name in (*CHECKS, GATE)]
                self.assertEqual(len(pq), 5 if target.startswith('linux/') else 0)
                if not target.startswith('linux/'):
                    continue
                previous = -1
                for filename, arguments in ORDINARY:
                    matched = [(i, command, options) for i, command, options in indexed
                               if Path(command[1]).name == filename]
                    self.assertEqual(len(matched), 1)
                    index, command, options = matched[0]
                    self.assertGreater(index, previous)
                    self.assertEqual(command[2:], ['captured-core', *arguments])
                    self.assertEqual(options, {'env': {'CAPTURED_ENV': '1'}, 'timeout': 3000})
                    previous = index
                self.assertGreater(pq[0][0], previous)
                for (_, command, options), filename in zip(pq[:2], CHECKS):
                    self.assertEqual(command, [sys.executable, str(ROOT/'deploy'/filename)])
                    self.assertEqual(options, {'cwd': ROOT, 'env': {'CAPTURED_ENV': '1'}, 'timeout': 60})
                for (_, command, options), (_, arguments, timeout) in zip(pq[2:], STAGES):
                    self.assertEqual(command, [sys.executable, str(ROOT/'deploy'/GATE), 'captured-core', *arguments])
                    self.assertEqual(options, {'env': {'CAPTURED_ENV': '1'}, 'timeout': timeout})

    def test_authoritative_host_stages_keep_ordinary_gates_and_deadlines(self):
        self.check_native(BUILDER.read_text())

    def test_every_pq_stage_failure_stops_the_authoritative_build(self):
        source = BUILDER.read_text()
        expected, _ = capture_native(source, 'linux/amd64')
        for failure in (*CHECKS, GATE, '--loopback-only', '--reference-only'):
            with self.subTest(failure=failure):
                calls, error = capture_native(source, 'linux/amd64', failure)
                self.assertIsNotNone(error)
                self.assertEqual(calls, expected[:len(calls)])
                self.assertLess(len(calls), len(expected))
                self.assertNotIn('test_desktop_node_pq.py', [Path(command[1]).name for command, _ in calls])

    def test_removed_stage_or_changed_deadline_is_detected(self):
        original = BUILDER.read_text()
        for old, new in (("source, '--loopback-only'], env=env, timeout=1200)",
                          "source, '--reference-only'], env=env, timeout=1200)"),
                         ("source, '--reference-only'], env=env, timeout=3000)",
                          "source, '--reference-only'], env=env, timeout=1)")):
            with self.subTest(change=new), self.assertRaises(AssertionError):
                self.check_native(original.replace(old, new), mutation=True)

    def test_new_gate_and_contract_are_in_the_native_source_identity(self):
        tree = ast.parse(BUILDER.read_text())
        inputs = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'inputs')
        values = {node.value for node in ast.walk(inputs) if isinstance(node, ast.Constant) and isinstance(node.value, str)}
        for filename in (GATE, *CHECKS):
            self.assertIn('deploy/'+filename, values)
        self.assertIn('mobile/routervpn_imported_xhttp_xray_native_test.go.tmpl', values)
        self.assertIn('android/test_android_imported_router.py', values)
        self.assertIn('.github/workflows/imported-socks-reality-native.yml', values)
        self.assertIn('.github/workflows/imported-xhttp-native.yml', values)
        self.assertIn('.github/workflows/release-candidate.yml', values)

    def focused_shell(self):
        workflow = WORKFLOW.read_text()
        ordinary = section(workflow, 'imported-socks-reality-reference:', 2)
        caller = section(workflow, 'imported-xhttp-reference:', 2)
        self.assertIn('    needs: imported-pq-reality-reference\n', caller)
        self.assertIn('    uses: ./.github/workflows/imported-xhttp-native.yml\n', caller)
        self.assertNotIn('if:', caller)
        pq_source = XHTTP_WORKFLOW.read_text()
        self.assertIn('  workflow_call:\n', pq_source)
        pq = section(pq_source, 'imported-xhttp-reference:', 2)
        self.assertIn('    timeout-minutes: 60\n', ordinary)
        self.assertEqual(ordinary.count('        timeout-minutes: 50\n'), 4)
        for filename, _ in ORDINARY:
            if filename != 'test_native_imported_packet_xray.py':
                self.assertEqual(ordinary.count('python3 deploy/'+filename+' '), 1)
        self.assertIn('    needs: xhttp-apple-graphs\n', pq)
        self.assertIn('    timeout-minutes: 120\n', pq)
        self.assertIn('      GOTOOLCHAIN: go1.26.3\n', pq)
        self.assertNotIn('continue-on-error:', pq)
        self.assertNotIn('\n    if:', pq)
        self.assertNotIn('\n        if:', pq)
        prepare = section(pq, '- name: Prepare the exact captured XHTTP desktop reference sources', 6)
        for pin in ('1ac1a339cb1223e9c70eae14c44411c75033c02d', '50231eaff98ccc31b5cbd247a721c16e97fe5ec1'):
            self.assertEqual(prepare.count('fetch --depth=1 origin '+pin), 1)
        for filename in ('prepare-relay-core.py', 'prepare-mobile-performance.py', 'mobile_openvpn_close_policy.py',
                         'prepare-desktop-external.py', 'prepare-mobile-buffers.py'):
            self.assertEqual(prepare.count('python3 deploy/'+filename+' '), 1)
        step = section(pq, '- name: Execute separate XHTTP parser protocol and imported peer inventories', 6)
        self.assertIn('        timeout-minutes: 90\n', step)
        return textwrap.dedent(step.split('        run: |\n', 1)[1])

    def run_focused(self, failure='', *, producers=False):
        script = self.focused_shell()
        if producers:
            step = section(XHTTP_WORKFLOW.read_text(), '- name: Export all 81 actual Android and desktop XHTTP source graphs', 6)
            script = textwrap.dedent(step.split('        run: |\n', 1)[1])
        with tempfile.TemporaryDirectory(prefix='xhttp-workflow-contract-') as temporary:
            work = Path(temporary)
            log = work/'calls.bin'
            executable = work/'python3'
            # Shell builtins capture argv without launching a Python runtime
            # for every modeled command while native CI compilers are active.
            executable.write_text(textwrap.dedent('''\
                #!/bin/bash
                printf '%s\\0' "$@" >> "$XHTTP_CALL_LOG"
                printf '\\0' >> "$XHTTP_CALL_LOG"
                stage=${1##*/}
                last=${!#}
                if [[ "$stage" == test_mobile_imported_xhttp_xray.py && "$last" == --* ]]; then
                    stage=$last
                fi
                if [[ "$stage" == "${XHTTP_FAILED_STAGE:-}" ]]; then exit 19; fi
                '''))
            executable.chmod(0o700)
            go = work/'go'
            go.write_bytes(executable.read_bytes())
            go.chmod(0o700)
            env = dict(os.environ, PATH=str(work)+os.pathsep+os.environ.get('PATH', ''),
                       RUNNER_TEMP=str(work), XHTTP_CALL_LOG=str(log), XHTTP_FAILED_STAGE=failure)
            completed = subprocess.run(['bash', '-c', script], env=env, capture_output=True, text=True, timeout=10)
            calls = [[part.decode() for part in record.split(b'\0')]
                     for record in log.read_bytes().split(b'\0\0') if record] if log.exists() else []
            expected = [['deploy/'+name] for name in CHECKS] + [
                ['deploy/'+GATE, str(work/'routervpn-imported-xhttp-core'), *arguments]
                for _, arguments, _ in STAGES]
            expected[2].extend(['--android', str(work/'xhttp-android'), '--apple', str(work/'xhttp-apple'),
                                '--desktop', str(work/'xhttp-desktop')])
            if producers:
                expected = [['android/test_android_imported_router.py',
                             *(part for kind in KINDS for part in ('--phase', 'xhttp--'+kind))],
                            ['test', '-race', './cmd/client', '-run', '^TestDesktopImportedXHTTP', '-count=1', '-timeout=180s']]
            return completed, calls, expected

    def test_focused_shell_executes_all_three_separate_stages(self):
        completed, calls, expected = self.run_focused()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(calls, expected)

    def test_focused_shell_stops_at_each_failed_stage(self):
        for index, failure in enumerate((*CHECKS, GATE, '--loopback-only', '--reference-only')):
            with self.subTest(failure=failure):
                completed, calls, expected = self.run_focused(failure)
                self.assertEqual(completed.returncode, 19, completed.stderr)
                self.assertEqual(calls, expected[:index+1])

    def test_actual_host_producers_are_required_before_native_parsing(self):
        workflow = XHTTP_WORKFLOW.read_text()
        apple = section(workflow, 'xhttp-apple-graphs:', 2)
        self.assertIn('    runs-on: macos-15\n', apple)
        self.assertIn('    timeout-minutes: 20\n', apple)
        self.assertIn('          ROUTERVPN_APPLE_IMPORTED_XHTTP_XRAY_FIXTURES: ${{ runner.temp }}/xhttp-apple\n', apple)
        self.assertEqual(apple.count('python3 deploy/test_ios_tor_profile.py\n'), 1)
        self.assertIn('      - uses: actions/upload-artifact@v4\n', apple)
        self.assertIn('          if-no-files-found: error\n', apple)
        self.assertNotIn('continue-on-error:', apple)
        self.assertNotIn('if:', apple)
        pq = section(workflow, 'imported-xhttp-reference:', 2)
        download = '      - uses: actions/download-artifact@v4\n        with:\n          name: imported-xhttp-apple-graphs\n          path: ${{ runner.temp }}/xhttp-apple\n'
        self.assertIn(download, pq)
        self.assertIn('          name: imported-xhttp-apple-graphs\n', apple)
        self.assertIn('      - uses: actions/setup-java@v5\n', pq)
        self.assertIn('          distribution: temurin\n          java-version: \'21\'\n', pq)
        self.assertIn('sudo apt-get install -y --no-install-recommends libandroid-json-java\n', pq)
        producer = section(pq, '- name: Export all 81 actual Android and desktop XHTTP source graphs', 6)
        self.assertIn('        timeout-minutes: 20\n', producer)
        for name in ('ANDROID', 'DESKTOP'):
            self.assertIn('          ROUTERVPN_'+name+'_IMPORTED_XHTTP_XRAY_FIXTURES: ${{ runner.temp }}/xhttp-'+name.lower()+'\n', producer)
        self.assertLess(pq.index(download), pq.index(producer))
        self.assertLess(pq.index(producer), pq.index('- name: Execute separate XHTTP parser protocol and imported peer inventories'))
        completed, calls, expected = self.run_focused(producers=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(calls, expected)

    def test_changed_producers_and_gate_schedule_the_focused_workflow(self):
        paths = WORKFLOW.read_text().split('    paths:\n', 1)[1].split('\npermissions:', 1)[0]
        patterns = [ast.literal_eval(line.strip()[2:]) for line in paths.splitlines() if line.strip().startswith('- ')]
        for source in ('internal/mobilemultihop/imported_entry.go', 'mobile/routervpn_imported_xhttp_xray_native_test.go.tmpl',
                       'android/app/src/main/java/com/eabusham/routervpn/AndroidImportedRouterPath.java',
                       'ios/RouterVPN/App/IOSMultihopExecution.swift', 'cmd/client/multihop_native_imported_xhttp_test.go',
                       'cmd/client/multihop_native_routes.go', 'cmd/client/controller_windows_catalog.go',
                       'deploy/'+GATE, 'deploy/'+CHECKS[0], 'deploy/'+CHECKS[1],
                       '.github/workflows/imported-xhttp-native.yml'):
            self.assertTrue(any(fnmatch.fnmatchcase(source, pattern) for pattern in patterns), source)

    def test_release_still_requires_actual_linux_host_builds(self):
        release = (ROOT/'.github/workflows/release-candidate.yml').read_text()
        native = section(release, 'native-runtimes:', 2)
        self.assertIn('    uses: ./.github/workflows/desktop-native-runtime.yml\n', native)
        self.assertIn('      platform: all\n', native)
        self.assertNotIn('if:', native)
        self.assertIn('    needs: native-runtimes\n', section(release, 'generic-builds:', 2))
        self.assertIn('generic-builds', section(release, 'aggregate:', 2).split('    needs: ', 1)[1].splitlines()[0])
        pq = section(release, 'imported-xhttp:', 2)
        self.assertIn('    uses: ./.github/workflows/imported-xhttp-native.yml\n', pq)
        self.assertNotIn('if:', pq)
        self.assertNotIn('continue-on-error:', pq)
        self.assertIn('imported-xhttp', section(release, 'aggregate:', 2).split('    needs: ', 1)[1].splitlines()[0])
        desktop = (ROOT/'.github/workflows/desktop-native-runtime.yml').read_text()
        for row in ("('linux', 'amd64', 'ubuntu-24.04')", "('linux', 'arm64', 'ubuntu-24.04-arm')"):
            self.assertIn(row, section(desktop, 'targets:', 2))
        build = section(desktop, '- name: Build and validate the complete native engine', 6)
        self.assertIn('python3 deploy/build-native-runtime.py "${runtime_args[@]}"', build)
        self.assertNotIn('\n        if:', build)
        self.assertNotIn('continue-on-error:', build)
        self.assertIn("output.write('sha256='+build.digest()", desktop)
        self.assertIn('${{ steps.policy.outputs.sha256 }}', desktop)


if __name__ == '__main__':
    unittest.main()
