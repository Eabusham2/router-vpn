#!/usr/bin/env python3
"""Gate-contract checks; synthetic events are never native acceptance."""
import ast
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('socks_final_layers', ROOT/'deploy/test_socks_server_final_layers.py')
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)

def require_registration(builder, workflow, release):
    """Pin the actual required Linux builder block, not diagnostic token presence."""
    tree = ast.parse(builder)
    blocks = [node for node in ast.walk(tree) if isinstance(node, ast.If)
              and any(isinstance(child, ast.Constant) and child.value == '^TestRouterVPNNodeSOCKSServer'
                      for child in ast.walk(node))
              and ast.dump(node.test) == ast.dump(ast.parse("target.startswith('linux/')", mode='eval').body)]
    if len(blocks) != 1:
        raise ValueError('original Linux SOCKS native boundary missing or repeated')
    expected = ast.parse("""if target.startswith('linux/'):
    run(['go', 'test', *race, '-p=1', '-mod=readonly', '-tags='+','.join(tags(target)),
         '-ldflags=-checklinkname=0', './protocol/routervpnamnezia', '-run', '^TestRouterVPNNodeSOCKSServer',
         '-count=1', '-timeout=120s'], cwd=source, env=env, timeout=600)
    run([sys.executable, ROOT/'deploy/test_socks_server_final_layers_runner.py'], cwd=ROOT, env=env, timeout=60)
    run([sys.executable, ROOT/'deploy/test_socks_server_final_layers.py', '--core', source,
         '--tags='+','.join(tags(target))], cwd=source, env=env, timeout=1900)
""").body[0]
    if ast.dump(blocks[0]) != ast.dump(expected):
        raise ValueError('mandatory layered suffix stages changed, skipped or weakened')
    inputs = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'inputs')
    paths = [node.value for node in ast.walk(inputs) if isinstance(node, ast.Constant) and isinstance(node.value, str)]
    for name in ('deploy/test_socks_server_final_layers.py', 'deploy/test_socks_server_final_layers_runner.py', '.github/workflows/desktop-native-runtime.yml'):
        if paths.count(name) != 1:
            raise ValueError('layer gate is not in original bundle fingerprint exactly once')
    accepting = '''      - name: Build and validate the complete native engine
        shell: bash
        run: |
          set -euo pipefail
          python3 deploy/test_socks_server_final_layers_runner.py
          python3 deploy/test_linux_native_concurrency.py
'''
    if workflow.count(accepting) != 1 or workflow.count('python3 deploy/test_socks_server_final_layers_runner.py') != 1:
        raise ValueError('required workflow layer contract skipped or duplicated')
    for row in ("('linux', 'amd64', 'ubuntu-24.04')", "('linux', 'arm64', 'ubuntu-24.04-arm')"):
        if workflow.count(row) != 1:
            raise ValueError('native Linux architecture omitted')
    if '          python3 deploy/build-native-runtime.py "${runtime_args[@]}"\n' not in workflow:
        raise ValueError('actual native builder invocation omitted')
    required = '''  native-runtimes:
    name: Build and verify complete native runtimes
    uses: ./.github/workflows/desktop-native-runtime.yml
    with:
      platform: all
'''
    if release.count(required) != 1 or '  linux:\n    needs: native-runtimes\n' not in release:
        raise ValueError('exact-source runtime gate detached from authoritative release')


def event(package, action, test=None, output=None):
    row = {'Package': G.RECEIPT.MODULE+'/'+package, 'Action': action}
    if test is not None: row['Test'] = test
    if output is not None: row['Output'] = output
    return row


def transcript(package):
    rows = [event(package, 'start')]
    for root, children in G.CASES[package].items():
        rows.append(event(package, 'run', root))
        for child in children:
            rows.extend((event(package, 'run', root+'/'+child), event(package, 'pass', root+'/'+child)))
        rows.append(event(package, 'pass', root))
    return rows+[event(package, 'pass')]


def failure():
    return [event(G.NATIVE, 'start'), event(G.NATIVE, 'run', G.CONTROL_ROOT),
            event(G.NATIVE, 'run', G.CONTROL_LEAF), event(G.NATIVE, 'output', G.CONTROL_LEAF, G.CONTROL_WITNESS+' refused'),
            event(G.NATIVE, 'fail', G.CONTROL_LEAF), event(G.NATIVE, 'fail', G.CONTROL_ROOT), event(G.NATIVE, 'fail')]


def encode(rows): return '\n'.join(json.dumps(row) for row in rows)+'\n'


class SOCKSFinalLayerRunner(unittest.TestCase):
    def test_required_native_workflow_and_original_block(self):
        builder = (ROOT/'deploy/build-native-runtime.py').read_text()
        workflow = (ROOT/'.github/workflows/desktop-native-runtime.yml').read_text()
        release = (ROOT/'.github/workflows/release-candidate.yml').read_text()
        require_registration(builder, workflow, release)
        mutations = (
            (builder.replace("ROOT/'deploy/test_socks_server_final_layers.py',", "ROOT/'deploy/omitted.py',", 1), workflow, release),
            (builder.replace("timeout=1900", "timeout=1"), workflow, release),
            (builder.replace("'--core', source, '--tags='", "'--core', 'foreign', '--tags='"), workflow, release),
            (builder.replace("'^TestRouterVPNNodeSOCKSServer'", "'^TestRouterVPNLayeredSOCKSServer'"), workflow, release),
            (builder.replace("run([sys.executable, ROOT/'deploy/test_socks_server_final_layers.py',", "False and run([sys.executable, ROOT/'deploy/test_socks_server_final_layers.py',"), workflow, release),
            (builder, workflow.replace('          python3 deploy/test_socks_server_final_layers_runner.py\n', ''), release),
            (builder, workflow.replace('          python3 deploy/test_socks_server_final_layers_runner.py', '          python3 deploy/test_socks_server_final_layers_runner.py || true'), release),
            (builder, workflow.replace('      - name: Build and validate the complete native engine\n', '      - name: Build and validate the complete native engine\n        if: false\n'), release),
            (builder, workflow.replace("('linux', 'arm64', 'ubuntu-24.04-arm')", "('linux', 'omitted', 'ubuntu-24.04-arm')"), release),
            (builder, workflow, release.replace('  linux:\n    needs: native-runtimes', '  linux:\n    needs: source-audit')),
            (builder, workflow, release.replace('      platform: all', '      platform: windows')),
        )
        for name in ('deploy/test_socks_server_final_layers.py', 'deploy/test_socks_server_final_layers_runner.py', '.github/workflows/desktop-native-runtime.yml'):
            needle = "ROOT/'"+name+"',"
            for change in ('', needle+' '+needle):
                with self.subTest(input=name, change=change), self.assertRaises(ValueError):
                    require_registration(builder.replace(needle, change, 1), workflow, release)
        for i, values in enumerate(mutations):
            with self.subTest(mutation=i), self.assertRaises(ValueError): require_registration(*values)

    def test_exact_independent_and_encrypted_inventory(self):
        self.assertEqual([len(G.RECEIPT.names(roots)) for roots in G.CASES.values()], [18, 12])
        for package in G.CASES:
            raw = transcript(package)
            self.assertEqual(len(G.RECEIPT.verdict(encode(raw), 0, package, G.CASES[package])), len(G.RECEIPT.names(G.CASES[package])))
            for i in range(len(raw)):
                for changed in (raw[:i]+raw[i+1:], raw[:i]+[raw[i]]+raw[i:]):
                    with self.assertRaises(ValueError): G.RECEIPT.verdict(encode(changed), 0, package, G.CASES[package])

    def test_foreign_failed_skipped_racing_and_wrong_exit_refused(self):
        for package in G.CASES:
            rows = transcript(package)
            for action in ('fail', 'skip', 'pause'):
                changed = [dict(row) for row in rows];changed[3]['Action'] = action
                with self.assertRaises(ValueError): G.RECEIPT.verdict(encode(changed), 0, package, G.CASES[package])
            for name, value in (('Package', 'github.com/foreign/owner'), ('Output', 'WARNING: DATA RACE')):
                changed = [dict(row) for row in rows];changed[1][name] = value
                with self.assertRaises(ValueError): G.RECEIPT.verdict(encode(changed), 0, package, G.CASES[package])
            with self.assertRaises(ValueError): G.RECEIPT.verdict(encode(rows), 1, package, G.CASES[package])

    def test_original_off_guard_requires_actual_failure_witness(self):
        rows = failure();G.control_verdict(encode(rows), 1)
        for i in range(len(rows)):
            for changed in (rows[:i]+rows[i+1:], rows[:i]+[rows[i]]+rows[i:]):
                with self.assertRaises(ValueError): G.control_verdict(encode(changed), 1)
        for code in (0, 2, -9):
            with self.assertRaises(ValueError): G.control_verdict(encode(rows), code)
        for text in ('unrelated refusal', 'panic: original owner', 'DATA RACE', 'build failed'):
            changed = [dict(row) for row in rows];changed[3]['Output'] = text
            with self.assertRaises(ValueError): G.control_verdict(encode(changed), 1)
        changed = [dict(row) for row in rows];changed[3]['Test'] = G.CONTROL_ROOT
        with self.assertRaises(ValueError): G.control_verdict(encode(changed), 1)

    def test_current_actual_preparation_bytes_required(self):
        with tempfile.TemporaryDirectory() as directory:
            core = Path(directory)
            contents = G.source_contents(core)
            self.assertEqual(len(contents), 5)
            for relative, raw in contents.items():
                target = core/relative;target.parent.mkdir(parents=True, exist_ok=True);target.write_bytes(raw)
            self.assertEqual(set(G.checked_sources(core)), set(contents))
            for relative, raw in contents.items():
                target = core/relative;target.write_bytes(raw+b'\n')
                with self.assertRaises(ValueError): G.checked_sources(core)
                target.write_bytes(raw)
            target = core/G.OWNER;target.unlink();target.symlink_to(ROOT/'mobile/chain/socks_server_owner.go.tmpl')
            with self.assertRaises(ValueError): G.checked_sources(core)

    def test_bounded_phases_and_real_off_guard_overlay_are_mandatory(self):
        with tempfile.TemporaryDirectory() as directory:
            core = Path(directory);target = core/G.OWNER;target.parent.mkdir(parents=True)
            original = (ROOT/'mobile/chain/socks_server_owner.go.tmpl').read_text();target.write_text(original)
            calls = []
            def run(args, **kwargs):
                calls.append(args)
                self.assertEqual(kwargs['timeout'], 600)
                self.assertIn('-timeout=120s', args);self.assertIn('-race', args);self.assertIn('-p=1', args)
                if len(calls) <= 2:
                    package = tuple(G.CASES)[len(calls)-1]
                    self.assertIn('./'+package, args)
                    self.assertEqual(args[-1], '^('+'|'.join(map(G.re.escape, G.CASES[package]))+')$')
                    return subprocess.CompletedProcess(args, 0, encode(transcript(package)))
                overlay = Path(next(x.removeprefix('-overlay=') for x in args if x.startswith('-overlay=')))
                mapping = json.loads(overlay.read_text())['Replace'];self.assertEqual(set(mapping), {str(target)})
                self.assertEqual(Path(mapping[str(target)]).read_text(), original.replace(G.CONTROL_ANCHOR, G.CONTROL_INSERT+G.CONTROL_ANCHOR, 1))
                self.assertEqual(target.read_text(), original)
                return subprocess.CompletedProcess(args, 1, encode(failure()))
            with patch.object(G.subprocess, 'check_output', return_value=G.PIN+'\n'), patch.object(G, 'checked_sources', return_value={'source': 'original'}), patch.object(G.subprocess, 'run', side_effect=run), contextlib.redirect_stdout(io.StringIO()):
                G.execute(core, 'go', G.TAGS)
            self.assertEqual(len(calls), 3)
            self.assertEqual(target.read_text(), original)
            with patch.object(G.subprocess, 'check_output', return_value=G.PIN+'\n'), patch.object(G, 'checked_sources', return_value={'source': 'original'}), patch.object(G.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '')) as child, contextlib.redirect_stdout(io.StringIO()), self.assertRaises(ValueError):
                G.execute(core, 'go', G.TAGS)
            self.assertEqual(child.call_count, 1)


if __name__ == '__main__': unittest.main()
