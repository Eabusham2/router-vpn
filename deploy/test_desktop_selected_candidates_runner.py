#!/usr/bin/env python3
"""Check the native selected-candidate gate's inventory, input identity and deadlines."""
import ast
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('selected_candidate_gate', ROOT/'deploy/test_desktop_selected_candidates.py')
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)

PREFIX = 'TestRouterVPNDesktopSelectedPacketCandidate'
PACKAGE = GATE.LATENCY.ORIGINAL.CHILD.MODULE+'/cmd/sing-box'
FIFTY = ('server', 'compare-server', 'compare-local', 'ordinary-entry')
REFUSALS = ('pre-metadata-cancel', 'expired-before-prepare', 'unadmitted-final', 'foreign-start-hash',
            'foreign-metadata-inode', 'foreign-source-inode', 'stale-pulse', 'foreign-revision',
            'foreign-selected-capture', 'cancel-after-metadata', 'failed-stop-retry')
PUBLICATION = ('before-link', 'after-link', 'result-before-link', 'result-after-link',
               'result-retry', 'result-foreign-before-prepare')
PHASES = [(PREFIX+'Fifty', (child,), '^'+PREFIX+'Fifty$/^'+child+'$') for child in FIFTY]
PHASES += [(PREFIX+suffix, children, '^'+PREFIX+suffix+'$') for suffix, children in (
    ('Refusals', REFUSALS), ('Generation', ()), ('Publication', PUBLICATION))]
RESPONSE_ROOT = 'TestRouterVPNDesktopSelectedServerResponseCandidate'
RESPONSE_CASES = ('server', 'compare-server', 'wrong-mac', 'wrong-operation')
PHASES += [(RESPONSE_ROOT,(child,), '^'+RESPONSE_ROOT+'$/^'+child+'$') for child in RESPONSE_CASES]
TYPED_ROOT = 'TestRouterVPNDesktopSelectedTypedEntryCandidate'
TYPED_ENTRIES = tuple(family+'-'+outcome for family in ('socks', 'connect') for outcome in
                      ('server', 'compare-local', 'compare-server', 'later-position'))
TYPED_PHASES = [(TYPED_ROOT, (child,), '^'+TYPED_ROOT+'$/^'+child+'$') for child in TYPED_ENTRIES]
CAUSAL = '^'+PREFIX+'Refusals$/^foreign-metadata-inode$'
WITNESS = 'selected candidate started with a replaced original inode'
TARGET = 'cmd/sing-box/routervpn_node_chain_execution_candidate.go'
ANCHOR = '!os.SameFile(f.info, actual.info) || '
PRIVATE = 'ROUTERVPN_MULTIPLE_IMPORTED_EXECUTION_NATIVE_FIXTURES'


def rows(root, children, package=PACKAGE, witness=None):
    def event(action, test=None, output=None):
        value = {'Action': action, 'Package': package}
        if test is not None:
            value['Test'] = test
        if output is not None:
            value['Output'] = output
        return value

    terminal = 'fail' if witness is not None else 'pass'
    events = [event('start'), event('run', root)]
    for child in children:
        name = root+'/'+child
        events.append(event('run', name))
        if witness is not None:
            events.append(event('output', name, witness))
        events.append(event(terminal, name))
    return events+[event(terminal, root), event(terminal)]


def encode(events):
    return '\n'.join(map(json.dumps, events))


class SelectedCandidateRunner(unittest.TestCase):
    def test_exact_native_source_inventory_and_measurement(self):
        source = (ROOT/'mobile/desktop/node_chain_execution_candidate_test.go.tmpl').read_text()
        roots = re.findall(r'^func (Test\w+)\(', source, re.M)
        self.assertEqual(roots, [PREFIX+'Fifty', TYPED_ROOT, PREFIX+'Refusals', PREFIX+'Generation', PREFIX+'Publication', RESPONSE_ROOT])
        self.assertEqual(GATE.RESPONSE_CASES, RESPONSE_CASES)
        self.assertEqual(GATE.RESPONSE_ROOT, RESPONSE_ROOT)
        self.assertEqual((GATE.TYPED_ROOT,GATE.TYPED_ENTRIES),(TYPED_ROOT,TYPED_ENTRIES))
        self.assertEqual(tuple(re.findall(r'\{"([\w-]+)", "(?:auto|server)",', source.split('func exerciseDesktopSelectedCandidateFifty(',1)[0])), FIFTY)
        for loop, expected, section in (('fault', REFUSALS, source.split('func '+PREFIX+'Refusals(', 1)[1]),
                                        ('race', PUBLICATION[:2], source.split('func '+PREFIX+'Publication(', 1)[1]),
                                        ('fault', PUBLICATION[2:], source.split('func '+PREFIX+'Publication(', 1)[1])):
            match = re.search(r'for _, '+loop+r' := range \[\]string\{([^}]+)\}', section)
            self.assertIsNotNone(match)
            self.assertEqual(tuple(re.findall(r'"([^"]+)"', match[1])), expected)
        self.assertEqual((GATE.PREFIX, GATE.FIFTY, GATE.REFUSALS), (PREFIX, FIFTY, REFUSALS))
        for check in ('Benchmark.Attempts != 50', 'tcp != 50', 'put != remote', 'del != remote',
                      'after.JSON() != last.JSON()', 'f.native.SelectionCount() != selection', WITNESS):
            self.assertIn(check, source)
        self.assertNotIn('t.Skip', source)

    def test_each_original_run_and_pass_record_is_required_once(self):
        for root, children, selection in PHASES+TYPED_PHASES:
            original = rows(root, children)
            def verify(events):
                return GATE.LATENCY.ORIGINAL.CHILD.verdict(encode(events), 0, 'cmd/sing-box', {root: children})
            self.assertEqual(len(verify(original)), 1+len(children))
            for i, row in enumerate(original):
                with self.subTest(selection=selection, event=row), self.assertRaises(ValueError):
                    verify(original[:i]+original[i+1:])
                with self.subTest(duplicate=selection, event=row), self.assertRaises(ValueError):
                    verify(original[:i]+[row]+original[i:])
                if row['Action'] == 'pass':
                    for action in ('skip', 'fail'):
                        with self.subTest(action=action, event=row), self.assertRaises(ValueError):
                            verify(original[:i]+[dict(row, Action=action)]+original[i+1:])
            for changed in (original+[original[-1]], [dict(row, Package='foreign') for row in original],
                            original[:2]+[dict(original[1], Test='TestForeign')]+original[2:],
                            original[:2]+[dict(original[1], Action='output', Output='DATA RACE')]+original[2:]):
                with self.assertRaises(ValueError):
                    verify(changed)
            if children:
                with self.assertRaises(ValueError):
                    verify(original[:2]+[original[-2]]+original[2:-2]+[original[-1]])

    def test_only_original_changed_inode_assertion_qualifies(self):
        root, child = PREFIX+'Refusals', 'foreign-metadata-inode'
        events = rows(root, (child,), witness=WITNESS)
        def rejected(sequence, code=1):
            return GATE.LATENCY.ORIGINAL.rejected(encode(sequence), code, root, child, WITNESS)
        self.assertTrue(rejected(events))
        for i, row in enumerate(events):
            with self.subTest(missing=row):
                self.assertFalse(rejected(events[:i]+events[i+1:]))
            if row['Action'] != 'output':
                with self.subTest(duplicate=row):
                    self.assertFalse(rejected(events[:i]+[row]+events[i:]))
        for code in (-9, 0, 2):
            self.assertFalse(rejected(events, code))
        for text in ('unrelated assertion', WITNESS+'; DATA RACE', WITNESS+'; panic: fixture failed',
                     WITNESS+'; test timed out', WITNESS+'; build failed'):
            self.assertFalse(rejected(rows(root, (child,), witness=text)))
        self.assertFalse(rejected(rows(root, ('foreign-source-inode',), witness=WITNESS)))
        self.assertFalse(rejected(rows(root, (child,))))

    def test_original_preparer_and_native_build_inputs(self):
        prep = GATE.LATENCY.load('selected_candidate_preparation_inputs', 'prepare-desktop-external.py')
        builder = GATE.LATENCY.load('selected_candidate_builder_inputs', 'build-native-runtime.py')
        inputs = set(GATE.FIXTURE.inputs())
        self.assertEqual(inputs, {ROOT/'deploy/prepare-desktop-selected-candidate-test.py',
                                  ROOT/'internal/mobilemultihop/node_chain_execution_remote_candidates_test.go',
                                  ROOT/'internal/mobilemultihop/node_chain_server_response_candidate_test.go',
                                  ROOT/'mobile/desktop_test/selected_candidate_fixture.go.tmpl'})
        templates = {ROOT/'mobile/desktop'/name for name in ('node_chain_execution_candidate.go.tmpl',
                                                              'node_chain_execution_candidate_test.go.tmpl')}
        self.assertTrue(inputs | templates <= set(prep.inputs()))
        fixture = GATE.FIXTURE.copies()
        self.assertEqual(set(fixture), {GATE.FIXTURE.TARGET})
        raw = fixture[GATE.FIXTURE.TARGET].decode()
        self.assertTrue(raw.startswith('//go:build '+GATE.LATENCY.FIXTURE.TAG+'\n'))
        for function in ('CaptureExecutionCandidateStop', 'serveCandidate', 'front'):
            self.assertRegex(raw, r'(?m)^func \([^\n]+\) '+function+r'\(')
        self.assertIn('net.Dial("tcp",r.destination.Addr().String())', raw)
        self.assertNotIn('func Test', raw)
        preparation = (ROOT/'deploy/prepare-desktop-external.py').read_text()
        self.assertIn('SELECTED_CANDIDATE_TEST.copies()', preparation)
        scripts = {Path(GATE.__file__).resolve(), Path(__file__).resolve()}
        self.assertTrue(scripts | inputs | templates <= set(builder.inputs()))
        tree = ast.parse(Path(builder.__file__).read_text())
        build = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'build')
        host = next(node for node in ast.walk(build) if isinstance(node, ast.If) and ast.unparse(node.test) == 'target == host')
        calls = [stmt.value for stmt in host.body if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call)
                 and isinstance(stmt.value.func, ast.Name) and stmt.value.func.id == 'run']
        names = [Path(__file__).name, Path(GATE.__file__).name]
        selected = [(name, ast.unparse(call)) for call in calls for name in names
                    if any(isinstance(node, ast.Constant) and node.value == 'deploy/'+name for node in ast.walk(call))]
        self.assertEqual([name for name, call in selected], names+[names[1]])
        self.assertIn("timeout=3000", selected[1][1])
        self.assertIn("timeout=1800", selected[2][1])
        self.assertIn("--phase=typed-entry", selected[2][1])
        call = selected[1][1]
        for arg in ("'--core', source", "'--tags='", 'tags(target)', "'--without-race'", 'if not race'):
            self.assertIn(arg, call)

    def exercise(self, fault=None):
        """Run real verifier orchestration against deterministic compiler and test2json doubles."""
        projection = GATE.FIXTURE.copies()
        completed = []
        checked_images = set()
        with tempfile.TemporaryDirectory() as temp:
            core = Path(temp)
            sources = dict(projection)
            for stem in ('node_chain_execution_candidate', 'node_chain_execution_candidate_test'):
                sources['cmd/sing-box/routervpn_'+stem+'.go'] = (ROOT/'mobile/desktop'/(stem+'.go.tmpl')).read_bytes()
            for relative, data in sources.items():
                target = core/relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)

            def change(stage, image, private):
                if not fault or fault[0] != stage:
                    return
                role, kind = fault[1:]
                target = {'source': core/TARGET, 'projection': core/GATE.FIXTURE.TARGET,
                          'image': image, 'private': private/(GATE.MULTIPLE.LAYOUTS[0]+'.json')}[role]
                if kind == 'bytes':
                    target.write_bytes(b'changed')
                else:
                    original = target.with_suffix('.original')
                    target.rename(original)
                    if kind == 'symlink':
                        target.symlink_to(original)
                    else:
                        target.write_bytes(original.read_bytes())
                    if role == 'private':
                        # Preserve the exact expected directory listing, exposing only the tested replacement.
                        if kind == 'inode':
                            original.unlink()
                        else:
                            out = private.parent/'original-private'
                            original.rename(out)
                            target.unlink()
                            target.symlink_to(out)

            identity = GATE.file_identity
            def check_identity(path):
                result = identity(path)
                if path.name in ('selected-candidate.test', 'changed.test') and path.name not in checked_images:
                    checked_images.add(path.name)
                    change('before-causal' if path.name == 'changed.test' else 'before-run', path, path.parent/'private')
                return result

            def run(argv, *, cwd, env, timeout, **options):
                private = Path(env[PRIVATE])
                def result(output='', code=0):
                    return subprocess.CompletedProcess(argv, code, stdout=output, stderr='')
                if argv[1] == 'test' and '-json' in argv:
                    self.assertEqual(cwd, ROOT)
                    self.assertEqual(timeout, 360)
                    self.assertEqual(argv, ['pinned-go', 'test', '-json', '-mod=readonly', '-p=1', '-count=1',
                                            '-race', '-timeout=160s', './internal/mobilemultihop', '-run',
                                            '^TestNodeChainMultipleImportedExecutionNativeFixtures$'])
                    for layout in GATE.MULTIPLE.LAYOUTS:
                        (private/(layout+'.json')).write_text(layout)
                    return result(encode(rows('TestNodeChainMultipleImportedExecutionNativeFixtures',
                                              GATE.MULTIPLE.LAYOUTS, 'router-vpn/internal/mobilemultihop')))
                self.assertEqual(cwd, core)
                if argv[1:3] == ['test', '-c']:
                    self.assertEqual(timeout, 600)
                    image = Path(argv[argv.index('-o')+1])
                    overlays = [Path(item.partition('=')[2]) for item in argv if item.startswith('-overlay=')]
                    self.assertEqual(argv, GATE.LATENCY.build_command('pinned-go', 'with_openvpn', True, image,
                                                                      overlays[0] if overlays else None))
                    for flag in ('-race', '-p=1', '-mod=readonly', '-tags=with_openvpn,'+GATE.LATENCY.FIXTURE.TAG):
                        self.assertIn(flag, argv)
                    if overlays:
                        contents = json.loads(overlays[0].read_text())
                        self.assertEqual(set(contents), {'Replace'})
                        self.assertEqual(set(contents['Replace']), {str(core/TARGET)})
                        self.assertEqual(sources[TARGET].decode().count(ANCHOR), 1)
                        self.assertEqual(Path(contents['Replace'][str(core/TARGET)]).read_text(),
                                         sources[TARGET].decode().replace(ANCHOR, '', 1))
                    image.write_bytes(b'changed image' if overlays else b'original image')
                    change('causal-compile' if overlays else 'compile', image, private)
                    return result()
                selection = argv[-1].removeprefix('-test.run=')
                self.assertEqual(timeout, 135)
                image = Path(argv[argv.index('-t')+1])
                self.assertEqual(argv, ['pinned-go', 'tool', 'test2json', '-p', PACKAGE, '-t', str(image),
                                        '-test.v', '-test.count=1', '-test.timeout=120s', '-test.run='+selection])
                self.assertEqual(selection, ([phase[2] for phase in PHASES]+[CAUSAL])[len(completed)])
                if fault and ((fault[0] in ('compile', 'before-run') and not completed) or
                              (fault[0] in ('causal-compile', 'before-causal') and selection == CAUSAL)):
                    self.fail('runner executed a phase after its inputs changed: '+str(fault))
                completed.append(selection)
                if selection == CAUSAL:
                    self.assertEqual(image.read_bytes(), b'changed image')
                    change('causal-run', image, private)
                    return result(encode(rows(PREFIX+'Refusals', ('foreign-metadata-inode',), witness=WITNESS)), 1)
                self.assertEqual(image.read_bytes(), b'original image')
                if len(completed) == 1:
                    change('run', image, private)
                root, children, _ = PHASES[len(completed)-1]
                return result(encode(rows(root, children)))

            with (patch.object(GATE.FIXTURE, 'copies', return_value=projection),
                  patch.object(GATE, 'file_identity', side_effect=check_identity),
                  patch.object(GATE.LATENCY, 'verify', return_value='inherited selection-owner fixture'),
                  patch.object(GATE.subprocess, 'run', side_effect=run),
                  contextlib.redirect_stdout(io.StringIO())):
                GATE.execute(core, 'pinned-go', 'with_openvpn')
        return completed

    def test_every_native_phase_and_changed_image_runs_with_original_bounds(self):
        self.assertEqual(self.exercise(), [phase[2] for phase in PHASES]+[CAUSAL])

    def test_typed_original_image_and_verdicts_bind_each_fifty_and_refusal(self):
        for fault in ('', 'source', 'image', 'missing', 'foreign'):
            selections = []
            source = ['pinned']
            with tempfile.TemporaryDirectory() as directory:
                def compile_image(core, go, tags, race, image, env):
                    self.assertEqual((core,go,tags,race), (Path(directory),'go','pinned-tags',True))
                    image.write_bytes(b'typed source image')
                    return GATE.file_identity(image)[2]
                def run(command, **kwargs):
                    selection=command[-1].split('=',1)[1]
                    root, children, expected = TYPED_PHASES[len(selections)]
                    self.assertEqual(selection, expected)
                    self.assertIn('-test.timeout=120s', command)
                    self.assertEqual((kwargs['cwd'], kwargs['timeout']), (Path(directory), 135))
                    selections.append(selection)
                    if fault == 'source':
                        source[0] += 'changed'
                    if fault == 'image':
                        Path(command[command.index('-t')+1]).write_bytes(b'foreign image')
                    records=rows(root, ('unrelated',) if fault == 'foreign' else children)
                    if fault == 'missing':
                        records.pop(-1)
                    return subprocess.CompletedProcess(command, 0, encode(records))
                with patch.object(GATE,'verify',side_effect=lambda core:source[0]), \
                     patch.object(GATE.LATENCY,'compile_image',side_effect=compile_image), \
                     patch.object(GATE.subprocess,'run',side_effect=run), contextlib.redirect_stdout(io.StringIO()):
                    if fault:
                        with self.subTest(fault=fault), self.assertRaises(ValueError):
                            GATE.execute_typed_entries(Path(directory),'go','pinned-tags')
                        self.assertEqual(len(selections),1)
                    else:
                        GATE.execute_typed_entries(Path(directory),'go','pinned-tags')
                        self.assertEqual(selections,[row[2] for row in TYPED_PHASES])

    def test_gate_rechecks_original_inputs_and_images(self):
        for stage in ('before-run', 'run', 'before-causal', 'causal-run'):
            for role in ('source', 'projection', 'private', 'image'):
                kinds = ('bytes', 'symlink', 'inode') if role in ('private', 'image') else ('bytes', 'symlink')
                for kind in kinds:
                    with self.subTest(stage=stage, role=role, kind=kind), self.assertRaises((ValueError, OSError)):
                        self.exercise((stage, role, kind))
        # Changed generator inputs or a compiler-generated symlink must be refused
        # before the first test2json process, including the independently built control.
        for stage in ('compile', 'causal-compile'):
            for role, kind in (('image', 'symlink'), ('private', 'bytes'), ('source', 'bytes')):
                with self.subTest(stage=stage, role=role, kind=kind), self.assertRaises((ValueError, OSError)):
                    self.exercise((stage, role, kind))

    def test_private_fixture_requires_exact_regular_inventory(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            for layout in GATE.MULTIPLE.LAYOUTS:
                (directory/(layout+'.json')).write_text(layout)
            original = GATE.fixture_identity(directory)
            for layout in GATE.MULTIPLE.LAYOUTS:
                path = directory/(layout+'.json')
                path.unlink()
                with self.subTest(missing=layout), self.assertRaises(ValueError):
                    GATE.fixture_identity(directory)
                path.write_text(layout)
            extra = directory/'foreign.json'
            extra.write_text('foreign')
            with self.assertRaises(ValueError):
                GATE.fixture_identity(directory)
            self.assertEqual(len(original), len(GATE.MULTIPLE.LAYOUTS))



if __name__ == '__main__':
    unittest.main()
