#!/usr/bin/env python3
"""Adversarial checks for the required typed SOCKS parent component gate."""
import ast
import contextlib
import importlib.util
import io
import json
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('socks_parent',Path(__file__).with_name('test_desktop_socks_execution_controller.py'))
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)


def events(root, children):
    rows = [{'Action':'start','Package':G.PACKAGE},{'Action':'run','Package':G.PACKAGE,'Test':root}]
    def append(child):
        rows.append({'Action':'run','Package':G.PACKAGE,'Test':root+'/'+child})
        for nested in children:
            if nested.startswith(child+'/') and not any(nested.startswith(parent+'/') for parent in children if parent!=child and parent.startswith(child+'/')):
                append(nested)
        rows.append({'Action':'pass','Package':G.PACKAGE,'Test':root+'/'+child})
    for child in children:
        if not any(child.startswith(parent+'/') for parent in children):
            append(child)
    rows += [{'Action':'pass','Package':G.PACKAGE,'Test':root},{'Action':'pass','Package':G.PACKAGE}]
    return rows


class SOCKSParentRunnerTests(unittest.TestCase):
    def test_complete_native_inventories_and_missing_records(self):
        for target, roots, records in (('linux/amd64',18,153),('windows/arm64',17,140),('darwin/arm64',13,132)):
            inventory = G.inventory(target)
            self.assertEqual((len(inventory),len(G.expected(inventory))),(roots,records))
            for root, children in inventory.items():
                rows = events(root,children)
                raw = '\n'.join(json.dumps(row) for row in rows)
                G.BUILDER.verify_imported_native_verdicts(raw,G.PACKAGE,G.expected({root:children}))
                for missing in G.expected({root:children}):
                    bad = '\n'.join(json.dumps(row) for row in rows if row.get('Test') != missing)
                    with self.subTest(target=target,missing=missing), self.assertRaises(ValueError):
                        G.BUILDER.verify_imported_native_verdicts(bad,G.PACKAGE,G.expected({root:children}))

    def test_layer_inventory_is_additive_exact_and_source_bound(self):
        for target,count in (('linux/amd64',27),('windows/arm64',27),('darwin/arm64',15)):
            roots=G.layer_inventory(target)
            self.assertEqual(len(G.expected(roots)),count)
            self.assertFalse(set(roots)&set(G.inventory(target)))
            for root,children in roots.items():
                rows=events(root,children)
                raw='\n'.join(json.dumps(row) for row in rows)
                G.BUILDER.verify_imported_native_verdicts(raw,G.PACKAGE,G.expected({root:children}))
                for missing in G.expected({root:children}):
                    bad='\n'.join(json.dumps(row) for row in rows if row.get('Test')!=missing)
                    with self.subTest(target=target,missing=missing),self.assertRaises(ValueError):
                        G.BUILDER.verify_imported_native_verdicts(bad,G.PACKAGE,G.expected({root:children}))
            self.assertEqual(len(self.exercise(target,phase='layers')),len(roots)+1)
        for fault in ('compile','source','image','status','missing','timeout'):
            self.assertLessEqual(len(self.exercise(fault=fault,phase='layers')),2)

    def test_layer_phases_are_required_without_changing_original_bounds(self):
        source=(G.ROOT/'deploy/build-native-runtime.py').read_text()
        def required(text):
            tree=ast.parse(text)
            loops=[n for n in ast.walk(tree) if isinstance(n,ast.For) and any(isinstance(v,ast.Constant) and v.value=='deploy/test_desktop_socks_execution_controller.py' for v in ast.walk(n))]
            self.assertEqual(len(loops),1)
            self.assertEqual(ast.literal_eval(loops[0].iter),('baselines','controls','layers','layer-controls','prefix-source','prefix-public','layer-prefixes'))
            self.assertEqual(len(loops[0].body),2)
            guard=loops[0].body[0]
            self.assertIsInstance(guard,ast.If)
            self.assertEqual(ast.unparse(guard.test), "socks_phase == 'prefix-public' and (not target.startswith(('linux/', 'windows/')))")
            self.assertEqual(len(guard.body),1)
            self.assertIsInstance(guard.body[0],ast.Continue)
            self.assertFalse(guard.orelse)
            call=loops[0].body[1].value
            self.assertIsInstance(call,ast.Call)
            self.assertEqual(call.func.id,'run')
            self.assertEqual(next(ast.literal_eval(k.value) for k in call.keywords if k.arg=='timeout'),1200)
        required(source)
        for phase in ('baselines','controls','layers','layer-controls','prefix-source','prefix-public','layer-prefixes'):
            with self.subTest(phase=phase),self.assertRaises(AssertionError):
                original="('baselines', 'controls', 'layers', 'layer-controls', 'prefix-source', 'prefix-public', 'layer-prefixes')"
                changed=repr(tuple(value for value in ('baselines','controls','layers','layer-controls','prefix-source','prefix-public','layer-prefixes') if value!=phase))
                self.assertEqual(source.count(original),1)
                required(source.replace(original,changed,1))
        self.assertLess(240+6*135,1200)
        self.assertEqual(len(G.LAYER_CONTROLS),1)
        relative,before,after,root,child,witness=G.LAYER_CONTROLS[0]
        original=(G.ROOT/relative).read_text()
        self.assertEqual(original.count(before),1)
        self.assertIn('members[final].Profile.StartLayer != "" && members[final].Profile.StartLayer != "off"',after)
        self.assertIn(root+'/'+child,G.expected(G.layer_inventory('darwin/arm64')))
        self.assertEqual(witness,'original layered SOCKS execution refused')

    def test_required_published_prefix_inventory_and_platform_scope(self):
        self.assertEqual(len(G.PREFIX_SOURCE),4)
        self.assertEqual(len(G.expected(G.PREFIX_SOURCE)),54)
        self.assertEqual(len(G.PREFIX_PUBLIC),6)
        self.assertIn('TestDesktopSOCKSPrefixExecutionSavedProfileRetainsSource/8/auto',G.expected(G.PREFIX_SOURCE))
        self.assertFalse(set(G.PREFIX_SOURCE)&set(G.CASES))
        for target in ('linux/amd64','windows/arm64','darwin/arm64'):
            self.assertEqual(len(self.exercise(target,phase='prefix-source')),5)
        for target in ('linux/amd64','windows/arm64'):
            self.assertEqual(len(self.exercise(target,phase='prefix-public')),7)
        with self.assertRaises(ValueError): G.phase_inventory('darwin/arm64','prefix-public')
        for target,roots,records in (('linux/amd64',4,10),('windows/arm64',4,10),('darwin/arm64',1,5)):
            self.assertEqual((len(G.phase_inventory(target,'layer-prefixes')),len(G.expected(G.phase_inventory(target,'layer-prefixes')))),(roots,records))
            self.assertEqual(len(self.exercise(target,phase='layer-prefixes')),roots+1)
        for roots in (G.PREFIX_SOURCE,G.PREFIX_PUBLIC,G.LAYER_PREFIX_SOURCE,G.LAYER_PREFIX_PUBLIC):
            for root,children in roots.items():
                rows=events(root,children)
                raw='\n'.join(json.dumps(row) for row in rows)
                G.BUILDER.verify_imported_native_verdicts(raw,G.PACKAGE,G.expected({root:children}))
                for missing in G.expected({root:children}):
                    bad='\n'.join(json.dumps(row) for row in rows if row.get('Test')!=missing)
                    with self.subTest(root=root,missing=missing),self.assertRaises(ValueError):
                        G.BUILDER.verify_imported_native_verdicts(bad,G.PACKAGE,G.expected({root:children}))

    def test_foreign_duplicate_late_racing_failed_and_skipped_records(self):
        root, children = next(iter(G.CASES.items()))
        for fault in ('foreign','duplicate','late','race','failed','skip','no-start','duplicate-key'):
            rows = events(root,children)
            if fault=='foreign': rows[2]['Package']='foreign'
            elif fault=='duplicate': rows.insert(2,dict(rows[1]))
            elif fault=='late': rows.append(dict(rows[1]))
            elif fault=='race': rows.insert(-1,{'Action':'output','Package':G.PACKAGE,'Output':'WARNING: DATA RACE\n'})
            elif fault in ('failed','skip'): rows[3]['Action']='fail' if fault=='failed' else 'skip'
            elif fault=='no-start': rows.pop(0)
            raw = '\n'.join(json.dumps(row) for row in rows)
            if fault=='duplicate-key': raw=raw.replace('"Action": "start"','"Action":"run", "Action":"start"',1)
            with self.subTest(fault=fault),self.assertRaises(ValueError):
                G.BUILDER.verify_imported_native_verdicts(raw,G.PACKAGE,G.expected({root:children}))

    def exercise(self,target='linux/amd64',fault=None,phase='baselines'):
        roots=G.phase_inventory(target,phase)
        calls=[]
        image=None
        def run(command,**options):
            nonlocal image
            calls.append(command)
            self.assertEqual(options['env'],{'CAPTURED':'original'})
            if command[1:3]==['test','-c']:
                self.assertEqual(options['timeout'],240)
                self.assertEqual(options['cwd'],G.ROOT)
                self.assertEqual('-race' in command,target!='windows/arm64')
                self.assertIn('-p=1',command)
                self.assertIn('-mod=readonly',command)
                image=Path(command[command.index('-o')+1])
                if fault!='compile': image.write_bytes(b'original native controller')
                return subprocess.CompletedProcess(command,1 if fault=='compile' else 0,'','')
            self.assertEqual(options['timeout'],135)
            self.assertEqual(options['cwd'],G.ROOT/'cmd/client')
            self.assertEqual(command[5],str(image))
            self.assertIn('-test.timeout=120s',command)
            self.assertIn('-test.count=1',command)
            root=command[-1].removeprefix('-test.run=^').removesuffix('$')
            children=roots[root]
            if fault=='timeout': raise subprocess.TimeoutExpired(command,135,output=b'original bounded stack\n')
            if fault=='image': image.write_bytes(b'changed image')
            rows=events(root,children)
            if fault=='missing': rows=[row for row in rows if row.get('Test') != root]
            return subprocess.CompletedProcess(command,1 if fault=='status' else 0,'\n'.join(json.dumps(row) for row in rows),'')
        identities=['original']*100
        if fault=='source': identities[1]='changed'
        with tempfile.TemporaryDirectory() as directory:
            receipt=Path(directory)/'receipt.json'
            output=io.StringIO()
            with patch.object(G,'native_environment',return_value=('/selected/go',{'CAPTURED':'original'},target)),patch.object(G,'source_identity',side_effect=identities),patch.object(G.subprocess,'run',side_effect=run),contextlib.redirect_stdout(output):
                if fault:
                    with self.assertRaises((ValueError,subprocess.TimeoutExpired)):
                        G.run(receipt=receipt,without_race=target=='windows/arm64',phase=phase)
                    self.assertFalse(receipt.exists())
                else:
                    result=G.run(receipt=receipt,without_race=target=='windows/arm64',phase=phase)
                    self.assertEqual(result,json.loads(receipt.read_text()))
                    self.assertEqual((result['compiler'],result['toolchain']),('/selected/go',G.BUILDER.TOOLCHAIN))
                    self.assertEqual(len(result['records']),len(roots))
                    self.assertEqual(len(list(Path(directory).glob('*.jsonl'))),len(roots))
                    self.assertEqual(len({row['image_sha256'] for row in result['records']}),1)
            if fault=='timeout': self.assertIn('original bounded stack',output.getvalue())
        return calls

    def test_each_native_target_keeps_original_environment_image_and_bounds(self):
        for target in ('linux/amd64','linux/arm64','windows/amd64','windows/arm64','darwin/amd64','darwin/arm64'):
            with self.subTest(target=target): self.assertEqual(len(self.exercise(target)),len(G.inventory(target))+1)

    def test_failure_never_produces_completed_receipt(self):
        for fault in ('compile','source','image','status','missing','timeout'):
            with self.subTest(fault=fault): self.assertLessEqual(len(self.exercise(fault=fault)),2)

    def test_native_target_and_race_mode_cannot_be_borrowed(self):
        for target,without,environment in (('linux/amd64',True,{}),('windows/arm64',False,{}),('darwin/arm64',True,{}),('linux/amd64',False,{'GOOS':'windows'}),('darwin/amd64',False,{'GOARCH':'arm64'}),('freebsd/amd64',False,{})):
            with self.subTest(target=target,without=without),patch.object(G.shutil,'which',return_value='/selected/go'),patch.object(G.subprocess,'check_output',return_value='/selected'),patch.object(G.BUILDER,'native_host_target',return_value=target),patch.dict(G.os.environ,environment,clear=True),self.assertRaises(ValueError):
                G.native_environment('go',without)

    def test_pinned_compiler_is_selected_before_local_lock_on_every_host(self):
        for target in G.BUILDER.TARGETS:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                root=Path(directory);compiler=root/'bin'/('go.exe' if target.startswith('windows/') else 'go')
                compiler.parent.mkdir();compiler.write_bytes(b'original selected compiler')
                system,arch=target.split('/')
                row=dict(GOROOT=str(root),GOVERSION=G.BUILDER.TOOLCHAIN,GOHOSTOS=system,GOHOSTARCH=arch)
                calls=[]
                def query(command,**options):
                    calls.append((command,dict(options['env'])))
                    if len(calls)==1:
                        self.assertEqual(command[0],'/original/bootstrap-go')
                        self.assertEqual(options['env']['GOTOOLCHAIN'],G.BUILDER.TOOLCHAIN)
                        self.assertNotIn('GOROOT',options['env'])
                    else:
                        self.assertEqual(command[0],str(compiler))
                        self.assertEqual(options['env']['GOTOOLCHAIN'],'local')
                        self.assertEqual(options['env']['GOROOT'],str(root))
                    self.assertEqual(command[1:],['env','-json','GOROOT','GOVERSION','GOHOSTOS','GOHOSTARCH'])
                    self.assertEqual(options['timeout'],15)
                    return json.dumps(row)
                with patch.object(G.shutil,'which',return_value='/original/bootstrap-go'),patch.object(G.subprocess,'check_output',side_effect=query),patch.object(G.BUILDER,'native_host_target',return_value=target),patch.dict(G.os.environ,{'GOROOT':'/foreign/root','GOTOOLCHAIN':'local','GOOS':system,'GOARCH':arch},clear=True):
                    executable,environment,observed=G.native_environment('go',target=='windows/arm64')
                self.assertEqual((executable,observed),(str(compiler),target))
                self.assertEqual(len(calls),2)
                self.assertEqual((environment['GOROOT'],environment['GOTOOLCHAIN']),(str(root),'local'))

    def test_foreign_or_changed_compiler_cannot_create_a_receipt(self):
        faults=('missing-bootstrap','missing-compiler','old-version','foreign-host','relative-root','empty-root','newline-root','extra-field','malformed-json','non-string','changed-version','changed-host','changed-root')
        for fault in faults:
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root=Path(directory);compiler=root/'bin'/'go';compiler.parent.mkdir()
                if fault!='missing-compiler':compiler.write_bytes(b'original selected compiler')
                row=dict(GOROOT=str(root),GOVERSION=G.BUILDER.TOOLCHAIN,GOHOSTOS='linux',GOHOSTARCH='amd64')
                rows=[dict(row),dict(row)]
                index=1 if fault.startswith('changed-') else 0
                if fault in ('old-version','changed-version'):rows[index]['GOVERSION']='go1.24.13'
                elif fault in ('foreign-host','changed-host'):rows[index]['GOHOSTARCH']='arm64'
                elif fault=='relative-root':rows[0]['GOROOT']='relative/root'
                elif fault=='empty-root':rows[0]['GOROOT']=''
                elif fault=='newline-root':rows[0]['GOROOT']=str(root)+'\n'
                elif fault=='extra-field':rows[0]['GOTOOLCHAIN']='foreign'
                elif fault=='non-string':rows[0]['GOHOSTOS']=None
                elif fault=='changed-root':rows[1]['GOROOT']=str(root/'foreign')
                replies=[json.dumps(row) for row in rows]
                if fault=='malformed-json':replies[0]='{'
                receipt=root/'receipt.json'
                with patch.object(G.shutil,'which',return_value=None if fault=='missing-bootstrap' else '/bootstrap/go'),patch.object(G.subprocess,'check_output',side_effect=replies),patch.object(G.BUILDER,'native_host_target',return_value='linux/amd64'),patch.dict(G.os.environ,{},clear=True),patch.object(G,'compile_image') as compile_image:
                    with self.assertRaises(ValueError):G.run(receipt=receipt)
                    compile_image.assert_not_called()
                self.assertFalse(receipt.exists())

    def test_actual_pinned_compiler_arguments_and_receipt(self):
        # This compiles a tiny source fixture with the actual selected native
        # Go compiler. It validates toolchain propagation, not product routing.
        root_name='TestOriginalPinnedCompiler'
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'cmd/client').mkdir(parents=True)
            module='module router-vpn\n\ngo 1.25.0\n\ntoolchain '+G.BUILDER.TOOLCHAIN+'\n'
            source='package main\nimport("runtime";"testing")\nfunc '+root_name+'(t *testing.T){if runtime.Version()!='+json.dumps(G.BUILDER.TOOLCHAIN)+'{t.Fatal("foreign original compiler",runtime.Version())}}\n'
            (root/'go.mod').write_text(module);(root/'cmd/client/compiler_test.go').write_text(source)
            identity=hashlib.sha256((module+source).encode()).hexdigest()
            queries=[];actual_query=G.subprocess.check_output
            def query(command,**options):
                queries.append((command,dict(options['env'])))
                return actual_query(command,**options)
            target=G.BUILDER.native_host_target();receipt=root/'receipt.json'
            with patch.object(G,'ROOT',root),patch.object(G,'source_identity',return_value=identity),patch.object(G,'inventory',return_value={root_name:()}),patch.object(G.subprocess,'check_output',side_effect=query),patch.dict(G.os.environ,{'GOROOT':str(root/'foreign'),'GOTOOLCHAIN':'local','GORACE':'atexit_sleep_ms=0'}),contextlib.redirect_stdout(io.StringIO()):
                result=G.run(receipt=receipt,without_race=target=='windows/arm64')
            self.assertEqual(len(queries),2)
            self.assertEqual(queries[0][1]['GOTOOLCHAIN'],G.BUILDER.TOOLCHAIN)
            self.assertNotIn('GOROOT',queries[0][1])
            self.assertEqual(queries[1][1]['GOTOOLCHAIN'],'local')
            self.assertEqual(result,json.loads(receipt.read_text()))
            self.assertEqual((result['target'],result['toolchain'],result['source_sha256']),(target,G.BUILDER.TOOLCHAIN,identity))
            self.assertEqual(result['compiler'],queries[1][0][0])
            self.assertEqual(result['records'][0]['command'][0],result['compiler'])
            self.assertEqual(result['records'][0]['tests'],1)

    def test_controls_bind_exact_production_boundaries_and_original_test_witnesses(self):
        self.assertEqual(len(G.CONTROLS),2)
        for source,before,after,root,child,witness in G.CONTROLS:
            original=(G.ROOT/source).read_text()
            self.assertEqual(original.count(before),1)
            self.assertNotEqual(before,after)
            self.assertIn(root,G.inventory('linux/amd64'))
            self.assertIn(root+('/'+child if child else ''),G.expected(G.inventory('linux/amd64')))
            self.assertTrue(witness)


    def test_causal_witness_followed_by_abort_cannot_supply_expected_failure(self):
        root, case, witness = 'TestOriginal', 'TestOriginal/selected', 'original assertion failed'
        rows = [
            {'Action':'start','Package':G.PACKAGE},
            {'Action':'run','Package':G.PACKAGE,'Test':root},
            {'Action':'run','Package':G.PACKAGE,'Test':case},
            {'Action':'output','Package':G.PACKAGE,'Test':case,'Output':witness+'\n'},
            {'Action':'fail','Package':G.PACKAGE,'Test':case},
            {'Action':'fail','Package':G.PACKAGE,'Test':root},
            {'Action':'fail','Package':G.PACKAGE},
        ]
        raw = lambda value: '\n'.join(json.dumps(row) for row in value)
        G.verify_causal_result(subprocess.CompletedProcess([],1,raw(rows),''),root,case,witness)
        for diagnostic in ('panic: late close', 'fatal error: concurrent map writes', 'signal: killed',
                           'SIGSEGV: segmentation violation', 'panic: test timed out after 120s',
                           'FAIL router-vpn/cmd/client [build failed]', 'build aborted',
                           'compile: signal: killed', 'link: running clang failed', 'exit status 2',
                           'WARNING: DATA RACE'):
            # Keep the valid assertion and failed case, then append an abort
            # before the package failure. A nonzero result alone cannot pass.
            changed = rows[:-1]+[{'Action':'output','Package':G.PACKAGE,'Output':diagnostic+'\n'}]+rows[-1:]
            with self.subTest(diagnostic=diagnostic), self.assertRaises(ValueError):
                G.verify_causal_result(subprocess.CompletedProcess([],1,raw(changed),''),root,case,witness)
        for status, stderr in ((0,''),(2,''),(-9,''),(1,'signal: killed\n')):
            with self.subTest(status=status,stderr=stderr), self.assertRaises(ValueError):
                G.verify_causal_result(subprocess.CompletedProcess([],status,raw(rows),stderr),root,case,witness)



if __name__=='__main__':
    unittest.main()
