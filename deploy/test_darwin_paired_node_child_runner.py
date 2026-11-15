#!/usr/bin/env python3
"""Executable controls for mandatory paired-node component phases."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import contextlib
import importlib.util
import io
import inspect
import os
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('paired_gate_parent',ROOT/'deploy/test_darwin_node_child_tun.py')
G=importlib.util.module_from_spec(spec);spec.loader.exec_module(G)
P=G.PAIRED

def transcript(names):
    return ''.join('=== RUN   '+name+'\n--- PASS: '+name+' (0.01s)\n' for name in names)+'PASS\n'

class PairedBoundaries(unittest.TestCase):
    def exercise(self, mutation=None):
        with tempfile.TemporaryDirectory() as directory:
            work=Path(directory);child=work/'child';peer=work/'peer'
            for path in (child,peer):path.write_bytes(path.name.encode());path.chmod(0o755)
            sources={'original':'a'*64};identities={path:G.image_identity(path) for path in (child,peer)}
            calls=[];verified=[];reads=[0]
            captured={'GOROOT':'/captured/go1.26.5','GOTOOLCHAIN':'local','PATH':'/captured/go1.26.5/bin','CC':'/captured/clang','CGO_ENABLED':'1'}
            def readback(_):
                reads[0]+=1
                return work, {'changed':'b'*64} if mutation=='source' and reads[0]>1 else sources
            def run(command,**kwargs):
                calls.append((command,kwargs))
                if command[1:3]==['test','-c']:
                    Path(command[command.index('-o')+1]).write_bytes(b'original box')
                    return ''
                if mutation=='nonzero':raise subprocess.CalledProcessError(1,command,output='native refusal')
                phase=P.PHASES[len(calls)-2]
                names=list(phase[2]);output=transcript(names)
                if mutation=='omit':output=transcript(names[:-1])
                if mutation=='repeat':output=transcript(names+[names[-1]])
                if mutation=='foreign':output=transcript(names+['TestForeign'])
                if mutation=='wrong-phase':output=transcript(P.PHASES[1][2])
                if mutation=='fail':output=output.replace('--- PASS:','--- FAIL:',1)
                if mutation=='skip':output=output.replace('--- PASS:','--- SKIP:',1)
                if mutation=='race':output+='WARNING: DATA RACE\n'
                if mutation=='image':child.write_bytes(b'changed original command')
                return output
            gate=SimpleNamespace(UID=SimpleNamespace(run=run,RACE=SimpleNamespace(verify_image=lambda *args:verified.append(args))),
                                 NODE=G.NODE,native_fixture_compile=G.native_fixture_compile,image_identity=G.image_identity,
                                 checked_sources=readback)
            with patch.dict(os.environ,{'GOROOT':'/ambient/go1.26.3','GOTOOLCHAIN':'auto'}),patch.object(P.READER,'execute') as reader,patch.object(P.PLATFORM,'verify') as platform,contextlib.redirect_stdout(io.StringIO()):
                receipt=P.execute(gate,work,sources,'/captured/go',captured,child,identities,work)
            platform.assert_called_once_with(go='/captured/go',environment=captured)
            reader.assert_called_once_with(go='/captured/go',environment=captured)
            self.assertEqual(len(calls),3);self.assertEqual(calls[0][1]['timeout'],600)
            self.assertEqual(calls[0][0][-1],'.');self.assertIn('-race',calls[0][0])
            self.assertEqual(len(verified),1)
            for index,(command,options) in enumerate(calls[1:]):
                self.assertEqual(options['timeout'],100);self.assertIn('-test.timeout=90s',command)
                self.assertEqual(command[1],'-test.run='+P.PHASES[index][1])
                self.assertEqual(command[0],child if index==0 else work/'paired-node-box.test')
            self.assertEqual(len(identities),3)
            P.validate_receipt(receipt,P.source_digest(sources),identities[child][-1])
            return receipt

    def test_original_images_run_exact_separate_phases(self):
        self.assertEqual(self.exercise()['verdicts'],105)

    def test_no_native_failure_or_changed_authority_can_publish(self):
        for mutation in ('omit','repeat','foreign','wrong-phase','fail','skip','race','image','source'):
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):self.exercise(mutation)
        with self.assertRaises(subprocess.CalledProcessError):self.exercise('nonzero')

    def test_omitted_repeated_or_wrong_phase_inventory_refuses(self):
        phases=P.PHASES
        variants=(phases[:1],phases+phases[:1],tuple(reversed(phases)),
                  ((phases[0][0],phases[1][1],phases[0][2]),phases[1]))
        for value in variants:
            with self.subTest(phases=value),patch.object(P,'PHASES',value),self.assertRaises(ValueError):P.checked_phases()

    def test_receipt_requires_all_original_evidence(self):
        original=self.exercise()
        for field in original:
            altered=dict(original);del altered[field]
            with self.subTest(missing=field),self.assertRaises(ValueError):
                P.validate_receipt(altered,original['source_sha256'],original['command_sha256'])
        for field,value in (('cases',original['cases'][:-1]),('cases',original['cases']+[original['cases'][0]]),
                            ('phases',['box','command']),('scope','native-full-host'),('box_sha256',''),
                            ('source_sha256','b'*64),('command_sha256','c'*64),('output_sha256','invalid')):
            altered=dict(original);altered[field]=value
            with self.subTest(changed=field),self.assertRaises(ValueError):
                P.validate_receipt(altered,original['source_sha256'],original['command_sha256'])

    def test_publication_rejects_missing_child_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/'receipt.json';gone=Path(directory)/'retired'
            result={'gate':'generated-darwin-ordered-child','source_sha256':'a'*64,
                    'artifacts':{'generated-child-test':{'sha256':'b'*64}}}
            with self.assertRaisesRegex(ValueError,'boundary receipt'):G.publish_receipt(target,result,gone)
            self.assertFalse(target.exists())


    def test_absolute_compiler_without_captured_environment_is_not_sufficient(self):
        source=inspect.getsource(P.execute)
        for call in ('PLATFORM.verify','READER.execute'):
            before=call+'(go=str(compiler), environment=captured)'
            self.assertEqual(source.count(before),1)
            namespace=dict(P.__dict__)
            exec(compile(source.replace(before,call+'(go=str(compiler))',1),'<omitted compiler environment>','exec'),namespace)
            with self.subTest(call=call),patch.object(P,'execute',namespace['execute']),self.assertRaises(AssertionError):self.exercise()

    def test_reader_compile_preserves_selected_root_and_standalone_default(self):
        captured={'GOROOT':'/selected/go1.26.5','GOTOOLCHAIN':'local','PATH':'/selected/go1.26.5/bin','CC':'/selected/clang','CGO_ENABLED':'1'}
        ambient={'GOROOT':'/ambient/go1.26.3','GOTOOLCHAIN':'auto','PATH':'/ambient/bin','CC':'/ambient/clang'}
        for supplied in (captured,None):
            calls=[];expected=dict(captured if supplied is not None else ambient,GOTOOLCHAIN='local')
            def run(command,**options):
                self.assertEqual(command[0],'/selected/go')
                self.assertEqual(options['env'],expected)
                self.assertEqual(options['timeout'],120)
                self.assertIn('-race',command)
                calls.append(command)
                # Explicit subprocess contract model: real compiler/17 native
                # source cases remain required by execute, never replaced here.
                output=''.join('--- PASS: TestActualPairedReaderConfirmation/case'+str(i)+'\n' for i in range(17)) if len(calls)==1 else 'paired reader causal refusal failed'
                return SimpleNamespace(returncode=0 if len(calls)==1 else 1,stdout=output,stderr='')
            with self.subTest(captured=supplied is not None),patch.dict(os.environ,ambient,clear=True),patch.object(P.READER.subprocess,'run',side_effect=run),contextlib.redirect_stdout(io.StringIO()):
                P.READER.execute(go='/selected/go',environment=supplied)
            self.assertEqual(len(calls),5)
        self.assertEqual(captured['GOROOT'],'/selected/go1.26.5')
        self.assertEqual(captured['GOTOOLCHAIN'],'local')

    def test_platform_selection_preserves_compiler_root_while_selecting_targets(self):
        captured={'GOROOT':'/selected/go1.26.5','GOTOOLCHAIN':'local','PATH':'/selected/go1.26.5/bin','CC':'/selected/clang','CGO_ENABLED':'1','GOOS':'darwin','GOARCH':'amd64'}
        original=dict(captured);calls=[]
        def run(command,**options):
            self.assertEqual(command[0],'/selected/go')
            env=options['env'];target=env['GOOS']
            for key in ('GOROOT','GOTOOLCHAIN','PATH','CC'):self.assertEqual(env[key],captured[key])
            self.assertEqual(env['CGO_ENABLED'],'0');self.assertEqual(env['GO111MODULE'],'off')
            self.assertEqual(env['GOARCH'],'arm64' if target in ('darwin','ios') else 'amd64')
            calls.append(target)
            names=[p.name for p in Path(options['cwd']).glob('*.go')]
            selected=[name for name in names if (target=='darwin') != name.endswith('_other.go')]
            return SimpleNamespace(returncode=0,stdout='\n'.join(selected),stderr='')
        with patch.dict(os.environ,{'GOROOT':'/ambient/go1.26.3','GOTOOLCHAIN':'auto'}),patch.object(P.PLATFORM.subprocess,'run',side_effect=run):
            selected=P.PLATFORM.verify(go='/selected/go',environment=captured)
        self.assertEqual(len(calls),12);self.assertEqual(len(selected),12)
        self.assertEqual(captured,original)

if __name__=='__main__':unittest.main()
