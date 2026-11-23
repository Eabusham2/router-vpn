#!/usr/bin/env python3
"""Exercise the compiled-image handoff and fail-closed Darwin evidence join without changing host networking."""
import contextlib
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('darwin_child_phases', ROOT/'deploy/darwin_child_phases.py')
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
G = P.G
FIXTURE = G.load('darwin_phase_fixture', 'test_darwin_node_child_tun_runner.py')
REPO = dict(repository='Eabusham2/router-vpn', commit='a'*40, tree='b'*40)
BUILD, RUN, ATTEMPT = 'c'*64, '51', '2'


def encoded(raw):
    return hashlib.sha256(raw).hexdigest()


class DarwinEvidence(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.inputs = self.base/'receipts'
        self.inputs.mkdir()
        self.output = self.base/'accepted'
        self.needs = {job: {'result': 'success'} for job in P.JOBS}
        self.before = {'cmd/sing-box/original.go': 'd'*64}
        self.source = G.PAIRED.source_digest(self.before)
        for arch in P.ARCHES:
            self.make_phases(arch)

    def folder(self, arch, phase):
        return self.inputs/P.artifact_name(phase, arch, REPO['commit'], RUN, ATTEMPT)

    def make_phases(self, arch):
        artifacts = {role: dict(bytes=20, sha256=encoded((arch+role).encode())) for role in P.IMAGES}
        xray_files={key:encoded(key.encode()) for key in P.XRAY_REQUIRED}
        xray=dict(pin=P.XRAY_PIN,files=xray_files,sha256=G.PAIRED.source_digest(xray_files))
        manifest = dict(artifacts=artifacts, source_files=self.before, source_sha256=self.source, toolchain=G.UID.RACE.TOOLCHAIN,xray_source=xray)
        common = dict(schema=1, source_files=self.before, source_sha256=self.source, target='darwin/'+arch,
                      toolchain=G.UID.RACE.TOOLCHAIN, xray_source_sha256=xray['sha256'])
        native_log, handshake_log = FIXTURE.transcript().encode(), FIXTURE.preflight_transcript().encode()
        handshake = dict(common, gate='generated-darwin-ordered-child-handshake', scope='native-handshake-only',
                         native_accepted=False, receipts=list(G.PREFLIGHT_RECEIPTS), output_sha256=encoded(handshake_log),
                         artifacts={r:v for r,v in artifacts.items() if r != 'paired-node-box'})
        native = dict(common, gate='generated-darwin-ordered-child', scope='generated-command-utun',
                      pins={'sing-box': G.BUILD.PIN, 'xray': G.BUILD.POLICY.XRAY.XRAY_PIN}, cases=list(G.CASES),
                      artifacts=artifacts, output_sha256=encoded(native_log), local_preflight=handshake)
        components = {}
        for field, mod in P.COMPONENTS.items():
            component = dict(schema=1, source_sha256=self.source, command_sha256=artifacts['generated-child-test']['sha256'],
                             box_sha256=artifacts['paired-node-box']['sha256'], output_sha256='e'*64, cases=list(mod.CASES))
            if mod is G.PAIRED:
                component.update(scope='paired-node-component-boundaries', verdicts=105, phases=['command','box'])
            elif mod is G.ORDERED_MTU:
                component['scope'] = 'ordinary-ordered-mtu-component-boundaries'
            else:
                component['scope'] = 'typed-execution-mtu-component-boundaries'
            components[field] = component
        results = {phase: dict(cases=list(P.control_cases(phase))) for phase in P.CONTROLS}
        results.update(images=manifest, preflight=dict(handshake, repository=REPO), components=dict(boundaries=components,xray_source_sha256=xray['sha256']), native=native)
        for phase, result in results.items():
            directory = self.folder(arch, phase)
            directory.mkdir()
            P.write_record(directory/'receipt.json', dict(P.scope(phase, arch, REPO, BUILD, RUN, ATTEMPT), result=result))
        (self.folder(arch, 'native')/'native.log').write_bytes(native_log)
        (self.folder(arch, 'native')/'handshake.log').write_bytes(handshake_log)

    def join(self):
        P.aggregate(self.inputs, self.output, REPO, BUILD, RUN, ATTEMPT, self.needs)

    def test_complete_both_targets_reparse_original_receipts_and_transcripts(self):
        self.join()
        self.assertEqual(len(list(self.output.iterdir())), 6)
        for arch in P.ARCHES:
            accepted = P.read_record(self.output/f'darwin-node-child-{arch}.json')
            self.assertEqual(accepted['target'], 'darwin/'+arch)
            self.assertEqual(accepted['repository'], REPO)
            self.assertEqual([len(accepted[key]['cases']) for key in P.COMPONENTS], [105,31,72])
            self.assertEqual((self.output/f'{arch}-native.log').read_bytes(), FIXTURE.transcript().encode())

    def test_missing_failed_skipped_or_cancelled_required_job_refuses_all_outputs(self):
        for job in P.JOBS:
            for fault in ('missing','cancelled','skipped','failure','in_progress'):
                with self.subTest(job=job, fault=fault), patch.dict(self.needs):
                    if fault=='missing':
                        del self.needs[job]
                    else:
                        self.needs[job] = dict(result=fault)
                    with self.assertRaises(ValueError):
                        self.join()
                    self.assertFalse(self.output.exists())

    def test_phase_source_inventory_arch_attempt_and_image_must_match(self):
        changes = (
            ('controls-skip','ordinary-runner',lambda r:r['result']['cases'].pop()),
            ('parent-method','typed-runner',lambda r:r['result']['cases'].remove(next(v for v in r['result']['cases'] if 'test_actual_typed_parent' in v))),
            ('nonce-replay','preflight',lambda r:r.update(run_attempt='1')),
            ('wrong-source','images',lambda r:r.update(repository=dict(REPO,commit='8'*40))),
            ('other-processor','native',lambda r:r.update(target='darwin/amd64')),
            ('foreign-build','preflight',lambda r:r.update(build_source_sha256='7'*64)),
            ('changed-dependency-asset','images',lambda r:r['result']['xray_source']['files'].update({'transport/internet/browser_dialer/dialer.html':'0'*64})),
            ('wrong-dependency-owner','components',lambda r:r['result'].update(xray_source_sha256='0'*64)),
            ('foreign-dependency','preflight',lambda r:r['result'].update(xray_source_sha256='0'*64)),
            ('lost-source','native',lambda r:r['result']['source_files'].clear()),
            ('wrong-image','components',lambda r:r['result']['boundaries']['ordinary_mtu_boundaries'].update(box_sha256='6'*64)),
            ('duplicate-case','components',lambda r:r['result']['boundaries']['typed_mtu_boundaries']['cases'].append('duplicate')),
            ('optional-handshake','native',lambda r:r['result']['local_preflight'].update(native_accepted=True)),
            ('foreign-handshake-image','native',lambda r:r['result']['local_preflight']['artifacts']['generated-child-test'].update(sha256='9'*64)),
            ('unsigned-copy','native',lambda r:r['result'].update(scope='native-compilation-only')),
            ('missing-native-case','native',lambda r:r['result']['cases'].pop()),
        )
        for name, phase, mutation in changes:
            with self.subTest(name=name):
                file = self.folder('arm64', phase)/'receipt.json'
                saved = file.read_bytes()
                value = json.loads(saved)
                mutation(value)
                file.write_text(json.dumps(value))
                with self.assertRaises(ValueError): self.join()
                self.assertFalse(self.output.exists())
                file.write_bytes(saved)

    def test_rehashed_partial_native_or_preflight_transcript_cannot_pass(self):
        for filename in ('native.log','handshake.log'):
            with self.subTest(file=filename):
                folder=self.folder('amd64','native')
                file=folder/filename
                receipt=folder/'receipt.json'
                saved=receipt.read_bytes()
                original=file.read_bytes()
                partial=original.replace(b'--- PASS:', b'--- SKIP:', 1)
                file.write_bytes(partial)
                with self.assertRaises(ValueError): self.join()
                value=json.loads(saved)
                record=value['result'] if filename=='native.log' else value['result']['local_preflight']
                record['output_sha256']=encoded(partial)
                receipt.write_text(json.dumps(value))
                with self.assertRaises(ValueError): self.join()
                self.assertFalse(self.output.exists())
                receipt.write_bytes(saved)
                file.write_bytes(original)

    def test_failed_only_retry_joins_prior_success_without_accepting_future_or_invalid_newest(self):
        import shutil
        phase='native'
        current=self.folder('arm64',phase)
        new=current.with_name(current.name.rpartition('-')[0]+'-3')
        shutil.copytree(current,new)
        record=new/'receipt.json'
        value=P.read_record(record)
        value['run_attempt']='3'
        record.write_text(json.dumps(value))
        with self.assertRaises(ValueError): self.join()
        P.aggregate(self.inputs,self.output,REPO,BUILD,RUN,'3',self.needs)
        final=P.read_record(self.output/'darwin-node-child-arm64.json')
        self.assertEqual(final['phase_attempts']['native'],'3')
        self.assertEqual(final['phase_attempts']['images'],'2')
        shutil.rmtree(self.output)
        value['result']['output_sha256']='0'*64
        record.write_text(json.dumps(value))
        with self.assertRaises(ValueError): P.aggregate(self.inputs,self.output,REPO,BUILD,RUN,'3',self.needs)
        self.assertFalse(self.output.exists())

    def test_missing_or_foreign_phase_directory_cannot_replace_one_processor(self):
        folder=self.folder('arm64','ordinary-box')
        folder.rename(self.inputs/'darwin-child-proof-foreign')
        with self.assertRaises(ValueError): self.join()
        self.assertFalse(self.output.exists())


class DarwinImageHandoff(unittest.TestCase):
    def test_exact_transferred_bytes_verified_again_against_local_files_and_race_compiler(self):
        for fault in ('none','bytes','link','missing','foreign-source','post-compile-replacement'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as location:
                root=Path(location)
                supplied,work=root/'supplied',root/'work'
                supplied.mkdir();work.mkdir()
                before={'original':'a'*64}
                values={}
                for role,(name,_) in P.IMAGES.items():
                    raw=name.encode()
                    (supplied/name).write_bytes(raw)
                    values[role]=dict(bytes=len(raw),sha256=encoded(raw))
                manifest=dict(artifacts=values,source_files=before,source_sha256=G.PAIRED.source_digest(before))
                child=supplied/'child.test'
                if fault=='bytes': child.write_bytes(b'x'*child.stat().st_size)
                if fault=='link': child.rename(root/'original');child.symlink_to(root/'original')
                if fault=='missing': child.unlink()
                if fault=='foreign-source':
                    manifest['source_files']={'foreign':'a'*64}
                    manifest['source_sha256']=G.PAIRED.source_digest(manifest['source_files'])
                def verify(_compiler,path,*_):
                    if fault=='post-compile-replacement':
                        original=path.read_bytes()
                        replacement=path.with_suffix('.new')
                        replacement.write_bytes(original);replacement.chmod(0o755);replacement.replace(path)
                with patch.object(G,'checked_sources',return_value=(root,before)),patch.object(G.UID.RACE,'verify_image',side_effect=verify) as compiler:
                    if fault!='none':
                        with self.assertRaises(ValueError): P.restore_images(root,before,'go',{},work,supplied,manifest)
                    else:
                        ids=P.restore_images(root,before,'go',{},work,supplied,manifest)
                        self.assertEqual(compiler.call_count,3)
                        self.assertEqual(P.image_record(ids,work),values)
                        self.assertNotEqual((work/'child.test').stat().st_ino,child.stat().st_ino)

    def test_workspace_refuses_preexisting_and_replaced_original_directory(self):
        import shutil
        parent=Path(tempfile.gettempdir()).resolve()
        for fault in ('none','existing','replaced'):
            with self.subTest(fault=fault):
                path=Path(tempfile.mkdtemp(prefix='routervpn-darwin-owner-test-',dir=parent))
                moved=path.with_name(path.name+'-original')
                try:
                    if fault=='existing':
                        (path/'foreign').write_text('other owner')
                        with self.assertRaises(FileExistsError):
                            with P.exclusive_source_workspace(path): self.fail('adopted foreign workspace')
                        self.assertEqual((path/'foreign').read_text(),'other owner')
                        continue
                    path.rmdir()
                    if fault=='none':
                        with P.exclusive_source_workspace(path):
                            self.assertEqual(path.stat().st_mode & 0o777,0o700)
                        self.assertFalse(path.exists())
                    else:
                        with self.assertRaisesRegex(ValueError,'original owner'):
                            with P.exclusive_source_workspace(path):
                                path.rename(moved);path.mkdir(mode=0o700)
                        self.assertTrue(moved.exists())
                        self.assertTrue(path.exists())
                finally:
                    for item in (path,moved):
                        if item.exists(): shutil.rmtree(item)

    def test_production_source_parent_requires_real_root_owned_sticky_directory(self):
        from types import SimpleNamespace
        import stat
        from unittest.mock import MagicMock
        path=MagicMock()
        path.resolve.return_value=path
        for owner,mode,valid in ((0,stat.S_IFDIR|0o1777,True),(501,stat.S_IFDIR|0o1777,False),
                                 (0,stat.S_IFDIR|0o777,False),(0,stat.S_IFREG|0o1777,False)):
            path.lstat.return_value=SimpleNamespace(st_uid=owner,st_mode=mode)
            with self.subTest(owner=owner,mode=mode), patch.object(P,'Path',return_value=path) as ctor:
                if valid: self.assertIs(P.native_workspace_parent(),path)
                else:
                    with self.assertRaises(ValueError): P.native_workspace_parent()
                ctor.assert_called_once_with('/private/tmp')

    def test_native_download_requires_same_producer_attempt_for_both_images_and_manifest(self):
        with tempfile.TemporaryDirectory() as location:
            root=Path(location)
            images,manifests=root/'images',root/'manifests'
            images.mkdir();manifests.mkdir()
            key='amd64-'+REPO['commit']+'-'+RUN
            image=images/('darwin-child-images-'+key+'-1');image.mkdir()
            proof=manifests/('darwin-child-proof-images-'+key+'-1');proof.mkdir()
            value=dict(toolchain=G.UID.RACE.TOOLCHAIN)
            P.write_record(proof/'receipt.json',dict(P.scope('images','amd64',REPO,BUILD,RUN,'1'),result=value))
            self.assertEqual(P.received_images(images,manifests,'amd64',REPO,BUILD,RUN,'2'),(image,value))
            (images/('darwin-child-images-'+key+'-2')).mkdir()
            with self.assertRaisesRegex(ValueError,'different attempts'):
                P.received_images(images,manifests,'amd64',REPO,BUILD,RUN,'2')

    def test_actual_selected_xray_module_must_be_the_exact_sibling(self):
        with tempfile.TemporaryDirectory() as location:
            root=Path(location).resolve()
            core,xray=root/'core',root/'xray'
            core.mkdir();xray.mkdir()
            mod=core/'go.mod'
            def selection(path):
                return json.dumps(dict(Path=P.XRAY_MODULE, Dir=str(path), GoMod=str(path/'go.mod'),
                                  Replace=dict(Path=str(path),Dir=str(path),GoMod=str(path/'go.mod'))))
            for fault in ('none','foreign-module','moved-replacement','unselected-absolute-alias'):
                with self.subTest(fault=fault):
                    actual=root/'foreign' if fault in ('moved-replacement','foreign-module') else xray
                    token=str(root/'foreign') if fault=='moved-replacement' else str(xray)
                    if fault=='unselected-absolute-alias': token=str(core)+'/../xray'
                    mod.write_text('module original\nreplace '+P.XRAY_MODULE+' => '+token+'\n')
                    with patch.object(G.UID,'run',return_value=selection(actual)) as proc:
                        if fault=='none': self.assertEqual(P.selected_xray(core,'compiler',{}),xray)
                        else:
                            with self.assertRaises(ValueError): P.selected_xray(core,'compiler',{})
                        proc.assert_called_once_with(['compiler','list','-m','-mod=readonly','-json',P.XRAY_MODULE],cwd=core,env={},timeout=30)

    def test_pinned_tree_binds_real_go_embedded_html_assembly_and_local_file_identity(self):
        import subprocess
        original=G.load('darwin_xray_causal_projection','test_mobile_imported_socks_xray.py')
        with tempfile.TemporaryDirectory() as location:
            xray=Path(location).resolve()
            tracked={'go.mod':b'module github.com/xtls/xray-core\n','go.sum':b'',
                     'core/original.go':b'package core\n',
                     **{name:name.encode() for name in P.XRAY_REQUIRED if name.endswith(('.html','.s'))}}
            for name,raw in tracked.items():
                path=xray/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
            def git(*args):
                return subprocess.check_output(['git',*args],cwd=xray,text=True)
            git('init','-q');git('add','.')
            git('-c','user.name=Darwin test','-c','user.email=fixture@localhost','-c','commit.gpgsign=false','commit','-qm','source')
            pin=git('rev-parse','HEAD').strip()
            generated={'proxy/routervpn_vision_state_test.go':'vision_state_test.go.tmpl','core/routervpn_packet.go':'core_packet.go.tmpl',
                       'transport/internet/routervpn_scoped_dialer.go':'scoped_dialer.go.tmpl',
                       'transport/internet/routervpn_scoped_dialer_test.go':'scoped_dialer_test.go.tmpl',
                       'transport/internet/splithttp/routervpn_response_test.go':'wait_reader_test.go.tmpl'}
            for name,template in generated.items():
                path=xray/name;path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes((ROOT/'mobile/applexray'/template).read_bytes())
            with (patch.object(P,'XRAY_PIN',pin),patch.object(G.NODE.PREP.RELAY.XRAY,'XRAY_PIN',pin),
                  patch.object(original.XRAY,'XRAY_PIN',pin),patch.object(G,'load',return_value=original)):
                witness,owners=P.xray_tree(xray,verify_preparation=True)
                self.assertEqual(set(witness['files']),set(tracked)|set(generated))
                P.check_xray_manifest(witness)
                for name in ('core/original.go','transport/internet/browser_dialer/dialer.html','common/net/find_process_darwin.s'):
                    with self.subTest(file=name):
                        path=xray/name
                        raw=path.read_bytes();path.write_bytes(raw+b'changed')
                        with self.assertRaises(ValueError): P.xray_tree(xray,verify_preparation=True)
                        path.write_bytes(raw)
                @contextlib.contextmanager
                def prepared(*args,**kwargs):
                    yield xray/'core','go',{},xray
                with (patch.object(G,'prepared_source',prepared),patch.object(G,'selected_compiler',return_value=('go',{})),
                      patch.object(P,'selected_xray',return_value=xray),patch.object(P,'native_workspace_parent',return_value=xray)):
                    with self.assertRaisesRegex(ValueError,'lost its original local Xray dependency'):
                        with P.prepared_phase_source('go',{},REPO,RUN):
                            path=xray/'core/original.go'
                            replacement=xray/'other';replacement.write_bytes(path.read_bytes());replacement.replace(path)
                now,new_owners=P.xray_tree(xray,verify_preparation=False)
                self.assertEqual(now,witness);self.assertNotEqual(new_owners,owners)
                (xray/'foreign.go').write_text('package xray')
                with self.assertRaises(ValueError): P.xray_tree(xray,verify_preparation=True)

    def test_current_host_signed_failure_prevents_pf_call_and_native_receipt(self):
        with tempfile.TemporaryDirectory() as location:
            root=Path(location)
            source,workspace=root/'source',root/'core'
            before={'original':'a'*64}
            manifest=root/'compiler.json'
            dependency=dict(sha256='e'*64)
            data=dict(toolchain=G.UID.RACE.TOOLCHAIN,xray_source=dependency)
            P.write_record(manifest, dict(P.scope('images','amd64',REPO,BUILD,RUN,ATTEMPT),result=data))
            @contextlib.contextmanager
            def prepared(*args):
                yield source,'go',{},workspace,dependency
            with (patch.object(G,'required_host',return_value=('amd64',501)), patch.object(P,'prepared_phase_source',prepared),
                  patch.object(G,'checked_sources',return_value=(source,before)),patch.object(G,'selected_compiler',return_value=('go',{})),
                  patch.object(P,'received_images',return_value=(root/'images',data)),patch.object(P,'restore_images',return_value={}),patch.object(G.UID,'privilege_tool',return_value='/usr/bin/sudo'),
                  patch.object(G,'execute_preflight_images',side_effect=ValueError('current host refused signature')) as handshake,
                  patch.object(G,'execute_native_images') as native):
                with self.assertRaisesRegex(ValueError,'current host refused signature'):
                    P.run_phase('native','amd64',REPO,BUILD,RUN,ATTEMPT,root/'proof','go',root/'images',manifest)
                handshake.assert_called_once()
                native.assert_not_called()
                self.assertFalse((root/'proof/receipt.json').exists())


if __name__=='__main__':
    unittest.main(verbosity=2)
