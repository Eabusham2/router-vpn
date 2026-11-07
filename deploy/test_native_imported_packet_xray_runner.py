#!/usr/bin/env python3
"""Exercise strict packet REALITY inventory, source and execution boundaries."""
from pathlib import Path
import ast
import contextlib
import fnmatch
import hashlib
import importlib.util
import io
import json
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('native_packet_reality_gate',ROOT/'deploy/test_native_imported_packet_xray.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class PacketReferenceInventory(unittest.TestCase):
    def events(self, expected):
        return '\n'.join(json.dumps({'Action':action,'Test':name}) for name in sorted(expected) for action in ('run','pass'))

    def test_every_original_input_schedules_its_recorded_reference_workflow(self):
        workflow = ROOT/'.github/workflows/imported-packet-reality-native.yml'
        sources = set(gate.inputs())
        self.assertIn(workflow, sources)
        paths = workflow.read_text().split('    paths:\n',1)[1].split('\npermissions:',1)[0]
        patterns = [ast.literal_eval(line.strip()[2:]) for line in paths.splitlines()
                    if line.strip().startswith('- ')]
        self.assertTrue(patterns)
        for source in sources:
            relative = source.relative_to(ROOT).as_posix()
            with self.subTest(source=relative):
                self.assertTrue(any(fnmatch.fnmatchcase(relative, pattern) for pattern in patterns),
                                'Original packet source no longer schedules its native reference: '+relative)

    def test_exact_original_capture_and_native_inventory(self):
        self.assertEqual(len(gate.CAPTURE.FILES),36)
        self.assertEqual(len(gate.CAPTURE.IMPORTED.names(gate.CAPTURE.CORE)),298)
        self.assertEqual(gate.CAPTURE.KINDS,('wireguard','amneziawg','openvpn-tcp','openvpn-udp'))
        self.assertEqual({name:len(gate.CAPTURE.IMPORTED.names({name:children})) for name,children in gate.PEERS.items()}, {
            'TestRouterVPNImportedWireGuardRealityNativeTraffic':75,
            'TestRouterVPNImportedAmneziaRealityNativeTraffic':76,
            'TestRouterVPNImportedOpenVPNTCPRealityNativeTraffic':73,
            'TestRouterVPNImportedOpenVPNUDPRealityNativeTraffic':73,
            gate.DNS_PARENT:49})
        expected=gate.CAPTURE.IMPORTED.names(gate.GROUPS)
        self.assertEqual(len(expected),351)
        self.assertIn('TestRouterVPNImportedCONNECTRealityDNSCertificateRefusal', gate.SUPPORT)
        self.assertEqual(sum(name.count('/')==2 for name in gate.CAPTURE.IMPORTED.names(gate.PEERS)),301)
        self.assertTrue(gate.TAGS.endswith(',routervpn_openvpn_remote_test'))
        gate.SOCKS.require_verdicts(self.events(expected),0,expected)

    def test_every_native_name_is_required_once_without_skip_or_replacement(self):
        expected=gate.CAPTURE.IMPORTED.names(gate.GROUPS)
        for missing in expected:
            with self.subTest(missing=missing),self.assertRaises(ValueError):
                gate.SOCKS.require_verdicts(self.events(expected-{missing}),0,expected)
        original=self.events(expected)
        for changed in (original+'\n'+json.dumps({'Action':'pass','Test':sorted(expected)[0]}),
                        original.replace('"pass"','"skip"',1),original.replace('"pass"','"fail"',1),
                        original.replace(sorted(expected)[0],'TestForeignPacketOwner')):
            with self.assertRaises(ValueError):gate.SOCKS.require_verdicts(changed,0,expected)
        with self.assertRaises(ValueError):gate.SOCKS.require_verdicts(original,1,expected)

    def test_prepared_packet_copies_cannot_be_missing_changed_or_linked(self):
        for _,target in gate.PEER_COPIES:
            for fault in ('success','missing','changed','symlink'):
                with self.subTest(target=target,fault=fault),tempfile.TemporaryDirectory() as temporary:
                    vendor=Path(temporary)
                    for source,relative in gate.PEER_COPIES:
                        path=vendor/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes((ROOT/source).read_bytes())
                    path=vendor/target
                    if fault=='missing':path.unlink()
                    if fault=='changed':path.write_bytes(path.read_bytes()+b'\n// foreign source\n')
                    if fault=='symlink':
                        foreign=vendor/'foreign.go';foreign.write_bytes(path.read_bytes());path.unlink();path.symlink_to(foreign)
                    with mock.patch.object(gate.CONNECT,'checked_sources',return_value={'retained':'a'*64}) as retained, \
                         mock.patch.object(gate.NODE,'checked_sources',return_value=(vendor,{'original-native':'b'*64})) as native:
                        if fault=='success':
                            records=gate.checked_sources(vendor)
                            self.assertEqual(records['retained'],'a'*64);self.assertEqual(records['native/original-native'],'b'*64)
                            for _,relative in gate.PEER_COPIES:self.assertIn(relative,records)
                        else:
                            with self.assertRaises(ValueError):gate.checked_sources(vendor)
                        retained.assert_called_once_with(vendor,True);native.assert_called_once_with(vendor)


class PacketReferenceExecution(unittest.TestCase):
    def test_compile_keeps_race_remote_tag_and_original_deadline(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace=Path(temporary);image=workspace/'packet-reality-peers'
            def compile_native(command,cwd,env,timeout):
                self.assertEqual(command,['go','test','-mod=readonly','-race','-c','-ldflags=-checklinkname=0','-tags',gate.TAGS,'-o',image,'./protocol/routervpnamnezia'])
                self.assertEqual((cwd,env,timeout),(Path('core'),{'captured':'1'},600))
                image.write_bytes(b'original native image');return 0,''
            with mock.patch.object(gate.CONNECT,'run_command',side_effect=compile_native):
                actual,digest=gate.compile_image('go',Path('core'),workspace,{'captured':'1'})
            self.assertEqual((actual,digest),(image,hashlib.sha256(image.read_bytes()).hexdigest()))
            diagnostic='first native cause\n'+'original detail\n'*3000+'last native cause\n'
            with mock.patch.object(gate.CONNECT,'run_command',return_value=(1,diagnostic)),contextlib.redirect_stdout(io.StringIO()) as shown:
                with self.assertRaises(ValueError):gate.compile_image('go',Path('core'),workspace,{})
            self.assertEqual(shown.getvalue(),diagnostic)

    def test_compiled_root_discovery_rejects_missing_duplicate_moved_and_changed_image(self):
        roots=sorted(gate.GROUPS)
        for fault in ('success','missing','duplicate','moved','failure','changed-image'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as temporary:
                image=Path(temporary)/'native';image.write_bytes(b'original image');digest=hashlib.sha256(image.read_bytes()).hexdigest()
                names=list(roots)
                if fault=='missing':names.pop()
                if fault=='duplicate':names[-1]=names[0]
                if fault=='moved':names[-1]+='/Moved'
                def execute(command,cwd,env,timeout):
                    self.assertEqual(command,[image,'-test.list=^('+'|'.join(gate.GROUPS)+')$'])
                    self.assertEqual(timeout,30)
                    if fault=='changed-image':image.write_bytes(b'changed image')
                    return int(fault=='failure'),'\n'.join(names)+'\n'
                with mock.patch.object(gate.CONNECT,'run_command',side_effect=execute),contextlib.redirect_stdout(io.StringIO()):
                    if fault=='success':self.assertEqual(gate.discover_roots('go',Path('core'),{},image,digest),roots)
                    else:
                        with self.assertRaises(ValueError):gate.discover_roots('go',Path('core'),{},image,digest)

    def test_every_reference_root_stops_on_original_failure_or_timeout(self):
        parents=list(gate.GROUPS)
        for failed in (None,*parents):
            for error_type in (ValueError,subprocess.TimeoutExpired):
                with self.subTest(failed=failed,error=error_type.__name__),tempfile.TemporaryDirectory() as temporary:
                    workspace=Path(temporary);binary=workspace/'reference';binary.write_bytes(b'original reference image')
                    digest=hashlib.sha256(binary.read_bytes()).hexdigest();original={'original-source':'a'*64};calls=[]
                    failure=error_type('original failure') if error_type is ValueError else error_type(['original-native'],195,output=b'original timeout')
                    def execute(compiler,vendor,env,image,image_digest,parent,expected,timeout):
                        self.assertEqual(image,workspace/'native');self.assertEqual(image_digest,'b'*64)
                        self.assertEqual(set(expected),gate.CAPTURE.IMPORTED.names({parent:gate.GROUPS[parent]}))
                        self.assertEqual(timeout,90 if parent in gate.SUPPORT else 180)
                        calls.append(parent)
                        if parent==failed:raise failure
                        return {'sha256':image_digest,'verdicts':expected}
                    with mock.patch.object(gate.CONNECT,'build_reference',return_value=(workspace/'xray',original,binary,digest,workspace/'overlay',{})), \
                         mock.patch.object(gate,'compile_image',return_value=(workspace/'native','b'*64)) as compile_native, \
                         mock.patch.object(gate,'discover_roots',return_value=sorted(parents)) as discover, \
                         mock.patch.object(gate.CONNECT,'execute_image',side_effect=execute), \
                         mock.patch.object(gate.SOCKS,'checked_xray',return_value=original) as recheck, \
                         mock.patch.object(gate.SOCKS,'check_reference_instrumentation') as instrumentation:
                        if failed:
                            with self.assertRaises(error_type) as caught:gate.reference_stage('go',Path('core'),workspace,{})
                            self.assertIs(caught.exception,failure);recheck.assert_not_called();instrumentation.assert_not_called()
                        else:
                            receipt=gate.reference_stage('go',Path('core'),workspace,{})
                            self.assertEqual(sum(len(value['verdicts']) for group in ('support','peers') for value in receipt[group].values()),351)
                            recheck.assert_called_once();instrumentation.assert_called_once()
                        compile_native.assert_called_once();discover.assert_called_once()
                    self.assertEqual(calls,parents[:parents.index(failed)+1] if failed else parents)

    def test_actual_source_export_and_final_capture_checks_bound_reference_stage(self):
        for fault in ('success','missing-capture','changed-capture','changed-source','changed-prepared','changed-xray','producer-failure'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as temporary:
                vendor=Path(temporary)/'core';vendor.mkdir();compiler=Path(temporary)/'go';compiler.write_bytes(b'compiler boundary')
                exported=[]
                def compiler_env(command,**options):
                    return {'GOVERSION':gate.SOCKS.TOOLCHAIN,'GOHOSTOS':'linux','GOHOSTARCH':'amd64'}[command[-1]]+'\n'
                def produce(command,cwd,env,expected,timeout):
                    self.assertEqual(cwd,ROOT);self.assertEqual(timeout,240);self.assertIn('-race',command);self.assertIn('-timeout=60s',command)
                    self.assertEqual(set(expected),gate.CAPTURE.IMPORTED.names(gate.CAPTURE.CORE))
                    if fault=='producer-failure':raise ValueError('original producer failure')
                    directory=Path(env[gate.CAPTURE.SHARED_ENV]);self.assertEqual(list(directory.iterdir()),[])
                    exported.append(directory)
                    for name in gate.CAPTURE.FILES:(directory/name).write_bytes(name.encode())
                    if fault=='missing-capture':(directory/next(iter(gate.CAPTURE.FILES))).unlink()
                def reference(*args):
                    self.assertEqual(len(gate.CAPTURE.captured_matrix(exported[0])),36)
                    if fault=='changed-capture':(exported[0]/next(iter(gate.CAPTURE.FILES))).write_bytes(b'changed after native execution')
                    return {}
                with mock.patch.object(gate.platform,'system',return_value='Linux'),mock.patch.object(gate.shutil,'which',return_value=str(compiler)), \
                     mock.patch.object(gate.subprocess,'check_output',side_effect=compiler_env),mock.patch.object(gate.subprocess,'run') as runner, \
                     mock.patch.object(gate,'source_receipt',side_effect=[{'source':'a'*64},{'source':('b' if fault=='changed-source' else 'a')*64}]), \
                     mock.patch.object(gate,'checked_sources',side_effect=[{'native':'a'*64},{'native':('b' if fault=='changed-prepared' else 'a')*64}]), \
                     mock.patch.object(gate.CONNECT.PROXY,'resolved_xray',side_effect=[(vendor,{'xray':'a'*64}),(vendor,{'xray':('b' if fault=='changed-xray' else 'a')*64})]), \
                     mock.patch.object(gate.CONNECT,'execute',side_effect=produce),mock.patch.object(gate,'reference_stage',side_effect=reference) as stage,contextlib.redirect_stdout(io.StringIO()):
                    if fault=='success':self.assertEqual(len(gate.run(vendor)['shared']),36)
                    else:
                        with self.assertRaises(ValueError):gate.run(vendor)
                    if fault in ('producer-failure','missing-capture'):stage.assert_not_called()
                    else:stage.assert_called_once()
                    self.assertEqual(runner.call_args.kwargs['timeout'],30)
                for directory in exported:self.assertFalse(directory.exists())


if __name__ == '__main__':
    unittest.main()
