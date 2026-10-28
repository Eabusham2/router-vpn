#!/usr/bin/env python3
"""Reject incomplete Tor matrices and stale native build evidence."""
from pathlib import Path
import hashlib
import importlib.util
import itertools
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('android_tor_graph_gate',ROOT/'deploy/test_android_tor_pinned.py')
GATE=importlib.util.module_from_spec(spec)
spec.loader.exec_module(GATE)


class TorNativeGate(unittest.TestCase):
    def build_prefix(self, sdk_variable='ANDROID_HOME', lose_selection=False, fail_install=False):
        shell=(ROOT/'android/build-sing-box-libbox.sh').read_text()
        prefix=shell.split('python3 "$ROOT/../deploy/stage-mobile-tor-notices.py"',1)[0]
        if lose_selection:
            original='export ANDROID_NDK_HOME="$SDK_ROOT/ndk/$NDK_VERSION"'
            self.assertIn(original,prefix)
            prefix=prefix.replace(original,'# reproduce the pre-selection Tor build')
        helper=r'''import json,os,sys
from pathlib import Path
args=sys.argv[1:];name=Path(sys.argv[0]).name
root=Path(os.environ['ROUTERVPN_TEST_SDK']);pin='28.0.13004108';ndk=root/'ndk'/pin
with open(os.environ['ROUTERVPN_TEST_CALLS'],'a') as out:
    out.write(json.dumps(dict(name=name,args=args,ndk_home=os.environ.get('ANDROID_NDK_HOME'),ndk_root=os.environ.get('ANDROID_NDK_ROOT')))+'\n')
if name=='sdkmanager':
    if args==['--licenses']:sys.exit(0)
    assert args==['ndk;'+pin],args
    if os.environ.get('ROUTERVPN_TEST_FAIL_INSTALL')=='1':sys.exit(23)
    ndk.mkdir(parents=True,exist_ok=True);(ndk/'source.properties').write_text('Pkg.Revision = '+pin+'\n')
elif '--digest' in args:print('0'*64)
else:
    assert Path(args[0]).name=='build-mobile-tor-package.py',args
    assert args[args.index('--platform')+1]=='android'
    assert args[args.index('--ndk')+1]==str(ndk)
    assert os.environ['ANDROID_NDK_HOME']==str(ndk) and os.environ['ANDROID_NDK_ROOT']==str(ndk)
    assert (ndk/'source.properties').read_text()=='Pkg.Revision = '+pin+'\n'
'''
        with tempfile.TemporaryDirectory(prefix='routervpn-pinned-ndk-') as temporary:
            root=Path(temporary);sdk=root/'sdk with spaces';binary=root/'tools';binary.mkdir()
            manager=sdk/'cmdline-tools/latest/bin/sdkmanager';manager.parent.mkdir(parents=True)
            for path in (manager,binary/'python3'):
                path.write_text('#!'+sys.executable+'\n'+helper);path.chmod(0o755)
            script=root/'android-prefix.sh';script.write_text(prefix)
            log=root/'calls.jsonl'
            env=dict(os.environ,PATH=str(binary)+os.pathsep+os.environ['PATH'],
                     ANDROID_HOME='',ANDROID_SDK_ROOT='',ANDROID_NDK_HOME=str(root/'foreign-ndk'),ANDROID_NDK_ROOT=str(root/'other-ndk'),
                     ROUTERVPN_TEST_SDK=str(sdk),ROUTERVPN_TEST_CALLS=str(log),ROUTERVPN_TEST_FAIL_INSTALL='1' if fail_install else '0')
            env[sdk_variable]=str(sdk)
            result=subprocess.run(['bash',str(script)],env=env,text=True,capture_output=True,timeout=15)
            calls=[json.loads(line) for line in log.read_text().splitlines()]
            return result,calls

    def test_real_builder_selects_one_pinned_ndk_before_tor(self):
        for variable in ('ANDROID_HOME','ANDROID_SDK_ROOT'):
            with self.subTest(variable=variable):
                result,calls=self.build_prefix(variable)
                self.assertEqual(result.returncode,0,result.stderr)
                install=next(i for i,call in enumerate(calls) if call['args']==['ndk;28.0.13004108'])
                tor=next(i for i,call in enumerate(calls) if call['name']=='python3' and Path(call['args'][0]).name=='build-mobile-tor-package.py')
                self.assertLess(install,tor)

    def test_missing_selection_or_failed_install_cannot_start_native_tor(self):
        result,calls=self.build_prefix(lose_selection=True)
        self.assertNotEqual(result.returncode,0,'ambient NDK regression was accepted')
        result,calls=self.build_prefix(fail_install=True)
        self.assertEqual(result.returncode,23,result.stderr)
        self.assertFalse(any(call['name']=='python3' and Path(call['args'][0]).name=='build-mobile-tor-package.py' for call in calls))

    def test_aar_verifier_explicitly_receives_the_builder_ndk(self):
        shell=(ROOT/'android/build-sing-box-libbox.sh').read_text()
        body=shell.split('verify_aar() {',1)[1].split('  python3 "$ROOT/../deploy/stage-mobile-tor-notices.py"',1)[0]
        helper='''import os,sys
from pathlib import Path
args=sys.argv[1:]
assert Path(args[0]).name=='verify-mobile-tor-link.py',args
assert args[1:]==['--native-package',os.environ['TOR_PACKAGE'],'--android-aar',os.environ['AAR'],'--ndk',os.environ['ANDROID_NDK_HOME']],args
'''
        with tempfile.TemporaryDirectory(prefix='routervpn-aar-ndk-') as temporary:
            root=Path(temporary);binary=root/'tools';binary.mkdir()
            python=binary/'python3';python.write_text('#!'+sys.executable+'\n'+helper);python.chmod(0o755)
            aar=root/'libbox.aar';aar.write_bytes(b'fixture')
            license=root/'LICENSE';license.write_bytes(b'fixture')
            env=dict(os.environ,PATH=str(binary)+os.pathsep+os.environ['PATH'],ROOT=str(ROOT/'android'),
                     AAR=str(aar),AMNEZIA_LICENSE_OUT=str(license),TOR_PACKAGE=str(root/'native tor'),
                     ANDROID_NDK_HOME=str(root/'sdk with spaces/ndk/28.0.13004108'),ANDROID_NDK_ROOT=str(root/'foreign'))
            result=subprocess.run(['bash','-c','set -euo pipefail\n'+body],env=env,text=True,capture_output=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn(' --ndk "$ANDROID_NDK_HOME"',body)
            original=body.replace(' --ndk "$ANDROID_NDK_HOME"','')
            result=subprocess.run(['bash','-c','set -euo pipefail\n'+original],env=env,text=True,capture_output=True,timeout=15)
            self.assertNotEqual(result.returncode,0,'Missing explicit AAR NDK argument was accepted')

    def populate(self,root):
        for kind,mode,layer in itertools.product(GATE.KINDS,GATE.MODES,GATE.LAYERS):
            (root/f'{kind}-{mode}-{layer}.json').write_text('{}')
            (root/f'server-{kind}-{mode}-{layer}.json').write_text('{}')
        for kind in GATE.KINDS:(root/f'{kind}-direct-off.json').write_text('{}')
        for kind,(mode,protocol) in itertools.product(GATE.KINDS,GATE.ORDINARY_MODES.items()):
            owner=dict(type='routervpn-tor',tag='routervpn-tor-exit',detour='custom-exit',session_id='captured-session',
                external_tor_profile=json.dumps(dict(id='tor-exit',multihop_enabled=True,
                    multihop_entry_id='ordinary-entry',multihop_entry_mode=protocol,multihop_exit_id='tor-exit',
                    multihop_exit_mode='tor' if kind=='tor' else 'tor-bridge',multihop_execution='local')),
                external_predecessor_profile=json.dumps(dict(id='ordinary-entry',node_kind='external',
                    external=dict(protocol=protocol,expected_public_ip='203.0.113.88'))),
                external_predecessor_config=json.dumps(dict(route=dict(final='custom-exit'))))
            (root/f'ordinary-{kind}-{mode}.json').write_text(json.dumps(dict(outbounds=[owner])))

    def test_matrix_requires_every_named_branch_and_no_extra_entry(self):
        for mutation in ('missing','empty','large','directory','link','extra','different-name'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);self.populate(root);GATE.matrix(root)
                self.assertEqual(len(list(root.iterdir())),738)
                path=root/'snowflake-max-quic-awg-aes-256-gcm.json'
                if mutation=='missing':path.unlink()
                elif mutation=='empty':path.write_text('')
                elif mutation=='large':
                    with path.open('wb') as output:output.truncate(4*1024*1024+1)
                elif mutation=='directory':path.unlink();path.mkdir()
                elif mutation=='link':path.unlink();path.symlink_to(root/'tor-direct-off.json')
                elif mutation=='extra':(root/'349.json').write_text('{}')
                else:path.rename(root/'snowflake-unknown-aes-256-gcm.json')
                with self.assertRaises(ValueError):GATE.matrix(root)

    def test_ordinary_matrix_preserves_all_transports_and_captured_authority(self):
        faults=('missing','old-graph','missing-profile','wrong-kind','wrong-protocol','wrong-entry','wrong-mode',
                'private-api','private-token','private-agent','server','unknown-source','foreign-route','empty-session','second-owner')
        for fault in faults:
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);self.populate(root);GATE.matrix(root)
                names={path.name for path in root.iterdir()}
                self.assertEqual(sum(name.startswith('ordinary-') for name in names),48)
                self.assertEqual(sum(name.startswith('server-') for name in names),342)
                self.assertEqual(sum(not name.startswith(('ordinary-','server-')) for name in names),348)
                graph=root/'ordinary-tor-socks5.json';body=json.loads(graph.read_text());owner=body['outbounds'][0]
                entry=json.loads(owner['external_predecessor_profile']);selected=json.loads(owner['external_tor_profile'])
                if fault=='missing':graph.unlink()
                elif fault=='old-graph':body={}
                elif fault=='missing-profile':del owner['external_predecessor_profile']
                elif fault=='wrong-kind':entry['node_kind']='router-vpn'
                elif fault=='wrong-protocol':entry['external']['protocol']='wireguard'
                elif fault=='wrong-entry':selected['multihop_entry_id']='foreign-entry'
                elif fault=='wrong-mode':selected['multihop_entry_mode']='wireguard'
                elif fault=='private-api':entry['router_api']='http://10.77.0.1:8787'
                elif fault=='private-token':entry['api_token']='unowned-private-credential'
                elif fault=='private-agent':entry['agent_token']='unowned-private-credential'
                elif fault=='server':selected['multihop_execution']='server'
                elif fault=='unknown-source':owner['external_predecessor_config']='null'
                elif fault=='foreign-route':owner['external_predecessor_config']=json.dumps(dict(route=dict(final='direct')))
                elif fault=='empty-session':owner['session_id']=''
                else:body['outbounds'].append(owner.copy())
                if fault!='missing-profile':owner['external_predecessor_profile']=json.dumps(entry)
                owner['external_tor_profile']=json.dumps(selected)
                if fault!='missing':graph.write_text(json.dumps(body))
                with self.assertRaises(ValueError):GATE.matrix(root)

    def populate_padding(self, root):
        def write(name, mode, kind, rate, ordinary):
            selected=dict(id='tor-exit',node_kind='external',daita_enabled=True,daita_rate_kbps=rate,
                          multihop_execution='local',multihop_enabled=mode!='direct',
                          external=dict(protocol='tor' if kind=='tor' else 'tor-bridge'))
            if kind!='tor':selected['external']['tor_bridge']=dict(transport=kind)
            source={}
            if mode!='direct':
                selected.update(multihop_entry_mode=mode,multihop_entry_id='captured-entry')
                entry=dict(id='captured-entry',node_kind='external' if ordinary else 'router-vpn')
                if ordinary:entry['external']=dict(protocol=mode)
                source.update(predecessor_profile=json.dumps(entry),predecessor_config='{"route":{}}')
            source['profile']=json.dumps(selected)
            owner=dict(type='routervpn-tor',tag='routervpn-tor-exit',session_id='captured',padding_source=source)
            (root/name).write_text(json.dumps(dict(outbounds=[owner])))
        for index,(mode,kind,rate) in enumerate(itertools.product(('direct',*GATE.MODES),('tor','obfs4'),(0,32,64,192))):
            write(f'padding-{index:03d}.json',mode,kind,rate,False)
        for index,(mode,kind,rate) in enumerate(itertools.product(GATE.ORDINARY_MODES.values(),('tor','obfs4'),(0,32,64,192)),8):
            write(f'ordinary-padding-{index:03d}.json',mode,kind,rate,True)

    def test_enabled_padding_matrix_requires_every_source_family_and_rate(self):
        faults=('missing','empty','linked','extra','repeat','disabled','typed-rate','missing-source','entry-id','private-authority','server')
        for fault in faults:
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);self.populate_padding(root);GATE.padding_matrix(root)
                self.assertEqual(len(list(root.iterdir())),224)
                path=root/'ordinary-padding-008.json'
                graph=json.loads(path.read_text());source=graph['outbounds'][0]['padding_source']
                selected=json.loads(source['profile']);entry=json.loads(source['predecessor_profile'])
                if fault=='missing':path.unlink()
                elif fault=='empty':path.write_text('')
                elif fault=='linked':path.unlink();path.symlink_to(root/'ordinary-padding-009.json')
                elif fault=='extra':(root/'unexpected.json').write_text('{}')
                elif fault=='repeat':path.write_bytes((root/'ordinary-padding-009.json').read_bytes())
                else:
                    if fault=='disabled':selected['daita_enabled']=False
                    elif fault=='typed-rate':selected['daita_rate_kbps']='64'
                    elif fault=='missing-source':source.pop('predecessor_config')
                    elif fault=='entry-id':selected['multihop_entry_id']='replacement'
                    elif fault=='private-authority':entry['node_kind']='router-vpn'
                    elif fault=='server':selected['multihop_execution']='server'
                    source['profile']=json.dumps(selected);source['predecessor_profile']=json.dumps(entry)
                    path.write_text(json.dumps(graph))
                with self.assertRaises(ValueError):GATE.padding_matrix(root)

    def test_enabled_native_gate_checks_actual_constructors_and_captured_sources(self):
        native=GATE.PADDING_TEMPLATE.read_text()
        for marker in ('len(entries) != 224','CheckConfig(string(data))','CheckConfig(string(bad))',
                       'RouterTorPaddingSource','routervpn-missing-tor-engine','daita_rate_kbps','RouterTorSetStateDirectory'):
            self.assertIn(marker,native)
        self.assertIn(GATE.JAVA/'AndroidTorPaddingReceipt.java',GATE.inputs())
        self.assertIn(GATE.PADDING_TEMPLATE,GATE.inputs())

    def test_linked_matrix_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);graphs=root/'graphs';graphs.mkdir();self.populate(graphs)
            alias=root/'alias';alias.symlink_to(graphs,target_is_directory=True)
            with self.assertRaises(ValueError):GATE.matrix(alias)

    def test_cache_digest_captures_tor_host_and_executable_fixture_changes(self):
        paths=GATE.inputs();self.assertEqual(len(paths),len(set(paths)))
        before=GATE.digest();read=Path.read_bytes
        for relative in ('android/app/src/main/java/com/eabusham/routervpn/AndroidTorProfile.java',
                         'android/app/src/main/java/com/eabusham/routervpn/AndroidTorSession.java',
                         'android/app/src/main/java/com/eabusham/routervpn/AndroidTorCompareRuntime.java',
                         'android/test_android_tor_compare.py',
                         'android/app/src/main/java/com/eabusham/routervpn/AndroidStartupPolicy.java',
                         'android/app/src/main/java/com/eabusham/routervpn/AndroidUnifiedConnectionController.java',
                         'android/app/src/main/java/com/eabusham/routervpn/AndroidMTUMeasurementGate.java',
                         'android/app/src/main/java/com/eabusham/routervpn/AndroidConnectionSelection.java',
                         'android/app/src/main/java/com/eabusham/routervpn/AndroidConnectionProfileStore.java',
                         'android/app/src/main/java/com/eabusham/routervpn/AndroidNodeStore.java',
                         'android/app/src/main/java/com/eabusham/routervpn/AndroidProfileSelection.java',
                         'android/app/src/main/java/com/eabusham/routervpn/AndroidPrivateFileStore.java',
                         'android/test_android_startup_policy.py',
                         'mobile/routervpn_openvpn.go','internal/nativeopenvpn/pairing.go',
                         'android/test_android_external_permission.py','android/test_android_speed_lab_restore.py',
                         'android/app/src/main/java/com/eabusham/routervpn/AndroidTorPaddingReceipt.java',
                         'android/app/src/main/java/com/eabusham/routervpn/LayeredVpnService.java',
                         'android/app/src/main/java/com/eabusham/routervpn/StandardExitActivity.java',
                         'android/test_android_tor_profile.py','android/test_android_tor_server_profile.py','android/test_android_tor_session.py',
                         'android/test_android_tor_form.py','android/test_android_start_layer_relay_lifecycle.py',
                         'deploy/native_tor_graph_host.py','deploy/test_native_tor_graph_host.py',
                         'mobile/routervpn_tor_android_graph_test.go.tmpl','mobile/routervpn_tor_android_padding_graph_test.go.tmpl'):
            changed=ROOT/relative;self.assertIn(changed,paths)
            with mock.patch.object(Path,'read_bytes',lambda path:read(path)+(b'\nchanged fixture\n' if path==changed else b'')):
                self.assertNotEqual(before,GATE.digest())

    def test_prepared_parser_requires_exact_owned_tor_source(self):
        copied={'protocol/routervpntor/owned.go':b'package owned\n'}
        dns=(ROOT/'mobile/toroutbound/dns_adapter.go.tmpl').read_bytes()
        for mutation in ('digest','source','extra-file-record','dns'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary)
                for relative,data in {**copied,'dns/transport_adapter.go':dns}.items():
                    target=root/relative;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
                record=dict(schema=1,core=GATE.M.PIN,source_sha256='current',
                            files={path:hashlib.sha256(data).hexdigest() for path,data in copied.items()},
                            dns_adapter_sha256=hashlib.sha256(dns).hexdigest())
                manifest=root/GATE.T.OWNER;manifest.write_text(json.dumps(record))
                with mock.patch.object(GATE.T,'copies',return_value=copied),mock.patch.object(GATE.T,'digest',return_value='current'):
                    GATE.verify_prepared(root)
                    if mutation=='digest':record['source_sha256']='stale'
                    elif mutation=='source':(root/'protocol/routervpntor/owned.go').write_bytes(b'changed')
                    elif mutation=='extra-file-record':record['files']['unexpected.go']='0'*64
                    else:(root/'dns/transport_adapter.go').write_bytes(b'unowned resolver')
                    manifest.write_text(json.dumps(record))
                    with self.assertRaises(ValueError):GATE.verify_prepared(root)

    def test_build_requires_native_graphs_proof_handles_and_host_lifecycle_tests(self):
        shell=(ROOT/'android/build-sing-box-libbox.sh').read_text()
        call='test_android_tor_pinned.py" "$VENDOR" --native-package "$TOR_HOST_PACKAGE"'
        self.assertIn(call,shell)
        self.assertLess(shell.index(call),shell.index('go_retry run ./cmd/internal/build_libbox -target android'))
        self.assertLess(shell.index('ANDROID_TOR_GRAPH_SHA='),shell.index('if [[ -s "$AAR"'))
        self.assertIn('"$OPENVPN_SHA" "$ANDROID_TOR_GRAPH_SHA"',shell)
        for symbol in ('routerCompileTorProfile','routerValidateTorProfile','routerCompileTorProfileWithPredecessor',
                       'routerCompileTorProfileWithExternalPredecessor',
                       'routerTorPaddingSource','java.lang.String paddingStatusJSON() throws java.lang.Exception;',
                       'routerTorSetStateDirectory','routerTorCreateProof',
                       'routerTorCreateProofWithPredecessor','routerStrategyDNSProof','routerStrategyCloseService',
                       'RouterTorProofRequest','java.lang.String run() throws java.lang.Exception;',
                       'void cancel();','boolean healthy();'):
            self.assertIn(symbol,shell)
        for symbol in ('routerPrepareExternalExecutionCapture','routerValidateExternalResponseProbe',
                       'java.lang.String execution();','void close() throws java.lang.Exception;'):
            self.assertIn(symbol,shell)
        gradle=(ROOT/'android/app/build.gradle').read_text()
        preparation=gradle.split("tasks.register('prepareSingBoxLibbox', Exec) {",1)[1].split('\n}\n',1)[0]
        self.assertIn("dependsOn 'testNativeTorNdkSelection'",preparation)
        self.assertIn("rootProject.file('../deploy/test_android_tor_ndk_selection.py')",preparation)
        regression=gradle.split("tasks.register('testNativeTorNdkSelection', Exec) {",1)[1].split('\n}\n',1)[0]
        self.assertIn("'../deploy/test_android_tor_ndk_selection.py', '--gradle'",regression)
        self.assertIn("new File(gradle.gradleHomeDir, 'bin/gradle').absolutePath",regression)
        self.assertIn('timeout = java.time.Duration.ofMinutes(8)',regression)
        self.assertIn("rootProject.file('../deploy/test_android_tor_pinned.py')",gradle)
        self.assertIn("rootProject.file('test_android_tor_profile.py')",gradle)
        for path in ('native_tor_graph_host.py','test_native_tor_graph_host.py'):
            self.assertIn("rootProject.file('../deploy/"+path+"')",gradle)
        runtime=(ROOT/'android/test_android_runtime_contract.py').read_text()
        for script in ('test_android_tor_profile.py','test_android_tor_session.py','deploy/test_android_tor_pinned_contract.py','deploy/test_native_tor_graph_host.py'):
            self.assertIn('"'+script+'"',runtime)
        source=(ROOT/'deploy/test_android_tor_pinned.py').read_text()
        self.assertIn('with_gvisor,with_openvpn,with_naive_outbound',source)
        self.assertIn('with_naive_outbound,routervpn_tor_native_test',source)
        self.assertIn('env=HOST.environment(go,library,clang)',source)
        self.assertIn("'^TestRouterTorAndroidGeneratedGraphs$|^TestRouterTorAndroidLocalPaddingGraphs$'",source)
        native=GATE.TEMPLATE.read_text()
        for marker in ('len(entries) != 738','CheckConfig(string(data))','CheckConfig(string(bad))',
                       'routervpn-missing-tor-engine','RouterTorSetStateDirectory'):
            self.assertIn(marker,native)


if __name__=='__main__':unittest.main()
