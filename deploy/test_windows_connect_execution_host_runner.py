#!/usr/bin/env python3
"""Strict Windows execution scheduling/receipt controls; no simulated native acceptance."""
from pathlib import Path
from contextlib import contextmanager,redirect_stdout
from copy import deepcopy
from types import SimpleNamespace
import importlib.util,io,json,os,re,tempfile,unittest
import hashlib
import shutil
import stat
import subprocess
from unittest.mock import patch,Mock
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('windows_execution_gate',ROOT/'deploy/test_windows_connect_execution_host.py')
G=importlib.util.module_from_spec(spec);spec.loader.exec_module(G)

def counters(case):
    value=dict(case=case,launches=1,entry_raw_udp=1,entry_tcp=1,entry_proofs=1,middle_raw_tcp=1,middle_tcp=1,middle_public=1,final_raw_tcp=1,final_tcp=1,final_proofs=1,dns=1,middle_raw_udp=0,final_raw_udp=0,auth_refusals=0,tls_refusals=0,open_streams=0,entry_layer=G.ENTRY_LAYERS[case],entry_layer_packets=0,entry_layer_ciphertext=0,entry_layer_auth=0,restore_launches=int(case in G.CASES[:6] and not case.endswith('auto-local')),comparison_trials=2 if '-auto-' in case else 0,native_joined=True,journal_settled=True,wfp_absent=True,tun_absent=True,aliases_removed=True)
    if value['entry_layer']!='off':value.update(entry_layer_packets=1,entry_layer_ciphertext=1)
    if case in ('http-wrong-auth','https-wrong-auth','https-tls-name'):
        value.update(middle_tcp=0,middle_public=0,final_raw_tcp=0,final_tcp=0,final_proofs=0,dns=0)
        value['tls_refusals' if case=='https-tls-name' else 'auth_refusals']=1
    if case=='http-wrong-public':value.update(final_raw_tcp=0,final_tcp=0,final_proofs=0,dns=0)
    if case=='https-wrong-final':value.update(final_tcp=0,final_proofs=0,dns=0)
    return value

def completed(case,value=None):
    value=counters(case) if value is None else value
    return ('=== RUN   '+G.TEST+'\n=== RUN   '+G.TEST+'/'+case+'\n'+
            '    desktop_connect_execution_windows_native_test.go:200: WINDOWS_CONNECT_EXECUTION_COUNTERS '+json.dumps(value)+'\n'+
            '    desktop_connect_execution_windows_native_test.go:201: '+G.receipt(case)+'\n'+
            '--- PASS: '+G.TEST+' (0.01s)\n    --- PASS: '+G.TEST+'/'+case+' (0.01s)\nPASS\n')

def worker_completed():
    root='TestRouterVPNWindowsExecutionPrivateWorker'
    names=[root,*(root+'/'+case for case in G.WORKER_CASES)]
    return ''.join('=== RUN   '+name+'\n--- PASS: '+name+' (0.01s)\n' for name in names)+'PASS\n'

def source_completed():
    names=[name for root,leaves in G.SOURCE_TESTS.items() for name in (root,*(root+'/'+leaf for leaf in leaves))]
    return ''.join('=== RUN   '+name+'\n--- PASS: '+name+' (0.01s)\n' for name in names)+'PASS\n'

class WindowsExecutionContract(unittest.TestCase):
    def test_exact_source_inventory_and_real_boundaries(self):
        self.assertEqual(G.case_inventory(),G.CASES)
        self.assertEqual(len(G.CASES),14);self.assertEqual(len(set(G.CASES)),14)
        self.assertEqual(len(G.source_verdict(source_completed())),31)
        raw=(ROOT/'cmd/client/desktop_connect_execution_windows_aliases_test.go').read_text()
        for boundary in ('CreateUnicastIpAddressEntry','GetUnicastIpAddressEntry','DeleteUnicastIpAddressEntry','CreationTimeStamp == current.CreationTimeStamp','if err := join(ctx); err != nil','!windowsCONNECTPhysicalAliasSame(original, current)','a.removed[i] = true'):
            self.assertIn(boundary,raw)
        source=(ROOT/'cmd/client/ordered_candidate_prefix_windows_native_test.go').read_text()
        self.assertIn('if err == nil && !execution',source)
        self.assertIn('releaseCONNECT, err = windowsCONNECTRegisterRoutes(mux, a, original)',source)
        self.assertEqual(len(G.ORIGINAL.CASES),18)
        self.assertEqual(len(G.ORIGINAL.SOCKS_GATE.CASES),11)
        self.assertEqual(len(G.ORIGINAL.PREFIX_GATE.CASES),8)

    def test_each_case_exact_verdict_and_retirement_required(self):
        for case in G.CASES:
            output=completed(case);G.check_verdict(output,case)
            for line in output.splitlines(True):
                for broken in (output.replace(line,'',1),output+line):
                    with self.subTest(case=case,line=line),self.assertRaises(ValueError):G.check_verdict(broken,case)
            for key in ('native_joined','journal_settled','wfp_absent','tun_absent','aliases_removed'):
                for bad in (False,1,'true',None):
                    value=counters(case);value[key]=bad
                    with self.subTest(case=case,key=key,bad=bad),self.assertRaises(ValueError):G.check_verdict(completed(case,value),case)
            for fault in ('--- FAIL:','--- SKIP:','WARNING: DATA RACE','panic:','fatal error:'):
                with self.assertRaises(ValueError):G.check_verdict(output+fault,case)

    def test_all_actual_transport_and_retained_choice_counters(self):
        for case in G.CASES:
            for key in ('launches','entry_raw_udp','entry_tcp','entry_proofs','middle_raw_tcp'):
                value=counters(case);value[key]=0
                with self.assertRaises(ValueError):G.check_verdict(completed(case,value),case)
            for key in ('open_streams','middle_raw_udp','final_raw_udp','restore_launches','comparison_trials','entry_layer_auth'):
                value=counters(case);value[key]+=1
                with self.assertRaises(ValueError):G.check_verdict(completed(case,value),case)
            for bad in (True,0.5,'1',-1):
                value=counters(case);value['launches']=bad
                with self.assertRaises(ValueError):G.check_verdict(completed(case,value),case)
            original=completed(case)
            with self.assertRaises(ValueError):G.check_verdict(original.replace('"launches": 1','"launches": 1, "launches": 1'),case)
            records=[line for line in original.splitlines(True) if 'WINDOWS_CONNECT_EXECUTION_' in line]
            for line in records:
                with self.assertRaises(ValueError):G.check_verdict(line+original.replace(line,''),case)

    def test_source_omission_duplicate_and_foreign_success_refused(self):
        output=source_completed()
        for line in output.splitlines(True):
            for broken in (output.replace(line,'',1),output+line):
                with self.assertRaises(ValueError):G.source_verdict(broken)

    def test_private_worker_inventory_cannot_be_omitted(self):
        output=worker_completed()
        self.assertEqual(len(G.worker_verdict(output)),11)
        for line in output.splitlines(True):
            for broken in (output.replace(line,'',1),output+line):
                with self.assertRaises(ValueError):G.worker_verdict(broken)
        for fault in ('--- FAIL:','--- SKIP:','WARNING: DATA RACE','panic:','fatal error:'):
            with self.assertRaises(ValueError):G.worker_verdict(output+fault)

    def test_actual_candidate_companion_is_projected_without_stubs(self):
        projector = G.SCOPE.PROJECTOR
        path = 'cmd/router-agent/multihop_node_chain_candidate_process.go'
        self.assertIn(path, projector.SOURCES)
        self.assertIn(ROOT/path, projector.inputs())
        original = (ROOT/path).read_text()
        start = 'type relayNodeChainCandidateOperation struct {'
        self.assertEqual(original.count(start), 1)
        body = original[original.index(start):].replace('relayNodeChainProcess', 'importedExecutionProcess').replace('relayNodeChainCandidateOperation', 'importedExecutionCandidateOperation').replace('torIPCNonce', 'importedExecutionNonce')
        projected = projector.copies()[projector.TARGET].decode()
        self.assertEqual(projected.count(body), 1)
        windows = G.SCOPE.peer_sources()['routervpn_windows_imported_execution_process_test.go'].decode()
        self.assertEqual(windows.count(body), 1)
        for imported in re.findall(r'^\s*"([^"\n]+)"', original, re.M):
            expected = imported.replace('router-vpn/internal/multihoprelay', 'github.com/sagernet/sing-box/experimental/libbox/routervpn/multihoprelay')
            self.assertIn('"'+expected+'"', projected)
        with tempfile.TemporaryDirectory(prefix='candidate-peer-source-') as temporary:
            root = Path(temporary)
            for name in projector.SOURCES:
                target = root/name; target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT/name).read_bytes())
            target = root/path
            with patch.object(projector, 'ROOT', root):
                for broken in (original.replace(start, 'type unrelated struct {'), original+'\n'+start+'\n}\n'):
                    target.write_text(broken)
                    with self.assertRaises(ValueError): projector.copies()
                target.unlink()
                with self.assertRaises(ValueError): projector.copies()

    def test_windows_projection_requires_exact_full_target_set(self):
        projector = G.SCOPE.PROJECTOR
        actual = projector.copies()
        lease = 'protocol/routervpnamnezia/routervpn_imported_execution_native_lease_linux_test.go'
        self.assertEqual(set(actual), {projector.TARGET, lease})
        self.assertTrue(actual[lease].startswith(b'//go:build linux && !android\n'))
        self.assertNotIn(lease, G.SCOPE.peer_sources())
        for broken in ({k:v for k,v in actual.items() if k!=projector.TARGET},
                       {k:v for k,v in actual.items() if k!=lease},
                       dict(actual, foreign_test_go=b'package routervpnamnezia')):
            with patch.object(projector, 'copies', return_value=broken), self.assertRaises(ValueError):
                G.SCOPE.peer_sources()

    def test_windows_projection_keeps_posix_original_and_real_dacl_bodies(self):
        files=G.SCOPE.peer_sources()
        projected=files['routervpn_windows_imported_execution_process_test.go'].decode()
        original=(ROOT/'cmd/router-agent/multihop_node_chain_process.go').read_text()
        self.assertIn('before.Mode().Perm()&0111 == 0',original)
        self.assertNotIn('before.Mode().Perm()&0111 == 0',projected)
        self.assertIn('windowsCONNECTExecutionCodePermissions(file, actual) != nil',projected)
        native=(ROOT/G.SCOPE.PRIVATE[1]).read_text().replace('//go:build windows\n\n','').replace('package main\n','package routervpnamnezia\n')
        self.assertEqual(files['routervpn_windows_execution_private_dacl_test.go'],(G.SCOPE.HEADER+native).encode())
        for stem in ('command','native'):
            original=(ROOT/('mobile/server_chain/'+stem+'.go.tmpl')).read_text()
            projected=G.SCOPE.worker_text(stem)
            self.assertIn('Mode().Perm() != 0700',original)
            self.assertIn('Mode().Perm() != 0600',original)
            self.assertNotIn('Mode().Perm() != 0700',projected)
            self.assertNotIn('Mode().Perm() != 0600',projected)
            self.assertEqual(projected.count('validatePrivateRuntimePathPermissions('),2)
        with tempfile.TemporaryDirectory(prefix='windows-worker-source-') as temporary:
            core=Path(temporary)
            for stem in ('command','native'):
                target=core/('cmd/sing-box/routervpn_server_chain_'+stem+'.go')
                target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes((ROOT/('mobile/server_chain/'+stem+'.go.tmpl')).read_bytes())
            values=G.SCOPE.worker_sources(core)
            self.assertEqual(values['cmd/sing-box/routervpn_native_library.go'],(ROOT/'mobile/desktop/native_library.go.tmpl').read_bytes())
            target=core/'cmd/sing-box/routervpn_native_library.go'
            target.write_bytes(b'foreign library authority')
            with self.assertRaises(ValueError):G.SCOPE.worker_sources(core)
        for mode in (0o444,0o666):
            self.assertTrue(mode&0o111==0)
            self.assertNotEqual(mode,0o600)
            self.assertNotEqual(mode|0o111,0o700)

    def test_private_worker_controls_preserve_originals_and_require_exact_causal_failures(self):
        worker=G.WORKER
        files=worker.sources()
        output=worker_completed()
        self.assertEqual(len(worker.verdict(output)),11)
        for name,file,before,after,case,witness in worker.MUTANTS:
            self.assertEqual(files[file].decode().count(before),1,name)
            failed=('=== RUN   '+worker.TEST+'\n=== RUN   '+worker.TEST+'/'+case+'\n'+witness+'\n--- FAIL: '+worker.TEST+' (0.01s)\n    --- FAIL: '+worker.TEST+'/'+case+' (0.01s)\nFAIL\n')
            worker.verdict(failed,(case,),failed=witness)
            for broken in (failed.replace(witness,'unrelated build error'),failed.replace('--- FAIL:','--- PASS:',1),failed+'--- SKIP: stray (0.01s)\n',failed.replace('=== RUN   '+worker.TEST+'/'+case+'\n','')):
                with self.assertRaises(ValueError):worker.verdict(broken,(case,),failed=witness)
        self.assertEqual(worker.sources(),files)

    def test_host_and_optin_are_not_optional(self):
        native=SimpleNamespace(shell32=SimpleNamespace(IsUserAnAdmin=lambda:True))
        with patch.object(G.platform,'system',return_value='Windows'),patch.object(G.ctypes,'windll',native,create=True):
            G.required_host({G.FLAG:'1'})
            for env in ({},{G.FLAG:'0'},{G.FLAG:'1','HOMEVPN_MTU_BENCH_FAKE':'0'}):
                with self.assertRaises(ValueError):G.required_host(env)
            native.shell32.IsUserAnAdmin=lambda:False
            with self.assertRaises(ValueError):G.required_host({G.FLAG:'1'})
        with patch.object(G.platform,'system',return_value='Linux'):
            with self.assertRaises(ValueError):G.required_host({G.FLAG:'1'})

class WindowsExecutionScheduling(unittest.TestCase):
    def exercise(self,target='windows/amd64',fail=None):
        with tempfile.TemporaryDirectory(prefix='windows-execution-schedule-') as temporary:
            work=Path(temporary);bundle=work/'bundle';bundle.mkdir();core=work/'core';core.mkdir()
            names=('sing-box-routervpn.exe','libcronet.dll')
            for name in names:(bundle/name).write_bytes(name.encode())
            original=dict(policy_sha256='a'*64,files={name:dict(size=(bundle/name).stat().st_size,sha256=G.sha(bundle/name)) for name in names})
            (bundle/'NATIVE-RUNTIME.json').write_text(json.dumps(original));calls=[]
            owner=SimpleNamespace(retired=True)
            @contextmanager
            def workspace(prefix):
                directory=work/'owned';directory.mkdir();yield directory
            def run(command,*,cwd,env,timeout):
                command=list(map(str,command));calls.append((command,Path(cwd),dict(env),timeout))
                if fail==len(calls):return 1,'specific original command failure'
                if command[0]=='captured-go':
                    self.assertEqual(timeout,600);self.assertIn('-p=1',command)
                    output=Path(command[command.index('-o')+1]);output.parent.mkdir(parents=True,exist_ok=True);output.write_bytes(('image:'+str(output)).encode());return 0,''
                if '--' not in command:
                    self.assertEqual(timeout,100);self.assertIn('-test.timeout=90s',command);return 0,(worker_completed() if 'execution-peer.test.exe' in command[0] else source_completed())
                self.assertEqual(timeout,250);self.assertIn('-test.timeout=240s',command)
                self.assertEqual(env[G.FLAG],'1');self.assertNotEqual(Path(env['ROUTERVPN_WINDOWS_CONNECT_EXECUTION_WORKER']),work/'owned/installed/runtime/native/sing-box-routervpn.exe')
                self.assertEqual(G.sha(env['ROUTERVPN_WINDOWS_CONNECT_EXECUTION_WORKER']),env['ROUTERVPN_WINDOWS_CONNECT_EXECUTION_WORKER_SHA256'])
                return 0,completed(command[-1])
            owner.workspace=workspace;owner.run=run
            def scope(directory,image,workspace):
                workspace.mkdir();p=workspace/'scope.json';p.write_text(json.dumps({'Replace':{}}));return p,{'same':'original'}
            def peer(directory,workspace):
                workspace.mkdir();p=workspace/'peer.json';p.write_text(json.dumps({'Replace':{}}));return p
            with patch.object(G.BUILD,'reuse',side_effect=lambda path,*a,**k: json.loads((Path(path)/'NATIVE-RUNTIME.json').read_text())),patch.object(G.BUILD,'digest',return_value='a'*64),patch.object(G.BUILD,'binary_name',return_value=names[0]),patch.object(G.BUILD,'tags',return_value=('shipping',)),patch.object(G.BUILD,'marker',return_value='original-marker'),patch.object(G,'sources',return_value=(core,{'captured':'source'})),patch.object(G.SCOPE,'overlay',side_effect=scope),patch.object(G.SCOPE,'peer_overlay',side_effect=peer),patch.object(G.SCOPE,'worker_overlay',side_effect=peer),patch.object(G.WORKER,'execute',return_value={'native':True}),patch.object(G.ORIGINAL.SOCKS_GATE,'execute') as old_gate,redirect_stdout(io.StringIO()):
                captured={'CGO_ENABLED':'1' if target.endswith('amd64') else '0'}
                if fail:
                    with self.assertRaisesRegex(ValueError,'failed'):G.execute_owned(bundle,core,'captured-go',captured,target,owner,'b'*40)
                    self.assertEqual(len(calls),fail)
                else:
                    receipt=G.execute_owned(bundle,core,'captured-go',captured,target,owner,'b'*40)
                    self.assertEqual(receipt['cases'],list(G.CASES));self.assertEqual(len(receipt['results']),14);self.assertEqual(receipt['target'],target)
                    self.assertEqual(len(calls),20)
                    self.assertEqual('-race' in calls[2][0],target.endswith('amd64'))
                    self.assertEqual('-race' in calls[3][0],target.endswith('amd64'))
                    self.assertEqual(receipt['worker_scope'],'separately-captured-windows-private-path-projection')
                old_gate.assert_not_called()
            return calls

    def test_both_native_targets_same_images_exact_fourteen_separate_phases(self):
        for target in ('windows/amd64','windows/arm64'):
            with self.subTest(target=target):self.exercise(target)

    def test_each_compile_source_and_native_failure_stops_before_successor(self):
        for stage in (1,2,3,4,5,6,7,20):
            with self.subTest(stage=stage):self.exercise(fail=stage)


def actual_alias_source():
    source=(ROOT/'cmd/client/desktop_connect_execution_windows_aliases_test.go').read_text()
    def block(marker):
        if source.count(marker)!=1:raise ValueError('Original alias boundary changed: '+marker)
        start=source.index(marker);return source[start:source.index('\n}',start)+2]
    bodies=[block(marker) for marker in ('type windowsCONNECTPhysicalAliasRow struct {','func windowsCONNECTPhysicalAliasAddress(', 'func windowsCONNECTPhysicalAliasIP(', 'func windowsCONNECTPhysicalAliasSame(', 'type windowsCONNECTExecutionAliases struct {','func (a *windowsCONNECTExecutionAliases) Close(', 'func TestWindowsCONNECTExecutionAliasOriginalCreation(')]
    return '\n\n'.join(bodies).replace('syscall.Filetime','fixtureFiletime').replace('syscall.ERROR_NOT_FOUND','fixtureMissing')

ALIAS_BOUNDARY=r'''
type fixtureFiletime struct{LowDateTime,HighDateTime uint32}
var fixtureMissing=errors.New("native address not found")
type fixtureDLL struct{released int}
func(d *fixtureDLL)Release()error{d.released++;return nil}
type fixtureProc struct{call func(*windowsCONNECTPhysicalAliasRow)error}
type windowsCONNECTPhysicalAliasAPI struct{dll *fixtureDLL;remove *fixtureProc;live map[netip.Addr]windowsCONNECTPhysicalAliasRow;deletes int;fail bool}
func(a *windowsCONNECTPhysicalAliasAPI)current(row windowsCONNECTPhysicalAliasRow)(windowsCONNECTPhysicalAliasRow,error){value,ok:=a.live[windowsCONNECTPhysicalAliasIP(row)];if !ok{return windowsCONNECTPhysicalAliasRow{},fixtureMissing};return value,nil}
func windowsCONNECTPhysicalAliasCall(p *fixtureProc,row *windowsCONNECTPhysicalAliasRow)error{return p.call(row)}
func fixtureOwner()(*windowsCONNECTExecutionAliases,*windowsCONNECTPhysicalAliasAPI){
 api:=&windowsCONNECTPhysicalAliasAPI{dll:&fixtureDLL{},live:map[netip.Addr]windowsCONNECTPhysicalAliasRow{}}
 owner:=&windowsCONNECTExecutionAliases{api:api,created:[2]bool{true,true},captured:[2]bool{true,true}}
 for i,address:=range []string{"10.78.0.1","10.78.0.2"}{row:=windowsCONNECTPhysicalAliasRow{InterfaceLuid:11,InterfaceIndex:7,CreationTimeStamp:fixtureFiletime{uint32(i+1),1},OnLinkPrefixLength:32,SkipAsSource:1,PrefixOrigin:1,SuffixOrigin:1};windowsCONNECTPhysicalAliasAddress(&row,netip.MustParseAddr(address));owner.rows[i]=row;api.live[netip.MustParseAddr(address)]=row}
 api.remove=&fixtureProc{call:func(row *windowsCONNECTPhysicalAliasRow)error{if api.fail && windowsCONNECTPhysicalAliasIP(*row)==netip.MustParseAddr("10.78.0.2"){return errors.New("held native deletion")};api.deletes++;delete(api.live,windowsCONNECTPhysicalAliasIP(*row));return nil}}
 return owner,api
}
func TestActualAliasRetirement(t *testing.T){
 t.Run("failed-join-retry",func(t *testing.T){owner,api:=fixtureOwner();held:=errors.New("original child held");calls:=0
 err:=owner.Close(context.Background(),func(context.Context)error{calls++;return held})
 if !errors.Is(err,held)||api.deletes!=0||api.dll.released!=0||owner.closed{t.Fatal("failed original join released kernel aliases")}
 if err=owner.Close(context.Background(),func(context.Context)error{calls++;return nil});err!=nil||api.deletes!=2||api.dll.released!=1||!owner.closed||calls!=2{t.Fatal("original retry did not join aliases",err)}
 if err=owner.Close(context.Background(),func(context.Context)error{calls++;return nil});err!=nil||api.deletes!=2||calls!=2{t.Fatal("completed original cleanup was repeated")}
 })
 t.Run("foreign-recreation",func(t *testing.T){owner,api:=fixtureOwner();key:=netip.MustParseAddr("10.78.0.1");row:=api.live[key];row.CreationTimeStamp.LowDateTime++;api.live[key]=row
 if owner.Close(context.Background(),func(context.Context)error{return nil})==nil||api.deletes!=0||owner.closed{t.Fatal("foreign replacement alias was deleted")}
 })
 t.Run("partial-native-delete-retry",func(t *testing.T){owner,api:=fixtureOwner();api.fail=true
 if owner.Close(context.Background(),func(context.Context)error{return nil})==nil||api.deletes!=1||owner.closed{t.Fatal("partial retirement lost original state")};api.fail=false
 if err:=owner.Close(context.Background(),func(context.Context)error{return nil});err!=nil||api.deletes!=2||!owner.closed{t.Fatal("partial retry repeated first deletion",err)}
 })
 t.Run("removed-tuple-reoccupied",func(t *testing.T){owner,api:=fixtureOwner();api.fail=true;_ =owner.Close(context.Background(),func(context.Context)error{return nil});api.fail=false;row:=owner.rows[0];row.CreationTimeStamp.LowDateTime++;api.live[windowsCONNECTPhysicalAliasIP(row)]=row
 if owner.Close(context.Background(),func(context.Context)error{return nil})==nil||api.deletes!=1{t.Fatal("retired alias tuple replacement was adopted")}
 })
 t.Run("uncaptured-created-row",func(t *testing.T){owner,api:=fixtureOwner();owner.captured[0]=false
 if owner.Close(context.Background(),func(context.Context)error{return nil})==nil||api.deletes!=0{t.Fatal("uncaptured creation authorized deletion")}
 })
 t.Run("cancelled",func(t *testing.T){owner,api:=fixtureOwner();ctx,cancel:=context.WithCancel(context.Background());cancel()
 if !errors.Is(owner.Close(ctx,func(context.Context)error{t.Fatal("cancelled cleanup joined successor");return nil}),context.Canceled)||api.deletes!=0{t.Fatal("cancelled original cleanup deleted aliases")}
 })
}
'''

def owner_fixture_receipt(path):
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not before.st_ino or
            getattr(before, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
        raise AssertionError("CONNECT fixture requires an original single-link regular file")
    with path.open("rb") as stream:
        if not os.path.samestat(before, os.fstat(stream.fileno())):
            raise AssertionError("CONNECT fixture changed before readback")
        digest = hashlib.file_digest(stream, "sha256").digest()
    after = path.lstat()
    if not os.path.samestat(before, after) or after.st_nlink != 1:
        raise AssertionError("CONNECT fixture changed during readback")
    return before.st_dev, before.st_ino, digest


def run_owner_fixture(compiler, environment, package, source):
    with tempfile.TemporaryDirectory(prefix="windows-execution-" + package + "-") as directory:
        work = Path(directory)
        sources = {work / "go.mod": "module " + package + "\n\ngo 1.25\n",
                   work / (package + "_test.go"): source}
        receipts = {}
        for path, text in sources.items():
            data = text.encode("utf-8")
            path.write_bytes(data)
            receipts[path] = owner_fixture_receipt(path)
            if receipts[path][-1] != hashlib.sha256(data).digest():
                raise AssertionError("CONNECT fixture lost its captured source")

        def run(command, timeout):
            if os.name == "nt":
                return G.CONTROLLER.NATIVE.run(command, cwd=work, env=environment, timeout=timeout)
            result = subprocess.run(command, cwd=work, env=environment, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, timeout=timeout)
            return result.returncode, result.stdout

        # Each exact source compiles once within the native Windows 240s build
        # budget. The actual alias and cleanup operations retain 15s/60s.
        image = work / (package + ".test.exe")
        status, output = run([compiler, "test", "-c", "-p=1", "-o", image, "."], 240)
        if status or any(owner_fixture_receipt(path) != receipt for path, receipt in receipts.items()):
            raise AssertionError("CONNECT fixture did not compile its original source:\n" + output)
        receipts[image] = owner_fixture_receipt(image)
        status, output = run([image, "-test.count=1", "-test.v", "-test.timeout=15s"], 60)
        if any(owner_fixture_receipt(path) != receipt for path, receipt in receipts.items()):
            raise AssertionError("CONNECT fixture source or executable changed during execution")
        return status, output


def execute_actual_alias_controls():
    compiler = shutil.which("go")
    if compiler is None:
        raise ValueError("Pinned actual Go is required for alias ownership controls")
    compiler = Path(compiler).resolve(strict=True)
    source = actual_alias_source()
    header = 'package alias\nimport("context";"errors";"net/netip";"sync";"syscall";"testing";"unsafe")\n'
    environment = dict(os.environ, GOWORK="off", GOTOOLCHAIN="local", GOFLAGS="", GOMAXPROCS="1")
    status, output = run_owner_fixture(compiler, environment, "alias", header + source + ALIAS_BOUNDARY)
    if status:
        raise AssertionError("Actual alias owner controls failed:\n" + output)
    print(output, end="")
    controls = (("original.CreationTimeStamp == current.CreationTimeStamp &&", "", "alias creation identity substituted original kernel owner"),
                ("if err := join(ctx); err != nil {", "if err := error(nil); err != nil {", "failed original join released kernel aliases"),
                ("err != nil || !windowsCONNECTPhysicalAliasSame(original, current)", "err != nil", "foreign replacement alias was deleted"))
    for before, after, witness in controls:
        if source.count(before) != 1:
            raise ValueError("Actual alias causal anchor changed: " + before)
        changed = source.replace(before, after)
        status, output = run_owner_fixture(compiler, environment, "alias", header + changed + ALIAS_BOUNDARY)
        if status != 1 or witness not in output or any(marker in output for marker in ("build failed", "panic:", "fatal error:", "--- SKIP:")):
            raise AssertionError("Actual alias causal control failed to reach original witness:\n" + output)
        print("rejected alias owner omission: " + witness)


class WindowsAliasActualOwner(unittest.TestCase):
    def test_compilation_cannot_consume_run_budget_or_substitute_owner_files(self):
        source = "package alias\n"
        compiler = Path("captured-go")
        for mode in ("complete", "build-failure", "go.mod", "alias_test.go", "alias.test.exe"):
            with self.subTest(mode=mode):
                limits = []

                def run(command, *, cwd, timeout, **kwargs):
                    limits.append(timeout)
                    image = cwd / "alias.test.exe"
                    if len(limits) == 1:
                        self.assertEqual(command, [compiler, "test", "-c", "-p=1", "-o", image, "."])
                        self.assertEqual((cwd / "alias_test.go").read_text(), source)
                        image.write_bytes(b"captured executable")
                        status = int(mode == "build-failure")
                    else:
                        self.assertEqual(command, [image, "-test.count=1", "-test.v", "-test.timeout=15s"])
                        if mode != "complete":
                            path = cwd / mode
                            original = path.rename(cwd / "retained-original")
                            path.write_bytes(original.read_bytes())
                        status = 0
                    return (status, "") if os.name == "nt" else SimpleNamespace(returncode=status, stdout="")

                with patch.object(subprocess, "run", side_effect=run), patch.object(G.CONTROLLER.NATIVE, "run", side_effect=run):
                    if mode == "complete":
                        self.assertEqual(run_owner_fixture(compiler, {}, "alias", source), (0, ""))
                    else:
                        with self.assertRaisesRegex(AssertionError, "did not compile|changed during execution"):
                            run_owner_fixture(compiler, {}, "alias", source)
                self.assertEqual(limits, [240] if mode == "build-failure" else [240, 60])

    def test_actual_creation_and_joined_retirement_controls(self):
        execute_actual_alias_controls()

def actual_cleanup_source():
    launcher=(ROOT/'cmd/client/desktop_connect_execution_windows_launcher_test.go').read_text()
    assert launcher.index('*retained = closeOwner') < launcher.index('windowscontroller.NewPipe()')
    assert launcher.index('go func() { waitErr = command.Wait(); close(done) }()') < launcher.index('windowscontroller.OpenProcess(')
    assert launcher.index('defer func() {\n\t\tif err := peer.Process.Close()') < launcher.index('primary, err := process.Identity()')
    body=launcher[launcher.index('\tcloseOwner := func('):launcher.index('\t*retained = closeOwner')]
    controller='func capturedController(pipe,image,process,client *resource,done chan struct{},waitErr error)func(context.Context)error { var terminal error;var mu sync.Mutex;closed:=false;diagnostic:=new(strings.Builder)\n'+body+'return closeOwner\n}\n'
    peer=(ROOT/'cmd/client/desktop_connect_execution_windows_peer_test.go').read_text()
    assert peer.index('*retained = p') < peer.index('windowscontroller.PinImage(')
    assert peer.index('go func() { p.waitErr = p.command.Wait(); close(p.done) }()') < peer.index('windowscontroller.OpenProcess(')
    close=peer[peer.index('func (p *windowsCONNECTExecutionPeer) close('):peer.index('func windowsCONNECTExecutionStartPeer(')]
    return controller+close

CLEANUP_BOUNDARY=r'''
type resource struct{count int;err error;verify int}
func(r *resource)Close()error{r.count++;return r.err}
func(r *resource)VerifyImage(image *resource)error{r.verify++;if image==nil{return errors.New("missing image")};return nil}
type input struct{resource}
func(i *input)Write(p []byte)(int,error){return len(p),nil}
type windowsCONNECTExecutionPeer struct{
 mu sync.Mutex;started,quit,joined,closed bool;terminal,waitErr error;done chan struct{}
 input *input;output,image,process *resource;reader *bufio.Reader;diagnostic *strings.Builder
}
func TestCapturedControllerCleanup(t *testing.T){
 for stage:=0;stage<5;stage++{t.Run(fmt.Sprint(stage),func(t *testing.T){
  values:=[]*resource{nil,nil,nil,nil};for i:=0;i<stage;i++{values[i]=&resource{}}
  close:=capturedController(values[0],values[1],values[2],values[3],nil,nil)
  if err:=close(context.Background());err!=nil{t.Fatal(err)}
  for _,v:=range values{if v!=nil&&v.count!=1{t.Fatal("partial startup resource leaked")}}
  if err:=close(context.Background());err!=nil{t.Fatal(err)}
  for _,v:=range values{if v!=nil&&v.count!=1{t.Fatal("original resource closed twice")}}
 })}
 t.Run("held-started-without-handle",func(t *testing.T){pipe,image:=&resource{},&resource{};done:=make(chan struct{});closeOwner:=capturedController(pipe,image,nil,nil,done,nil)
  ctx,cancel:=context.WithCancel(context.Background());cancel()
  if !errors.Is(closeOwner(ctx),context.Canceled)||image.count!=0{t.Fatal("unjoined original child released image")}
  close(done);if err:=closeOwner(context.Background());err!=nil||image.count!=1{t.Fatal("original command retry was not joined",err)}
 })
 t.Run("pipe-error-still-joins",func(t *testing.T){broken:=errors.New("pipe close failure");pipe,image:=&resource{err:broken},&resource{};done:=make(chan struct{});close(done)
  closeOwner:=capturedController(pipe,image,nil,nil,done,nil)
  if !errors.Is(closeOwner(context.Background()),broken)||image.count!=1{t.Fatal("pipe failure abandoned original resources")}
 })
 t.Run("child-failure-stays-failure",func(t *testing.T){broken:=errors.New("child failed");image:=&resource{};done:=make(chan struct{});close(done);closeOwner:=capturedController(nil,image,nil,nil,done,broken)
  if !errors.Is(closeOwner(context.Background()),broken)||image.count!=1||!errors.Is(closeOwner(context.Background()),broken){t.Fatal("failed original join became successful cleanup")}
 })
}
func fixturePeer()*windowsCONNECTExecutionPeer{done:=make(chan struct{});close(done);return &windowsCONNECTExecutionPeer{started:true,done:done,input:&input{},output:&resource{},image:&resource{},process:&resource{},reader:bufio.NewReader(strings.NewReader("{\"joined\":true}\nPASS\n")),diagnostic:new(strings.Builder)}}
func TestCapturedPeerCleanup(t *testing.T){
 t.Run("before-start",func(t *testing.T){p:=fixturePeer();p.started=false;image,out,in:=p.image,p.output,p.input;if err:=p.close(context.Background());err!=nil||image.count!=1||out.count!=1||in.count!=1{t.Fatal("unstarted peer resources leaked",err)}})
 t.Run("original-joined",func(t *testing.T){p:=fixturePeer();process:=p.process;if err:=p.close(context.Background());err!=nil||!p.joined||process.verify!=1||process.count!=1{t.Fatal("original joined peer proof missing",err)}})
 t.Run("missing-process-held-command",func(t *testing.T){p:=fixturePeer();p.process=nil;p.done=make(chan struct{});image:=p.image;ctx,cancel:=context.WithCancel(context.Background());cancel()
 if !errors.Is(p.close(ctx),context.Canceled)||image.count!=0{t.Fatal("uncaptured started peer was not joined")}
 close(p.done);if p.close(context.Background())==nil||image.count!=1||p.joined{t.Fatal("missing process capture accepted or leaked original image")}
 if p.close(context.Background())==nil{t.Fatal("failed peer cleanup became successful retry")}
 })
 t.Run("failed-command",func(t *testing.T){p:=fixturePeer();p.waitErr=errors.New("child failed");image:=p.image;if p.close(context.Background())==nil||image.count!=1||p.joined{t.Fatal("failed peer command escaped retirement")}})
 t.Run("missing-manager-join",func(t *testing.T){p:=fixturePeer();p.reader=bufio.NewReader(strings.NewReader("PASS\n"));if p.close(context.Background())==nil||p.joined{t.Fatal("missing real manager join accepted")}})
}
'''

class WindowsStagedCleanup(unittest.TestCase):
    def test_actual_cleanup_partial_start_join_retry_and_failures(self):
        compiler = shutil.which("go")
        if compiler is None:
            raise ValueError("Actual Go is required for retained cleanup controls")
        compiler = Path(compiler).resolve(strict=True)
        source = actual_cleanup_source()
        header = 'package cleanup\nimport("bufio";"context";"encoding/json";"errors";"fmt";"io";"strings";"sync";"testing")\n'
        environment = dict(os.environ, GOWORK="off", GOTOOLCHAIN="local", GOFLAGS="", GOMAXPROCS="1")
        status, output = run_owner_fixture(compiler, environment, "cleanup", header + source + CLEANUP_BOUNDARY)
        if status:
            raise AssertionError(output)
        print(output, end="")
        controls = (("if done != nil {", "if false && done != nil {", "unjoined original child released image"),
                    ("if image != nil {", "if false && image != nil {", "partial startup resource leaked"),
                    ("if p.started {", "if false && p.started {", "original joined peer proof missing"),
                    ("return p.terminal", "return nil", "failed peer cleanup became successful retry"))
        for before, after, witness in controls:
            if before not in source:
                raise ValueError("Missing captured cleanup control: " + before)
            changed = source.replace(before, after, 1)
            status, output = run_owner_fixture(compiler, environment, "cleanup", header + changed + CLEANUP_BOUNDARY)
            if status != 1 or witness not in output or any(marker in output for marker in ("build failed", "panic:", "fatal error:", "--- SKIP:")):
                raise AssertionError("Cleanup omission failed intended witness:\n" + output)
            print("rejected actual cleanup omission: " + witness)

if __name__=='__main__':unittest.main()

