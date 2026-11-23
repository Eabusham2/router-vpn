#!/usr/bin/env python3
"""Causal verdict and source controls for the actual paired Darwin host gate."""
from pathlib import Path
import importlib.util
import unittest
import os
import tempfile
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('paired_host_gate',ROOT/'deploy/test_macos_paired_node_host.py')
G=importlib.util.module_from_spec(spec);spec.loader.exec_module(G)
class PairedHostGate(unittest.TestCase):
    def complete(self,case):
        lines=['=== RUN   '+G.TEST,'=== RUN   '+G.TEST+'/'+case,
          '    desktop_node_host_darwin_native_test.go:1: '+G.receipt(case)]
        if case.endswith('/mtu-rollback'): lines+=['    desktop_node_host_darwin_mtu_native_test.go:1: '+G.MTU_RECEIPT]
        return '\n'.join(lines+['--- PASS: '+G.TEST+' (1.0s)','    --- PASS: '+G.TEST+'/'+case+' (1.0s)','PASS'])+'\n'
    def test_all_exact_cases(self):
        self.assertEqual(G.case_inventory(),G.CASES)
        self.assertEqual(len(G.CASES),69)
        self.assertEqual(len(set(G.CASES)),69)
        for case in G.CASES: G.check_verdict(self.complete(case),case)
    def test_native_proof_receipt_cannot_be_missing_duplicate_or_borrowed(self):
        for case in G.CASES:
            valid=self.complete(case); line='    desktop_node_host_darwin_native_test.go:1: '+G.receipt(case)+'\n'
            for bad in (valid.replace(line,''),valid.replace(line,line+line),valid.replace(G.receipt(case),G.receipt(G.CASES[-1] if case!=G.CASES[-1] else G.CASES[0])),valid.replace('--- PASS:','--- SKIP:',1),valid+'WARNING: DATA RACE\n',valid.replace('=== RUN   '+G.TEST+'\n',''),valid+'PASS\n'):
                with self.subTest(case=case),self.assertRaises(ValueError):G.check_verdict(bad,case)
    def test_actual_mtu_receipt_required_only_for_full_mtu_case(self):
        for case in G.CASES:
            valid=self.complete(case);line='    desktop_node_host_darwin_mtu_native_test.go:1: '+G.MTU_RECEIPT+'\n'
            bad=valid.replace(line,'') if case.endswith('/mtu-rollback') else valid.replace('--- PASS:',line+'--- PASS:',1)
            with self.subTest(case=case),self.assertRaises(ValueError):G.check_verdict(bad,case)
    def test_public_routes_and_inventory_cannot_be_comment_decoys(self):
        source=(ROOT/'cmd/client/desktop_node_host_darwin_native_test.go').read_text()
        for needle in ('mux.HandleFunc("/api/connect", a.connect)','mux.HandleFunc("/api/disconnect", a.disconnect)','registerMTURetestRoute(mux, a)','"mtu-rollback"','"awg2-strong", "shadowsocks"'):
            bad=source.replace(needle,'removedOriginalBoundary',1)+'\n// '+needle+'\n'
            with self.subTest(needle=needle),self.assertRaises(ValueError):G.case_inventory(bad)
    def test_platform_requires_explicit_real_acceptance(self):
        for environment in ({},{G.FLAG:'0'},{G.FLAG:'1','HOMEVPN_MTU_BENCH_FAKE':'1'}):
            with self.assertRaises(ValueError):G.required_host(environment)

    def test_exact_reader_inventory_keeps_same_alias_proofs_mandatory(self):
        required=('same-alias-fresh-index','same-alias-rollback','same-alias-old-reader-retained','same-alias-rollback-old-reader-retained')
        self.assertEqual(len(G.READER_CASES),17)
        self.assertEqual(len(set(G.READER_CASES)),17)
        for leaf in required:self.assertIn(G.READER_ROOT+'/'+leaf,G.READER_CASES)
        lines=[]
        for case in G.READER_CASES:lines.append('=== RUN   '+case)
        lines+=['--- PASS: '+G.READER_ROOT+' (0.1s)']
        lines+=['    --- PASS: '+case+' (0.0s)' for case in G.READER_CASES[1:]]
        lines+=['PASS']
        valid='\n'.join(lines)+'\n'
        G.ORDERED.check_authority_verdict(valid,selected=(G.READER_ROOT,G.READER_CASES))
        for leaf in required:
            case=G.READER_ROOT+'/'+leaf
            run='=== RUN   '+case+'\n';passed='    --- PASS: '+case+' (0.0s)\n'
            for bad in (valid.replace(run,'').replace(passed,''),valid.replace(passed,passed+passed),valid.replace(passed,passed.replace('PASS','FAIL')),valid.replace(case,case+'-foreign')):
                with self.subTest(leaf=leaf),self.assertRaises(ValueError):G.ORDERED.check_authority_verdict(bad,selected=(G.READER_ROOT,G.READER_CASES))

    def test_actual_parent_reader_accepts_only_proved_fresh_identity(self):
        def function(path, marker):
            text=(ROOT/path).read_text();start=text.index(marker);end=text.find('\nfunc ',start+1)
            return text[start:end if end>=0 else None]
        method=function('cmd/client/desktop_node_paired_mtu_darwin.go','func (owner *desktopMacOSPairedNodeMTUOwner) verifyReaderChangeLocked(')
        validate=function('cmd/client/desktop_node_paired_reader.go','func validateDesktopMacOSPairedNodeReaderRetirement(')
        compare=function('cmd/client/desktop_node_mtu_darwin.go','func sameDesktopMacOSMTUReadback(')
        name=function('cmd/client/desktop_node_chain_launch.go','func desktopNodeChainDarwinInterfaceName(')
        record=(ROOT/'cmd/client/desktop_node_mtu.go').read_text();record=record[record.index('type desktopNodeMTURecord struct {'):record.index('type desktopNodeMTUCommand struct {')]
        header='''package parentreader
import("context";"errors";"net";"strings";"sync/atomic";"router-vpn/internal/nativeopenvpn")
type desktopNodeMTUOwner struct{record desktopNodeMTURecord}
type desktopNodeLaunch struct{ack desktopNodeMTURecord}
type desktopMacOSPairedNodeHost struct{reader *desktopNodeMTURecord;measurementEpoch atomic.Uint64;proofs int;refused bool}
func(h *desktopMacOSPairedNodeHost)proveReaderLocked(ctx context.Context,r desktopNodeMTURecord)(bool,error){h.proofs++;if h.refused{return false,errors.New("modeled actual paired proof refused")};return true,ctx.Err()}
type desktopMacOSPairedNodeMTUOwner struct{native *desktopNodeMTUOwner;launch *desktopNodeLaunch;host *desktopMacOSPairedNodeHost;snapshot int;foreign bool}
func(o *desktopMacOSPairedNodeMTUOwner)originalLocked()error{if o.foreign{return errors.New("modeled original host owner replaced")};return nil}
func validateDesktopMacOSPairedNodeMTUSnapshotLocked(h *desktopMacOSPairedNodeHost,s int)error{return nil}
func readDesktopNodeMTUContext(ctx context.Context,l *desktopNodeLaunch)(desktopNodeMTURecord,error){return l.ack,ctx.Err()}
var kernel []net.Interface
var desktopnetwork=struct{InterfacesContext func(context.Context)([]net.Interface,error)}{func(ctx context.Context)([]net.Interface,error){return kernel,ctx.Err()}}
'''
        test='''package parentreader
import("context";"net";"testing")
func TestActualPairedParentReader(t *testing.T){
 for _,alias:=range []string{"fresh-name","same-name"}{for _,fault:=range []string{"original","rollback","foreign-owner","foreign-ack","old-index-present","same-index","stale-reader","foreign-source","proof-refusal","cancelled"}{t.Run(alias+"/"+fault,func(t *testing.T){
  old:=desktopNodeMTURecord{Session:"session",Config:"config",Path:"path",Lease:"lease",Request:"nonce",Generation:7,Reader:4,Interface:"utun91",Index:100,MTU:1376}
  next:=old;next.Reader++;next.Index=101;next.Interface="utun92";next.MTU=1420
  if alias=="same-name"{next.Interface=old.Interface}
  owner:=&desktopMacOSPairedNodeMTUOwner{native:&desktopNodeMTUOwner{record:old},launch:&desktopNodeLaunch{},host:&desktopMacOSPairedNodeHost{}}
  ctx,cancel:=context.WithCancel(context.Background());defer cancel()
  switch fault{case "rollback":next.Reader++;next.MTU=old.MTU;case "foreign-owner":owner.foreign=true;case "same-index":next.Index=old.Index;case "stale-reader":next.Reader=old.Reader;case "foreign-source":next.Config+="-foreign";case "proof-refusal":owner.host.refused=true;case "cancelled":cancel()}
  owner.launch.ack=next;if fault=="foreign-ack"{owner.launch.ack.Lease+="-foreign"}
  kernel=[]net.Interface{{Index:next.Index,Name:next.Interface,MTU:next.MTU,Flags:net.FlagUp}}
  if fault=="old-index-present"{kernel=append(kernel,net.Interface{Index:old.Index,Name:old.Interface,MTU:old.MTU,Flags:net.FlagUp})}
  err:=owner.verifyReaderChangeLocked(ctx,old,next);success:=fault=="original"||fault=="rollback"
  if (err==nil)!=success{t.Fatal("exact paired parent reader verdict changed",alias,fault,err)}
  if success{if owner.host.reader==nil||*owner.host.reader!=next||owner.host.proofs!=1||owner.host.measurementEpoch.Load()!=1{t.Fatal("paired reproof or epoch adoption omitted")}}else if owner.host.reader!=nil||owner.host.measurementEpoch.Load()!=0{t.Fatal("unproved successor changed captured reader")}
 })}}
}
'''
        variants=[('original',method,validate),
          ('parent-fixed-name',method.replace('next.Reader <= old.Reader','old.Interface == next.Interface || next.Reader <= old.Reader',1),validate),
          ('kernel-fixed-name',method,validate.replace('old.Index <= 0','old.Interface == next.Interface || old.Index <= 0',1))]
        self.assertEqual(method.count('next.Reader <= old.Reader'),1)
        self.assertEqual(validate.count('old.Index <= 0'),1)
        gate=G.load('paired_parent_mtu_fixture','test_darwin_node_child_tun.py')
        root='TestActualPairedParentReader'
        faults=('original','rollback','foreign-owner','foreign-ack','old-index-present','same-index',
                'stale-reader','foreign-source','proof-refusal','cancelled')
        expected=(root,*(f'{root}/{alias}/{fault}' for alias in ('fresh-name','same-name') for fault in faults))
        with tempfile.TemporaryDirectory(prefix='paired-parent-reader-') as temporary:
            work=Path(temporary)
            (work/'go.mod').write_text('module router-vpn/paired-parent-fixture\n\ngo 1.26.3\nrequire router-vpn v0.0.0\nreplace router-vpn => '+str(ROOT)+'\n')
            (work/'parent_test.go').write_text(test)
            for label,actual,retirement in variants:
                (work/'parent.go').write_text('\n'.join((header,record,name,compare,retirement,actual)))
                result=gate.ORDERED_MTU.execute_mtu_variant(gate,work,label,go=os.environ.get('GO','go'))
                with self.subTest(variant=label):
                    if label=='original':
                        self.assertEqual(result.returncode,0,result.stdout)
                        G.ORDERED.check_authority_verdict(result.stdout,selected=(root,expected))
                    else:
                        self.assertNotEqual(result.returncode,0,result.stdout)
                        self.assertNotRegex(result.stdout,r'\[build failed\]|DATA RACE|panic:|fatal error:')
                        for fault in ('original','rollback'):
                            self.assertIn(f'--- FAIL: {root}/same-name/{fault} (',result.stdout)
                            self.assertIn('exact paired parent reader verdict changed same-name '+fault,result.stdout)

if __name__=='__main__': unittest.main()
