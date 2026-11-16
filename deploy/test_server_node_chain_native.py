#!/usr/bin/env python3
"""Run the exact generated ordered Server command/front component inventory.

This proves native SOCKS/UoT, IPC and cleanup boundaries. It does not substitute
for encrypted multi-node/private-network acceptance or client Connected proof.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('server_chain_native_prep',ROOT/'deploy/prepare-server-node-chain.py')
PREP=importlib.util.module_from_spec(spec);spec.loader.exec_module(PREP)
ROOTS=('TestServerChainFrontPendingCannotForward','TestServerChainFrontOriginalCredentialAndTCP',
 'TestServerChainFrontNativeUoTFinalPacketsAndJoinedClose','TestServerChainFrontRejectsForeignAndUnsupportedWire',
 'TestServerChainFrontFailedCloseRetainsExactRetry','TestServerChainCommandPendingAndRetryingOriginalStop',
 'TestServerChainCommandEOFWithholdsUntilOriginalJoin','TestServerChainCommandAmbiguousCaptureNeverCreatesOwner',
 'TestServerChainSelectedDNSChecksEveryLiteralAnswer','TestServerChainFrontLateNativeReturnRetainsFailedClose',
 'TestServerChainNativeCloseDeadlineRetainsOriginalAttempt','TestServerChainNativeCloseErrorRetriesSameObject',
 'TestServerChainNativeUnreturnedTCPAndPacketRemainOwned',
 'TestServerChainCommandFailureDiagnosticsPreserveRefusal','TestServerChainFailureDiagnosticsSanitizeNativeErrors',
 'TestServerChainImportedBenchmarkChecksEverySelectedAnswer',
 'TestServerChainDNSOwnersRetainEveryNativeTransport','TestServerChainDNSOwnersRejectForeignCapture',
 'TestServerChainDNSOwnersRequireCompleteConfiguration','TestServerChainDNSOwnersKeepCallerCancellation',
 'TestServerChainFrontRetirementJoinsBeforeFinalAcknowledgement',
 'TestServerChainTransportLifetimeJoinsOriginalDrain',
 'TestServerChainOpenVPNOriginalPacketReceipt',
 'TestServerChainCandidateInitialObservationJoined','TestServerChainCandidateCapturedRefusals',
 'TestServerChainCandidateCloseOwnership','TestServerChainCandidateExpiredAbsenceAcknowledgement')
CHILDREN={
 ROOTS[3]:('wrong-password','foreign-user','no-auth','prefix-foreign-tuple','prefix-uot','legacy-uot','udp-associate','retired-proof'),
 ROOTS[5]:('native-owner','partial-construction'),ROOTS[7]:('duplicate','null','alias','foreign-request','linked-capture'),
 ROOTS[8]:('none','private-first','private-after-good','loopback-after-good','ipv6-after-good','mapped-after-good','zoned','invalid','over-bound'),
 ROOTS[13]:('snapshot-bootstrap','construction','stop-retry'),
 ROOTS[15]:('private-after-good','loopback-after-good','disabled-ipv6','mapped','empty'),
 ROOTS[16]:('replace-selected','replace-bootstrap','replace-prefix-bootstrap','remove-bootstrap','remove-prefix-bootstrap'),
 ROOTS[17]:('missing-owner','copied-owner','foreign-manager','selected-owner','selected-tag','router-policy','device-policy','binding','destination','missing-dependency','nil-dependency','extra-dependency','retired-server','copied-server'),
 ROOTS[18]:('missing','empty','empty-tag','duplicate-tag','missing-selected','missing-dependency','wrong-final','wrong-selected-owner','changed-binding'),
 ROOTS[19]:('cancelled','expired','during-dependency','during-capture'),
 ROOTS[20]:('joined','late-front','front-worker-pending','proof-worker-pending','missing-receipt','foreign-original','foreign-error','unjoined-receipt','foreign-front'),
 ROOTS[21]:('explicit-stop','parent-cancel','lease-expiry','partial-construction','failed-close-retry','deadline-retains-original','bounded-cancel'),
 ROOTS[22]:('original','no-initial','nil-context','cancelled','expired','held-lock','pending-generation','pending-time','wrong-remote','wrong-network','under-capacity','reconnect','changed-time','capacity-up','capacity-down','remote-changed','caller-copy')}
CHILDREN.update({ROOTS[23]:(), ROOTS[24]:('hostname','other-target','foreign-peer','expired','copied-handle'), ROOTS[25]:('copied-handle','replacement','failed-resource'), ROOTS[26]:('pruned-absence','retained-replacement','same-id-foreign-capture','wrong-packet-member')})
EXPECTED=set(ROOTS)|{root+'/'+child for root,children in CHILDREN.items() for child in children}
PACKAGE='github.com/sagernet/sing-box/cmd/sing-box'


def records(output):
 rows=[]
 for line in output.splitlines():
  if not line.strip():continue
  try:row=json.loads(line)
  except json.JSONDecodeError as error:raise ValueError('Non-JSON native test verdict') from error
  if not isinstance(row,dict) or row.get('Package')!=PACKAGE:raise ValueError('Foreign native test package')
  rows.append(row)
 return rows


def verdict(output,code,diagnostics=''):
 if 'WARNING: DATA RACE' in diagnostics:raise ValueError('Raced native component diagnostics')
 rows=records(output);runs={};passes={};package_pass=0
 for row in rows:
  action,name=row.get('Action'),row.get('Test')
  if action in ('fail','skip') or 'WARNING: DATA RACE' in row.get('Output',''):raise ValueError('Failed, skipped or raced native component')
  if name:
   if not any(name==root or name.startswith(root+'/') for root in ROOTS):raise ValueError('Foreign selected native test')
   if action=='run':runs[name]=runs.get(name,0)+1
   if action=='pass':passes[name]=passes.get(name,0)+1
  elif action=='pass':package_pass+=1
 if code!=0 or package_pass!=1 or not EXPECTED.issubset(runs) or set(runs)!=set(passes) or any(count!=1 for count in [*runs.values(),*passes.values()]):
  raise ValueError('Incomplete or duplicated ordered Server native inventory')
 return {'roots':len(ROOTS),'required_records':len(EXPECTED),'executed_records':len(passes)}


def rejected(output,code,name,witness,diagnostics=''):
 rows=records(output)
 if any(marker in output or marker in diagnostics for marker in ('panic:', 'fatal error:', 'test timed out', 'WARNING: DATA RACE')):return False
 return code!=0 and 'build failed' not in diagnostics and 'WARNING: DATA RACE' not in diagnostics and any(row.get('Action')=='fail' and row.get('Test')==name for row in rows) and any(witness in row.get('Output','') for row in rows) and not any('build failed' in row.get('Output','') for row in rows)


def execute_test(command,core):
 # Go's toolchain/download diagnostics use stderr; test2json verdicts use
 # stdout. Keep their streams intact instead of accepting arbitrary non-JSON
 # lines in the verdict parser when the build cache happens to be cold.
 result=subprocess.run(command,cwd=core,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 if result.stderr:sys.stderr.write(result.stderr);sys.stderr.flush()
 return result


def verify_sources(core):
 if subprocess.check_output(['git','-C',str(core),'rev-parse','HEAD'],text=True).strip()!=PREP.CORE:raise ValueError('Wrong native core pin')
 record=json.loads((core/PREP.OWNER).read_text());expected=PREP.copies()
 if record.get('schema')!=1 or record.get('core')!=PREP.CORE or record.get('source_sha256')!=PREP.digest() or record.get('files')!={n:hashlib.sha256(raw).hexdigest() for n,raw in sorted(expected.items())}:raise ValueError('Stale original native source record')
 for name,raw in expected.items():
  path=PREP.destination(core,name)
  if path.read_bytes()!=raw:raise ValueError('Changed original native worker source')
 return record['source_sha256']


STUB_ROOT = 'TestServerOpenVPNWithoutNative'

def stub_verdict(output, code, diagnostics=''):
 if code != 0 or 'WARNING: DATA RACE' in diagnostics:raise ValueError('Failed OpenVPN stub build or runtime')
 spec=importlib.util.spec_from_file_location('server_stub_receipt',ROOT/'deploy/test_desktop_native_root_phases.py')
 helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper);helper.PACKAGE=PACKAGE
 rows,runs,passes,failures,ended=helper.load_receipt().complete_receipt(output)
 if ended!='pass' or failures or runs!={STUB_ROOT:1} or passes!={STUB_ROOT:1} or any(any(marker in row.get('Output','') for marker in ('panic:', 'fatal error:', 'test timed out')) for row in rows):
  raise ValueError('Missing or foreign actual OpenVPN stub refusal')
 return {'root':STUB_ROOT,'required_records':1,'stdout_sha256':hashlib.sha256(output.encode()).hexdigest()}

def run_without_openvpn(core,go,tags,race,ldflags):
 stripped=','.join(tag for tag in tags.split(',') if tag and tag!='with_openvpn')
 command=[go,'test','-json','-count=1','-timeout=90s','-p=1']
 if race:command+=['-race']
 if stripped:command+=['-tags',stripped]
 if ldflags:command+=['-ldflags',ldflags]
 command+=['./cmd/sing-box','-run','^'+STUB_ROOT+'$']
 tested=subprocess.run(command,cwd=core,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=300)
 if tested.stderr:sys.stderr.write(tested.stderr);sys.stderr.flush()
 print(tested.stdout,end='')
 return stub_verdict(tested.stdout,tested.returncode,tested.stderr)

def run(core,go,tags,race=False,ldflags='',receipt=None):
 source=verify_sources(core);stub=run_without_openvpn(core,go,tags,race,ldflags)
 if verify_sources(core)!=source:raise ValueError('OpenVPN stub changed native source')
 base=[go,'test','-json','-count=1','-timeout=90s','-p=1']
 if race:base+=['-race']
 if tags:base+=['-tags',tags]
 if ldflags:base+=['-ldflags',ldflags]
 baseline=execute_test([*base,'./cmd/sing-box','-run','^TestServerChain'],core)
 print(baseline.stdout,end='');result=verdict(baseline.stdout,baseline.returncode,baseline.stderr)
 file=core/'cmd/sing-box/routervpn_server_chain_front.go';original=file.read_text()
 controls=(
 ('candidate-initial',ROOTS[23],'initial native observation ran before handshake reservation', [('if source.Addr != op.front.peer || destination.Fqdn != "" || destination.String() != op.address {','if !op.current(bounded) || source.Addr != op.front.peer || destination.Fqdn != "" || destination.String() != op.address {')]),
 ('prefix',ROOTS[3]+'/prefix-foreign-tuple','refusal reached captured/native routing', [('!route.AllowsResolvedDestination("tcp", original.String(), destination.String()) || ','false && !route.AllowsResolvedDestination("tcp", original.String(), destination.String()) || ')]),
 ('uot',ROOTS[3]+'/prefix-uot','prefix UoT negotiation was accepted', [('if !route.Final || route.UDPOverTCPVersion != 2 {','if false && (!route.Final || route.UDPOverTCPVersion != 2) {')]),
 ('close',ROOTS[4],'failed native close was acknowledged',[('if remaining != 0 {','if false && remaining != 0 {')]),
 ('late',ROOTS[9],'late original native close was acknowledged',[('f.originals[original] = true','if f.retiring { return false }; f.originals[original] = true')]),
 ('native-close',ROOTS[11],'failed original native resource was discarded',[('n.connections[owner] = true','// removed original close retention')]),
 ('benchmark-answers',ROOTS[15]+'/private-after-good','imported benchmark accepted a foreign selected-DNS answer', [('for _, address := range answers {','for _, address := range answers[:1] {')]),
 ('dns-dependency',ROOTS[16]+'/replace-bootstrap','replaced configured DNS transport retained authority', [('for _, tag := range r.tags {','for _, tag := range []string{r.capture.ResolverTag} {')]),
 ('dns-original',ROOTS[17]+'/copied-owner','foreign DNS inventory or captured server retained authority', [('r.original != r || ', 'false || ')]),
 ('front-retirement-order',ROOTS[20]+'/joined','joined original front prevented final retirement', [('n.front.joinContext(ctx)', 'n.front.Close(ctx)')]),
 ('front-retirement-proof',ROOTS[20]+'/proof-worker-pending','retirement preceded original proof join', [('if begun {', 'if false && begun {')]),
 ('transport-early-cancel',ROOTS[21]+'/explicit-stop','original packet transport cancelled before drain', [('n.ctx, n.cancel, n.transportCancel = work, cancelWork, cancelTransport','n.ctx, n.cancel, n.transportCancel = work, cancelTransport, cancelTransport')]),
 ('transport-join',ROOTS[21]+'/explicit-stop','joined native transport was not retired', [('n.closeTransportContext(ctx)','context.Background().Err()')]),
 ('openvpn-generation',ROOTS[22]+'/reconnect','fresh proof replaced original native packet receipt', [('r.state == nil || *r.state != state','r.state == nil')]),
 ('openvpn-capacity',ROOTS[22]+'/under-capacity','foreign configured packet receipt acquired authority', [('state.MTU < uint32(r.capture.Middle.ConfiguredMTU)','false && state.MTU < uint32(r.capture.Middle.ConfiguredMTU)')]))
 with tempfile.TemporaryDirectory(prefix='server-chain-controls-') as directory:
  for label,name,witness,changes in controls:
   file=core/('cmd/sing-box/routervpn_server_chain_candidates.go' if label.startswith('candidate-') else 'cmd/sing-box/routervpn_server_chain_openvpn.go' if label.startswith('openvpn-') else 'cmd/sing-box/routervpn_server_chain_resources.go' if label=='native-close' else 'cmd/sing-box/routervpn_server_chain_dns_owners.go' if label.startswith('dns-') else 'cmd/sing-box/routervpn_server_chain_native.go' if label=='benchmark-answers' or label.startswith(('front-retirement-','transport-')) else 'cmd/sing-box/routervpn_server_chain_front.go')
   mutated=file.read_text()
   for before,after in changes:
    if mutated.count(before)!=1:raise ValueError('Native causal anchor changed: '+label)
    mutated=mutated.replace(before,after,1)
   target=Path(directory)/(label+'.go');target.write_text(mutated);overlay=Path(directory)/(label+'.json');overlay.write_text(json.dumps({'Replace':{str(file):str(target)}}))
   tested=execute_test([*base,'-overlay',str(overlay),'./cmd/sing-box','-run','^'+name.replace('/','$/^')+'$'],core)
   if not rejected(tested.stdout,tested.returncode,name,witness,tested.stderr):print(tested.stdout,end='');raise ValueError('Native causal control missed exact witness: '+label)
   print('Rejected actual compiled native control:',label,name)
 result.update(openvpn_without_native=stub,schema=1,source_sha256=source,core=PREP.CORE,causal_controls=len(controls),scope='actual native protocol/component; encrypted multi-node acceptance remains separate')
 if receipt:Path(receipt).write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
 print(json.dumps(result,sort_keys=True));return result

if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--core',type=Path,required=True);parser.add_argument('--go',default='go');parser.add_argument('--tags',default='with_quic,with_wireguard,with_gvisor,with_openvpn');parser.add_argument('--race',action='store_true');parser.add_argument('--ldflags',default='');parser.add_argument('--receipt',type=Path);args=parser.parse_args();run(args.core,args.go,args.tags,args.race,args.ldflags,args.receipt)
