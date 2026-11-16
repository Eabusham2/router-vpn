#!/usr/bin/env python3
"""Require actual agent pipe/terminal ownership; native traffic is a separate gate."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
import time

ROOT=Path(__file__).resolve().parents[1]
PACKAGE='router-vpn/cmd/router-agent'
LEGACY=('TestServerNodeChainIPCRealProcessJoinedReceipt','TestServerNodeChainIPCRejectsFalseProofAuthority','TestServerNodeChainIPCRetainsUnconfirmedOriginalCleanup','TestServerNodeChainIPCFailedCloseRetriesExactOwner','TestServerNodeChainIPCReplacementWorkspaceCannotBeAdopted','TestServerNodeChainIPCCallerCancelAtOriginalReadback')
ROOTS=(*LEGACY,'TestServerNodeChainCandidateIPCChild','TestServerNodeChainCandidateProcessOriginalLifecycle','TestServerNodeChainCandidateProcessRefusals','TestServerNodeChainCandidateProcessCloseRetainsOriginal','TestServerNodeChainCandidateProcessTerminalCleanup')
CHILDREN={LEGACY[1]:('wrong-source','wrong-capture','wrong-nonce','replay','pending-traffic','missing-dns','missing-member','foreign-member','future-proof','duplicate-schema','missing-native-field'),LEGACY[2]:('no-cleanup','wrong-cleanup-owner','wrong-cleanup-capture','duplicate-cleanup','trailing-malformed','exit-error'),ROOTS[8]:('wrong-operation','wrong-capture','wrong-owner','wrong-deadline','not-ok','wrong-nonce','duplicate'),ROOTS[9]:('retry-close','held-prepare','copied-owner'),ROOTS[10]:('terminal-original','terminal-missing','terminal-wrong','terminal-duplicate','terminal-nonzero')}
EXPECTED=set(ROOTS)|{r+'/'+c for r,children in CHILDREN.items() for c in children}
FORBIDDEN=('WARNING: DATA RACE','panic:','fatal error:','test timed out','build failed')
CONTROL=ROOTS[10]+'/terminal-missing'
WITNESS='unproved terminal exit discarded candidate owner'

def records(output,stderr=''):
 if any(s in output or s in stderr for s in FORBIDDEN):raise ValueError('Compiler, race, panic or deadline failure is not a verdict')
 rows=[]
 for line in output.splitlines():
  if not line.strip():continue
  row=json.loads(line)
  if not isinstance(row,dict) or row.get('Package')!=PACKAGE:raise ValueError('Foreign agent record')
  rows.append(row)
 return rows

def verdict(output,code,stderr=''):
 rows=records(output,stderr);runs={};passes={};ended=[]
 for row in rows:
  name,action=row.get('Test'),row.get('Action')
  if action in ('fail','skip'):raise ValueError('Failed or skipped agent record')
  if name:
   if name not in EXPECTED:raise ValueError('Uninventoried agent record')
   if action=='run':runs[name]=runs.get(name,0)+1
   if action=='pass':passes[name]=passes.get(name,0)+1
  elif action=='pass':ended.append(row)
 if code or set(runs)!=EXPECTED or runs!=passes or any(n!=1 for n in runs.values()) or len(ended)!=1:raise ValueError('Incomplete agent inventory')
 return {'roots':len(ROOTS),'records':len(EXPECTED),'legacy_records':len(LEGACY)+sum(len(CHILDREN.get(r,())) for r in LEGACY)}

def rejected(output,code,stderr=''):
 rows=records(output,stderr)
 return code==1 and sum(r.get('Action')=='fail' and r.get('Test')==CONTROL for r in rows)==1 and any(WITNESS in r.get('Output','') and r.get('Test')==CONTROL for r in rows) and not any(r.get('Action')=='skip' for r in rows)

def closure():
 names=subprocess.check_output(['git','ls-files','-co','--exclude-standard','-z'],cwd=ROOT).decode().split('\0')
 out={}
 for name in sorted(set(names)):
  p=ROOT/name
  if not name or not p.is_file() or '__pycache__' in p.parts:continue
  if p.is_symlink():raise ValueError('Linked source input')
  out[name]=hashlib.sha256(p.read_bytes()).hexdigest()
 return out

def main():
 parser=argparse.ArgumentParser();parser.add_argument('--phase',choices=('agent','terminal-control'),required=True);parser.add_argument('--go',default='go');parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
 args.output.mkdir(parents=True,exist_ok=False);before=closure();(args.output/'source.json').write_text(json.dumps(before,sort_keys=True,indent=2)+'\n')
 receipt={'phase':args.phase,'status':'failed','started':time.time(),'source_sha256':hashlib.sha256(json.dumps(before,sort_keys=True).encode()).hexdigest(),'bounds':{'go_seconds':180,'process_seconds':240,'race':True,'vet':'default'}}
 path=ROOT/'cmd/router-agent/multihop_node_chain_process.go';original=path.read_bytes();mutated=False
 try:
  pattern='^('+'|'.join(ROOTS)+')$'
  if args.phase=='terminal-control':
   text=original.decode();old='if !p.closed.Load() || p.bad.Load() || p.waitError != nil {'
   if text.count(old)!=1:raise ValueError('Changed exact terminal proof predicate')
   path.write_text(text.replace(old,'if false && (!p.closed.Load() || p.bad.Load() || p.waitError != nil) {'));mutated=True;pattern='^'+ROOTS[10]+'$/^terminal-missing$'
  command=[args.go,'test','-json','-race','-count=1','-p=1','-timeout=180s','./cmd/router-agent','-run',pattern]
  receipt['command']=command
  result=subprocess.run(command,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=240)
  (args.output/'go.jsonl').write_text(result.stdout);(args.output/'compiler.log').write_text(result.stderr)
  receipt['exit_code']=result.returncode
  if args.phase=='agent':receipt['verdict']=verdict(result.stdout,result.returncode,result.stderr)
  elif not rejected(result.stdout,result.returncode,result.stderr):raise ValueError('Original terminal proof omission did not cause exact refusal')
  else:receipt['verdict']={'compiled_control':CONTROL,'witness':WITNESS}
  receipt['status']='passed'
 except Exception as error:
  receipt['error']=str(error)
  if isinstance(error,subprocess.TimeoutExpired):
   for key,value in [('go.jsonl',error.stdout),('compiler.log',error.stderr)]:
    if value is not None:(args.output/key).write_bytes(value if isinstance(value,bytes) else value.encode())
 finally:
  if mutated:path.write_bytes(original)
  receipt['ended']=time.time();receipt['source_unchanged']=closure()==before
  if not receipt['source_unchanged']:receipt['status']='failed'
  for name in ('go.jsonl','compiler.log'):
   p=args.output/name
   if p.exists():receipt[name+'_sha256']=hashlib.sha256(p.read_bytes()).hexdigest()
  (args.output/'receipt.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
 if receipt['status']!='passed':raise SystemExit(1)
 print(json.dumps(receipt,sort_keys=True))
if __name__=='__main__':main()
