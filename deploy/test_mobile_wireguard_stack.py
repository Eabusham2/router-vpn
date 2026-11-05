#!/usr/bin/env python3
"""Run the actual pinned WG/AWG link drain and reject the two causal regressions."""
from pathlib import Path
import argparse,importlib.util,json,os,subprocess,tempfile
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('wg_stack_policy',ROOT/'deploy/mobile_wireguard_stack_policy.py');POLICY=importlib.util.module_from_spec(spec);spec.loader.exec_module(POLICY)
CASE='TestRouterVPNWireGuardStackCloseDrainsOriginalDelivery'
def verdict(raw,failed=False):
 events=[]
 for line in raw.splitlines():
  try:events.append(json.loads(line))
  except ValueError:pass
 tests=[e for e in events if e.get('Test')]
 if any(e['Test']!=CASE or e.get('Action')=='skip' for e in tests):raise ValueError('Foreign or skipped native WireGuard drain verdict')
 for action in ('run','fail' if failed else 'pass'):
  if sum(e.get('Action')==action for e in tests)!=1:raise ValueError('Missing or duplicate native WireGuard drain verdict')
 if any(e.get('Action')==('pass' if failed else 'fail') for e in tests):raise ValueError('Unexpected native WireGuard drain result')
def run(vendor):
 vendor=vendor.resolve(strict=True)
 if subprocess.check_output(['git','-C',str(vendor),'rev-parse','HEAD'],text=True).strip()!=POLICY.PIN:raise ValueError('Wrong native WireGuard source pin')
 POLICY.verify(vendor)
 source=vendor/'transport/wireguard/device_stack.go';original=source.read_text()
 env=dict(os.environ,GOTOOLCHAIN='go1.26.3',GOWORK='off')
 for key in ('GOOS','GOARCH'):env[key]=subprocess.check_output(['go','env','GOHOST'+key[2:]],env=env,text=True).strip()
 command=['go','test','-mod=readonly','-race','-ldflags=-checklinkname=0','-json','-tags','with_gvisor,with_wireguard','./transport/wireguard','-run','^'+CASE+'$','-count=1','-timeout=20s']
 with tempfile.TemporaryDirectory(prefix='routervpn-wg-drain-') as temp:
  for name,body,marker in [('current',original,''),('old-delivery',original.replace(POLICY.REPLACEMENTS[1][1],POLICY.REPLACEMENTS[1][0],1),'Close did not retain original packet delivery'),('stack-lock-drain',original.replace('\t\t(*wireEndpoint)(w).Attach(nil)\n','',1),'Close held stack lock while draining original delivery')]:
   cmd=command[:]
   if name!='current':
    if body==original:raise ValueError('Native WireGuard causal scope absent')
    mutation=Path(temp)/(name+'.go');mutation.write_text(body);overlay=Path(temp)/(name+'.json');overlay.write_text(json.dumps({'Replace':{str(source):str(mutation)}}));cmd=command[:2]+['-overlay',str(overlay)]+command[2:]
   result=subprocess.run(cmd,cwd=vendor,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=180)
   if folder:=os.environ.get('ROUTERVPN_WIREGUARD_STACK_EVIDENCE'):
    directory=Path(folder);directory.mkdir(parents=True,exist_ok=True);(directory/(name+'.jsonl')).write_text(result.stdout)
   verdict(result.stdout,name!='current')
   if (result.returncode==0)!=(name=='current') or marker and marker not in result.stdout:raise ValueError('Native WireGuard drain missed exact '+name+' witness:\n'+result.stdout[-12000:])
   print(name+': exact actual native delivery/close verdict verified')
 POLICY.verify(vendor)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('vendor',type=Path);run(p.parse_args().vendor)
