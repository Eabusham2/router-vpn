#!/usr/bin/env python3
"""Require concrete CONNECT final owners and exact encrypted retirement records."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('connect_final_preparation', ROOT/'deploy/prepare-mobile-connect.py')
PREP = importlib.util.module_from_spec(spec); spec.loader.exec_module(PREP)
spec = importlib.util.spec_from_file_location('connect_final_stream', ROOT/'deploy/mobile_shadowsocks_stream_policy.py')
STREAM = importlib.util.module_from_spec(spec); spec.loader.exec_module(STREAM)
PREFIX = 'github.com/sagernet/sing-box'
LAYERS = ('aes-256-gcm', 'aes-256-gcm+xor-whitening')

def inventory(leaves):
    # These fixtures call t.Run once with the complete slash-containing name.
    # Go emits that child and its real root; slash segments are selectors, not
    # additional t.Run invocations or implicit passing test records.
    result = set()
    for leaf in leaves:
        result.update((leaf.split('/', 1)[0], leaf))
    return result

PHASES = {
    'encrypted-retirement': ('./protocol/routervpnnodeconnect', inventory(
        f'{root}/{key}' for root in ('TestCONNECTServerEncryptedRetirementKeepsTrialFailure', 'TestCONNECTServerWhitenedEncryptedRetirementKeepsTrialFailure') for key in ('correct-key', 'wrong-key'))),
    'concrete-final': ('./protocol/routervpnwhitening', inventory([
        'TestCONNECTWhiteningFinalReadbackKeepsActualNativeOwners/'+fault for fault in ('original','owner','method','dialer','key','server','uot-client','uot-version','uot-dialer','reset','close','cancel','wrong-options-key','wrong-options-uot')]+['TestCONNECTWhiteningFinalEncryptedUoTOriginalOwner'])),
    # The four real Box roots run in independent bounded processes. Their
    # complete 48-record union is unchanged; no one root borrows time from
    # another or exhausts the 90-second alarm during the race runtime's exit.
    'native-box-owners': ('.', inventory(
        f'TestRouterVPNCONNECTFinalLayersNativeOwners/{count}/{protocol}/{layer}/{execution}'
        for count in (3,4,8) for protocol in ('http-connect','https-connect') for layer in LAYERS for execution in ('server','auto'))),
    'native-box-replacement': ('.', inventory(
        f'TestRouterVPNCONNECTFinalLayersNativeRefusesReplacement/{layer}/{fault}' for layer in LAYERS for fault in ('final-slot','uot-owner','uot-version','uot-dialer'))),
    'native-box-last': ('.', inventory(
        f'TestRouterVPNCONNECTFinalLayersNativeLast/{count}/{layer}/{selected}' for count in (3,8) for layer in LAYERS for selected in ('local','server'))),
    'native-box-server': ('.', inventory(
        f'TestRouterVPNCONNECTFinalLayersServerOwners/{protocol}/{layer}' for protocol in ('http-connect','https-connect') for layer in LAYERS))
}
ABORT = re.compile(r'WARNING: DATA RACE|panic:|fatal error:|signal:|signal killed|build failed|runtime: out of memory|test timed out', re.I)

def records(text, package):
    rows = []
    for line in text.splitlines():
        if not line.strip(): continue
        row = json.loads(line)
        if not isinstance(row,dict) or row.get('Package') != package:
            raise ValueError('Foreign or malformed CONNECT final verdict')
        rows.append(row)
    if not rows or rows[0].get('Action')!='start' or rows[0].get('Test') or sum(row.get('Action')=='start' for row in rows)!=1:
        raise ValueError('Missing or duplicate original package start')
    terminal=[i for i,row in enumerate(rows) if not row.get('Test') and row.get('Action') in ('pass','fail','skip')]
    if terminal!=[len(rows)-1]: raise ValueError('Missing, repeated or nonfinal package terminal')
    return rows

def verdict(text, code, package, expected, diagnostics=''):
    rows=records(text,package); runs={}; passed={}; terminal=0
    if code != 0 or ABORT.search(text+'\n'+diagnostics): raise ValueError('Failed or aborted CONNECT final phase')
    for row in rows:
        action,name=row.get('Action'),row.get('Test')
        if action in ('fail','skip'): raise ValueError('Failed or skipped CONNECT final record')
        if name and action=='run': runs[name]=runs.get(name,0)+1
        if name and action=='pass': passed[name]=passed.get(name,0)+1
        if not name and action=='pass': terminal+=1
    if terminal!=1 or set(runs)!=expected or set(passed)!=expected or any(n!=1 for n in [*runs.values(),*passed.values()]):
        raise ValueError('Missing, foreign or duplicated CONNECT final records')
    return len(expected)

def rejected(text, code, package, target, witness, diagnostics=''):
    rows=records(text,package); expected=inventory([target]);runs={};failures={};terminal=0
    if code!=1 or ABORT.search(text+'\n'+diagnostics): raise ValueError('Control did not end with an ordinary assertion failure')
    for row in rows:
        action,name=row.get('Action'),row.get('Test')
        if action=='skip' or action=='pass': raise ValueError('Control skipped or passed an intended failing case')
        if name and action=='run': runs[name]=runs.get(name,0)+1
        if name and action=='fail': failures[name]=failures.get(name,0)+1
        if not name and action=='fail': terminal+=1
    if terminal!=1 or set(runs)!=expected or set(failures)!=expected or any(n!=1 for n in [*runs.values(),*failures.values()]) or not any(row.get('Test')==target and witness in row.get('Output','') for row in rows):
        raise ValueError('Control missed its exact ordinary failure witness')

def package_name(relative):
    return PREFIX if relative=='.' else PREFIX+'/'+relative.removeprefix('./')

def verify(core):
    if subprocess.check_output(['git','-C',str(core),'rev-parse','HEAD'],text=True).strip()!=PREP.PIN:
        raise ValueError('Wrong original native core pin')
    owner=json.loads((core/PREP.OWNER).read_text())
    if owner.get('schema')!=1 or owner.get('core')!=PREP.PIN: raise ValueError('Foreign CONNECT source record')
    captured={}
    for name,target in PREP.TEMPLATES.items():
        if target.startswith('experimental/libbox/') or name in PREP.DESKTOP_ONLY: continue
        source=(ROOT/'mobile/chain'/name).read_bytes(); actual=core/target
        digest=hashlib.sha256(source).hexdigest()
        if actual.is_symlink() or actual.read_bytes()!=source or owner['files'].get(target)!=digest: raise ValueError('Changed original CONNECT source: '+target)
        captured[target]=digest
    for name in ('node_chain_server.go', 'node_chain_connect_server.go'):
        source=ROOT/'internal/mobilemultihop'/name
        expected=source.read_text().replace('router-vpn/internal/', 'github.com/sagernet/sing-box/experimental/libbox/routervpn/').encode()
        target=core/'experimental/libbox/routervpn/mobilemultihop'/name
        if target.is_symlink() or target.read_bytes()!=expected: raise ValueError('Changed actual shared CONNECT Server source: '+name)
        captured[str(target.relative_to(core))]=hashlib.sha256(expected).hexdigest()
    for source in sorted((ROOT/'internal/startwhitening').glob('*.go')):
        target=core/'experimental/libbox/routervpn/startwhitening'/source.name
        if target.is_symlink() or target.read_bytes()!=source.read_bytes(): raise ValueError('Changed actual whitening policy owner')
        captured[str(target.relative_to(core))]=hashlib.sha256(source.read_bytes()).hexdigest()
    for source in sorted((ROOT/'mobile/startwhitening').glob('*.tmpl')):
        target=core/'protocol/shadowsocks'/STREAM.TEMPLATES[source.name] if source.name in STREAM.TEMPLATES else core/'protocol/routervpnwhitening'/source.name.removesuffix('.tmpl')
        if target.is_symlink() or target.read_bytes()!=source.read_bytes(): raise ValueError('Changed concrete native whitening source')
        captured[str(target.relative_to(core))]=hashlib.sha256(source.read_bytes()).hexdigest()
    stream=core/'protocol/shadowsocks/outbound.go'
    if stream.is_symlink() or STREAM.patch(stream.read_text())!=stream.read_text(): raise ValueError('Changed pinned original SS stream owner')
    captured[str(stream.relative_to(core))]=hashlib.sha256(stream.read_bytes()).hexdigest()
    return captured

def run(core,go,tags,race,receipt):
    captured=verify(core)
    base=[go,'test','-json','-p=1','-mod=readonly','-count=1','-timeout=90s','-ldflags=-checklinkname=0']
    if tags: base+=['-tags='+tags]
    if race: base+=['-race']
    outcomes={}
    for phase,(relative,expected) in PHASES.items():
        roots=sorted(name for name in expected if '/' not in name)
        selector='^('+'|'.join(re.escape(name) for name in roots)+')$'
        result=subprocess.run([*base,relative,'-run',selector],cwd=core,text=True,capture_output=True,timeout=600)
        print(result.stdout,end='');print(result.stderr,end='',file=__import__('sys').stderr)
        outcomes[phase]=verdict(result.stdout,result.returncode,package_name(relative),expected,result.stderr)
    controls=(
        ('key','h.dialer != dialer || h.key != key ||','h.dialer != dialer ||','key'),
        ('generation','return originalOwner(ctx)','_ = originalOwner; return ctx.Err()','reset'),
    )
    original=core/'protocol/routervpnwhitening/routervpn_connect_final.go'
    with tempfile.TemporaryDirectory(prefix='connect-final-controls-') as directory:
        for name,before,after,leaf in controls:
            source=original.read_text()
            if source.count(before)!=1: raise ValueError('Changed actual CONNECT final causal boundary: '+name)
            changed=Path(directory)/(name+'.go'); changed.write_text(source.replace(before,after,1))
            overlay=Path(directory)/(name+'.json');overlay.write_text(json.dumps({'Replace':{str(original):str(changed)}}))
            target='TestCONNECTWhiteningFinalReadbackKeepsActualNativeOwners/'+leaf
            selector='/'.join('^'+re.escape(part)+'$' for part in target.split('/'))
            result=subprocess.run([*base,'-overlay='+str(overlay),'./protocol/routervpnwhitening','-run',selector],cwd=core,text=True,capture_output=True,timeout=600)
            print(result.stdout,end='');print(result.stderr,end='',file=__import__('sys').stderr)
            rejected(result.stdout,result.returncode,package_name('./protocol/routervpnwhitening'),target,'replaced final acquired original native readback',result.stderr)
            outcomes['control-'+name]='ordinary intended failure'
    if verify(core)!=captured: raise ValueError('CONNECT source changed during native proof')
    result={'core':PREP.PIN,'source_files':captured,'results':outcomes,'native_boundary':'actual concrete finals/UoT/retirement; Box TUN/prefix/resolver boundaries remain explicit components'}
    if receipt: receipt.write_text(json.dumps(result,indent=2)+'\n')
    return result

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--core',required=True,type=Path);p.add_argument('--go',default='go');p.add_argument('--tags',default='');p.add_argument('--race',action='store_true');p.add_argument('--receipt',type=Path);a=p.parse_args()
    print(json.dumps(run(a.core.resolve(),a.go,a.tags,a.race,a.receipt),sort_keys=True))
