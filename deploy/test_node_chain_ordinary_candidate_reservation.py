#!/usr/bin/env python3
"""Additional ordinary reservation gate; original source clocks remain intact.

Actual full-core Libbox compilation, original five candidate roots, seven unique
reservation leaves, and three compiled omissions. No device or encryption claim.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
PACKAGE='github.com/sagernet/sing-box/experimental/libbox'
RESERVATION='TestRouterNodeChainBridgeCandidateReservationOwnership'
ROOTS={"TestRouterNodeChainBridgeCandidates"+suffix:() for suffix in (
 'ShareOriginalOwnerAndMTUExclusion','RetainLateCatalogThroughClose',
 'RejectForeignFactoryAndRetireOnNetworkChange','KeepMTUHoldUntilLateCatalogWorkerJoins',
 'FailedFactoryRetainsScopedCleanup')}
ROOTS[RESERVATION]=('duplicate','stale-same-inventory','copied-handle','copied-owner','foreign-slot','original-deadline','held-prepare')
NATIVE='experimental/libbox/routervpn_node_chain_candidates.go'
LIFECYCLE='experimental/libbox/routervpn_node_chain_lifecycle.go'
TEMPLATES=('candidates.go.tmpl','candidates_test.go.tmpl','lifecycle.go.tmpl')


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def verdict(raw,code):
    gate=load('ordinary_reservation_events',ROOT/'deploy/test_node_chain_candidate_preparation.py')
    gate.ROOTS={PACKAGE:ROOTS}
    names={root+suffix for root,children in ROOTS.items() for suffix in ('',*('/'+child for child in children))}
    gate.verdict(raw,code,{PACKAGE:names});return len(names)


def negative(raw,code,fault,witness):
    if code!=1:raise ValueError('connected omission did not fail normally')
    root=RESERVATION;leaf=root+'/'+fault
    decoded=[json.loads(line) for line in raw.splitlines()]
    rows=[];started=False;build_bytes=0
    for row in decoded:
        if not isinstance(row,dict):raise ValueError('invalid connected omission event')
        if row.get('Action')=='build-output':
            output=row.get('Output')
            if started or row.get('ImportPath')!=PACKAGE+'.test' or 'Package' in row or 'Test' in row or not isinstance(output,str):
                raise ValueError('foreign or late connected build event')
            build_bytes+=len(output.encode())
            if build_bytes>64*1024:raise ValueError('unbounded connected build output')
            continue
        if row.get('Action')=='start':started=True
        rows.append(row)
    if any(not isinstance(row,dict) or row.get('Action') in ('skip','build-fail') or any(x in row.get('Output','') for x in ('DATA RACE','panic:','signal: killed','build failed','test timed out')) for row in rows):
        raise ValueError('connected omission aborted instead of refusing')
    if not rows or rows[0].get('Action')!='start' or sum(row.get('Action')=='start' for row in rows)!=1 or sum(row.get('Action')=='fail' and not row.get('Test') for row in rows)!=1:
        raise ValueError('connected omission package lifecycle changed')
    if any(row.get('Action') not in ('start','run','output','fail') or row.get('Test') and row['Test'] not in (root,leaf) for row in rows):
        raise ValueError('foreign connected omission event')
    for action in ('run','fail'):
        actual=[row['Test'] for row in rows if row.get('Action')==action and row.get('Test')]
        if len(actual)!=2 or set(actual)!={root,leaf}:raise ValueError('connected omission lost exact failed inventory')
    if any(row.get('Package')!=PACKAGE for row in rows) or not any(row.get('Test')==leaf and witness in row.get('Output','') for row in rows):
        raise ValueError('connected omission lost original witness')
    if not rows or rows[-1].get('Action')!='fail' or rows[-1].get('Test'):raise ValueError('connected omission package did not join')


def controls():
    return (
      ('duplicate',NATIVE,(('m.candidate.Load() != nil || ',''),),'duplicate failure gained original reservation authority'),
      ('stale-same-inventory',NATIVE,(('\tif retained := m.owner.candidate.Load(); retained != nil && retained != m {\n\t\treturn errors.New("candidate close lost its original owner slot")\n\t}\n',''),),'stale same-inventory close retired replacement'),
      ('copied-owner',LIFECYCLE,(
        ('\tif m.self != nil && m.self != m {\n\t\treturn\n\t}\n',''),
        ('\tif m.self != nil && m.self != m {\n\t\treturn errors.New("ordered close belongs to a different original owner")\n\t}\n',''),
        ('\tif candidate := m.candidate.Load(); candidate != nil &&\n\t\t(m.self != m || candidate.self != candidate || candidate.owner != m) {\n\t\treturn\n\t}\n',''),
        ('\tif candidate := m.candidate.Load(); candidate != nil &&\n\t\t(m.self != m || candidate.self != candidate || candidate.owner != m) {\n\t\treturn errors.New("ordered close lost its original candidate owner")\n\t}\n',''),
       ),'copied owner retired original candidate lifetime false'),
    )
CONTROLS=controls()


def mutation(source,changes):
    for before,after in changes:
        if source.count(before)!=1:raise ValueError('ordinary reservation causal anchor changed')
        source=source.replace(before,after,1)
    return source


def checked_sources(core):
    prep=load('ordinary_reservation_preparer',ROOT/'deploy/prepare-mobile-node-chain.py')
    for name in TEMPLATES:
        if (ROOT/'mobile/chain'/name).read_bytes()!=(core/prep.TEMPLATES[name]).read_bytes():
            raise ValueError('changed ordinary native projection: '+name)
    typed=load('ordinary_reservation_typed_dependency',ROOT/'deploy/test_node_chain_typed_connected_candidates.py')
    if len(typed.OWNERSHIP_CONTROLS)!=4:raise ValueError('typed original retirement controls changed')
    typed.checked_sources(core)


def command(go):
    return [go,'test','-race','-json','-count=1','-p=1','-mod=readonly',
       '-tags=with_quic,with_wireguard,with_gvisor','-ldflags=-checklinkname=0','-timeout=150s']


def execute(core,go,phase):
    checked_sources(core)
    env=dict(os.environ,GOMAXPROCS='2',GOGC='50',GOMEMLIMIT='900MiB')
    base=command(go)
    if phase=='baselines':
        result=subprocess.run([*base,'./experimental/libbox','-run','^('+'|'.join(ROOTS)+')$'],cwd=core,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=600)
        try: count=verdict(result.stdout,result.returncode)
        except ValueError: print(result.stdout,flush=True);raise
        print('PASS ordinary reservation records:',count,flush=True)
        checked_sources(core)
        return
    with tempfile.TemporaryDirectory(prefix='ordinary-reservation-controls-') as directory:
        for fault,relative,changes,witness in CONTROLS:
            original=core/relative;source=original.read_text()
            mutant=Path(directory)/'mutant.go';mutant.write_text(mutation(source,changes))
            overlay=Path(directory)/'overlay.json';overlay.write_text(json.dumps({'Replace':{str(original.resolve()):str(mutant.resolve())}}))
            result=subprocess.run([*base,'-overlay='+str(overlay),'./experimental/libbox','-run','^'+RESERVATION+'$/^'+fault+'$'],cwd=core,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=300)
            try: negative(result.stdout,result.returncode,fault,witness)
            except ValueError: print(result.stdout,flush=True);raise
            if original.read_text()!=source:raise ValueError('ordinary reservation source mutated')
            print('PASS ordinary reservation control:',fault,flush=True)
    checked_sources(core)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--core',required=True,type=Path);p.add_argument('--phase',required=True,choices=('baselines','controls'));p.add_argument('--go',default='go');a=p.parse_args();execute(a.core.resolve(),a.go,a.phase)
