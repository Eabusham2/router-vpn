#!/usr/bin/env python3
"""Require connected typed native identity and joined catalog ownership.

This phase is additional to, and has no budget/inventory overlap with, the
original closed-prefix native preparation baseline and its fourteen controls.
Encrypted fifty-sample routing is separately mandatory in the focused native
SOCKS and CONNECT executors; these controls do not fabricate a proved runtime.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = 'github.com/sagernet/sing-box/experimental/libbox'
ROOTS = {f'TestRouterNodeChain{family}ConnectedCandidateRequiresProof': ('3','4','8') for family in ('SOCKS','CONNECT')}
ROOTS.update({f'TestRouterNodeChain{family}ConnectedCandidateNativeOwnership': ('original','catalog','copied-handle','copied-owner','copied-owner-cleared','foreign-slot','duplicate-constructor','prepare-once','held-prepare','stale-close','engine','runtime','held-close','network') for family in ('SOCKS','CONNECT')})
TEMPLATES = ('typed_candidates.go.tmpl','typed_candidates_test.go.tmpl','socks_lifecycle.go.tmpl','connect_lifecycle.go.tmpl')
TEMPLATE_PREPARERS = {
    'typed_candidates.go.tmpl': 'prepare-mobile-node-chain',
    'typed_candidates_test.go.tmpl': 'prepare-mobile-node-chain',
    'socks_lifecycle.go.tmpl': 'prepare-mobile-node-chain',
    'connect_lifecycle.go.tmpl': 'prepare-mobile-connect',
}
SHARED = ('node_chain_socks_runtime.go','node_chain_connect_runtime.go','node_chain_typed_connected_candidates.go')
NATIVE = 'experimental/libbox/routervpn_node_chain_typed_candidates.go'
CONTROLS = tuple((family, fault, before, after, witness) for family in ('SOCKS','CONNECT') for fault,before,after,witness in (
 ('engine', ' || m.state.engine.Load() != m.engine', '', 'replacement native engine accepted'),
 ('held-close', '\tif err := m.joinCatalog(ctx); err != nil {\n\t\treturn err\n\t}\n', '', 'held catalog callback fabricated joined cleanup'),
 ('held-prepare', '\tif started {\n\t\tselect {\n\t\tcase <-done:\n\t\tcase <-ctx.Done():\n\t\t\treturn ctx.Err()\n\t\t}\n\t}\n', '\t_ = started\n\t_ = done\n', 'held preparation fabricated joined cleanup'),
 ('stale-close', '\tif retained := m.owner.candidate.Load(); retained != nil && retained != m {\n\t\treturn errors.New("typed candidate close lost its original owner slot")\n\t}\n', '', 'stale handle acknowledged same-inventory replacement cleanup'),
))


def ownership_guard(family):
    return '\tif m.self != nil && m.self != m {\n\t\treturn errRouterNodeChain'+family+'()\n\t}\n'

OWNERSHIP_CONTROLS = tuple((family, fault,
    'experimental/libbox/routervpn_node_chain_'+family.lower()+'_lifecycle.go',
    ownership_guard(family) + ('\tif candidate := m.candidate.Load(); candidate != nil &&\n\t\t(m.self != m || candidate.self != candidate || candidate.owner != m) {\n\t\treturn errRouterNodeChain'+family+'()\n\t}\n' if fault == 'copied-owner' else ''),
    'copied owner borrowed original candidate retirement' if fault == 'copied-owner' else 'copied owner with cleared slot retired original runtime')
    for family in ('SOCKS','CONNECT') for fault in ('copied-owner','copied-owner-cleared'))


def parser():
    spec=importlib.util.spec_from_file_location('typed_connected_strict_events', ROOT/'deploy/test_node_chain_candidate_preparation.py')
    gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
    gate.ROOTS={PACKAGE:ROOTS}
    return gate


def verdict(raw, code, roots=None):
    selected=ROOTS if roots is None else roots
    if not selected or any(name not in ROOTS or children!=ROOTS[name] for name,children in selected.items()):
        raise ValueError('foreign connected native partition')
    names={name+suffix for name,children in selected.items() for suffix in ('',*('/'+child for child in children))}
    parser().verdict(raw,code,{PACKAGE:names})
    return len(names)


def negative(raw,code,family,fault,witness):
    if code!=1:raise ValueError('connected omission did not fail normally')
    root=f'TestRouterNodeChain{family}ConnectedCandidateNativeOwnership';leaf=root+'/'+fault
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


def source_projections():
    if set(TEMPLATE_PREPARERS) != set(TEMPLATES):
        raise ValueError('connected template registry inventory changed')
    preparers = {}
    for name in set(TEMPLATE_PREPARERS.values()):
        spec=importlib.util.spec_from_file_location('typed_connected_'+name.replace('-', '_'),ROOT/'deploy'/(name+'.py'))
        prep=importlib.util.module_from_spec(spec);spec.loader.exec_module(prep)
        preparers[name] = prep
    projections = {}
    for name in TEMPLATES:
        registry = preparers[TEMPLATE_PREPARERS[name]].TEMPLATES
        if name not in registry:
            raise ValueError('connected template lost its original preparer: '+name)
        projections[name] = registry[name]
    if len(set(projections.values())) != len(TEMPLATES):
        raise ValueError('connected native projections collide')
    return projections


def checked_sources(core):
    for name, target in source_projections().items():
        if (ROOT/'mobile/chain'/name).read_bytes()!=(core/target).read_bytes():
            raise ValueError('changed connected native projection: '+name)
    for name in SHARED:
        expected=(ROOT/'internal/mobilemultihop'/name).read_text().replace('"router-vpn/internal/','"'+PACKAGE+'/routervpn/')
        if expected!=(core/'experimental/libbox/routervpn/mobilemultihop'/name).read_text():
            raise ValueError('changed connected shared owner: '+name)


def execute(core,go):
    checked_sources(core)
    env=dict(os.environ,GOMAXPROCS='2',GOGC='50',GOMEMLIMIT='900MiB')
    base=[go,'test','-race','-json','-count=1','-p=1','-mod=readonly','-tags=with_quic,with_wireguard,with_gvisor','-ldflags=-checklinkname=0','-timeout=150s']
    selection='^('+ '|'.join(ROOTS) +')$'
    result=subprocess.run([*base,'./experimental/libbox','-run',selection],cwd=core,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=600)
    try:count=verdict(result.stdout,result.returncode)
    except ValueError:print(result.stdout,flush=True);raise
    print('PASS connected typed native component records:',count,flush=True)
    original=core/NATIVE;source=original.read_text()
    with tempfile.TemporaryDirectory(prefix='typed-connected-causal-') as directory:
        for family,fault,before,after,witness in CONTROLS:
            # Each family occupies a distinct body in the same source file.
            start=source.index('type RouterNodeChain'+family+'CandidateMeasurement struct')
            end=source.find('\ntype RouterNodeChain',start+1)
            if end<0:end=len(source)
            body=source[start:end]
            if body.count(before)!=1:raise ValueError('connected original causal boundary changed')
            mutant=Path(directory)/'mutant.go';mutant.write_text(source[:start]+body.replace(before,after,1)+source[end:])
            overlay=Path(directory)/'overlay.json';overlay.write_text(json.dumps({'Replace':{str(original.resolve()):str(mutant)}}))
            root=f'TestRouterNodeChain{family}ConnectedCandidateNativeOwnership/{fault}'
            result=subprocess.run([*base,'-overlay='+str(overlay),'./experimental/libbox','-run','^'+root+'$'],cwd=core,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=300)
            try:negative(result.stdout,result.returncode,family,fault,witness)
            except ValueError:print(result.stdout,flush=True);raise
            if original.read_text()!=source:raise ValueError('connected source mutated')
            print('PASS connected typed native control:',family,fault,flush=True)
    with tempfile.TemporaryDirectory(prefix='typed-connected-owner-causal-') as directory:
        for family,fault,relative,before,witness in OWNERSHIP_CONTROLS:
            original=core/relative;source=original.read_text()
            if source.count(before)!=2:raise ValueError('connected retirement authority boundaries changed')
            mutant=Path(directory)/'mutant.go';mutant.write_text(source.replace(before,''))
            overlay=Path(directory)/'overlay.json';overlay.write_text(json.dumps({'Replace':{str(original.resolve()):str(mutant)}}))
            root=f'TestRouterNodeChain{family}ConnectedCandidateNativeOwnership/{fault}'
            result=subprocess.run([*base,'-overlay='+str(overlay),'./experimental/libbox','-run','^'+root+'$'],cwd=core,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=300)
            try:negative(result.stdout,result.returncode,family,fault,witness)
            except ValueError:print(result.stdout,flush=True);raise
            if original.read_text()!=source:raise ValueError('connected lifecycle source mutated')
            print('PASS connected typed native retirement control:',family,flush=True)
    checked_sources(core)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--vendor',type=Path,required=True);p.add_argument('--go',default='go');a=p.parse_args();execute(a.vendor.resolve(),a.go)
