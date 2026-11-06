#!/usr/bin/env python3
"""Actual sealed validator child, inherited authentication and terminal join gate."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import os
import platform
import shutil
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('dnssec_namespace_gate', ROOT/'deploy/test_desktop_dnssec_namespace.py')
G=importlib.util.module_from_spec(spec);spec.loader.exec_module(G)
TEMPLATES=(*G.TEMPLATES,'standard_dnssec_command_linux.go.tmpl','standard_dnssec_command_native_linux_test.go.tmpl')
PARENT='TestRouterVPNDNSSECAuthenticatedCommand'
CASES=(PARENT,*(PARENT+'/'+case for case in ('secure','bogus','proven-unsigned','captured-nta','missing-signature','cname-proof','dname-proof','cross-name-proof','tampered-cname','tampered-dname','foreign-terminal-receipt','closed-terminal-channel','zero-anchor-unsigned','zero-anchor-signed','zero-anchor-tampered','positive-island-secure','positive-island-bogus','positive-island-missing-signature')))

PRIVATE_PARENT='TestRouterVPNDNSSECPrivateTLDCommand'
PRIVATE_CASES=(PRIVATE_PARENT,*(PRIVATE_PARENT+'/'+case for case in ('root-secure','root-forged','root-expired','root-insecure','root-nodata','root-wrong-name','root-unrelated-nta','root-alias-nxdomain')))
PRIVATE_FIXTURE=ROOT/'mobile/dnssec/private_tld_fixture.go.tmpl'

def execute(source,bundle,target,go='go'):
    host='linux/'+{'x86_64':'amd64','aarch64':'arm64','arm64':'arm64'}.get(platform.machine(),'')
    if platform.system()!='Linux' or target!=host:raise ValueError('validator command gate requires its exact native Linux target')
    G.TEMPLATES=TEMPLATES
    source,before=G.checked_sources(source)
    private_before=hashlib.sha256(PRIVATE_FIXTURE.read_bytes()).hexdigest()
    bundle=Path(bundle).resolve();receipt=G.BUNDLE.verify(bundle,target)
    env=dict(os.environ,GOWORK='off',GOMAXPROCS='2')
    compiler,env=G.UID.compiler_toolchain(source,go,env)
    unshare=shutil.which('unshare',path=env.get('PATH'))
    if not unshare:raise ValueError('actual inherited child gate requires unshare')
    with tempfile.TemporaryDirectory(prefix='dnssec_command_',dir=source/'cmd') as package, tempfile.TemporaryDirectory(prefix='dnssec-command-') as tmp:
        package,tmp=Path(package),Path(tmp)
        for name in TEMPLATES:shutil.copyfile(ROOT/'mobile/desktop'/name,package/name.removesuffix('.tmpl'))
        (package/'main_test.go').write_text('package main\nimport "github.com/spf13/cobra"\nvar mainCommand = &cobra.Command{}\n')
        peer_source=tmp/'authority';peer_source.mkdir()
        for original,name in (('zone_fixture.go.tmpl','main.go'),('fixture.go.mod','go.mod'),('fixture.go.sum','go.sum')):
            shutil.copyfile(ROOT/'native/dnssec'/original,peer_source/name)
        peer=tmp/'signed-authority'
        G.UID.run([compiler,'build','-buildvcs=false','-mod=readonly','-p=1','-o',peer,'.'],cwd=peer_source,env=env,timeout=300)
        private_source=tmp/'private-authority';private_source.mkdir()
        shutil.copyfile(PRIVATE_FIXTURE,private_source/'main.go')
        for name in ('go.mod','go.sum'):shutil.copyfile(peer_source/name,private_source/name)
        private_peer=tmp/'private-authority-bin'
        G.UID.run([compiler,'build','-buildvcs=false','-mod=readonly','-p=1','-o',private_peer,'.'],cwd=private_source,env=env,timeout=300)
        env['ROUTERVPN_DNSSEC_PRIVATE_TLD_PEER']=str(private_peer)
        env.update(ROUTERVPN_DNSSEC_NATIVE_LIBRARY=str(bundle/G.BUNDLE.LIBRARY),ROUTERVPN_DNSSEC_NATIVE_PEER=str(peer))
        binary=tmp/'validator-command.test'
        G.UID.run([compiler,'test','-c','-race','-p=1','-mod=readonly','-tags=with_purego,routervpn_dnssec_native','-ldflags=-checklinkname=0','-o',binary,'./'+package.relative_to(source).as_posix()],cwd=source,env=env,timeout=600)
        if G.checked_sources(source)[1]!=before:raise ValueError('source changed during fixed child compilation')
        output=G.UID.run([unshare,'--user','--map-root-user','--net',sys.executable,'-c',G.NAMESPACE,os.readlink('/proc/self/ns/net'),binary,'-test.run','^('+PARENT+'|'+PRIVATE_PARENT+')$','-test.v','-test.timeout=55s'],cwd=tmp,env=env,timeout=65)
        G.CASES=(*CASES,*PRIVATE_CASES);G.require_verdicts(output)
        print(output,end='' if output.endswith('\n') else '\n',flush=True)
        implementation=package/'standard_dnssec_command_linux.go'
        original=implementation.read_text()
        start=original.index('\treceipt, err := standardengine.DNSSECTerminalReceipt')
        end=original.index('\n\treturn nil',start)
        implementation.write_text(original[:start]+original[end:])
        # Removing receipt comparison also removes bytes' sole use.
        implementation.write_text(implementation.read_text().replace('\t"bytes"\n',''))
        mutant=tmp/'premature-exit.test'
        G.UID.run([compiler,'test','-c','-race','-p=1','-mod=readonly','-tags=with_purego,routervpn_dnssec_native','-ldflags=-checklinkname=0','-o',mutant,'./'+package.relative_to(source).as_posix()],cwd=source,env=env,timeout=600)
        try:
            G.UID.run([unshare,'--user','--map-root-user','--net',sys.executable,'-c',G.NAMESPACE,os.readlink('/proc/self/ns/net'),mutant,'-test.run','^'+PARENT+'$/^secure$','-test.v','-test.timeout=20s'],cwd=tmp,env=env,timeout=30)
        except subprocess.CalledProcessError as exc:
            text=exc.output.decode() if isinstance(exc.output,bytes) else str(exc.output)
            if 'validator exited before authenticated terminal receipt' not in text and 'original terminal receipt/exit false' not in text:
                raise ValueError('premature-exit control failed outside original terminal process proof: '+text)
            print('Premature clean exit control: rejected before verdict adoption',flush=True)
        else:raise ValueError('child without terminal receipt was admitted')
        if G.checked_sources(source)[1]!=before or G.BUNDLE.verify(bundle,target)!=receipt or hashlib.sha256(PRIVATE_FIXTURE.read_bytes()).hexdigest()!=private_before:
            raise ValueError('original validator source or bundle changed across actual and causal gates')


def main():
    p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--bundle',type=Path,required=True);p.add_argument('--target',required=True);p.add_argument('--go',default='go');a=p.parse_args()
    execute(a.source,a.bundle,a.target,a.go)
if __name__=='__main__':
    try:main()
    except subprocess.CalledProcessError as exc:
        print(exc.output, file=sys.stderr);raise
