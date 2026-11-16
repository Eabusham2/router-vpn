#!/usr/bin/env python3
"""Require the original desktop OpenVPN parent, pairing, profile and callbacks.

The actual shipping parent executes against explicit child/kernel observations.
This gate does not establish installed OpenVPN provider or physical OS traffic.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('openvpn_parent_native_driver', ROOT/'deploy/test_desktop_socks_execution_controller.py')
BASE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BASE)
PACKAGE = BASE.PACKAGE
SOURCE = {
 'TestDesktopOpenVPNExecutionOriginalPreparation': tuple(target+'/'+str(n)+'/'+choice for target in ('linux','windows','darwin') for n in (3,4,8) for choice in ('server','auto')),
 'TestDesktopOpenVPNExecutionSourceRefusals': ('missing-pair','invalid-local-credential','foreign-server-peer','shared-provider-identity','paired-middle','middle-layer','duplicate-proof','duplicate-id','wrong-final','wrong-prefix','CONNECT-family'),
 'TestDesktopOpenVPNExecutionPublicHintKeepsPairPrivate': ('true','false'),
 'TestDesktopOpenVPNExecutionSavedProfileKeepsCompleteSource': tuple(item for n in (3,4,8) for item in (str(n),str(n)+'/server',str(n)+'/auto')),
 'TestDesktopOpenVPNExecutionProtectionRetainsOriginalSource': ('server','auto','missing-execution','foreign-execution','foreign-launch','local-config','equal-policy','missing-policy','SOCKS-policy','CONNECT-policy'),
 'TestDesktopOpenVPNExecutionProtectionBeginChecksOriginalBeforeBackend': ('server','auto','equal-policy','missing-policy','mixed-CONNECT','missing-preparation','cancelled'),
 'TestMacOSOpenVPNExecutionArgumentsRetainOriginalPreparation': ('server','auto'),
 'TestMacOSOpenVPNExecutionArgumentsRejectForeignOwner': ('session','source','config','execution-as-physical','local-family','CONNECT-family','missing-preparation','missing-physical','copied-preparation','copied-physical','CONNECT-preparation','linux','windows'),
}
PUBLIC = {
 **{'TestDesktopOpenVPNExecutionPublic'+str(n)+choice: () for n in (3,4,8) for choice in ('Server','CompareLocal','CompareServer')},
 'TestDesktopOpenVPNExecutionRestoreKeepsWinnerEndpointAndMTU': ('local','server'),
 'TestDesktopOpenVPNExecutionReadyRejectsChangedReceipt': ('generic-kind','CONNECT-kind','identity','transfer','preparation','reader','MTU','selected-proof'),
}
LINUX = {'TestDesktopLinuxOpenVPNExecutionKeepsExactTransaction': ('server','auto','omitted-execution','foreign-execution','foreign-source','foreign-process','local-config','missing-adjunct','equal-policy','missing-policy','socks-policy','connect-policy')}
DARWIN = {'TestMacOSOpenVPNExecutionRetirementKeepsOriginalPhysicalOwner': ('original','missing-host','mixed-host','foreign-child','mixed-child','foreign-preparation')}
CONTROLS = (
 ('cmd/client/desktop_node_chain_execution_launch.go', 'if desktopNodeChainHasOpenVPN(nodeChainSelectedReferences(original.selection.Nodes)) {', 'if false && desktopNodeChainHasOpenVPN(nodeChainSelectedReferences(original.selection.Nodes)) {', 'TestDesktopOpenVPNExecutionOriginalPreparation', 'linux/3/server', 'original OpenVPN execution preparation'),
 ('cmd/client/desktop_node_chain_execution_graph.go', ' || e.openvpnPhysical != proof.openvpnPhysical', '', 'TestDesktopOpenVPNExecutionPublic4CompareServer', '', 'OpenVPN public proof accepted a substituted retained owner'),
)
REQUIRED = (
 'deploy/test_desktop_openvpn_execution_controller.py',
 'deploy/test_desktop_openvpn_execution_controller_runner.py',
 'cmd/client/desktop_node_chain_openvpn_execution.go',
 'cmd/client/desktop_node_chain_openvpn_execution_test.go',
 'cmd/client/desktop_node_chain_openvpn_execution_profile_test.go',
 'cmd/client/desktop_node_chain_openvpn_execution_product_test.go',
 'cmd/client/desktop_node_chain_openvpn_execution_protection_test.go',
 'cmd/client/desktop_node_chain_openvpn_execution_linux_test.go',
 'cmd/client/desktop_node_chain_openvpn_execution_darwin_test.go',
 'cmd/client/desktop_macos_openvpn_execution_process_arguments.go',
 'cmd/client/desktop_macos_openvpn_execution_process_arguments_test.go',
 'internal/mobilemultihop/desktop_node_chain_openvpn_execution_adoption.go',
 'internal/mobilemultihop/desktop_node_chain_openvpn_execution_ready.go',
 'internal/mobilemultihop/desktop_node_chain_openvpn_execution_records_test.go',
)


def inventory(target, phase):
    if target not in ('linux/amd64','linux/arm64','windows/amd64','windows/arm64','darwin/amd64','darwin/arm64'):
        raise ValueError('OpenVPN parent requires a supported native host')
    if phase == 'source':
        return {**SOURCE, **(LINUX if target.startswith('linux/') else DARWIN if target.startswith('darwin/') else {})}
    if phase == 'public' and not target.startswith('darwin/'):
        return dict(PUBLIC)
    raise ValueError('OpenVPN parent phase is unavailable on this host')


def source_identity():
    paths = set(BASE.BUILDER.inputs())
    if not {ROOT/p for p in REQUIRED}.issubset(paths):
        raise ValueError('OpenVPN parent required source inventory is incomplete')
    rows = []
    for path in sorted(paths):
        if path.is_symlink() or not path.is_file():
            raise ValueError('OpenVPN parent input is not its original regular source')
        rows.append((path.relative_to(ROOT).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest()))
    return hashlib.sha256(json.dumps(rows,separators=(',',':')).encode()).hexdigest()


def verify_causal(result, root, case, witness):
    BASE.verify_causal_result(result, root, case, witness)
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('duplicate causal JSON key')
            value[key] = item
        return value
    events = [json.loads(line, object_pairs_hook=unique) for line in result.stdout.splitlines()]
    # These controls select either a standalone root or one t.Run with a
    # slash-delimited name; there are no separately executed ancestor t.Runs.
    parents = [root] if case == root else [root, case]
    runs = [e.get('Test') for e in events if e.get('Action') == 'run']
    failures = [e.get('Test') for e in events if e.get('Action') == 'fail' and 'Test' in e]
    if runs != parents or failures != list(reversed(parents)) or any(e.get('Action') not in ('start','run','output','fail') for e in events):
        raise ValueError('OpenVPN causal verdict lost its exact selected test identity')
    if any(e.get('Test') not in parents for e in events if 'Test' in e):
        raise ValueError('OpenVPN causal output belongs to a foreign test')


def run(go='go', receipt=None, without_race=False, phase='source'):
    executable, environment, target = BASE.native_environment(go, without_race)
    roots = inventory(target, 'source' if phase == 'controls' else phase)
    identity, rows = source_identity(), []
    with tempfile.TemporaryDirectory(prefix='routervpn-openvpn-parent-') as directory:
        directory = Path(directory)
        image = directory/('controller.test.exe' if target.startswith('windows/') else 'controller.test')
        if phase != 'controls':
            _, digest = BASE.compile_image(executable, environment, image, without_race)
            for root, children in roots.items():
                if source_identity() != identity or hashlib.sha256(image.read_bytes()).hexdigest() != digest:
                    raise ValueError('OpenVPN parent source or image changed')
                command = [executable,'tool','test2json','-p',PACKAGE,str(image),'-test.v=test2json','-test.count=1','-test.timeout=120s','-test.run=^'+root+'$']
                result = BASE.invoke(command, environment, ROOT/'cmd/client',135)
                if receipt:
                    Path(str(receipt)+'.'+root+'.jsonl').write_text(result.stdout)
                if result.returncode or result.stderr.strip():
                    raise ValueError('OpenVPN parent root failed: '+root)
                BASE.BUILDER.verify_imported_native_verdicts(result.stdout,PACKAGE,BASE.expected({root:children}))
                if source_identity() != identity or hashlib.sha256(image.read_bytes()).hexdigest() != digest:
                    raise ValueError('OpenVPN parent changed during observation')
                rows.append({'root':root,'records':1+len(children),'image_sha256':digest,'stdout_sha256':hashlib.sha256(result.stdout.encode()).hexdigest(),'command':command})
        else:
            for relative, before, after, root, child, witness in (CONTROLS[:1] if target.startswith('darwin/') else CONTROLS):
                path = ROOT/relative
                original = path.read_text()
                if original.count(before) != 1:
                    raise ValueError('OpenVPN original causal boundary changed')
                changed, overlay = directory/path.name, directory/'overlay.json'
                changed.write_text(original.replace(before,after,1))
                overlay.write_text(json.dumps({'Replace':{str(path):str(changed)}}))
                _, digest = BASE.compile_image(executable,environment,image,without_race,overlay)
                case = root+('/'+child if child else '')
                selection = '/'.join('^'+re.escape(piece)+'$' for piece in case.split('/'))
                command = [executable,'tool','test2json','-p',PACKAGE,str(image),'-test.v=test2json','-test.count=1','-test.timeout=120s','-test.run='+selection]
                result = BASE.invoke(command,environment,ROOT/'cmd/client',135)
                verify_causal(result,root,case,witness)
                if source_identity() != identity or path.read_text()!=original or hashlib.sha256(image.read_bytes()).hexdigest()!=digest:
                    raise ValueError('OpenVPN causal input changed')
                rows.append({'root':case,'witness':witness,'image_sha256':digest,'stdout_sha256':hashlib.sha256(result.stdout.encode()).hexdigest(),'command':command})
    value = {'schema':1,'target':target,'phase':phase,'race':not without_race,'compiler':executable,'source_sha256':identity,'records':rows,'scope':'actual parent/source/protection/profile/public callbacks with explicit native child and kernel observations; no provider or installed OS acceptance'}
    if receipt:
        Path(receipt).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
    print(json.dumps(value,sort_keys=True),flush=True)
    return value


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go',default='go')
    parser.add_argument('--receipt',type=Path)
    parser.add_argument('--without-race',action='store_true')
    parser.add_argument('--phase',required=True,choices=('source','public','controls'))
    args = parser.parse_args()
    run(args.go,args.receipt,args.without_race,args.phase)
