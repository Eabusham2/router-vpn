#!/usr/bin/env python3
"""Run captured CONNECT final layers through actual desktop source consumers.

Shared native encrypted-provider evidence is a separate mandatory gate. The
public controller cases here model process/kernel replies explicitly.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('connect_layer_native_driver', ROOT/'deploy/test_desktop_socks_execution_controller.py')
DRIVER = importlib.util.module_from_spec(spec)
spec.loader.exec_module(DRIVER)
PACKAGE = DRIVER.PACKAGE
LAYERS = ('off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening')
SOURCE = {
    'TestDesktopCONNECTExecutionCapturedFinalLayers': tuple(a+'/'+b for a in LAYERS for b in LAYERS),
    'TestDesktopCONNECTExecutionLayeredSavedProfiles': tuple(str(n)+'/'+layer for n in (4,8) for layer in LAYERS[1:]),
}
PUBLIC = {
    'TestDesktopCONNECTExecutionLayeredPublicServer': ('http-connect-server-server','https-connect-server-server'),
    'TestDesktopCONNECTExecutionLayeredPublicCompareLocal': ('http-connect-auto-local','https-connect-auto-local'),
    'TestDesktopCONNECTExecutionLayeredPublicCompareServer': ('http-connect-auto-server','https-connect-auto-server'),
    'TestDesktopCONNECTExecutionLayeredLast': tuple(name for n in (4,8) for name in (str(n), str(n)+'/local', str(n)+'/server')),
}
CONTROLS = (
    ('cmd/client/desktop_node_chain_imported_execution.go',
     '!desktopCONNECTExecutionPairedLayer(members[final].Profile.StartLayer)',
     'members[final].Profile.StartLayer != "" && members[final].Profile.StartLayer != "off"',
     'TestDesktopCONNECTExecutionCapturedFinalLayers','off/aes-256-gcm+xor-whitening',
     'original layered CONNECT execution refused'),
    ('cmd/client/connection_profile_node_chain.go',
     '!desktopCONNECTExecutionPairedLayer(final.StartLayer)',
     'final.StartLayer != "" && final.StartLayer != "off"',
     'TestDesktopCONNECTExecutionLayeredSavedProfiles','4/aes-256-gcm',
     'layered CONNECT Save'),
)


def inventory(target):
    if target not in ('linux/amd64','linux/arm64','windows/amd64','windows/arm64','darwin/amd64','darwin/arm64'):
        raise ValueError('Unknown native CONNECT source target')
    return dict(SOURCE) if target.startswith('darwin/') else {**SOURCE, **PUBLIC}


def source_identity():
    required = {ROOT/'deploy'/name for name in (
        'test_desktop_connect_execution_layers.py',
        'test_desktop_connect_execution_layers_runner.py')}
    required.add(ROOT/'cmd/client/desktop_node_chain_connect_execution_layers_test.go')
    if not required.issubset(DRIVER.BUILDER.inputs()):
        raise ValueError('CONNECT final-layer validation is missing from native inputs')
    return DRIVER.source_identity()


def require_verdicts(output, roots):
    DRIVER.BUILDER.verify_imported_native_verdicts(output, PACKAGE, DRIVER.expected(roots))


def run(go='go', receipt=None, without_race=False, phase='source'):
    executable, environment, target = DRIVER.native_environment(go, without_race)
    original, rows = source_identity(), []
    roots = inventory(target)
    if phase not in ('source','controls'):
        raise ValueError('Unknown CONNECT layer phase')
    with tempfile.TemporaryDirectory(prefix='routervpn-connect-layers-') as directory:
        directory = Path(directory)
        image = directory/('controller.test.exe' if target.startswith('windows/') else 'controller.test')
        if phase == 'source':
            _, digest = DRIVER.compile_image(executable, environment, image, without_race)
            for root, children in roots.items():
                if source_identity() != original or image.is_symlink() or hashlib.sha256(image.read_bytes()).hexdigest() != digest:
                    raise ValueError('CONNECT original source or image changed')
                command = [executable,'tool','test2json','-p',PACKAGE,str(image),'-test.v=test2json','-test.count=1','-test.timeout=120s','-test.run=^'+root+'$']
                result = DRIVER.invoke(command, environment, ROOT/'cmd/client', 135)
                if result.returncode:
                    raise ValueError('CONNECT final-layer source consumer failed: '+root)
                require_verdicts(result.stdout, {root:children})
                if receipt:
                    Path(str(receipt)+'.'+root+'.jsonl').write_text(result.stdout)
                rows.append({'root':root,'tests':1+len(children),'image_sha256':digest,'output_sha256':hashlib.sha256(result.stdout.encode()).hexdigest()})
        else:
            for relative, before, after, root, child, witness in CONTROLS:
                path = ROOT/relative
                raw = path.read_text()
                if raw.count(before) != 1:
                    raise ValueError('CONNECT original causal boundary changed')
                changed, overlay = directory/path.name, directory/'overlay.json'
                changed.write_text(raw.replace(before, after, 1))
                overlay.write_text(json.dumps({'Replace':{str(path):str(changed)}}))
                _, digest = DRIVER.compile_image(executable, environment, image, without_race, overlay)
                selection = '^'+re.escape(root)+'$/'+ '/'.join('^'+re.escape(part)+'$' for part in child.split('/'))
                command = [executable,'tool','test2json','-p',PACKAGE,str(image),'-test.v=test2json','-test.count=1','-test.timeout=120s','-test.run='+selection]
                result = DRIVER.invoke(command, environment, ROOT/'cmd/client', 135)
                DRIVER.verify_causal_result(result, root, root+'/'+child, witness)
                if path.read_text() != raw:
                    raise ValueError('CONNECT control mutated original source')
                if receipt:
                    Path(str(receipt)+'.'+root+'.jsonl').write_text(result.stdout)
                rows.append({'root':root+'/'+child,'witness':witness,'image_sha256':digest,'output_sha256':hashlib.sha256(result.stdout.encode()).hexdigest()})
        if source_identity() != original or image.is_symlink() or hashlib.sha256(image.read_bytes()).hexdigest() != digest:
            raise ValueError('CONNECT final source or image changed')
    expected = len(roots) if phase == 'source' else len(CONTROLS)
    if len(rows) != expected:
        raise ValueError('CONNECT omitted a required final-layer result')
    result = {'schema':1,'target':target,'phase':phase,'race':not without_race,'compiler':executable,
              'toolchain':DRIVER.BUILDER.TOOLCHAIN,'source_sha256':original,'records':rows,
              'scope':'actual shared source, profile CRUD, public controller and retained Last; process/kernel interfaces modeled'}
    if receipt:
        Path(receipt).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,sort_keys=True),flush=True)
    return result


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go',default='go')
    parser.add_argument('--receipt',type=Path)
    parser.add_argument('--without-race',action='store_true')
    parser.add_argument('--phase',required=True,choices=('source','controls'))
    args=parser.parse_args()
    run(args.go,args.receipt,args.without_race,args.phase)
