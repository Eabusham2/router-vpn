#!/usr/bin/env python3
"""Require original typed SOCKS parent, profile and public controller evidence."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = 'router-vpn/cmd/client'
spec = importlib.util.spec_from_file_location('socks_parent_builder', ROOT/'deploy/build-native-runtime.py')
BUILDER = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BUILDER)
CASES = {
    'TestDesktopSOCKSExecutionParentRetainsOriginalAssociationSource': tuple(target+'/'+mode+'/'+auth+'/'+choice for target in ('linux','windows','darwin') for mode in ('wg','awg2-fast','awg2-strong') for auth in ('password','none') for choice in ('server','auto')),
    'TestDesktopSOCKSExecutionParentRejectsSubstitutedAuthority': ('equal-policy','equal-preparation','source-pointer','paired-physical','connect-physical','missing-physical','paired-policy','connect-policy','changed-credential','changed-final-token','late-workspace'),
    'TestDesktopSOCKSExecutionProtectionRetainsOriginalSource': ('server','auto','missing-execution','foreign-execution','foreign-launch','local-config','equal-policy','missing-policy','paired-policy','CONNECT-policy'),
    'TestDesktopSOCKSExecutionProtectionBeginChecksOriginalBeforeBackend': ('server','auto','equal-policy','missing-policy','mixed-CONNECT','missing-preparation','cancelled'),
    'TestMacOSSOCKSExecutionArgumentsRetainOriginalPreparation': ('server','auto'),
    'TestMacOSSOCKSExecutionArgumentsRejectForeignOwner': ('session','source','config','execution-as-physical','local-family','CONNECT-family','missing-preparation','missing-physical','copied-preparation','copied-physical','CONNECT-preparation','linux','windows'),
    'TestDesktopSOCKSExecutionSelectionKeepsExactTrio': tuple(mode+'/'+choice for mode in ('wg','awg2-fast','awg2-strong') for choice in ('server','auto')),
    'TestDesktopSOCKSExecutionSavedProfileKeepsCompleteSource': ('server','auto'),
    'TestDesktopSOCKSPublicCapabilityRetainsStrictSourceAndSecrets': ('original','anonymous','hostname','wrong-endpoint','layer','paired-token','paired-proof','paired-api','missing-source','partial-auth','oversized-auth','bad-port','http-connect','https-connect'),
    'TestDesktopSOCKSRegisteredPublicRouteRefusesStaleAndUnsupportedGraphs': ('stale-middle','partial-capture','cancelled','unknown-execution','uppercase-execution','layer','hostname','first','final','connect'),
    'TestDesktopSOCKSRegisteredPublicExecutionRequiresOriginalNativeReceipt': ('server','auto'),
    'TestDesktopOrderedExecutionChoicesKeepProxyNativeAdmissionClosed': (),
}
PUBLIC = {
    'TestDesktopSOCKSExecutionPublicServer': (),
    'TestDesktopSOCKSExecutionPublicCompareLocal': (),
    'TestDesktopSOCKSExecutionPublicCompareServer': (),
    'TestDesktopSOCKSExecutionRestoreKeepsWinnerEndpointAndMTU': ('local','server'),
    'TestDesktopSOCKSExecutionReadyRejectsChangedReceipt': ('generic-kind','CONNECT-kind','identity','transfer','preparation','reader','MTU','selected-proof'),
}
LINUX = {'TestDesktopLinuxSOCKSExecutionKeepsExactTransaction': ('server','auto','omitted-execution','foreign-execution','foreign-source','foreign-process','local-config','missing-adjunct','equal-policy','missing-policy','paired-policy','connect-policy')}
DARWIN = {'TestMacOSSOCKSExecutionRetirementKeepsOriginalPhysicalOwner': ('original','missing-host','mixed-host','foreign-child','mixed-child','foreign-preparation')}
CONTROLS = (
    ('cmd/client/desktop_node_chain_execution_launch.go', 'if original.socksPolicy != nil {\n\t\tprep, err :=', 'if false && original.socksPolicy != nil {\n\t\tprep, err :=', 'TestDesktopSOCKSExecutionParentRetainsOriginalAssociationSource', 'linux/wg/password/server', 'typed original SOCKS execution preparation'),
    ('cmd/client/desktop_node_chain_execution_graph.go', ' || e.socksPhysical != proof.socksPhysical', '', 'TestDesktopSOCKSExecutionPublicCompareServer', '', 'SOCKS public proof accepted a substituted retained owner'),
)


def inventory(target):
    system = target.split('/')[0]
    if system not in ('linux','windows','darwin'):
        raise ValueError('unknown SOCKS parent native target')
    result = dict(CASES)
    result.update(DARWIN if system == 'darwin' else PUBLIC)
    if system == 'linux':
        result.update(LINUX)
    return result


def expected(roots):
    return {name for root, children in roots.items() for name in (root, *(root+'/'+child for child in children))}


def source_identity():
    paths = set(BUILDER.inputs())
    required = {ROOT/'deploy/test_desktop_socks_execution_controller.py', ROOT/'deploy/test_desktop_socks_execution_controller_runner.py',
                ROOT/'cmd/client/desktop_node_chain_socks_execution.go', ROOT/'cmd/client/desktop_node_chain_socks_execution_product_test.go'}
    if not required.issubset(paths):
        raise ValueError('SOCKS parent gate omitted original sources or required runner')
    rows = []
    for path in sorted(paths):
        if path.is_symlink() or not path.is_file():
            raise ValueError('SOCKS parent source is not an original regular file')
        rows.append((path.relative_to(ROOT).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest()))
    return hashlib.sha256(json.dumps(rows, separators=(',', ':')).encode()).hexdigest()


def native_environment(go, without_race):
    executable = shutil.which(go)
    if not executable:
        raise ValueError('SOCKS parent compiler unavailable')
    environment = dict(os.environ, GOTOOLCHAIN='local')
    environment.pop('GOROOT', None)
    environment['GOROOT'] = subprocess.check_output([executable,'env','GOROOT'], env=environment, text=True, timeout=15).strip()
    target = BUILDER.native_host_target()
    if target not in ('linux/amd64','linux/arm64','windows/amd64','windows/arm64','darwin/amd64','darwin/arm64') or without_race != (target == 'windows/arm64'):
        raise ValueError('SOCKS parent requires its native host and supported race mode')
    if environment.get('GOOS', target.split('/')[0]) != target.split('/')[0] or environment.get('GOARCH', target.split('/')[1]) != target.split('/')[1]:
        raise ValueError('SOCKS parent cannot execute a cross-compiled host')
    environment.setdefault('GOMAXPROCS','2')
    environment.setdefault('GOGC','50')
    environment.setdefault('GOMEMLIMIT','1800MiB')
    return executable, environment, target


def invoke(command, environment, cwd, timeout):
    try:
        completed = subprocess.run(command, cwd=cwd, env=environment, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        for value in (error.stdout, error.stderr):
            if value:
                print(value.decode(errors='replace') if isinstance(value,bytes) else value, end='', flush=True)
        raise
    print(completed.stdout, end='', flush=True)
    if completed.stderr:
        print(completed.stderr, end='', flush=True)
    return completed


def compile_image(executable, environment, image, without_race, overlay=None):
    command = [executable,'test','-c',*([] if without_race else ['-race']),'-p=1','-mod=readonly','-o',str(image)]
    if overlay is not None:
        command.append('-overlay='+str(overlay))
    command.append('./cmd/client')
    result = invoke(command, environment, ROOT, 240)
    if result.returncode or image.is_symlink() or not image.is_file():
        raise ValueError('SOCKS parent original compilation failed')
    return command, hashlib.sha256(image.read_bytes()).hexdigest()



def verify_causal_result(result, root, case, witness):
    # A causal control is an ordinary assertion failure, never an abort which
    # happens to print the expected assertion before losing its process.
    events = [json.loads(line) for line in result.stdout.splitlines()]
    output = "\n".join(event.get('Output', '') for event in events)
    abort = re.compile(r"panic:|fatal error:|runtime: out of memory|signal:|\bSIG(?:ABRT|BUS|FPE|ILL|KILL|QUIT|SEGV|TERM)\b|test timed out|\[build failed\]|build (?:failed|aborted)|compile(?:r)?:|link:|exit status [2-9]", re.IGNORECASE)
    if (result.returncode != 1 or result.stderr.strip() or abort.search(output) or
            not events or events[0].get('Action') != 'start' or
            events[-1].get('Action') != 'fail' or 'Test' in events[-1] or
            sum(event.get('Action') == 'run' and event.get('Test') == root for event in events) != 1 or
            sum(event.get('Action') == 'fail' and event.get('Test') == case for event in events) != 1 or
            not any(event.get('Action') == 'output' and event.get('Test') == case and witness in event.get('Output', '') for event in events) or
            any(event.get('Package') != PACKAGE or event.get('Action') == 'skip' or 'DATA RACE' in event.get('Output', '') for event in events)):
        raise ValueError('SOCKS parent causal result is not its normal original assertion failure')


def run(go='go', receipt=None, without_race=False, phase='baselines'):
    executable, environment, target = native_environment(go, without_race)
    identity, rows = source_identity(), []
    roots = inventory(target)
    with tempfile.TemporaryDirectory(prefix='routervpn-socks-parent-') as directory:
        directory = Path(directory)
        image = directory/('controller.test.exe' if target.startswith('windows/') else 'controller.test')
        if phase == 'baselines':
            compile_command, digest = compile_image(executable, environment, image, without_race)
            for root, children in roots.items():
                if source_identity() != identity or image.is_symlink() or hashlib.sha256(image.read_bytes()).hexdigest() != digest:
                    raise ValueError('SOCKS parent source or original executable changed')
                command = [executable,'tool','test2json','-p',PACKAGE,str(image),'-test.v=test2json','-test.count=1','-test.timeout=120s','-test.run=^'+root+'$']
                print('SOCKS parent root: '+root, flush=True)
                result = invoke(command, environment, ROOT/'cmd/client', 135)
                if receipt:
                    Path(str(receipt)+'.'+root+'.jsonl').write_text(result.stdout)
                if result.returncode:
                    raise ValueError('SOCKS parent native root failed: '+root)
                BUILDER.verify_imported_native_verdicts(result.stdout, PACKAGE, expected({root:children}))
                if source_identity() != identity or image.is_symlink() or hashlib.sha256(image.read_bytes()).hexdigest() != digest:
                    raise ValueError('SOCKS parent source or executable changed during original root')
                rows.append({'root':root,'tests':1+len(children),'output_sha256':hashlib.sha256(result.stdout.encode()).hexdigest(),'image_sha256':digest,'command':command})
            if len(rows) != len(roots) or sum(row['tests'] for row in rows) != len(expected(roots)):
                raise ValueError('SOCKS parent omitted a required original root')
        elif phase == 'controls':
            controls = CONTROLS[:1] if target.startswith('darwin/') else CONTROLS
            for relative, before, after, root, child, witness in controls:
                path = ROOT/relative
                original = path.read_text()
                if original.count(before) != 1:
                    raise ValueError('SOCKS parent causal source boundary changed')
                changed, overlay = directory/path.name, directory/'overlay.json'
                changed.write_text(original.replace(before, after, 1))
                overlay.write_text(json.dumps({'Replace':{str(path):str(changed)}}))
                compile_command, digest = compile_image(executable, environment, image, without_race, overlay)
                selection = '^'+re.escape(root)+'$'
                if child:
                    selection += '/'+ '/'.join('^'+re.escape(part)+'$' for part in child.split('/'))
                command = [executable,'tool','test2json','-p',PACKAGE,str(image),'-test.v=test2json','-test.count=1','-test.timeout=120s','-test.run='+selection]
                result = invoke(command, environment, ROOT/'cmd/client', 135)
                case = root+('/'+child if child else '')
                verify_causal_result(result, root, case, witness)
                if (source_identity() != identity or path.read_text() != original or image.is_symlink() or hashlib.sha256(image.read_bytes()).hexdigest() != digest):
                    raise ValueError('SOCKS parent compiled causal witness missing')
                rows.append({'root':case,'witness':witness,'returncode':result.returncode,'image_sha256':digest,'output_sha256':hashlib.sha256(result.stdout.encode()).hexdigest(),'command':command})
        else:
            raise ValueError('unknown SOCKS parent phase')
    result = {'schema':1,'target':target,'phase':phase,'race':not without_race,'source_sha256':identity,'records':rows,
              'scope':'shipping parent/source/protection/profile/public lifecycle; child process, kernel and encrypted-path observations have explicit component models'}
    if receipt:
        Path(receipt).write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print(json.dumps(result,sort_keys=True),flush=True)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go',default='go')
    parser.add_argument('--receipt',type=Path)
    parser.add_argument('--without-race',action='store_true')
    parser.add_argument('--phase',required=True,choices=('baselines','controls'))
    args = parser.parse_args()
    run(args.go,args.receipt,args.without_race,args.phase)
