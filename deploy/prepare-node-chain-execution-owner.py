#!/usr/bin/env python3
"""Bind ordered Server preparation to the original native Box and managers."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PIN = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
OWNER = 'routervpn-node-chain-execution-owner-source.json'
DAEMON_CLOSE_ORIGINAL = '''func (s *StartedService) CloseService() error {
\ts.interruptStart()
\ts.lifecycleAccess.Lock()
\tdefer s.lifecycleAccess.Unlock()
\ts.serviceAccess.Lock()
\tinstance := s.instance
\tif instance == nil && s.serviceStatus.Status != ServiceStatus_STARTING && s.serviceStatus.Status != ServiceStatus_STARTED {
\t\ts.serviceAccess.Unlock()
\t\treturn nil
\t}
\ts.instance = nil
\ts.updateStatus(ServiceStatus_STOPPING)
\ts.serviceAccess.Unlock()
\tif instance != nil {
\t\t_ = instance.Close()
\t}
\ts.serviceAccess.Lock()
\ts.startedAt = time.Time{}
\ts.updateStatus(ServiceStatus_IDLE)
\ts.serviceAccess.Unlock()
\truntimeDebug.FreeOSMemory()
\treturn nil
}
'''
TEMPLATES = {
    'execution_close.go.tmpl': 'routervpn_node_chain_execution_close.go',
    'execution_close_test.go.tmpl': 'routervpn_node_chain_execution_close_test.go',
    'execution_box.go.tmpl': 'routervpn_node_chain_execution.go',
    'execution_box_test.go.tmpl': 'routervpn_node_chain_execution_test.go',
    'execution_outbound.go.tmpl': 'adapter/outbound/routervpn_node_chain_execution.go',
    'execution_outbound_test.go.tmpl': 'adapter/outbound/routervpn_node_chain_execution_test.go',
}


def inputs():
    path = ROOT/'deploy/prepare-node-chain-execution.py'
    spec = importlib.util.spec_from_file_location('execution_owner_admission_inputs', path)
    admission = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(admission)
    return list(dict.fromkeys([Path(__file__).resolve(), *(ROOT/'mobile/chain'/name for name in sorted(TEMPLATES)),
                              *admission.inputs(), *sorted((ROOT/'internal/mobilemultihop').glob('node_chain*.go'))]))


def digest():
    value = hashlib.sha256()
    for path in inputs():
        value.update(path.relative_to(ROOT).as_posix().encode()+b'\0'+path.read_bytes())
    return value.hexdigest()


def box_source(source):
    source = source.replace('\r\n', '\n')
    for before, added in (
        ('\trouterVPNNodeChainOptions string\n', '\trouterVPNNodeChainExecutionOptions string\n'),
        ('\tchainOptionsDigest := routerVPNNodeChainOptionsDigest(options.Context, options.Options)\n',
         '\tchainExecutionOptionsDigest := routerVPNNodeChainExecutionOptionsDigest(options.Context, options.Options)\n'),
        ('\t\trouterVPNNodeChainOptions: chainOptionsDigest,\n', '\t\trouterVPNNodeChainExecutionOptions: chainExecutionOptionsDigest,\n'),
        ('\trouterVPNNodeChainExecutionOptions string\n', '\trouterVPNNativeClose routerVPNNativeCloseState\n'),
    ):
        after = before+added
        if source.count(after) == 1 and source.count(before) == 1 and source.count(added) == 1:
            continue
        if source.count(before) != 1 or added in source:
            raise ValueError('ordered execution Box capture boundary changed')
        source = source.replace(before, after, 1)
    if source.count('routerVPNNodeChainExecutionOptions') != 3 or source.count('chainExecutionOptionsDigest') != 2:
        raise ValueError('ordered execution Box capture duplicated or moved')
    old = 'func (s *Box) Close() error {'
    new = 'func (s *Box) routerVPNCloseOriginal() error {'
    if source.count(old) == 1 and new not in source:
        source = source.replace(old, new, 1)
    elif old in source or source.count(new) != 1:
        raise ValueError('original native Box close boundary changed')
    return source.encode()


def daemon_source(source):
    source = source.replace('\r\n', '\n')
    start = source.index('func (s *StartedService) CloseService() error {')
    end = source.index('\nfunc (s *StartedService) SetError(', start)
    body = source[start:end]
    old = '\tif instance != nil {\n\t\t_ = instance.Close()\n\t}'
    new = '\tvar closeErr error\n\tif instance != nil {\n\t\tcloseErr = instance.Close()\n\t}'
    tail = '\truntimeDebug.FreeOSMemory()\n\treturn nil\n}'
    changed = '\truntimeDebug.FreeOSMemory()\n\treturn closeErr\n}'
    status = '\ts.updateStatus(ServiceStatus_IDLE)'
    failed_status = '\tif closeErr != nil {\n\t\ts.updateStatusError(closeErr)\n\t} else {\n\t\ts.updateStatus(ServiceStatus_IDLE)\n\t}'
    expected = DAEMON_CLOSE_ORIGINAL.replace(old, new, 1).replace(tail, changed, 1).replace(status, failed_status, 1)
    if body not in (DAEMON_CLOSE_ORIGINAL, expected):
        raise ValueError('pinned daemon close body changed')
    if body.count(old) == 1 and body.count(tail) == 1 and 'closeErr' not in body:
        body = body.replace(old, new, 1).replace(tail, changed, 1).replace(status, failed_status, 1)
    elif old in body or tail in body or body.count(new) != 1 or body.count(changed) != 1:
        raise ValueError('original daemon close error ownership changed')
    return (source[:start] + body + source[end:]).encode()


def target(vendor, relative):
    path = vendor/relative
    if any(item.is_symlink() for item in (path, *path.parents)) or not path.resolve().is_relative_to(vendor):
        raise ValueError('linked ordered execution owner target')
    return path


def prepare(vendor):
    if any(path.is_symlink() for path in (vendor, *vendor.parents)):
        raise ValueError('linked ordered execution owner checkout')
    vendor = vendor.resolve()
    if subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip() != PIN:
        raise ValueError('ordered execution owner requires the pinned native core')
    if not (vendor/'go.mod').read_text().startswith('module github.com/sagernet/sing-box\n'):
        raise ValueError('ordered execution owner requires the original native module')
    box = target(vendor, 'box.go')
    before = box.read_bytes()
    after = box_source(before.decode())
    daemon = target(vendor, 'daemon/started_service.go')
    daemon_before = daemon.read_bytes()
    daemon_after = daemon_source(daemon_before.decode())
    previous = {}
    owner = target(vendor, OWNER)
    if owner.exists():
        if not owner.is_file() or owner.stat().st_size > 65536:
            raise ValueError('invalid ordered execution owner receipt')
        record = json.loads(owner.read_bytes())
        if not isinstance(record, dict) or set(record) != {'schema', 'core', 'files'} or record['schema'] != 1 or record['core'] != PIN or not isinstance(record['files'], dict) or set(record['files']) not in (set(TEMPLATES.values()), set(TEMPLATES.values()) - {'routervpn_node_chain_execution_close.go', 'routervpn_node_chain_execution_close_test.go'}):
            raise ValueError('invalid ordered execution owner source record')
        previous = record['files']
        for name, checksum in previous.items():
            if name not in TEMPLATES.values() or not isinstance(checksum, str) or len(checksum) != 64 or any(ch not in '0123456789abcdef' for ch in checksum):
                raise ValueError('ordered execution owner source widened')
            path = target(vendor, name)
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != checksum:
                raise ValueError('ordered execution owner source changed outside its owner')
    templates = {name: (ROOT/'mobile/chain'/template).read_bytes() for template, name in TEMPLATES.items()}
    for name, raw in templates.items():
        path = target(vendor, name)
        if path.exists() and (not path.is_file() or name not in previous and path.read_bytes() != raw):
            raise ValueError('refusing unowned ordered execution owner overwrite')
    if box.read_bytes() != before or daemon.read_bytes() != daemon_before:
        raise ValueError('ordered execution Box changed during preparation')
    for name, raw in templates.items():
        path = target(vendor, name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    box.write_bytes(after)
    daemon.write_bytes(daemon_after)
    owner.write_text(json.dumps({'schema': 1, 'core': PIN, 'files': {name: hashlib.sha256(raw).hexdigest() for name, raw in templates.items()}}, sort_keys=True, separators=(',', ':'))+'\n')
    print('Owned ordered execution Box source:', digest())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor', type=Path, nargs='?')
    parser.add_argument('--digest', action='store_true')
    args = parser.parse_args()
    if args.digest:
        print(digest())
    elif args.vendor:
        prepare(args.vendor)
    else:
        parser.error('vendor or --digest required')
