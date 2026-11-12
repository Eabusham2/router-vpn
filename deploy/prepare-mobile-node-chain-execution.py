#!/usr/bin/env python3
"""Install the mobile ordered execution bridge and original native close receipt."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PIN = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
OWNER = 'routervpn-mobile-node-chain-execution-source.json'
TEMPLATES = {
    'last.go.tmpl': 'experimental/libbox/routervpn_node_chain_execution_last.go',
    'last_test.go.tmpl': 'experimental/libbox/routervpn_node_chain_execution_last_test.go',
    'bridge.go.tmpl': 'experimental/libbox/routervpn_node_chain_execution.go',
    'lifecycle.go.tmpl': 'experimental/libbox/routervpn_node_chain_execution_lifecycle.go',
    'restore.go.tmpl': 'experimental/libbox/routervpn_node_chain_execution_restore.go',
    'activities.go.tmpl': 'experimental/libbox/routervpn_node_chain_execution_activities.go',
    'measurement.go.tmpl': 'experimental/libbox/routervpn_node_chain_execution_measurement.go',
    'measurement_test.go.tmpl': 'experimental/libbox/routervpn_node_chain_execution_measurement_test.go',
    'mtu.go.tmpl': 'experimental/libbox/routervpn_node_chain_execution_mtu.go',
    'mtu_test.go.tmpl': 'experimental/libbox/routervpn_node_chain_execution_mtu_test.go',
    'bridge_test.go.tmpl': 'experimental/libbox/routervpn_node_chain_execution_test.go',
    'lifecycle_test.go.tmpl': 'experimental/libbox/routervpn_node_chain_execution_lifecycle_test.go',
    'instance_close.go.tmpl': 'daemon/routervpn_instance_close.go',
    'instance_close_test.go.tmpl': 'daemon/routervpn_instance_close_test.go',
    'instance_capture.go.tmpl': 'daemon/routervpn_instance_capture.go',
    'instance_capture_test.go.tmpl': 'daemon/routervpn_instance_capture_test.go',
}
PREREQUISITES = {
    'routervpn_node_chain_execution.go': 'mobile/chain/execution_box.go.tmpl',
    'adapter/outbound/routervpn_node_chain_execution.go': 'mobile/chain/execution_outbound.go.tmpl',
    'experimental/libbox/routervpn_node_chain.go': 'mobile/chain/bridge.go.tmpl',
    'experimental/libbox/routervpn_mtu_bridge.go': 'mobile/mtu/bridge.go.tmpl',
    'experimental/libbox/routervpn_hop_measurement.go': 'mobile/routervpn_hop_measurement.go.tmpl',
}
CLOSE_BEFORE = '''func (i *Instance) Close() error {
	i.cancel()
	i.urlTestHistoryStorage.Close()
	return i.instance.Close()
}'''
CLOSE_AFTER = '''func (i *Instance) Close() error {
	return i.routerVPNCloseOriginal(func() error {
		i.cancel()
		i.urlTestHistoryStorage.Close()
		return i.instance.Close()
	})
}'''
FIELD_BEFORE = 'type Instance struct {\n'
FIELD_AFTER = FIELD_BEFORE+'\trouterVPNCloseReceipt routerVPNInstanceCloseReceipt\n'
SERVICE_FIELD_BEFORE = 'type StartedService struct {\n'
SERVICE_FIELD_AFTER = SERVICE_FIELD_BEFORE+'\trouterVPNCloseCapture *RouterVPNInstanceCloseCapture\n\trouterVPNConstructionStarted bool\n'
CONSTRUCT_BEFORE = 'func (s *StartedService) newInstance(ctx context.Context, profileContent string, overrideOptions *OverrideOptions) (*Instance, error) {\n'
CONSTRUCT_AFTER = '''func (s *StartedService) newInstance(ctx context.Context, profileContent string, overrideOptions *OverrideOptions) (result *Instance, failure error) {
\tcapture, err := s.routerVPNBeginInstanceCapture(ctx)
\tif err != nil {
\t\treturn nil, err
\t}
\tvar capturedInstance *Instance
\tvar captureBoxAttempted bool
\tdefer func() { capture.routerVPNCompleteInstanceCapture(capturedInstance, failure, captureBoxAttempted) }()
'''
BOX_BEFORE = '\tboxInstance, err := box.New(box.Options{\n'
BOX_AFTER = '\tcaptureBoxAttempted = true\n'+BOX_BEFORE
ACQUIRE_BEFORE = '\ti.instance = boxInstance\n'
ACQUIRE_AFTER = ACQUIRE_BEFORE+'\tcapturedInstance = i\n'


def inputs():
    return [Path(__file__).resolve(), *(ROOT/'mobile/chain_execution'/name for name in sorted(TEMPLATES)), *(ROOT/path for path in sorted(PREREQUISITES.values()))]


def digest():
    value = hashlib.sha256()
    for path in inputs():
        value.update(path.relative_to(ROOT).as_posix().encode()+b'\0'+path.read_bytes())
    return value.hexdigest()


def destination(vendor, relative):
    path = vendor/relative
    if any(parent.is_symlink() for parent in (path, *path.parents)) or not path.resolve().is_relative_to(vendor):
        raise ValueError('linked mobile execution target')
    return path


def instance_source(source):
    source = source.replace('\r\n', '\n')
    for before, after in ((FIELD_BEFORE, FIELD_AFTER), (CLOSE_BEFORE, CLOSE_AFTER), (CONSTRUCT_BEFORE, CONSTRUCT_AFTER), (BOX_BEFORE, BOX_AFTER), (ACQUIRE_BEFORE, ACQUIRE_AFTER)):
        if source.count(after) == 1 and source.count(before) == (1 if before in after else 0):
            continue
        if source.count(before) != 1 or after in source:
            raise ValueError('original instance close boundary changed')
        source = source.replace(before, after, 1)
    if source.count('routerVPNCloseReceipt') != 1 or source.count('routerVPNCloseOriginal') != 1:
        raise ValueError('original close receipt moved or duplicated')
    return source.encode()


def service_source(source):
    source = source.replace('\r\n', '\n')
    if source.count(SERVICE_FIELD_AFTER) == 1 and source.count(SERVICE_FIELD_BEFORE) == 1 and source.count('routerVPNCloseCapture') == 1 and source.count('routerVPNConstructionStarted') == 1:
        return source.encode()
    if source.count(SERVICE_FIELD_BEFORE) != 1 or 'routerVPNCloseCapture' in source or 'routerVPNConstructionStarted' in source:
        raise ValueError('original service construction boundary changed')
    return source.replace(SERVICE_FIELD_BEFORE, SERVICE_FIELD_AFTER, 1).encode()


def prepare(vendor):
    if any(path.is_symlink() for path in (vendor, *vendor.parents)):
        raise ValueError('linked mobile execution checkout')
    vendor = vendor.resolve()
    if subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip() != PIN:
        raise ValueError('mobile execution requires exact pinned native core')
    for relative, template in PREREQUISITES.items():
        source, target = ROOT/template, destination(vendor, relative)
        if not source.is_file() or source.is_symlink() or not target.is_file() or target.read_bytes() != source.read_bytes():
            raise ValueError('mobile execution requires original native owner: '+relative)
    instance = destination(vendor, 'daemon/instance.go')
    original = instance.read_bytes()
    derived = instance_source(original.decode())
    service = destination(vendor, 'daemon/started_service.go')
    service_original = service.read_bytes()
    service_derived = service_source(service_original.decode())
    manifest = destination(vendor, OWNER)
    previous = {}
    if manifest.exists():
        if not manifest.is_file() or manifest.stat().st_size > 16384:
            raise ValueError('invalid mobile execution ownership file')
        record = json.loads(manifest.read_bytes())
        if not isinstance(record, dict) or set(record) != {'schema', 'core', 'files'} or record['schema'] != 1 or record['core'] != PIN or not isinstance(record['files'], dict) or set(record['files']) not in (set(TEMPLATES.values()), set(TEMPLATES.values()) - {'experimental/libbox/routervpn_node_chain_execution_last.go', 'experimental/libbox/routervpn_node_chain_execution_last_test.go'}):
            raise ValueError('invalid mobile execution ownership inventory')
        previous = record['files']
        for relative, checksum in previous.items():
            target = destination(vendor, relative)
            if not isinstance(checksum, str) or len(checksum) != 64 or any(c not in '0123456789abcdef' for c in checksum) or not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != checksum:
                raise ValueError('changed owned mobile execution source')
    values = {}
    for template, relative in TEMPLATES.items():
        source, target = ROOT/'mobile/chain_execution'/template, destination(vendor, relative)
        if source.is_symlink() or not source.is_file():
            raise ValueError('missing mobile execution template')
        values[target] = source.read_bytes()
        if target.exists() and (not target.is_file() or relative not in previous and target.read_bytes() != values[target]):
            raise ValueError('foreign mobile execution source')
    if instance.read_bytes() != original or service.read_bytes() != service_original:
        raise ValueError('original instance changed during preparation')
    for target, raw in values.items():
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    instance.write_bytes(derived)
    service.write_bytes(service_derived)
    manifest.write_text(json.dumps({'schema': 1, 'core': PIN, 'files': {path.relative_to(vendor).as_posix(): hashlib.sha256(raw).hexdigest() for path, raw in values.items()}}, sort_keys=True, separators=(',', ':'))+'\n')
    print('Owned mobile ordered execution source:', digest())


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
