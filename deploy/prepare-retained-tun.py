#!/usr/bin/env python3
"""Prepare the ownership-checked TUN reader transaction in a pinned core."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PIN = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
MANAGER = 'adapter/inbound/manager.go'
OBSERVATION_TEMPLATE = ROOT / 'mobile/strategy/observation.go.tmpl'
OBSERVATION_TARGET = 'adapter/routervpn_observation.go'
INBOUND_OBSERVATION_TEMPLATES = {ROOT / 'mobile/strategy/inbound_context.go.tmpl': 'adapter/inbound/routervpn_observation.go'}
# Exact previous published preparation, accepted only for this bounded upgrade.
PREVIOUS_TEMPLATES = {'routervpn_mtu.go': ('79603bccd07497e8d01cc99b87e61bce7b45c3c0f9c89c1725c697e0f4878669', '7241c2a70cc00f8ff8eeeaf4ad2f95312fb19fd4cede8512a4b9e4ff09762830')}


TUN_MODULE = 'github.com/sagernet/sing-tun'
TUN_VERSION = 'v0.9.3'
FLOW_NAT_SHA256 = '55f38abaaffacef2d3c9da453994a9869759fcd8809b87b009e8b36afb371b4f'


def flow_nat_patch(raw):
    """Preserve a free original port when the outbound has no selector range."""
    before = b'\t\tclientSelector >= rangeStart && uint32(clientSelector-rangeStart) < rangeCount {'
    after = b'\t\t(n.selectorCount == 0 || clientSelector >= rangeStart && uint32(clientSelector-rangeStart) < rangeCount) {'
    if hashlib.sha256(raw).hexdigest() != FLOW_NAT_SHA256 or raw.count(before) != 1:
        raise ValueError('Pinned native port selector source changed')
    # Source ports below 49152 must not collapse onto the first fallback port
    # after every engine restart; the remote TCP TIME_WAIT may still be live.
    # Explicit port ranges, collision lookup and fallback allocation stay intact.
    return raw.replace(before, after, 1)


def prepare_mobile_tun(vendor):
    """Give Libbox the shared selector correction without desktop ownership code."""
    vendor = Path(vendor).resolve()
    destination = vendor / 'routervpn-mobile-tun'
    replacement = {'Old': {'Path': TUN_MODULE}, 'New': {'Path': './' + destination.name}}
    manifest = json.loads(subprocess.check_output(['go', 'mod', 'edit', '-json'], cwd=vendor, text=True))
    replacements = [item for item in (manifest.get('Replace') or []) if item['Old']['Path'] == TUN_MODULE]
    if replacements and replacements != [replacement]:
        raise ValueError('Refusing to replace another prepared native TUN module')
    module = json.loads(subprocess.check_output(['go', 'mod', 'download', '-json', TUN_MODULE+'@'+TUN_VERSION], cwd=vendor, text=True))
    expected = [line.split()[2] for line in (vendor/'go.sum').read_text().splitlines()
                if line.startswith(TUN_MODULE+' '+TUN_VERSION+' ')]
    if expected != [module.get('Sum')] or module.get('Version') != TUN_VERSION:
        raise ValueError('Mobile selector preparation requires the checksum-pinned TUN module')
    source = Path(module['Dir']).resolve()
    if destination.is_symlink() or (destination.exists() and not destination.is_dir()):
        raise ValueError('Unsafe prepared mobile TUN destination')
    outputs = {}
    for path in source.rglob('*'):
        if path.is_symlink():
            raise ValueError('Linked native TUN source')
        if not path.is_file() and not path.is_dir():
            raise ValueError('Unexpected native TUN source entry')
        if path.is_file():
            relative = path.relative_to(source)
            raw = path.read_bytes()
            outputs[relative] = flow_nat_patch(raw) if relative.as_posix() == 'flow_nat.go' else raw
    if Path('flow_nat.go') not in outputs:
        raise ValueError('Pinned native TUN selector source is missing')
    if destination.exists():
        existing = {}
        for path in destination.rglob('*'):
            if path.is_symlink():
                raise ValueError('Linked prepared mobile TUN source')
            if not path.is_file() and not path.is_dir():
                raise ValueError('Unexpected prepared mobile TUN entry')
            if path.is_file():
                existing[path.relative_to(destination)] = path.read_bytes()
        if existing != outputs:
            raise ValueError('Refusing to overwrite a changed prepared mobile TUN module')
    else:
        for relative, raw in outputs.items():
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
    subprocess.run(['go', 'mod', 'edit', '-replace='+TUN_MODULE+'=./'+destination.name], cwd=vendor, check=True)


def patch_manager(source):
    changes = [
        ('\taccess       sync.Mutex', '\troutervpnLifecycle sync.Mutex\n\troutervpnRetired []adapter.Inbound\n\troutervpnMTUPending []*RouterVPNTunTransaction\n\taccess       sync.Mutex'),
        ('\treturn m.inbounds\n', '\treturn append([]adapter.Inbound(nil), m.inbounds...)\n'),
        ('\tinbounds := m.inbounds\n\tm.inbounds = nil', '\tinbounds := append(append([]adapter.Inbound(nil), m.inbounds...), m.routervpnRetired...)\n\tm.routervpnRetired = nil\n\tm.inbounds = nil'),
    ]
    for signature in (
        'func (m *Manager) Start(stage adapter.StartStage) error {',
        'func (m *Manager) Close() error {',
        'func (m *Manager) Remove(tag string) error {',
        'func (m *Manager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, outboundType string, options any) error {',
    ):
        changes.append((signature, signature + '\n\tm.routervpnLifecycle.Lock()\n\tdefer m.routervpnLifecycle.Unlock()'))
    for old, new in changes:
        if source.count(old) != 1:
            raise ValueError('The pinned native manager boundary changed; no file was written.')
        source = source.replace(old, new)
    return source


def checked_close(source):
    """The exact later STRATEGY correction may already own this manager.

    Compare complete pinned variants, including every TUN lifecycle edit;
    accepting the final error return must not accept unrelated source edits.
    """
    marker = 'func (m *Manager) Close() error {'
    if source.count(marker) != 1:
        raise ValueError('Pinned native close ownership boundary changed.')
    start = source.index(marker)
    end = source.index('\n}\n', start) + 2
    close = source[start:end]
    tail = '\treturn nil\n}'
    if not close.endswith(tail):
        raise ValueError('Pinned native close result boundary changed.')
    return source[:start] + close[:-len(tail)] + '\treturn err\n}' + source[end:]


def verify(vendor):
    """Read-only equality against the complete pinned lifecycle projection."""
    vendor = Path(vendor).resolve()
    if subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True, timeout=30).strip() != PIN:
        raise ValueError('The exact pinned native core is required.')
    original = subprocess.check_output(['git', '-C', str(vendor), 'show', PIN + ':' + MANAGER], text=True, timeout=30)
    expected = patch_manager(original)
    records = {}
    manager = vendor / MANAGER
    if manager.is_symlink() or not manager.is_file() or manager.read_text() not in (expected, checked_close(expected)):
        raise ValueError('Native manager lost its complete retained lifecycle projection.')
    records[MANAGER] = hashlib.sha256(manager.read_bytes()).hexdigest()
    template = ROOT / 'mobile/mtu/manager.go.tmpl'
    path = manager.parent / 'routervpn_mtu.go'
    if template.is_symlink() or path.is_symlink() or not path.is_file() or path.read_bytes() != template.read_bytes():
        raise ValueError('Native manager lost its captured transaction source: ' + path.name)
    records[path.relative_to(vendor).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    records['gate/' + template.relative_to(ROOT).as_posix()] = hashlib.sha256(template.read_bytes()).hexdigest()
    observation = vendor / OBSERVATION_TARGET
    if OBSERVATION_TEMPLATE.is_symlink() or observation.is_symlink() or not observation.is_file() or observation.read_bytes() != OBSERVATION_TEMPLATE.read_bytes():
        raise ValueError('Native manager lost its original caller observation helper.')
    records[OBSERVATION_TARGET] = hashlib.sha256(observation.read_bytes()).hexdigest()
    records['gate/' + OBSERVATION_TEMPLATE.relative_to(ROOT).as_posix()] = hashlib.sha256(OBSERVATION_TEMPLATE.read_bytes()).hexdigest()
    for template, relative in INBOUND_OBSERVATION_TEMPLATES.items():
        path = vendor / relative
        if template.is_symlink() or path.is_symlink() or not path.is_file() or path.read_bytes() != template.read_bytes():
            raise ValueError('Native manager lost its original bounded observation: ' + relative)
        records[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        records['gate/' + template.relative_to(ROOT).as_posix()] = hashlib.sha256(template.read_bytes()).hexdigest()
    records['gate/deploy/prepare-retained-tun.py'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return records


def prepare(vendor):
    vendor = vendor.resolve()
    head = subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip()
    if head != PIN: raise ValueError('The exact pinned native core is required.')
    original = subprocess.check_output(['git', '-C', str(vendor), 'show', PIN + ':' + MANAGER], text=True)
    expected = patch_manager(original)
    original_checked = checked_close(original)
    expected_checked = checked_close(expected)
    prior = expected.replace("\troutervpnMTUPending []*RouterVPNTunTransaction\n", "")
    prior_checked = checked_close(prior)
    manager = vendor / MANAGER
    if manager.is_symlink():
        raise ValueError('Refusing to overwrite a changed native manager.')
    current = manager.read_text()
    if current not in (original, expected, original_checked, expected_checked, prior, prior_checked):
        raise ValueError('Refusing to overwrite a changed native manager.')
    # Re-running the full native preparation must never discard the checked
    # teardown proof installed after this TUN transaction in the first run.
    if current in (original_checked, expected_checked, prior_checked):
        expected = expected_checked
    if OBSERVATION_TEMPLATE.is_symlink():
        raise ValueError('Linked native manager observation helper.')
    outputs = {manager: expected, manager.parent / 'routervpn_mtu.go': (ROOT / 'mobile/mtu/manager.go.tmpl').read_text(), vendor / OBSERVATION_TARGET: OBSERVATION_TEMPLATE.read_text()}
    # The shared adapter helper requires the actual manager's context method.
    # Selective MTU preparation must carry the same implementation and tests
    # as full strategy preparation, without installing a partial substitute.
    for template, relative in INBOUND_OBSERVATION_TEMPLATES.items():
        if template.is_symlink():
            raise ValueError('Linked native manager observation source.')
        outputs[vendor / relative] = template.read_text()
    for target, content in outputs.items():
        if target.is_symlink() or not target.parent.resolve().is_relative_to(vendor):
            raise ValueError('Unsafe native source destination.')
        if target != manager and target.exists() and target.read_text() != content and hashlib.sha256(target.read_bytes()).hexdigest() not in PREVIOUS_TEMPLATES.get(target.name, ()):
            raise ValueError('Refusing to replace an unrelated native extension.')
    # Extension receipts compare canonical bytes on every host. Windows text
    # writes would otherwise translate these exact LF templates to CRLF.
    for target, content in outputs.items():target.write_bytes(content.encode('utf-8'))
    print('Prepared retained-TUN manager transaction; no application or service started.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor', type=Path)
    prepare(parser.parse_args().vendor)
