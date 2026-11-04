#!/usr/bin/env python3
"""Prepare the ownership-checked TUN reader transaction in a pinned core."""
from pathlib import Path
import argparse
import hashlib
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PIN = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
MANAGER = 'adapter/inbound/manager.go'
# Exact previous published preparation, accepted only for this bounded upgrade.
PREVIOUS_TEMPLATES = {
    'routervpn_mtu_native_linux_test.go': ('c357330566e837ebab6e084db5072f21c896d5c08248163d31ec226d2711c7c7',),
    'routervpn_mtu.go': (
        '79603bccd07497e8d01cc99b87e61bce7b45c3c0f9c89c1725c697e0f4878669',
        '7241c2a70cc00f8ff8eeeaf4ad2f95312fb19fd4cede8512a4b9e4ff09762830',
    ),
    'routervpn_mtu_test.go': (
        '67979009bbb57a8c6e4287dd0a502f35745878f7c86e3216a7585356d91f8be3',
        'c2cbfd26a5cb5b150beb43f5ffc65852c31ee543284aa60860d7e4deb1f5d405',
    ),
}


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
    for source, target in (('manager.go.tmpl', 'routervpn_mtu.go'), ('manager_test.go.tmpl', 'routervpn_mtu_test.go'), ('manager_native_linux_test.go.tmpl', 'routervpn_mtu_native_linux_test.go')):
        template = ROOT / 'mobile/mtu' / source
        path = manager.parent / target
        if template.is_symlink() or path.is_symlink() or not path.is_file() or path.read_bytes() != template.read_bytes():
            raise ValueError('Native manager lost its captured transaction source: ' + target)
        records[path.relative_to(vendor).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
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
    outputs = {
        manager: expected,
        manager.parent / 'routervpn_mtu.go': (ROOT / 'mobile/mtu/manager.go.tmpl').read_text(),
        manager.parent / 'routervpn_mtu_test.go': (ROOT / 'mobile/mtu/manager_test.go.tmpl').read_text(),
        manager.parent / 'routervpn_mtu_native_linux_test.go': (ROOT / 'mobile/mtu/manager_native_linux_test.go.tmpl').read_text(),
    }
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
