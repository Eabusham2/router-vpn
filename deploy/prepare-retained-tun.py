#!/usr/bin/env python3
"""Prepare the ownership-checked TUN reader transaction in a pinned core."""
from pathlib import Path
import argparse
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PIN = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
MANAGER = 'adapter/inbound/manager.go'


def patch_manager(source):
    changes = [
        ('\taccess       sync.Mutex', '\troutervpnLifecycle sync.Mutex\n\troutervpnRetired []adapter.Inbound\n\taccess       sync.Mutex'),
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


def prepare(vendor):
    vendor = vendor.resolve()
    head = subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip()
    if head != PIN: raise ValueError('The exact pinned native core is required.')
    original = subprocess.check_output(['git', '-C', str(vendor), 'show', PIN + ':' + MANAGER], text=True)
    expected = patch_manager(original)
    original_checked = checked_close(original)
    expected_checked = checked_close(expected)
    manager = vendor / MANAGER
    if manager.is_symlink():
        raise ValueError('Refusing to overwrite a changed native manager.')
    current = manager.read_text()
    if current not in (original, expected, original_checked, expected_checked):
        raise ValueError('Refusing to overwrite a changed native manager.')
    # Re-running the full native preparation must never discard the checked
    # teardown proof installed after this TUN transaction in the first run.
    if current in (original_checked, expected_checked):
        expected = expected_checked
    outputs = {
        manager: expected,
        manager.parent / 'routervpn_mtu.go': (ROOT / 'mobile/mtu/manager.go.tmpl').read_text(),
        manager.parent / 'routervpn_mtu_test.go': (ROOT / 'mobile/mtu/manager_test.go.tmpl').read_text(),
    }
    for target, content in outputs.items():
        if target.is_symlink() or not target.parent.resolve().is_relative_to(vendor):
            raise ValueError('Unsafe native source destination.')
        if target != manager and target.exists() and target.read_text() != content:
            raise ValueError('Refusing to replace an unrelated native extension.')
    for target, content in outputs.items():target.write_text(content)
    print('Prepared retained-TUN manager transaction; no application or service started.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor', type=Path)
    prepare(parser.parse_args().vendor)
