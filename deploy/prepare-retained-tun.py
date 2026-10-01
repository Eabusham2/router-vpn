#!/usr/bin/env python3
"""Prepare only the verified retained-TUN manager transaction in a disposable core.

This does not activate mobile Auto-MTU, replace an OS interface, start a service,
or alter the normal application build. Platform adapters need separate validation.
"""
from pathlib import Path
import argparse
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PIN = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
MANAGER = 'adapter/inbound/manager.go'


def patch_manager(source):
    changes = [
        ('\taccess       sync.Mutex', '\troutervpnLifecycle sync.Mutex\n\taccess       sync.Mutex'),
        ('\treturn m.inbounds\n', '\treturn append([]adapter.Inbound(nil), m.inbounds...)\n'),
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


def prepare(vendor):
    vendor = vendor.resolve()
    head = subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip()
    if head != PIN:
        raise ValueError('The exact pinned native core is required.')
    original = subprocess.check_output(['git', '-C', str(vendor), 'show', PIN + ':' + MANAGER], text=True)
    expected = patch_manager(original)
    manager = vendor / MANAGER
    if manager.is_symlink() or manager.read_text() not in (original, expected):
        raise ValueError('Refusing to overwrite a changed native manager.')
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
    for target, content in outputs.items():
        target.write_text(content)
    print('Prepared retained-TUN manager transaction; no application or service started.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor', type=Path)
    prepare(parser.parse_args().vendor)
