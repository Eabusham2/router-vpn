#!/usr/bin/env python3
"""Prove retained-TUN and checked strategy teardown compose on the real pin."""
from pathlib import Path
import argparse
import contextlib
import importlib.util
import io
import subprocess
import tempfile
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / ('deploy/' + name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def main(vendor):
    retained = load('prepare-retained-tun')
    strategy = load('prepare-mobile-strategy')
    vendor = vendor.resolve()
    head = subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip()
    if head != retained.PIN:
        raise RuntimeError('The exact pinned core is required for this executable gate')
    original = subprocess.check_output(['git', '-C', str(vendor), 'show', head + ':' + retained.MANAGER], text=True)
    expected = retained.patch_manager(original)
    checked = retained.checked_close(expected)
    count = 0
    # Actual shipping preparers run twice on the real disposable core. Every
    # source byte, including checked-close and MTU reader ownership, is stable.
    retained.prepare(vendor)
    strategy.prepare(vendor)
    paths = [vendor / retained.MANAGER, vendor / 'route/network.go']
    paths += [vendor / relative for relative in ('adapter/outbound/manager.go',
        'adapter/endpoint/manager.go', 'adapter/service/manager.go', 'dns/transport_manager.go')]
    before = {path: path.read_bytes() for path in paths}
    retained.prepare(vendor)
    strategy.prepare(vendor)
    assert before == {path: path.read_bytes() for path in paths}, 'Repeated preparation changed native ownership'
    assert (vendor / retained.MANAGER).read_text() == checked
    count += 2
    with tempfile.TemporaryDirectory(prefix='routervpn-retained-strategy-') as temporary:
        fixture = Path(temporary)
        manager = fixture / retained.MANAGER
        manager.parent.mkdir(parents=True)
        # Only Git is a boundary double here. The tested complete source bytes
        # were read from the verified immutable pin above, never a small model.
        def git(arguments, **kwargs):
            return retained.PIN + '\n' if arguments[-1] == 'HEAD' else original
        with mock.patch.object(retained.subprocess, 'check_output', side_effect=git), contextlib.redirect_stdout(io.StringIO()):
            for source, result in ((original, expected), (expected, expected),
                    (retained.checked_close(original), checked), (checked, checked)):
                manager.write_text(source)
                retained.prepare(fixture)
                assert manager.read_text() == result
                count += 1
            mutations = [checked + '\n// foreign edit\n',
                checked.replace('return err\n}', 'return nil\n}', 1).replace('m.routervpnRetired = nil', 'm.routervpnRetired = m.inbounds', 1),
                checked.replace('defer m.routervpnLifecycle.Unlock()', '// missing lifecycle unlock', 1),
                checked.replace('err = E.Append(err,', 'err = E.Append(nil,', 1),
                checked.replace('return append([]adapter.Inbound(nil), m.inbounds...)', 'return m.inbounds', 1)]
            for changed in mutations:
                assert changed not in (original, expected, retained.checked_close(original), checked)
                manager.write_text(changed)
                snapshot = {p: p.read_bytes() for p in fixture.rglob('*') if p.is_file()}
                try:
                    retained.prepare(fixture)
                except ValueError as error:
                    assert 'changed native manager' in str(error)
                else:
                    raise AssertionError('Foreign native manager edit was accepted')
                assert snapshot == {p: p.read_bytes() for p in fixture.rglob('*') if p.is_file()}
                count += 1
    print('Retained-TUN/STRATEGY preparation:', count, 'actual-source checks passed')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor', type=Path)
    main(parser.parse_args().vendor)
