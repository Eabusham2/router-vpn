#!/usr/bin/env python3
"""Verify the shipping Tor DNS preparation guard against the exact native pin."""
from pathlib import Path
import argparse
import importlib.util
import subprocess
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load_preparer(root):
    spec = importlib.util.spec_from_file_location('native_tor_dns_preparer', root/'deploy/prepare-mobile-tor.py')
    preparer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(preparer)
    return preparer


def verify(preparer, vendor):
    core = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=vendor, text=True).strip()
    if core != preparer.CORE:
        raise ValueError('Tor DNS guard fixture requires the actual pinned native core')
    relative = 'dns/transport_adapter.go'
    original = subprocess.check_output(['git', 'show', core+':'+relative], cwd=vendor)
    generated = (preparer.ROOT/'mobile/toroutbound/dns_adapter.go.tmpl').read_bytes()
    mutations = {
        'changed-resolver': generated.replace(b'server: remoteOptions.Server', b'server: "192.0.2.53"'),
        'erased-detour': generated.replace(b'detour: remoteOptions.Detour', b'detour: ""'),
        'tor-recursion': generated.replace(b'return a.routerVPNTorBootstrap.detour', b'return "tor-final"'),
        'uncaptured-route': generated.replace(b'if a.routerVPNTorBootstrap == nil {', b'if false {'),
        'unowned-addition': generated+b'\n// unowned adapter edit\n',
    }
    if any(value == generated for value in mutations.values()):
        raise ValueError('Tor DNS guard mutation no longer changes its shipping source')

    def captured_git(command, **kwargs):
        # The guard's real git path was exercised above and by the mandatory
        # repeated full preparation. Only metadata is captured here so file
        # mutations remain in a private disposable directory, never the vendor.
        if command == ['git', 'rev-parse', 'HEAD']:
            return core+'\n'
        if command == ['git', 'show', core+':'+relative]:
            return original
        raise AssertionError('Unexpected native preparation command: '+repr(command))

    def rejected(directory, expected):
        try:
            preparer.bootstrap_dns_source(directory, generated)
        except ValueError as error:
            if expected not in str(error):
                raise AssertionError('Wrong native DNS rejection: '+str(error)) from error
        else:
            raise AssertionError('Unsafe native DNS preparation was accepted')

    with tempfile.TemporaryDirectory(prefix='routervpn-tor-dns-guard-') as directory:
        fixture = Path(directory)
        destination = fixture/relative
        destination.parent.mkdir()
        with patch.object(preparer.subprocess, 'check_output', side_effect=captured_git):
            for form in (original, generated):
                destination.write_bytes(form)
                if preparer.bootstrap_dns_source(fixture, generated) != generated or destination.read_bytes() != form:
                    raise AssertionError('Tor DNS preflight changed an accepted input')
            for name, data in mutations.items():
                destination.write_bytes(data)
                rejected(fixture, 'changed outside')
                if destination.read_bytes() != data:
                    raise AssertionError('Tor DNS preflight wrote after rejecting '+name)
            destination.unlink()
            target = fixture/'owned-target.go'
            target.write_bytes(original)
            destination.symlink_to(target)
            rejected(fixture, 'Linked')
            if target.read_bytes() != original:
                raise AssertionError('Tor DNS preflight wrote through a linked destination')
        with patch.object(preparer.subprocess, 'check_output', return_value='different-core\n'):
            rejected(fixture, 'exact pinned')
            if target.read_bytes() != original:
                raise AssertionError('Tor DNS preflight wrote against the wrong core')
    return {'accepted_exact_forms': 2, 'mutation_rejections_without_writes': len(mutations),
            'wrong_core_rejected': True, 'linked_destination_rejected': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vendor', type=Path, required=True)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    args = parser.parse_args()
    result = verify(load_preparer(args.source_root.resolve()), args.vendor.resolve())
    print('PASS native Tor DNS source guard:', result)


if __name__ == '__main__':
    main()
