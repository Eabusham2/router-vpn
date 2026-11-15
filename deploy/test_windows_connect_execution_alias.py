#!/usr/bin/env python3
"""Execute the original Windows CONNECT fixture alias owner and causal controls.

Only the IP Helper adapter is modeled here. This source receipt cannot certify
native addresses, WFP, the protected controller or CONNECT execution on Windows.
"""
from collections import Counter
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
OWNER = 'cmd/client/desktop_connect_execution_alias_owner_test.go'
CONTROLS = 'cmd/client/desktop_connect_execution_alias_controls_test.go'
NATIVE = 'cmd/client/desktop_connect_execution_alias_windows_native_test.go'
LOCK = 'internal/desktopnetwork/desktop_network_lock.go'
HEADER = '//go:build windows && routervpn_windows_candidate_prefix_native && go1.25\n\n'
TEST = 'TestWindowsCONNECTAliasOwnerControls'
CASES = ('joined-idempotent', 'collision-before-mutation', 'failed-create-retains-first',
         'partial-create-retains-second', 'failed-join-keeps-owner', 'failed-delete-keeps-owner',
         'address-index', 'address-luid', 'mask', 'skip', 'recreated', 'loopback-index',
         'loopback-luid', 'unobserved-create', 'absent-original', 'nil-join', 'cancelled-cleanup', 'cancelled-waiter')


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise ValueError('Original Windows alias causal seam changed: ' + before)
    return text.replace(before, after, 1)


def mutations(source):
    return {
        'collision': (replace_once(source, 'if _, exists := present[address]; exists {',
                                  'if _, exists := present[address]; exists && false {'),
                      'collision-before-mutation', 'existing second alias allowed an earlier mutation'),
        'partial-create': (replace_once(source, 'if record != nil {', 'if record != nil && createErr == nil {'),
                           'partial-create-retains-second', 'partial native creation escaped original cleanup'),
        'join': (replace_once(source, 'if err := join(ctx); err != nil {\n\t\treturn err\n\t}', '_ = join(ctx)'),
                 'failed-join-keeps-owner', 'failed native join retired original aliases'),
        'record': (replace_once(source, 'if record.Created <= 0 || current != record {',
                               'if record.Created <= 0 || current.Address != record.Address {'),
                   'recreated', 'replaced native alias acquired deletion authority'),
        'loopback': (replace_once(source, 'if err != nil || identity != owner.identity {\n\t\t\treturn errors.Join(err, errors.New("CONNECT alias cleanup replaced its loopback identity"))',
                                 'if err != nil || identity.Index != owner.identity.Index {\n\t\t\treturn errors.Join(err, errors.New("CONNECT alias cleanup replaced its loopback identity"))'),
                     'loopback-luid', 'replaced native alias acquired deletion authority'),
        'delete-retry': (replace_once(source, 'if err := owner.kernel.Delete(ctx, record); err != nil {\n\t\t\treturn err\n\t\t}',
                                     'if err := owner.kernel.Delete(ctx, record); err != nil {\n\t\t\towner.added = nil\n\t\t\treturn err\n\t\t}'),
                         'failed-delete-keeps-owner', 'failed removal discarded original retry owner'),
        'cancelled-waiter': (replace_once(source, 'if err := desktopnetwork.LockContext(ctx, &windowsCONNECTAliasGate); err != nil {',
                                         '_ = desktopnetwork.LockContext\n\twindowsCONNECTAliasGate.Lock()\n\tif err := ctx.Err(); err != nil {\n\t\twindowsCONNECTAliasGate.Unlock()'),
                             'cancelled-waiter', 'original alias waiter never entered its context gate'),
    }


def require_verdict(result, case=None, witness=None):
    text = result.stdout + result.stderr
    expected = [TEST, TEST + '/' + case] if case else [TEST, *(TEST + '/' + c for c in CASES)]
    if re.search(r'DATA RACE|panic:|fatal error:|build failed|no tests to run|--- SKIP:', text, re.I):
        raise ValueError('Unrelated Windows alias runtime/compiler failure:\n' + text)
    runs = re.findall(r'^=== RUN   (\S+)\r?$', text, re.M)
    verdict = 'FAIL' if witness else 'PASS'
    ended = re.findall(r'^[ \t]*--- ' + verdict + r': (\S+) \(', text, re.M)
    opposite = 'PASS' if witness else 'FAIL'
    if Counter(runs) != Counter(expected) or Counter(ended) != Counter(expected) or re.search(r'--- ' + opposite + ':', text):
        raise ValueError('Windows alias exact run/verdict inventory changed:\n' + text)
    if witness:
        records = re.findall(r'^[ \t]+controls_test\.go:\d+: (.*)\r?$', text, re.M)
        if result.returncode != 1 or records != [witness] or not re.search(r'^FAIL\s+router-vpn/probe\s', text, re.M):
            raise ValueError('Windows alias causal failure lacks its exact witness:\n' + text)
    elif result.returncode != 0 or len(re.findall(r'^PASS\r?$', text, re.M)) != 1 or not re.search(r'^ok\s+router-vpn/probe\s', text, re.M):
        raise ValueError('Windows alias owner omitted its successful terminal verdict:\n' + text)


def execute(root=ROOT, go='go'):
    root = Path(root)
    paths = (OWNER, CONTROLS, NATIVE, LOCK, 'deploy/test_windows_connect_execution_alias.py')
    originals = {}
    for name in paths:
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('Windows alias gate lost its original source: ' + name)
        originals[name] = path.read_bytes()
    bodies = {}
    for name in (OWNER, CONTROLS):
        text = originals[name].decode()
        if not text.startswith(HEADER):
            raise ValueError('Windows alias source changed its explicit build boundary')
        bodies[name] = text.removeprefix(HEADER)
    native = originals[NATIVE].decode()
    for api in ('CreateUnicastIpAddressEntry', 'DeleteUnicastIpAddressEntry', 'GetUnicastIpAddressEntry',
                'GetUnicastIpAddressTable', 'ConvertInterfaceIndexToLuid', 'InitializeUnicastIpAddressEntry'):
        if native.count('library.NewProc("' + api + '")') != 1:
            raise ValueError('Windows alias native adapter omitted its exact IP Helper API: ' + api)
    variants = {'original': (bodies[OWNER], None, None), **mutations(bodies[OWNER])}
    environment = dict(os.environ, GOMAXPROCS='2')
    for key in ('GOOS', 'GOARCH', 'GOARM', 'GOAMD64', 'GOROOT', 'GOTOOLDIR'):
        environment.pop(key, None)
    with tempfile.TemporaryDirectory(prefix='routervpn-windows-connect-alias-') as temporary:
        directory = Path(temporary)
        (directory / 'probe').mkdir()
        (directory / 'internal/desktopnetwork').mkdir(parents=True)
        (directory / 'go.mod').write_text('module router-vpn\n\ngo 1.25.0\n')
        (directory / LOCK).write_bytes(originals[LOCK])
        (directory / 'probe/controls_test.go').write_text(bodies[CONTROLS])
        for name, (source, case, witness) in variants.items():
            (directory / 'probe/owner.go').write_text(source)
            selection = '^' + TEST + '$' + ('/^' + case + '$' if case else '')
            result = subprocess.run([go, 'test', '-race', '-v', '-count=1', '-p=1', '-timeout=15s', '-run', selection, './probe'],
                                    cwd=directory, env=environment, text=True, capture_output=True, timeout=45)
            require_verdict(result, case, witness)
            print('PASS Windows CONNECT alias owner ' + name, flush=True)
    if any((root / name).read_bytes() != body for name, body in originals.items()):
        raise ValueError('Original Windows alias source changed during execution')
    receipt = dict(scope='windows-connect-alias-source-controls', native=False, cases=list(CASES),
                   mutations=list(variants)[1:], sources={name: hashlib.sha256(body).hexdigest() for name, body in originals.items()})
    print('Windows CONNECT alias ownership source controls: ' + json.dumps(receipt, sort_keys=True), flush=True)
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', default=shutil.which('go') or 'go')
    execute(go=parser.parse_args().go)
