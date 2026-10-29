#!/usr/bin/env python3
"""Exercise the shipping GTK launcher, shutdown callback, HTTP and exact child join."""
from pathlib import Path
import argparse
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'client/linux'


def run(command, *, timeout=45, expected_failure=None):
    result = subprocess.run([str(part) for part in command], text=True, capture_output=True, timeout=timeout)
    if expected_failure:
        if result.returncode != 1 or expected_failure not in result.stdout+'\n'+result.stderr:
            raise AssertionError('Broken launcher ownership control did not fail its intended assertion: '+result.stdout+'\n'+result.stderr)
        return
    if result.returncode:
        raise RuntimeError(result.stdout + '\n' + result.stderr)
    if result.stdout.strip():
        print(result.stdout.strip(), flush=True)


def compile_fixture(directory, change=None):
    for name in ('test-controller-shutdown.c', 'routervpn-gtk-product.c', 'routervpn-controller-shutdown-v1.inc',
                 'routervpn-controller-auth-v1.h', 'routervpn-controller-launch-v1.inc'):
        shutil.copyfile(SOURCE / name, directory / name)
    helper = directory / 'routervpn-controller-shutdown-v1.inc'
    if change is not None:
        old, new = change
        text = helper.read_text()
        if text.count(old) != 1:
            raise AssertionError('Negative control anchor drifted: ' + old)
        helper.write_text(text.replace(old, new, 1))
    flags = subprocess.check_output(['pkg-config', '--cflags', '--libs', 'gtk+-3.0', 'libcurl', 'json-glib-1.0'], text=True).split()
    binary = directory / 'shutdown-fixture'
    run(['gcc', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-I'+str(directory), directory/'test-controller-shutdown.c', '-o', binary, *flags, '-lm', '-pthread'])
    return binary


def exercise(binary, scenario, directory, expected_failure=None):
    package = directory / ('package-' + scenario)
    package.mkdir()
    shutil.copyfile(binary, package / 'router-vpn-client')
    (package / 'router-vpn-client').chmod(0o700)
    (package / 'client.json').write_text('{}\n')
    command = [binary, scenario, package]
    if not os.environ.get('DISPLAY'):
        command = ['xvfb-run', '-a', *command]
    run(command, timeout=45, expected_failure=expected_failure)


def test(negative=True):
    with tempfile.TemporaryDirectory(prefix='routervpn-gtk-controller-shutdown-') as temporary:
        root = Path(temporary)
        source = root / 'source'
        source.mkdir()
        binary = compile_fixture(source)
        scenarios = ('foreign', 'occupied', 'wrong-proof', 'wrong-pid', 'wrong-challenge', 'auth-cancel',
                     'pending', 'delay-exit', 'exit-during-body', 'wrong-owner', 'duplicate', 'lost-receipt', 'abnormal-exit', 'replace-owner')
        for scenario in scenarios:
            exercise(binary, scenario, root)
        if negative:
            mutations = (
                ('foreign-nonce', 'strcmp(captured_owner,owner)==0', 'TRUE', 'wrong-owner', 'different launch nonce rejected'),
                ('missing-receipt', 'if(shutdown->receipt&&child==1)', 'if(child==1)', 'lost-receipt', 'unconfirmed or abnormal exit leaves owned UI intact'),
                ('discard-buffered-reply', 'shutdown->receipt=code==CURLE_OK&&', 'shutdown->receipt=controller_child_observe(shutdown->process)==0&&code==CURLE_OK&&', 'exit-during-body', 'receipt and normal exit both completed before closing'),
                ('replacement-owner', 'app->owns_controller&&app->controller_pid==shutdown->process&&strcmp(app->controller_owner,shutdown->owner)==0', 'app->owns_controller', 'replace-owner', 'old completion cannot clear or close replacement owner'),
            )
            for name, old, new, scenario, assertion in mutations:
                directory = root / name
                directory.mkdir()
                mutant = compile_fixture(directory, (old, new))
                exercise(mutant, scenario, directory, expected_failure='GTK controller shutdown failure: '+assertion)
                print('Rejected launcher ownership mutation: ' + name, flush=True)
        print('GTK checked controller shutdown: real callbacks, subprocesses, bounded HTTP, cleanup receipt and exact process join PASS', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shipping-only', action='store_true')
    args = parser.parse_args()
    test(negative=not args.shipping_only)
