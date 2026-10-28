#!/usr/bin/env python3
"""Compile the actual mobile Tor copy set without desktop-only dependencies."""
from pathlib import Path
import argparse
import importlib.util
import inspect
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('mobile_tor_closure', ROOT/'deploy/prepare-mobile-tor.py')
PREP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREP)
PREFIXES = ('routervpn/common/', 'routervpn/mobiletor/', 'routervpn/awgpolicy/',
            'routervpn/nativeopenvpn/', 'routervpn/dnsmeasure/',
            'experimental/libbox/routervpn/')


def compile_sources(content, go, pattern):
    with tempfile.TemporaryDirectory(prefix='routervpn-mobile-tor-closure-') as directory:
        root = Path(directory)
        (root/'go.mod').write_text('module '+PREP.MODULE+'\n\ngo 1.26.3\n')
        for relative, raw in content.items():
            if relative.startswith(PREFIXES) and relative.endswith('.go'):
                path = root/relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
        environment = os.environ.copy()
        environment['GOTOOLCHAIN'] = 'local'
        return subprocess.run([go, 'test', '-mod=readonly', '-race', './routervpn/mobiletor',
                               '-run', pattern, '-count=1'], cwd=root, env=environment,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=180)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', default='go')
    args = parser.parse_args()
    content = PREP.copies()
    expected = {'routervpn/mobiletor/'+path.name for path in PREP.mobile_policy_sources()}
    actual = {name for name in content if name.startswith('routervpn/mobiletor/')}
    if actual != expected or any(Path(name).name.startswith('desktop_') for name in actual):
        raise AssertionError('Mobile Tor copied a desktop owner or omitted shared policy/test source')
    for source in PREP.mobile_policy_sources():
        if content['routervpn/mobiletor/'+source.name] != PREP.rewrite(source.read_bytes()):
            raise AssertionError('Mobile Tor changed shared policy bytes: '+source.name)
    for source in PREP.lease_policy_sources():
        path = 'experimental/libbox/routervpn/'+source.parent.name+'/'+source.name
        if content.get(path) != PREP.lease_rewrite(source.read_bytes()):
            raise AssertionError('Mobile Tor changed the shared lease validator: '+source.name)
    result = compile_sources(content, args.go,
                             '^Test(TorProfilePreservesSavedResolverAndDynamicSession|'
                             'PredecessorFingerprintBindsCompleteCapturedEntry|ExternalPredecessor|MobileExternalTor|TorJumbo|MobileServerTor|ServerTorRetained|PaddingControl|PaddingLease)')
    if result.returncode:
        raise RuntimeError('Actual mobile Tor generated closure failed:\n'+result.stdout)
    print(result.stdout.strip())
    # Execute the real copy function with the one intended filter removed.
    # The generated scope validator must reject the actual leaked host files.
    # Ordinary predecessor policy now shares the complete multihop closure;
    # missing that dependency is no longer a valid negative-control oracle.
    source = inspect.getsource(PREP.copies)
    guard = "            if name == 'mobiletor' and path.name.startswith('desktop_'):\n                continue\n"
    if source.count(guard) != 1:
        raise AssertionError('Mobile Tor copy boundary changed')
    namespace = dict(PREP.__dict__)
    exec(compile(source.replace(guard, ''), '<desktop-copy-defect>', 'exec'), namespace)
    try:
        namespace['copies']()
    except ValueError as failure:
        if 'desktop owner' not in str(failure):
            raise
    else:
        raise AssertionError('Leaked desktop owners were not rejected by actual preparation')
    missing = dict(content)
    missing.pop('routervpn/mobiletor/external_predecessor.go')
    broken = compile_sources(missing, args.go, '^$')
    if broken.returncode == 0 or 'undefined: ExternalPredecessorProof' not in broken.stdout:
        raise AssertionError('Missing ordinary predecessor source was not rejected by actual Go compilation:\n'+broken.stdout)
    print('PASS: exact mobile source/test closure, desktop-copy rejection and missing ordinary proof compiler rejection')


if __name__ == '__main__':
    main()
