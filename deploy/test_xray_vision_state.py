#!/usr/bin/env python3
"""Prove pinned Vision parser synchronization using the real reader and writer.

The original unsynchronized source is a declared negative build overlay. It
must expose the real Vision data race; compiler errors or arbitrary failures
cannot satisfy that control. Existing encrypted DNS and imported peer gates
remain separate required evidence.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('vision_state_original_sources', ROOT / 'deploy/test_mobile_imported_proxy_xray.py')
PROXY = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PROXY)
SOCKS = PROXY.SOCKS
POLICY = SOCKS.XRAY.SHARED.VISION
DUPLEX = 'TestRouterVPNVisionSharedParserDuplex'
NAMES = {DUPLEX, DUPLEX + '/datagram', DUPLEX + '/tls13',
         'TestRouterVPNVisionReadIOReleasesParser', 'TestRouterVPNVisionWriteIOReleasesParser',
         'TestRouterVPNVisionFilterLoggingReleasesParser'}
CONTROL_NAMES = {DUPLEX, DUPLEX + '/datagram', DUPLEX + '/tls13'}
PATTERN = '^TestRouterVPNVision(SharedParserDuplex|ReadIOReleasesParser|WriteIOReleasesParser|FilterLoggingReleasesParser)$'
CHILD_KEY = 'ROUTER_VPN_VISION_LOG_CHILD'


def inputs():
    return sorted(set(PROXY.inputs()) | {
        Path(__file__).resolve(), ROOT / 'deploy/test_xray_vision_state_runner.py',
        ROOT / 'deploy/test_native_xray_udp443.py', ROOT / 'deploy/test_native_xray_udp443_runner.py',
        ROOT / '.github/workflows/imported-socks-reality-native.yml',
        ROOT / '.github/workflows/apple-xray-native.yml', ROOT / 'android/app/build.gradle',
    })


def source_receipt():
    result = {}
    for path in inputs():
        if path.is_symlink() or not path.is_file():
            raise ValueError('Vision parser lost an original source or mandatory caller: ' + str(path))
        result[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def compile_image(compiler, source, workspace, env, *, overlay=None):
    suffix = '.exe' if env['GOOS'] == 'windows' else ''
    image = workspace / (('vision-original' if overlay else 'vision-synchronized') + suffix)
    command = [compiler, 'test', '-mod=readonly', '-race', '-c', '-ldflags=-checklinkname=0']
    if overlay is not None:
        command.append('-overlay=' + str(overlay))
    command += ['-o', image, './proxy']
    status, output = SOCKS.run_command(command, source, env, 600)
    if status or image.is_symlink() or not image.is_file():
        raise ValueError('Actual Vision parser image did not compile:\n' + output[-24000:])
    return image, hashlib.sha256(image.read_bytes()).hexdigest()


def execute_image(compiler, source, env, image, digest, pattern):
    if image.is_symlink() or hashlib.sha256(image.read_bytes()).hexdigest() != digest:
        raise ValueError('Vision parser image changed before execution')
    status, output = SOCKS.run_command([compiler, 'tool', 'test2json', '-t', '-p', 'github.com/xtls/xray-core/proxy',
        image, '-test.v', '-test.run=' + pattern, '-test.count=1', '-test.timeout=30s'], source, env, 45)
    # Preserve original race and ownership diagnostics before strict validation.
    print(output, end='' if output.endswith('\n') else '\n', flush=True)
    if image.is_symlink() or hashlib.sha256(image.read_bytes()).hexdigest() != digest:
        raise ValueError('Vision parser image changed during execution')
    return status, output


def require_original_race(output, status):
    runs, terminals, diagnostics = [], [], []
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        name, action = event.get('Test'), event.get('Action')
        if name and action == 'run':
            runs.append(name)
        if name and action in ('pass', 'fail', 'skip'):
            terminals.append((name, action))
        if action == 'output':
            diagnostics.append(event.get('Output', ''))
    text = ''.join(diagnostics)
    if (status == 0 or len(runs) != len(CONTROL_NAMES) or set(runs) != CONTROL_NAMES or
        len(terminals) != len(CONTROL_NAMES) or {name for name, _ in terminals} != CONTROL_NAMES or
        any(action == 'skip' for _, action in terminals) or
        not any(action == 'fail' and name != DUPLEX for name, action in terminals) or
        'WARNING: DATA RACE' not in text or 'proxy.(*VisionWriter).WriteMultiBuffer' not in text or
        'proxy.XtlsFilterTls' not in text or 'race detected during execution of test' not in text or
        'panic:' in text or 'fatal error:' in text):
        raise ValueError('Original Vision source did not causally expose its reader/writer parser race:\n' + output[-24000:])


def original_overlay(source, workspace):
    original = subprocess.check_output(['git', '-C', str(source), 'show', SOCKS.XRAY.XRAY_PIN + ':' + POLICY.SOURCE])
    if hashlib.sha256(original).hexdigest() != POLICY.SOURCE_SHA256:
        raise ValueError('Vision negative control lost the exact original pinned parser')
    target = source / POLICY.SOURCE
    prepared = POLICY.patch_text(POLICY.SOURCE, original.decode()).replace('\n', os.linesep).encode()
    if target.is_symlink() or target.read_bytes() != prepared:
        raise ValueError('Vision negative control was not based on the complete prepared repair')
    copy = workspace / 'original-proxy.go'
    copy.write_bytes(original)
    overlay = workspace / 'original-parser-overlay.json'
    overlay.write_text(json.dumps({'Replace': {str(target): str(copy)}}, sort_keys=True))
    return overlay, {copy.name: hashlib.sha256(original).hexdigest(),
                     overlay.name: hashlib.sha256(overlay.read_bytes()).hexdigest()}


def run(source, compiler=None, environment=None):
    source = source.resolve(strict=True)
    compiler_path = compiler or shutil.which('go')
    if not compiler_path:
        raise ValueError('Vision parser requires the original shipping Go compiler')
    compiler = Path(compiler_path).resolve(strict=True)
    env = dict(os.environ if environment is None else environment,
               GOTOOLCHAIN=SOCKS.TOOLCHAIN, GOWORK='off')
    env.pop(CHILD_KEY, None)
    for key, value in (('GOMAXPROCS', '1'), ('GOGC', '5'), ('GOMEMLIMIT', '256MiB')):
        env.setdefault(key, value)
    if subprocess.check_output([compiler, 'env', 'GOVERSION'], env=env, text=True).strip() != SOCKS.TOOLCHAIN:
        raise ValueError('Vision parser requires the original shipping Go compiler')
    for key in ('GOOS', 'GOARCH'):
        env[key] = subprocess.check_output([compiler, 'env', 'GOHOST' + key[2:]], env=env, text=True).strip()
    original = source_receipt()
    before = SOCKS.checked_xray(source)
    subprocess.run([sys.executable, ROOT / 'deploy/test_xray_vision_state_runner.py'],
                   cwd=ROOT, env=env, check=True, timeout=30)
    receipt = {'scope': 'actual pinned Vision parser synchronization and I/O ownership',
               'xray_pin': SOCKS.XRAY.XRAY_PIN, 'toolchain': SOCKS.TOOLCHAIN,
               'source_count': len(original), 'source_sha256': SOCKS.record_digest(original),
               'xray_count': len(before), 'xray_sha256': SOCKS.record_digest(before)}
    with tempfile.TemporaryDirectory(prefix='routervpn-vision-state-') as temporary:
        workspace = Path(temporary)
        image, digest = compile_image(compiler, source, workspace, env)
        status, output = execute_image(compiler, source, env, image, digest, PATTERN)
        SOCKS.require_verdicts(output, status, NAMES)
        overlay, control_records = original_overlay(source, workspace)
        control, control_digest = compile_image(compiler, source, workspace, env, overlay=overlay)
        status, output = execute_image(compiler, source, env, control, control_digest, '^' + DUPLEX + '$')
        require_original_race(output, status)
        for name, expected in control_records.items():
            path = workspace / name
            if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise ValueError('Original Vision negative-control overlay changed')
        if source_receipt() != original or SOCKS.checked_xray(source) != before:
            raise ValueError('Vision parser lost its captured source or prepared engine during execution')
        receipt.update(native={'sha256': digest, 'verdicts': sorted(NAMES)},
                       original_control={'sha256': control_digest, 'sources': control_records,
                                         'verdicts': sorted(CONTROL_NAMES), 'causal_data_race': True})
    print(json.dumps(receipt, sort_keys=True), flush=True)
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('xray', type=Path)
    run(parser.parse_args().xray)
