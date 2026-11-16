#!/usr/bin/env python3
"""Actual encrypted Local Box/OpenVPN proof, with explicit component boundaries.

The application TUN, first physical tuple mapping and discovery advertisement
are fixtures. Original endpoint registration, mutual TLS/data, WG, final SS,
selected DNS and joined Box retirement are required. This is not installed TUN
acceptance or a complete execution Run/Last claim.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = 'github.com/sagernet/sing-box/protocol/routervpnamnezia'
TEST = 'TestOpenVPNExecutionEncryptedOriginalLocal'
TEMPLATE = 'mobile/chain_component/openvpn_execution_test.go.tmpl'
CASES = tuple(f'{network}/{layer}/original' for network in ('tcp', 'udp')
              for layer in ('off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening')) + tuple(
    f'{network}/off/{fault}' for fault in ('provider-password', 'selected-dns', 'final-identity', 'reconnect')
    for network in ('tcp', 'udp'))
CONTROLS = (
    ('original-source', 'tcp/off/original', 'routervpn_node_chain_openvpn_execution.go',
     'if !ok || c == nil || c.source != original {', 'if !ok || c == nil {',
     'equal Local source replaced original Box owner'),
    ('connected-receipt', 'udp/off/reconnect', 'routervpn_node_chain_openvpn_execution.go',
     'if *c.state != actual {', 'if false {',
     'reconnected Local endpoint replaced retained original receipt'),
    ('joined-box', 'tcp/off/original', 'routervpn_node_chain_openvpn_execution_retirement.go',
     'if err := c.close.JoinContext(ctx, c.instance); err != nil {',
     'if err := ctx.Err(); err != nil {',
     'unjoined Local Box manufactured original retirement'),
)


def load(name):
    spec = importlib.util.spec_from_file_location('openvpn_local_'+name, ROOT/'deploy'/name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sources():
    # The original Server component supplies only its actual reference-source
    # helpers. Keep that complete closed projection and every shipping method.
    result = load('test_server_node_chain_openvpn_native.py').sources()
    result['openvpn_execution_component_test.go'] = (ROOT/TEMPLATE).read_bytes()
    return result


def expected(case):
    if case not in CASES:
        raise ValueError('Uncaptured encrypted Local OpenVPN case')
    return {TEST: 1, TEST+'/'+case.replace('/', '_'): 1}


def receipt(output):
    helper = load('test_desktop_native_root_phases.py')
    helper.PACKAGE = PACKAGE
    return helper.load_receipt().complete_receipt(output)


def verdict(output, case):
    rows, runs, passed, failed, terminal = receipt(output)
    if terminal != 'pass' or failed or runs != expected(case) or passed != expected(case):
        raise ValueError('Encrypted Local OpenVPN omitted, duplicated or failed its original native case')
    if any(any(marker in row.get('Output', '') for marker in
               ('panic:', 'fatal error:', 'test timed out', 'WARNING: DATA RACE')) for row in rows):
        raise ValueError('Encrypted Local OpenVPN contains fatal native output')
    return 2


def rejected(output, case, witness):
    rows, runs, passed, failed, terminal = receipt(output)
    forbidden = ('panic:', 'fatal error:', 'test timed out', 'WARNING: DATA RACE',
                 'original retirement did not join', 'reference source did not join', 'failed retirement')
    return (terminal == 'fail' and runs == expected(case) and failed == expected(case) and not passed
            and any(witness in row.get('Output', '') for row in rows)
            and not any(any(marker in row.get('Output', '') for marker in forbidden) for row in rows))


def execute(core, target, tags, env, runner):
    if 'with_openvpn' not in tags.split(','):
        raise ValueError('Encrypted Local proof requires the original OpenVPN implementation')
    if (target not in ('linux/amd64', 'linux/arm64') or
            (env.get('GOOS'), env.get('GOARCH')) != tuple(target.split('/')) or env.get('CGO_ENABLED') != '1'):
        raise ValueError('Encrypted Local proof requires the actual Linux native race target')
    core = Path(core).resolve()
    captured = dict(env)
    owner = load('test_node_chain_openvpn_execution_owner.py')
    worker = load('test_server_node_chain_native.py')
    peers = load('prepare-desktop-external.py')
    helpers = load('test_desktop_native_root_phases.py')

    def verify():
        worker.verify_sources(core)
        owner.verify(core, desktop=True)
        for name, relative in peers.PEER_TEMPLATES.items():
            actual = core/relative
            if actual.is_symlink() or not actual.is_file() or actual.read_bytes() != (ROOT/'mobile/desktop'/name).read_bytes():
                raise ValueError('Encrypted Local proof changed its original native provider source')

    verify()
    original = helpers.source_digest(core)
    content = sources()
    source_hash = hashlib.sha256(b''.join(name.encode()+b'\0'+raw for name, raw in sorted(content.items()))).hexdigest()
    with tempfile.TemporaryDirectory(prefix='routervpn-openvpn-encrypted-local-') as directory:
        workspace = Path(directory)
        overlay = {}
        for name, raw in content.items():
            path = workspace/name
            path.write_bytes(raw)
            overlay[str(core/'protocol/routervpnamnezia'/name)] = str(path)
        overlay_file = workspace/'original.json'
        overlay_file.write_text(json.dumps({'Replace': overlay}))
        image = workspace/'original.test'
        base = ['go', 'test', '-c', '-race', '-p=1', '-mod=readonly', '-tags='+tags, '-ldflags=-checklinkname=0']
        runner([*base, '-overlay='+str(overlay_file), '-o', image, './protocol/routervpnamnezia'],
               cwd=core, env=captured, timeout=300)
        identity = helpers.image_identity(image)

        def unchanged():
            if (env != captured or sources() != content or helpers.source_digest(core) != original
                    or helpers.image_identity(image) != identity
                    or any(Path(overlay[str(core/'protocol/routervpnamnezia'/name)]).read_bytes() != raw
                           for name, raw in content.items())):
                raise ValueError('Encrypted Local proof changed its captured source, environment or image')
            verify()

        unchanged()
        listing = runner([image, '-test.list=^'+TEST+'$'], cwd=core, env=captured, timeout=60).strip().splitlines()
        if listing != [TEST]:
            raise ValueError('Encrypted Local compiled root discovery changed')
        receipts = {}
        for case in CASES:
            unchanged()
            output = runner(['go', 'tool', 'test2json', '-p', PACKAGE, '-t', image, '-test.v', '-test.count=1',
                             '-test.timeout=60s', '-test.run=^'+TEST+'$'], cwd=core,
                            env=dict(captured, ROUTERVPN_OPENVPN_EXECUTION_COMPONENT=case), timeout=75)
            receipts[case] = verdict(output, case)
            unchanged()
        for label, case, relative, before, after, witness in CONTROLS:
            unchanged()
            source = core/relative
            raw = source.read_text()
            if raw.count(before) != 1:
                raise ValueError('Encrypted Local causal source changed: '+label)
            mutant = workspace/(label+'.go')
            mutant.write_text(raw.replace(before, after, 1))
            changed = dict(overlay)
            changed[str(source)] = str(mutant)
            control = workspace/(label+'.json')
            control.write_text(json.dumps({'Replace': changed}))
            control_image = workspace/(label+'.test')
            runner([*base, '-overlay='+str(control), '-o', control_image, './protocol/routervpnamnezia'],
                   cwd=core, env=captured, timeout=300)
            control_identity = helpers.image_identity(control_image)
            result = subprocess.run(['go', 'tool', 'test2json', '-p', PACKAGE, '-t', str(control_image),
                                     '-test.v', '-test.count=1', '-test.timeout=60s', '-test.run=^'+TEST+'$'],
                                    cwd=core, env=dict(captured, ROUTERVPN_OPENVPN_EXECUTION_COMPONENT=case),
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=75)
            if (result.returncode != 1 or result.stderr or not rejected(result.stdout, case, witness)
                    or helpers.image_identity(control_image) != control_identity):
                raise ValueError('Encrypted Local causal lacked its original assertion: '+label+'\n'+result.stdout+result.stderr)
            print('Original encrypted Local OpenVPN causal: '+label, flush=True)
            print(result.stdout, end='', flush=True)
            unchanged()
        result = dict(kind='native-openvpn-local-encrypted-v1', target=target, source_sha256=original,
                      projection_sha256=source_hash, image_sha256=identity[1], race=True, cases=receipts,
                      controls=[row[0] for row in CONTROLS], application_tun_acceptance=False,
                      complete_execution_run=False)
        print('Original encrypted Local OpenVPN components: '+json.dumps(result, sort_keys=True), flush=True)
        return result
