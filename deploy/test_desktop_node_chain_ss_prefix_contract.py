#!/usr/bin/env python3
"""Require actual source/runtime/desktop and original-Box ImportedSS prefix controls."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'deploy' / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


G = load('ss_prefix_contract_native', 'test_desktop_node_chain_ss_prefix.py')
CORE = load('ss_prefix_contract_executor', 'test_focused_multihop_clocks.py')
MOBILE = 'router-vpn/internal/mobilemultihop'
DESKTOP = 'router-vpn/cmd/client'
HOPS = 'router-vpn/internal/hopmeasure'
POINTER = 'TestNodeChainImportedSSPrefixOriginalPointers'
POINTER_WITNESS = 'equivalent foreign imported SS path owner accepted'
POINTER_SOURCE = 'internal/mobilemultihop/node_chain.go'
POINTER_GUARD = ' || !c.importedOwners.current(c)'
BOX = 'TestRouterVPNNodeChainImportedSSPrefixMTUOriginalOwners'
BOX_OLD = 'TestRouterVPNNodeChainOriginalImportedSSPhysicalTarget'
BOX_CASES = (BOX, *(BOX + '/' + str(count) + '-' + case for count in (2, 6)
    for case in ('candidate', 'rollback', 'prefix', 'middle', 'final', 'resolver', 'cancel', 'stale-owner')))
BOX_TEMPLATES = {'imported_prefix_box_test.go.tmpl': 'routervpn_node_chain_imported_prefix_test.go'}
DESKTOP_BOX_TEMPLATES = {
    'node_chain_imported_prefix_physical_test.go.tmpl': 'routervpn_desktop_node_chain_imported_prefix_physical_test.go',
    'node_chain_openvpn_box_physical_test.go.tmpl': 'routervpn_desktop_node_chain_openvpn_box_physical_test.go'}
PHYSICAL = 'TestRouterVPNNodeChainImportedSSPrefixPhysicalTarget'
PHYSICAL_SOURCE = 'routervpn_desktop_node_chain_box_physical.go'
PHYSICAL_GUARD = 'middle.Tag == "" && len(meta.Prefixes) >= 3 && prefix.Mode == "shadowsocks"'
ORIGINAL_PHYSICAL_GUARD = 'middle.Tag == "" && len(meta.Prefixes) == 3 && position == 1 && prefix.Mode == "shadowsocks"'
# Current published helper with only the original SS trio restriction restored;
# preserve the independent Hysteria layer/platform admission in this control.
ORIGINAL_PHYSICAL_SHA256 = '340411853b4f2ac31f35a7b37ecaefff402b80b39907f4d569fb2fc260bdf545'
BOX_CASES += (PHYSICAL, *(PHYSICAL + '/' + str(count) + '-' + target for count in (1, 2, 6) for target in ('linux', 'windows', 'darwin')),
              *(PHYSICAL + '/' + fault for fault in ('position', 'tag', 'source', 'mode', 'layer', 'kind', 'node-kind', 'paired-id', 'prefix', 'final')),
              BOX_OLD, *(BOX_OLD + '/' + target for target in ('linux', 'windows', 'darwin')))
BOX_CASES += tuple(G.NODE.ORDERED_PHYSICAL_VERDICTS)
BOX_FILES = (PHYSICAL_SOURCE, 'routervpn_node_chain_imported_prefix_test.go',
             'routervpn_mtu.go', 'adapter/inbound/routervpn_mtu.go', *DESKTOP_BOX_TEMPLATES.values())


def rows(root, leaves=()):
    return (root, *(root + '/' + leaf for leaf in leaves))


def case(name, package, roots, expected, selection=None, mutation=False):
    chosen = '^(' + '|'.join(roots) + ')$' if selection is None else selection
    return package, CORE.Case(name, chosen, frozenset(expected), 120, 600,
        'original-pointer' if mutation else '', POINTER_WITNESS if mutation else '',
        frozenset(row for row in expected if row != POINTER) if mutation else frozenset())

def original_physical_mutant(raw):
    if raw.count(PHYSICAL_GUARD) != 1:
        raise ValueError('SS original physical causal boundary changed')
    changed = raw.replace(PHYSICAL_GUARD, ORIGINAL_PHYSICAL_GUARD, 1)
    if hashlib.sha256(changed.encode()).hexdigest() != ORIGINAL_PHYSICAL_SHA256:
        raise ValueError('SS physical causal overlay lost the exact published helper')
    return changed


def physical_controls():
    names = rows(PHYSICAL, (str(count)+'-'+target for count in (2, 6) for target in ('linux', 'windows', 'darwin')))
    return (CORE.Case('original-physical-ss', '^'+PHYSICAL+'$/^(2|6)-(linux|windows|darwin)$',
        frozenset(names), 120, 130, 'original-physical-factory', 'original sealed SS prefix physical target refused', frozenset(names[1:])),)


def source_cases():
    root = 'TestNodeChainImportedMiddleSourceAndNativeProjection'
    result = [case('original-ss-projection', MOBILE, (root,), rows(root,
        (mode+'/'+layer for mode in G.MODES for layer in ('', 'aes-256-gcm', 'aes-256-gcm+xor-whitening'))))]
    authority, proof, owner, ciphers, cancel = (
        'TestNodeChainImportedMiddleRejectsUncapturedAuthority', 'TestNodeChainImportedMiddleRequiresPublicProof',
        'TestNodeChainImportedMiddleDesktopPolicyRetainsPhysicalOwner', 'TestNodeChainImportedMiddleCiphersAndCompleteFinalDNS',
        'TestNodeChainImportedMiddleCancellationJoinsOriginalPublicSocket')
    result.append(case('original-ss-authority-runtime', MOBILE, (authority, proof, owner, ciphers, cancel),
        (*rows(authority, ('schema1', 'unknown-schema', 'two', 'four', 'missing-identities', 'middle-identity',
            'missing-first-identity', 'missing-final-identity', 'reorder', 'paired-middle', 'double-imported', 'canonical-middle',
            'duplicate-middle-key', 'fake-api', 'fake-proof', 'layer', 'hostname', 'wrong-credential', 'legacy-method',
            'identity-chain', 'changed-expected-ip', 'extra-route')),
         *rows(proof, ('#00', 'middle-stopped', 'wrong-public-ip', 'changed-source')),
         *rows(owner, ('linux', 'darwin', 'windows')),
         *rows(ciphers, (method+'/'+protocol for method in G.METHODS.values() for protocol in ('https', 'h3'))), cancel)))
    root = 'TestNodeChainImportedSSCompletePacketPrefixes'
    for mode in G.MODES:
        for form in G.FORMS:
            result.append(case('shared-prefix-'+mode+'-'+form, MOBILE, (root,), rows(root,
                (mode+'/'+form+'/'+method+'/'+str(count) for method in G.METHODS.values() for count in range(1, 7))),
                '^'+root+'$/^'+mode+'$/^'+form+'$'))
    pointer_rows = rows(POINTER, (*(str(index) for index in range(8)), 'whole', 'policy', 'hostname', 'omitted', 'reordered'))
    result.append(case('original-prefix-pointers', MOBILE, (POINTER,), pointer_rows))
    root = 'TestNodeChainImportedSSPrefixSourceRefusals'
    result.append(case('prefix-source-refusals', MOBILE, (root,), rows(root,
        ('nine-nodes', 'missing-prefix', 'reordered-identities', 'foreign-prefix-mode', 'second-import', 'middle-first',
         'middle-final', 'middle-identity', 'missing-final-identity', 'legacy-method', 'wrong-key-length', 'changed-profile-key',
         'start-layer', 'hostname-ambient', 'hostname-udp', 'hostname-resolver-hostname'))))
    root = 'TestNodeChainImportedSSPrefixPurposeBoundary'
    result.append(case('prefix-local-purpose', MOBILE, (root,), rows(root, (str(count) for count in range(1, 7)))))
    root = 'TestNodeChainImportedSSPrefixCompleteRuntime'
    result.append(case('prefix-original-runtime', MOBILE, (root,), rows(root,
        (*(str(count)+'-hostname-'+host for count in (2, 6) for host in ('false', 'true')),
         *('original-network-during-prefix-'+str(position) for position in range(8))))))
    root, refused = 'TestOrderedImportedSSPrefixMeasurementAuthority', 'TestOrderedImportedSSPrefixRefusedObservation'
    result.append(case('prefix-measurement-authority', HOPS, (root, refused),
        (*rows(root, (*(str(count) for count in range(3, 9)), 'omission', 'reorder', 'public-first', 'public-final',
                     'two-public', 'middle-token', 'duplicate-proof', 'duplicate-id', 'wrong-tag')), refused)))
    old = {
        'TestDesktopOrderedHostnameCaptureUsesSavedResolverWithoutPhysicalBootstrap': G.MODES,
        'TestDesktopOrderedHostnameAdmissionRequiresOriginalExplicitPolicy': ('home', 'rescue', 'fastest', 'udp', 'dot',
            'resolver-hostname', 'resolver-loopback', 'missing-port', 'bad-port', 'resolver-tls', 'resolver-path',
            'wrong-endpoint', 'host-case-mismatch', 'paired-api', 'layer', 'first', 'final'),
        'TestDesktopOrderedHostnamePublicCaptureRejectsChangedResolver': (),
        'TestDesktopOrderedHostnameSavedProfileRestoresExactPolicy': (),
        'TestDesktopOrderedImportedOriginalSourceCapture': (),
        'TestDesktopOrderedImportedRejectsUnsupportedPlacementAndIdentity': ('first', 'final', 'paired-token', 'hostname',
            'wrong-mode', 'start-layer', 'legacy-cipher', 'missing-source'),
        'TestConnectionProfileOrderedImportedRestoresOriginalPolicyAndRejectsCredentials': (),
        'TestStartupOrderedImportedRetainsSourceKindAndDigest': (),
        'TestDesktopOrderedImportedMeasurementPreservesPublicKind': (),
        'TestDesktopOrderedImportedPublicCapabilityContainsNoCredentials': (),
        'TestDesktopOrderedImportedPublicRequestRetainsEveryCurrentSource': (),
        'TestDesktopOrderedImportedPreservesExactAWGPhysicalEntry': G.MODES[1:],
        'TestDesktopOrderedImportedThreeCiphersRetainOriginalSource': tuple(mode+'/'+method for mode in G.MODES for method in G.METHODS.values()),
    }
    result.append(case('original-desktop-ss', DESKTOP, tuple(old), tuple(name for root, leaves in old.items() for name in rows(root, leaves))))
    root, saved, layer = ('TestDesktopOrderedImportedPacketPrefixes', 'TestDesktopOrderedImportedPrefixSavedAndMeasuredPositions',
                         'TestDesktopOrderedImportedPrefixStartLayers')
    methods, endpoints = tuple(G.METHODS.values()), ('203.0.113.81', '2001:db8::81', 'Middle.Example.Test')
    result.append(case('desktop-prefix-capture-saved-layer', DESKTOP, (root, saved, layer),
        (*rows(root, (mode+'/'+methods[(li+mi)%3]+'/'+str(count)+'/'+endpoints[(2*li+mi)%3]
                    for li, count in enumerate((1, 2, 6)) for mi, mode in enumerate(G.MODES))),
         *rows(saved, (str(count)+'/'+endpoint for count in (2, 6) for endpoint in (endpoints[0], endpoints[2]))),
         *rows(layer, (mode+'/'+kind for mode in G.MODES for kind in ('aes-256-gcm', 'aes-256-gcm+xor-whitening'))))))
    causal_rows = rows(POINTER, (*(str(index) for index in range(8)), 'whole', 'policy', 'hostname'))
    result.append(case('omitted-original-prefix-pointers', MOBILE, (POINTER,), causal_rows,
        '^'+POINTER+'$/^([0-7]|whole|policy|hostname)$', mutation=True))
    return tuple(result)


def source_command(compiler, package, record, overlay=None):
    command = [str(compiler), 'test', '-json', '-race', '-count=1', '-p=1', '-mod=readonly',
               '-timeout=120s', '-run', record.selection]
    if overlay is not None:
        command += ['-overlay=' + str(overlay)]
    return [*command, './' + package.removeprefix('router-vpn/')]


def source_contracts(source, compiler, captured, output):
    before = CORE.snapshot(source)
    attempts = []
    for package, record in source_cases():
        overlay = None
        if record.mutation:
            original = source / POINTER_SOURCE
            raw = original.read_text()
            if raw.count(POINTER_GUARD) != 1:
                raise ValueError('ImportedSS original-pointer causal boundary changed')
            mutant = output / 'original-pointer-mutant.go'
            mutant.write_text(raw.replace(POINTER_GUARD, '', 1))
            overlay = output / 'original-pointer-overlay.json'
            overlay.write_text(json.dumps({'Replace': {str(original): str(mutant)}}, indent=2) + '\n')
        if CORE.snapshot(source) != before:
            raise ValueError('ImportedSS source changed before compiled contract')
        log = output / (record.name + '.jsonl')
        command = source_command(compiler, package, record, overlay)
        code, timeout, joined = CORE.execute(command, source, captured, log, record.outer_seconds)
        CORE.PACKAGE = package
        result = CORE.verdict(log.read_bytes(), record, code, timeout, joined)
        attempts.append({'name': record.name, 'package': package, 'command': command, **result,
                         'output_sha256': hashlib.sha256(log.read_bytes()).hexdigest()})
        print(record.name + ': ' + ('accepted' if result['accepted'] else 'refused') + ' (' + str(len(record.expected)) + ' required verdicts)', flush=True)
        if not result['accepted']:
            print(log.read_text()[-24000:], flush=True)
            raise ValueError('ImportedSS compiled contract refused: ' + record.name + ': ' + result['reason'])
        if CORE.snapshot(source) != before:
            raise ValueError('ImportedSS source changed during compiled contract')
    return before, attempts


def box_contracts(source, compiler, captured, output):
    source, before = G.checked_sources(source)
    for template, relative in BOX_TEMPLATES.items():
        if (source / relative).read_bytes() != (ROOT / 'mobile/chain' / template).read_bytes():
            raise ValueError('ImportedSS Box source differs from its shipping template: ' + relative)
    for template, relative in DESKTOP_BOX_TEMPLATES.items():
        if (G.NODE.PREP.BOX_TEMPLATES.get(template) != relative or
                (source / relative).read_bytes() != (ROOT / 'mobile/desktop' / template).read_bytes()):
            raise ValueError('ImportedSS desktop physical source differs from its canonical template: ' + relative)
    for relative in BOX_FILES:
        path = source / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError('ImportedSS original Box contract dependency missing: ' + relative)
        before[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    image = output / 'ss-box.test'
    command = [str(compiler), 'test', '-c', '-race', '-p=1', '-mod=readonly', '-tags=' + ','.join(G.NODE.TAGS),
               '-ldflags=-checklinkname=0', '-o', image, '.']
    status, text = G.NODE.run(command, cwd=source, env=captured, timeout=600)
    (output / 'box-build.log').write_text(text)
    if status:
        print(text[-24000:], flush=True)
        raise ValueError('ImportedSS original Box contract compilation failed')
    identity = G.NODE.retained_binary(image)
    status, text = G.NODE.run([image, '-test.run=^(' + '|'.join(sorted({name.split('/')[0] for name in BOX_CASES})) + ')$', '-test.count=1', '-test.timeout=120s', '-test.v'],
                             cwd=source, env=captured, timeout=130)
    (output / 'box.log').write_text(text)
    print(text, end='' if text.endswith('\n') else '\n', flush=True)
    if status:
        raise ValueError('ImportedSS original Box contract process failed')
    G.NODE.require_native_verdicts(text, BOX_CASES, 'ImportedSS original Box MTU/session')
    after = G.checked_sources(source)[1]
    for relative in BOX_FILES:
        after[relative] = hashlib.sha256((source / relative).read_bytes()).hexdigest()
    if after != before or G.NODE.retained_binary(image) != identity:
        raise ValueError('ImportedSS original Box image or source changed')
    original = source / PHYSICAL_SOURCE
    mutant = output / 'original-physical-factory.go'
    mutant.write_text(original_physical_mutant(original.read_text()))
    overlay = output / 'original-physical-factory-overlay.json'
    overlay.write_text(json.dumps({'Replace': {str(original): str(mutant)}}, indent=2) + '\n')
    mutant_image = output / 'original-physical-factory.test'
    mutant_command = [*command]
    mutant_command[mutant_command.index(image)] = mutant_image
    mutant_command.insert(-1, '-overlay=' + str(overlay))
    status, build_output = G.NODE.run(mutant_command, cwd=source, env=captured, timeout=600)
    (output / 'physical-causal-build.log').write_text(build_output)
    if status:
        raise ValueError('Original physical-factory causal image did not compile')
    mutant_identity = G.NODE.retained_binary(mutant_image)
    controls = []
    for record in physical_controls():
        log = output / (record.name + '.jsonl')
        run = [str(compiler), 'tool', 'test2json', '-t', '-p', 'box', str(mutant_image), '-test.v=test2json',
               '-test.count=1', '-test.timeout=120s', '-test.run=' + record.selection]
        code, timeout, joined = CORE.execute(run, source, captured, log, 130)
        CORE.PACKAGE = 'box'
        result = CORE.verdict(log.read_bytes(), record, code, timeout, joined)
        if not result['accepted'] or G.NODE.retained_binary(mutant_image) != mutant_identity:
            raise ValueError('Original physical-factory causal refusal was not demonstrated: ' + record.name)
        controls.append({'name': record.name, **result, 'image_sha256': mutant_identity[-1],
                         'output_sha256': hashlib.sha256(log.read_bytes()).hexdigest()})
    after = G.checked_sources(source)[1]
    for relative in BOX_FILES:
        after[relative] = hashlib.sha256((source / relative).read_bytes()).hexdigest()
    if after != before or G.NODE.retained_binary(image) != identity:
        raise ValueError('Original physical-factory control changed the baseline image/source')
    return {'verdicts': list(BOX_CASES), 'image_sha256': identity[-1],
            'original_physical_sha256': ORIGINAL_PHYSICAL_SHA256, 'controls': controls,
            'output_sha256': hashlib.sha256(text.encode()).hexdigest(), 'source_files': before,
            'scope': 'original-box-component', 'kernel_tun_accepted': False}


def execute(source_checkout, required_commit, receipt, go='go'):
    source_checkout = Path(source_checkout).resolve(strict=True)
    selection = G.published_identity(source_checkout, required_commit)
    repository = G.HOST.repository_identity(required_commit)
    receipt = G.HOST.new_receipt_path(receipt)
    if repository is None or receipt is None:
        raise ValueError('ImportedSS contracts require a captured commit and fresh receipt')
    output = receipt.parent / 'ss-prefix-contract-logs'
    output.mkdir(mode=0o700)
    compiler, captured, _ = G.NODE.selected_compiler(go, source_checkout, dict(os.environ))
    captured['GOWORK'] = 'off'
    if captured.get('CGO_ENABLED', '1') != '1':
        raise ValueError('ImportedSS contracts require native race/CGO execution')
    captured['CGO_ENABLED'] = '1'
    source_files, attempts = source_contracts(source_checkout, compiler, captured, output)
    with G.prepared_native(compiler, captured) as (source, workspace):
        native = box_contracts(source, compiler, captured, output)
    if G.published_identity(source_checkout, required_commit) != selection or CORE.snapshot(source_checkout) != source_files:
        raise ValueError('ImportedSS contracts source or validator changed')
    result = {'schema': 1, 'gate': 'ss-prefix-source-runtime-mtu', 'repository': repository,
              'selection': selection, 'validator': G.validator_identity(), 'source_files': source_files,
              'attempts': attempts, 'native': native, 'installed_host_accepted': False, 'kernel_tun_accepted': False}
    G.HOST.publish_receipt(receipt, result, workspace)
    return result


def check_receipt(receipt, repository, selection, original_sources):
    if (not isinstance(receipt, dict) or type(receipt.get('schema')) is not int or receipt['schema'] != 1 or
            receipt.get('gate') != 'ss-prefix-source-runtime-mtu' or receipt.get('repository') != repository or
            receipt.get('selection') != selection or receipt.get('validator') != G.validator_identity() or
            receipt.get('source_files') != original_sources or receipt.get('installed_host_accepted') is not False or
            receipt.get('kernel_tun_accepted') is not False):
        raise ValueError('ImportedSS contract receipt lost its original source, validator or scope')
    expected = source_cases()
    attempts = receipt.get('attempts')
    if not isinstance(attempts, list) or len(attempts) != len(expected):
        raise ValueError('ImportedSS contract receipt omitted required compiled attempts')
    for attempt, (package, record) in zip(attempts, expected):
        action = 'fail' if record.mutation else 'pass'
        names = sorted(record.expected)
        if (not isinstance(attempt, dict) or attempt.get('name') != record.name or attempt.get('package') != package or
                attempt.get('accepted') is not True or attempt.get('reason') != '' or
                type(attempt.get('exit')) is not int or attempt['exit'] != (1 if record.mutation else 0) or
                attempt.get('timed_out') is not False or attempt.get('process_group_joined') is not True or
                attempt.get('expected') != names or attempt.get('ran') != names or
                attempt.get('passed') != ([] if record.mutation else names) or
                attempt.get('failed') != (names if record.mutation else []) or attempt.get('skipped') != [] or
                attempt.get('package_terminals') != [action]):
            raise ValueError('ImportedSS contract receipt lost a compiled original verdict: ' + record.name)
        G.require_digest(attempt.get('output_sha256'))
    native = receipt.get('native')
    if (not isinstance(native, dict) or native.get('verdicts') != list(BOX_CASES) or
            native.get('scope') != 'original-box-component' or native.get('kernel_tun_accepted') is not False or
            not isinstance(native.get('source_files'), dict) or not set(BOX_FILES).issubset(native['source_files'])):
        raise ValueError('ImportedSS contract receipt omitted original Box ownership/MTU cases')
    if native.get('original_physical_sha256') != ORIGINAL_PHYSICAL_SHA256 or not isinstance(native.get('controls'), list) or len(native['controls']) != 1:
        raise ValueError('ImportedSS physical-factory original counterfactual is missing')
    image = None
    for control, record in zip(native['controls'], physical_controls()):
        names = sorted(record.expected)
        if (control.get('name') != record.name or control.get('accepted') is not True or control.get('reason') != '' or
                type(control.get('exit')) is not int or control['exit'] != 1 or control.get('timed_out') is not False or
                control.get('process_group_joined') is not True or control.get('expected') != names or control.get('ran') != names or
                control.get('failed') != names or control.get('passed') != [] or control.get('skipped') != [] or control.get('package_terminals') != ['fail']):
            raise ValueError('ImportedSS physical-factory original refusal lost its exact compiled verdict')
        G.require_digest(control.get('image_sha256'))
        G.require_digest(control.get('output_sha256'))
        if image is not None and image != control['image_sha256']:
            raise ValueError('ImportedSS physical-factory controls borrowed another compiled image')
        image = control['image_sha256']
    G.require_digest(native.get('image_sha256'))
    G.require_digest(native.get('output_sha256'))
    for value in native['source_files'].values():
        G.require_digest(value)
    return native['source_files']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-checkout', type=Path, required=True)
    parser.add_argument('--require-commit', required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--go', default='go')
    args = parser.parse_args()
    execute(args.source_checkout, args.require_commit, args.receipt, args.go)
