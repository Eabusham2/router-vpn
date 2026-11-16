#!/usr/bin/env python3
"""Execute the real AAR guard on explicit javap-text boundary inputs.

This checks the guard's positive and refusal behavior. It does not assert that
a generated AAR or Android device is present; the shipping verifier obtains
these three inputs from javap against its actual generated classes.jar.
"""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def verify_factory_abi():
    source = (ROOT/'android/build-sing-box-libbox.sh').read_text()
    start = source.index('require_typed_connected_candidate_api() {')
    end = source.index('\n}\n', start)+3
    body = source[start:end]
    call = '  require_typed_connected_candidate_api "$api_list" "$tmp/router-node-chain-socks-candidate.javap" "$tmp/router-node-chain-connect-candidate.javap" || return 1'
    if source.count(call) != 1:
        raise AssertionError('Typed candidate guard must run exactly once against actual AAR outputs')
    before = source[:source.index(call)]
    for cls, destination in (('Libbox', '$api_list'), ('RouterNodeChainSOCKSCandidateMeasurement', '$tmp/router-node-chain-socks-candidate.javap'), ('RouterNodeChainCONNECTCandidateMeasurement', '$tmp/router-node-chain-connect-candidate.javap')):
        expected = 'javap -classpath "$classes" io.nekohasekai.libbox.'+cls+' >"'+destination+'"'
        if before.count(expected) != 1:
            raise AssertionError('Typed candidate guard lost actual generated class input: '+cls)
    signatures = []
    for family in ('SOCKS', 'CONNECT'):
        signatures.extend([
            f'io.nekohasekai.libbox.RouterNodeChain{family}CandidateMeasurement routerNodeChain{family}NewCandidateMeasurement(io.nekohasekai.libbox.RouterNodeChain{family}, io.nekohasekai.libbox.CommandServer, int, java.lang.String, io.nekohasekai.libbox.RouterNodeChainCandidateCatalog) throws java.lang.Exception;',
        ])
    handles = [
        'void prepare() throws java.lang.Exception;',
        'java.lang.String metadata();', 'java.lang.String captureSHA256();',
        'void start(java.lang.String, java.lang.String) throws java.lang.Exception;',
        'void cancel(java.lang.String);',
        'void drain(java.lang.String) throws java.lang.Exception;',
        'java.lang.String statusJSON();', 'void networkChanged();',
        'void close() throws java.lang.Exception;',
    ]
    cases = [('complete', [list(signatures), list(handles), list(handles)], True)]
    original = [signatures, handles, handles]
    for file_index, rows in enumerate(original):
        for row_index, value in enumerate(rows):
            mutations = [('missing', '')]
            if file_index == 0:
                mutations.extend([
                    ('foreign-owner', value.replace('io.nekohasekai.libbox.RouterNodeChainSOCKS,', 'io.nekohasekai.libbox.RouterNodeChain,').replace('io.nekohasekai.libbox.RouterNodeChainCONNECT,', 'io.nekohasekai.libbox.RouterNodeChain,')),
                    ('wrong-position', value.replace(', int,', ', long,')),
                    ('missing-error', value.replace(' throws java.lang.Exception', '')),
                ])
            else:
                mutations.append(('renamed', value.replace('(', 'Other(', 1)))
            for label, changed in mutations:
                if changed == value:
                    raise AssertionError('ABI refusal input did not change')
                rows_copy = [list(part) for part in original]
                rows_copy[file_index][row_index] = changed
                cases.append((f'{file_index}-{row_index}-{label}', rows_copy, False))
    with tempfile.TemporaryDirectory(prefix='routervpn-typed-connected-abi-') as directory:
        paths = [Path(directory)/(str(index)+'.txt') for index in range(3)]
        for label, rows, accepted in cases:
            for path, lines in zip(paths, rows):
                path.write_text('\n'.join(lines)+'\n')
            result = subprocess.run(['bash', '-c', body+'\nrequire_typed_connected_candidate_api "$1" "$2" "$3"', 'typed-candidate-abi', *map(str, paths)], text=True, capture_output=True, timeout=10)
            if (result.returncode == 0) != accepted or not accepted and 'missing ' not in result.stderr:
                raise AssertionError('Actual typed candidate ABI guard missed '+label+'\n'+result.stdout+result.stderr)
    print(f'Android typed connected candidate actual AAR guard: {len(cases)} boundary cases PASS', flush=True)
    verify_ordinary_reservation_abi()


def verify_ordinary_reservation_abi():
    source = (ROOT/'android/build-sing-box-libbox.sh').read_text()
    start = source.index('require_ordinary_candidate_reservation_api() {')
    body = source[start:source.index('\n}\n', start)+3]
    call = '  require_ordinary_candidate_reservation_api "$api_list" "$tmp/router-node-chain-candidate.javap" || return 1'
    if source.count(call) != 1:
        raise AssertionError('Ordinary candidate guard must verify the actual AAR exactly once')
    before = source[:source.index(call)]
    for cls, target in (('Libbox', '$api_list'), ('RouterNodeChainCandidateMeasurement', '$tmp/router-node-chain-candidate.javap')):
        actual = 'javap -classpath "$classes" io.nekohasekai.libbox.'+cls+' >"'+target+'"'
        if before.count(actual) != 1:
            raise AssertionError('Ordinary reservation lost generated class input: '+cls)
    factory = 'io.nekohasekai.libbox.RouterNodeChainCandidateMeasurement routerNodeChainNewCandidateMeasurement(io.nekohasekai.libbox.RouterNodeChain, io.nekohasekai.libbox.CommandServer, int, java.lang.String, io.nekohasekai.libbox.RouterNodeChainCandidateCatalog) throws java.lang.Exception;'
    methods = ['void prepare() throws java.lang.Exception;', 'java.lang.String metadata();', 'java.lang.String captureSHA256();', 'void start(java.lang.String, java.lang.String) throws java.lang.Exception;', 'void cancel(java.lang.String);', 'void drain(java.lang.String) throws java.lang.Exception;', 'java.lang.String statusJSON();', 'void networkChanged();', 'void close() throws java.lang.Exception;']
    cases = [('complete', factory, methods, True, ''), ('missing-factory', '', methods, False, 'missing the ordinary candidate reservation factory'), ('owner-key-cleanup', factory+'\nvoid routerNodeChainCloseCandidateMeasurement();', methods, False, 'unsafe ordinary candidate owner-key cleanup')]
    cases += [('missing-'+str(i), factory, methods[:i]+methods[i+1:], False, 'missing the original ordinary candidate handle API') for i in range(len(methods))]
    with tempfile.TemporaryDirectory(prefix='ordinary-candidate-abi-') as directory:
        paths = [Path(directory)/name for name in ('api.txt', 'handle.txt')]
        for label, api, handle, accepted, witness in cases:
            paths[0].write_text(api+'\n'); paths[1].write_text('\n'.join(handle)+'\n')
            result = subprocess.run(['bash', '-c', body+'\nrequire_ordinary_candidate_reservation_api "$1" "$2"', 'ordinary-candidate-abi', *map(str, paths)], text=True, capture_output=True, timeout=10)
            if (result.returncode == 0) != accepted or not accepted and witness not in result.stderr:
                raise AssertionError('Actual ordinary reservation ABI guard missed '+label+'\n'+result.stdout+result.stderr)
    print(f'Android ordinary reservation actual AAR guard: {len(cases)} boundary cases PASS', flush=True)


if __name__ == '__main__':
    verify_factory_abi()
