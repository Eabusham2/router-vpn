#!/usr/bin/env python3
"""Exercise captured HTTP(S) ordered source while preserving original source gates."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
BASE_PATH = ROOT / "deploy/test_focused_socks_source.py"
spec = importlib.util.spec_from_file_location("connect_original_source_gate", BASE_PATH)
BASE = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = BASE
spec.loader.exec_module(BASE)
SUITE = "connect-source"
ORIGINAL_CASES = BASE.cases(BASE.SUITE)
ORIGINAL_MUTATIONS = dict(BASE.CONTROL_MUTATIONS)
ORIGINAL_SOURCE_PATHS = tuple(BASE.SOURCE_PATHS)
ORIGINAL_FORMAT_PATHS = tuple(BASE.FORMAT_PATHS)

INVENTORY = {'controls': [{'after': '',
               'before': '\tif connect != nil {\n'
                         '\t\tif err := connect.validate(nodes, closures); err != nil {\n'
                         '\t\t\treturn fail(err)\n'
                         '\t\t}\n'
                         '\t}\n',
               'failures': ['TestNodeChainCONNECTConstructionReceiptIsPrivateAndExact',
                            'TestNodeChainCONNECTConstructionReceiptIsPrivateAndExact/foreign-closure'],
               'name': 'foreign-original-closure',
               'path': 'internal/mobilemultihop/node_chain_graph.go',
               'selector': '^TestNodeChainCONNECTConstructionReceiptIsPrivateAndExact$/^foreign-closure$',
               'witness': 'invalid CONNECT construction receipt acquired physical authority'},
              {'after': '',
               'before': 'capture.scope != s || ',
               'failures': ['TestNodeChainCONNECTPhysicalReceiptOwnsExactUoTFinal',
                            'TestNodeChainCONNECTPhysicalReceiptOwnsExactUoTFinal/foreign-scope'],
               'name': 'foreign-physical-receipt-owner',
               'path': 'internal/mobilemultihop/node_chain_connect_physical.go',
               'selector': '^TestNodeChainCONNECTPhysicalReceiptOwnsExactUoTFinal$/^foreign-scope$',
               'witness': 'changed or foreign UoT receipt acquired physical traversal'},
              {'after': '',
               'before': 'p.digest() != p.seal || ',
               'failures': ['TestNodeChainCONNECTSourceDoesNotBroadenGenericAuthority'],
               'name': 'changed-private-config-seal',
               'path': 'internal/mobilemultihop/node_chain_connect_source.go',
               'selector': '^TestNodeChainCONNECTSourceDoesNotBroadenGenericAuthority$',
               'witness': 'changed private config retained source seal'}],
 'files': ['internal/mobilemultihop/node_chain_imported_connect.go',
           'internal/mobilemultihop/node_chain_connect_source.go',
           'internal/mobilemultihop/node_chain_graph.go',
           'internal/mobilemultihop/node_chain_connect_physical.go',
           'internal/mobilemultihop/desktop_egress.go',
           'internal/mobilemultihop/node_chain_connect_source_test.go'],
 'original': {'name': 'original-connect-methods-uot-dns',
              'records': 52,
              'required': ['TestImportedEntryCONNECTGraphs',
                           'TestImportedEntryCONNECTGraphs/http-connect--2022-blake3-aes-128-gcm--custom',
                           'TestImportedEntryCONNECTGraphs/http-connect--2022-blake3-aes-128-gcm--home',
                           'TestImportedEntryCONNECTGraphs/http-connect--2022-blake3-aes-256-gcm--custom',
                           'TestImportedEntryCONNECTGraphs/http-connect--2022-blake3-aes-256-gcm--home',
                           'TestImportedEntryCONNECTGraphs/http-connect--2022-blake3-chacha20-poly1305--custom',
                           'TestImportedEntryCONNECTGraphs/http-connect--2022-blake3-chacha20-poly1305--home',
                           'TestImportedEntryCONNECTGraphs/https-connect--2022-blake3-aes-128-gcm--custom',
                           'TestImportedEntryCONNECTGraphs/https-connect--2022-blake3-aes-128-gcm--home',
                           'TestImportedEntryCONNECTGraphs/https-connect--2022-blake3-aes-256-gcm--custom',
                           'TestImportedEntryCONNECTGraphs/https-connect--2022-blake3-aes-256-gcm--home',
                           'TestImportedEntryCONNECTGraphs/https-connect--2022-blake3-chacha20-poly1305--custom',
                           'TestImportedEntryCONNECTGraphs/https-connect--2022-blake3-chacha20-poly1305--home',
                           'TestImportedEntryCONNECTServiceAuthorityRefusals',
                           'TestImportedEntryCONNECTServiceAuthorityRefusals/dns-h3',
                           'TestImportedEntryCONNECTServiceAuthorityRefusals/entry-layer',
                           'TestImportedEntryCONNECTServiceAuthorityRefusals/extra-asset',
                           'TestImportedEntryCONNECTServiceAuthorityRefusals/foreign-node',
                           'TestImportedEntryCONNECTServiceAuthorityRefusals/inline-uot',
                           'TestImportedEntryCONNECTServiceAuthorityRefusals/missing',
                           'TestImportedEntryCONNECTServiceAuthorityRefusals/stale-source',
                           'TestImportedEntryCONNECTServiceAuthorityRefusals/unsupported-layer',
                           'TestImportedEntryCONNECTServiceAuthorityRefusals/wrong-home',
                           'TestImportedEntryCONNECTServiceAuthorityRefusals/wrong-image',
                           'TestImportedEntryCONNECTServiceAuthorityRefusals/wrong-key',
                           'TestImportedEntryCONNECTServiceAuthorityRefusals/wrong-port',
                           'TestImportedEntryCONNECTServiceAuthorityRefusals/wrong-version',
                           'TestImportedEntryCONNECTServiceConfiguredGraphs',
                           'TestImportedEntryCONNECTServiceConfiguredGraphs/http-connect/aes-256-gcm+xor-whitening/custom/tcp',
                           'TestImportedEntryCONNECTServiceConfiguredGraphs/http-connect/aes-256-gcm+xor-whitening/custom/udp',
                           'TestImportedEntryCONNECTServiceConfiguredGraphs/http-connect/aes-256-gcm+xor-whitening/home/tcp',
                           'TestImportedEntryCONNECTServiceConfiguredGraphs/http-connect/aes-256-gcm+xor-whitening/home/udp',
                           'TestImportedEntryCONNECTServiceConfiguredGraphs/http-connect/aes-256-gcm/custom/tcp',
                           'TestImportedEntryCONNECTServiceConfiguredGraphs/http-connect/aes-256-gcm/custom/udp',
                           'TestImportedEntryCONNECTServiceConfiguredGraphs/http-connect/aes-256-gcm/home/tcp',
                           'TestImportedEntryCONNECTServiceConfiguredGraphs/http-connect/aes-256-gcm/home/udp',
                           'TestImportedEntryCONNECTServiceConfiguredGraphs/http-connect/off/custom/tcp',
                           'TestImportedEntryCONNECTServiceConfiguredGraphs/http-connect/off/custom/udp',
                           'TestImportedEntryCONNECTServiceConfiguredGraphs/http-connect/off/home/tcp',
                           'TestImportedEntryCONNECTServiceConfiguredGraphs/http-connect/off/home/udp',
                           'TestImportedEntryCONNECTServiceConfiguredGraphs/https-connect/aes-256-gcm+xor-whitening/custom/tcp',
                           'TestImportedEntryCONNECTServiceConfiguredGraphs/https-connect/aes-256-gcm+xor-whitening/custom/udp',
                           'TestImportedEntryCONNECTServiceConfiguredGraphs/https-connect/aes-256-gcm+xor-whitening/home/tcp',
                           'TestImportedEntryCONNECTServiceConfiguredGraphs/https-connect/aes-256-gcm+xor-whitening/home/udp',
                           'TestImportedEntryCONNECTServiceConfiguredGraphs/https-connect/aes-256-gcm/custom/tcp',
                           'TestImportedEntryCONNECTServiceConfiguredGraphs/https-connect/aes-256-gcm/custom/udp',
                           'TestImportedEntryCONNECTServiceConfiguredGraphs/https-connect/aes-256-gcm/home/tcp',
                           'TestImportedEntryCONNECTServiceConfiguredGraphs/https-connect/aes-256-gcm/home/udp',
                           'TestImportedEntryCONNECTServiceConfiguredGraphs/https-connect/off/custom/tcp',
                           'TestImportedEntryCONNECTServiceConfiguredGraphs/https-connect/off/custom/udp',
                           'TestImportedEntryCONNECTServiceConfiguredGraphs/https-connect/off/home/tcp',
                           'TestImportedEntryCONNECTServiceConfiguredGraphs/https-connect/off/home/udp'],
              'selector': '^(TestImportedEntryCONNECTGraphs|TestImportedEntryCONNECTServiceConfiguredGraphs|TestImportedEntryCONNECTServiceAuthorityRefusals)$'},
 'required': ['TestNodeChainCONNECTConstructionReceiptIsPrivateAndExact',
              'TestNodeChainCONNECTConstructionReceiptIsPrivateAndExact/changed-final-dns',
              'TestNodeChainCONNECTConstructionReceiptIsPrivateAndExact/changed-member-source',
              'TestNodeChainCONNECTConstructionReceiptIsPrivateAndExact/foreign-closure',
              'TestNodeChainCONNECTConstructionReceiptIsPrivateAndExact/missing-final-uot',
              'TestNodeChainCONNECTConstructionReceiptIsPrivateAndExact/missing-scope',
              'TestNodeChainCONNECTConstructionReceiptIsPrivateAndExact/ordinary-member',
              'TestNodeChainCONNECTConstructionReceiptIsPrivateAndExact/wrong-mode',
              'TestNodeChainCONNECTConstructionReceiptIsPrivateAndExact/wrong-physical',
              'TestNodeChainCONNECTConstructionReceiptIsPrivateAndExact/wrong-position',
              'TestNodeChainCONNECTPhysicalReceiptOwnsExactUoTFinal',
              'TestNodeChainCONNECTPhysicalReceiptOwnsExactUoTFinal/changed-config',
              'TestNodeChainCONNECTPhysicalReceiptOwnsExactUoTFinal/changed-final',
              'TestNodeChainCONNECTPhysicalReceiptOwnsExactUoTFinal/changed-paired-source',
              'TestNodeChainCONNECTPhysicalReceiptOwnsExactUoTFinal/changed-receipt-config',
              'TestNodeChainCONNECTPhysicalReceiptOwnsExactUoTFinal/changed-receipt-final',
              'TestNodeChainCONNECTPhysicalReceiptOwnsExactUoTFinal/copied-receipt',
              'TestNodeChainCONNECTPhysicalReceiptOwnsExactUoTFinal/direct-http-udp',
              'TestNodeChainCONNECTPhysicalReceiptOwnsExactUoTFinal/exact-final',
              'TestNodeChainCONNECTPhysicalReceiptOwnsExactUoTFinal/foreign-final-owner',
              'TestNodeChainCONNECTPhysicalReceiptOwnsExactUoTFinal/foreign-scope',
              'TestNodeChainCONNECTPhysicalReceiptOwnsExactUoTFinal/inline-only',
              'TestNodeChainCONNECTPhysicalReceiptOwnsExactUoTFinal/missing-receipt',
              'TestNodeChainCONNECTPhysicalReceiptOwnsExactUoTFinal/unrelated-tag',
              'TestNodeChainCONNECTPhysicalReceiptOwnsExactUoTFinal/wrong-version',
              'TestNodeChainCONNECTSourceDoesNotBroadenGenericAuthority',
              'TestNodeChainCONNECTSourceKeepsOriginalGraph',
              'TestNodeChainCONNECTSourceKeepsOriginalGraph/awg2-fast/http-connect/2022-blake3-aes-128-gcm',
              'TestNodeChainCONNECTSourceKeepsOriginalGraph/awg2-fast/http-connect/2022-blake3-aes-256-gcm',
              'TestNodeChainCONNECTSourceKeepsOriginalGraph/awg2-fast/http-connect/2022-blake3-chacha20-poly1305',
              'TestNodeChainCONNECTSourceKeepsOriginalGraph/awg2-fast/https-connect/2022-blake3-aes-128-gcm',
              'TestNodeChainCONNECTSourceKeepsOriginalGraph/awg2-fast/https-connect/2022-blake3-aes-256-gcm',
              'TestNodeChainCONNECTSourceKeepsOriginalGraph/awg2-fast/https-connect/2022-blake3-chacha20-poly1305',
              'TestNodeChainCONNECTSourceKeepsOriginalGraph/awg2-strong/http-connect/2022-blake3-aes-128-gcm',
              'TestNodeChainCONNECTSourceKeepsOriginalGraph/awg2-strong/http-connect/2022-blake3-aes-256-gcm',
              'TestNodeChainCONNECTSourceKeepsOriginalGraph/awg2-strong/http-connect/2022-blake3-chacha20-poly1305',
              'TestNodeChainCONNECTSourceKeepsOriginalGraph/awg2-strong/https-connect/2022-blake3-aes-128-gcm',
              'TestNodeChainCONNECTSourceKeepsOriginalGraph/awg2-strong/https-connect/2022-blake3-aes-256-gcm',
              'TestNodeChainCONNECTSourceKeepsOriginalGraph/awg2-strong/https-connect/2022-blake3-chacha20-poly1305',
              'TestNodeChainCONNECTSourceKeepsOriginalGraph/wg/http-connect/2022-blake3-aes-128-gcm',
              'TestNodeChainCONNECTSourceKeepsOriginalGraph/wg/http-connect/2022-blake3-aes-256-gcm',
              'TestNodeChainCONNECTSourceKeepsOriginalGraph/wg/http-connect/2022-blake3-chacha20-poly1305',
              'TestNodeChainCONNECTSourceKeepsOriginalGraph/wg/https-connect/2022-blake3-aes-128-gcm',
              'TestNodeChainCONNECTSourceKeepsOriginalGraph/wg/https-connect/2022-blake3-aes-256-gcm',
              'TestNodeChainCONNECTSourceKeepsOriginalGraph/wg/https-connect/2022-blake3-chacha20-poly1305',
              'TestNodeChainCONNECTSourceRejectsWrongMemberOrPath',
              'TestNodeChainCONNECTSourceRejectsWrongMemberOrPath/auto',
              'TestNodeChainCONNECTSourceRejectsWrongMemberOrPath/changed-credential',
              'TestNodeChainCONNECTSourceRejectsWrongMemberOrPath/changed-server',
              'TestNodeChainCONNECTSourceRejectsWrongMemberOrPath/changed-tls',
              'TestNodeChainCONNECTSourceRejectsWrongMemberOrPath/duplicate-final',
              'TestNodeChainCONNECTSourceRejectsWrongMemberOrPath/extra-entry',
              'TestNodeChainCONNECTSourceRejectsWrongMemberOrPath/extra-execution',
              'TestNodeChainCONNECTSourceRejectsWrongMemberOrPath/extra-node',
              'TestNodeChainCONNECTSourceRejectsWrongMemberOrPath/foreign-middle-identity',
              'TestNodeChainCONNECTSourceRejectsWrongMemberOrPath/hostname',
              'TestNodeChainCONNECTSourceRejectsWrongMemberOrPath/injected-udp',
              'TestNodeChainCONNECTSourceRejectsWrongMemberOrPath/member-kind',
              'TestNodeChainCONNECTSourceRejectsWrongMemberOrPath/member-layer',
              'TestNodeChainCONNECTSourceRejectsWrongMemberOrPath/missing-first-identity',
              'TestNodeChainCONNECTSourceRejectsWrongMemberOrPath/missing-node',
              'TestNodeChainCONNECTSourceRejectsWrongMemberOrPath/paired-middle',
              'TestNodeChainCONNECTSourceRejectsWrongMemberOrPath/protocol-alias',
              'TestNodeChainCONNECTSourceRejectsWrongMemberOrPath/schema1',
              'TestNodeChainCONNECTSourceRejectsWrongMemberOrPath/schema2',
              'TestNodeChainCONNECTSourceRejectsWrongMemberOrPath/schema3',
              'TestNodeChainCONNECTSourceRejectsWrongMemberOrPath/server',
              'TestNodeChainCONNECTSourceRequiresOriginalPairedUoTAndDNS',
              'TestNodeChainCONNECTSourceRequiresOriginalPairedUoTAndDNS/dns-substitution',
              'TestNodeChainCONNECTSourceRequiresOriginalPairedUoTAndDNS/foreign-node',
              'TestNodeChainCONNECTSourceRequiresOriginalPairedUoTAndDNS/inline-uot',
              'TestNodeChainCONNECTSourceRequiresOriginalPairedUoTAndDNS/missing',
              'TestNodeChainCONNECTSourceRequiresOriginalPairedUoTAndDNS/stale-source',
              'TestNodeChainCONNECTSourceRequiresOriginalPairedUoTAndDNS/wrong-image',
              'TestNodeChainCONNECTSourceRequiresOriginalPairedUoTAndDNS/wrong-key',
              'TestNodeChainCONNECTSourceRequiresOriginalPairedUoTAndDNS/wrong-port',
              'TestNodeChainCONNECTSourceRequiresOriginalPairedUoTAndDNS/wrong-version',
              'TestNodeChainCONNECTSourceRetainsSupportedLayersAndOptionalAuthentication',
              'TestNodeChainCONNECTSourceRetainsSupportedLayersAndOptionalAuthentication/http-connect/aes',
              'TestNodeChainCONNECTSourceRetainsSupportedLayersAndOptionalAuthentication/http-connect/aes-xor',
              'TestNodeChainCONNECTSourceRetainsSupportedLayersAndOptionalAuthentication/http-connect/off',
              'TestNodeChainCONNECTSourceRetainsSupportedLayersAndOptionalAuthentication/https-connect/aes',
              'TestNodeChainCONNECTSourceRetainsSupportedLayersAndOptionalAuthentication/https-connect/aes-xor',
              'TestNodeChainCONNECTSourceRetainsSupportedLayersAndOptionalAuthentication/https-connect/off'],
 'roots': ['TestNodeChainCONNECTSourceKeepsOriginalGraph',
           'TestNodeChainCONNECTSourceRetainsSupportedLayersAndOptionalAuthentication',
           'TestNodeChainCONNECTSourceRejectsWrongMemberOrPath',
           'TestNodeChainCONNECTSourceRequiresOriginalPairedUoTAndDNS',
           'TestNodeChainCONNECTConstructionReceiptIsPrivateAndExact',
           'TestNodeChainCONNECTSourceDoesNotBroadenGenericAuthority',
           'TestNodeChainCONNECTPhysicalReceiptOwnsExactUoTFinal']}

def cases(suite=SUITE):
    if suite != SUITE:
        raise ValueError("Only the fixed CONNECT source suite is accepted")
    additional = [
        BASE.Case("ordered-connect-source", "^(" + "|".join(INVENTORY["roots"]) + ")$",
                  frozenset(INVENTORY["required"]), 120, 600),
        BASE.Case("original-connect-methods-uot-dns", INVENTORY["original"]["selector"],
                  frozenset(INVENTORY["original"]["required"]), 120, 600),
    ]
    for control in INVENTORY["controls"]:
        required = frozenset(control["failures"])
        witnesses = frozenset(name for name in required if "/" in name) or required
        additional.append(BASE.Case("connect-" + control["name"], control["selector"],
                          required, 120, 600, "connect-" + control["name"], control["witness"], witnesses))
    return (*ORIGINAL_CASES, *additional)

# One private module instance composes the existing executor, read-only source
# snapshot, Go commands, overlay checks and verdict parser. Original case
# objects, controls and deadlines remain intact.
BASE.SUITE = SUITE
BASE.cases = cases
BASE.SOURCE_PATHS = tuple(dict.fromkeys((*ORIGINAL_SOURCE_PATHS, *INVENTORY["files"])))
BASE.FORMAT_PATHS = tuple(dict.fromkeys((*ORIGINAL_FORMAT_PATHS, *INVENTORY["files"])))
BASE.CONTROL_MUTATIONS = {
    **ORIGINAL_MUTATIONS,
    **{"connect-" + c["name"]: (c["path"], c["before"], c["after"]) for c in INVENTORY["controls"]},
}

def validate(args):
    cases(args.suite)
    output = Path(args.output).resolve()
    manifest = output / "manifest.json"
    if manifest.exists() or manifest.is_symlink():
        raise ValueError("CONNECT validation requires a fresh original manifest")
    try:
        BASE.validate(args)
    finally:
        path = output / "manifest.json"
        if path.is_file() and not path.is_symlink():
            value = json.loads(path.read_bytes())
            if value.get("suite") != SUITE or value.get("actual_source_sha") != args.source_sha:
                raise ValueError("Original source manifest lost its fixed CONNECT purpose")
            value["composition"] = {
                "driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "original_driver_sha256": hashlib.sha256(BASE_PATH.read_bytes()).hexdigest(),
                "original_attempts": len(ORIGINAL_CASES),
                "new_source_records": len(INVENTORY["required"]),
                "original_connect_records": len(INVENTORY["original"]["required"]),
                "new_compiled_controls": len(INVENTORY["controls"]),
                "runtime_native_host_delivery": "unfinished",
            }
            path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", required=True, choices=(SUITE,))
    parser.add_argument("--source", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", required=True)
    validate(parser.parse_args())

if __name__ == "__main__":
    main()
