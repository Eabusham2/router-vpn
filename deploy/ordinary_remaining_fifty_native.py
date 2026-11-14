#!/usr/bin/env python3
"""Append actual ordinary HY2-final/imported-SS fifty proofs to the original60."""
import hashlib
import json

ROOT = 'TestRouterNodeChainRemainingEncryptedOrderedFifty'
CASES = (
    ('ss-middle', 'wg', 3, 0, '2022-blake3-aes-128-gcm'),
    ('ss-middle', 'wg', 3, 1, '2022-blake3-aes-128-gcm'),
    ('ss-middle', 'wg', 3, 2, '2022-blake3-aes-128-gcm'),
    ('ss-middle', 'awg2-fast', 3, 1, '2022-blake3-aes-256-gcm'),
    ('ss-middle', 'awg2-strong', 3, 1, '2022-blake3-chacha20-poly1305'),
    ('hysteria2-final', 'wg', 2, 1, ''),
    ('hysteria2-final', 'awg2-fast', 3, 2, ''),
    ('hysteria2-final', 'awg2-strong', 8, 7, ''),
)
PROJECTIONS = (
    ('latency_remaining_native_test.go.tmpl', 'experimental/libbox/routervpn_node_chain_latency_remaining_native_test.go'),
    ('box.go.tmpl', 'routervpn_node_chain.go'),
)
PEER_PROJECTION = ('node_chain_fifty_remaining_peer_test.go.tmpl',
                   'protocol/routervpnamnezia/routervpn_desktop_node_chain_fifty_remaining_peer_test.go')
CONTROL = dict(name='ordinary-remaining-fifty-old-adapter', path='routervpn_node_chain.go',
    before='func (e *RouterVPNNodeChainEngine) Dial(ctx context.Context, tag, address string) (net.Conn, error) {\n',
    after='func (e *RouterVPNNodeChainEngine) Dial(ctx context.Context, tag, address string) (net.Conn, error) {\n\treturn e.observation.Dial(ctx, tag, address) // causal restore of the original literal-only adapter\n',
    witness='remaining actual public fifty refused: native dial=ordered chain proofs require their literal destination')

def name(case):
    if case not in CASES:
        raise ValueError('Uncaptured remaining ordinary graph/mode/cipher/position')
    graph, mode, count, position, method = case
    return 'ordinary-remaining-fifty-%s-%s-%d-%d-%s' % (graph, mode, count, position, method or 'native')

def witness(case):
    name(case)
    return 'ORDINARY_REMAINING_FIFTY graph=%s mode=%s count=%d position=%d method=%s samples=50' % case

def environment(env, case, peer):
    name(case)
    graph, mode, count, position, method = case
    return dict(env, ROUTERVPN_ORDINARY_FIFTY_PEER=str(peer), ROUTERVPN_ORDINARY_FIFTY_GRAPH=graph,
        ROUTERVPN_ORDINARY_FIFTY_MODE=mode, ROUTERVPN_ORDINARY_FIFTY_COUNT=str(count),
        ROUTERVPN_ORDINARY_FIFTY_POSITION=str(position), ROUTERVPN_ORDINARY_FIFTY_METHOD=method,
        GODEBUG='x509usefallbackroots=1')

def events(base, raw, status, case, control=None):
    name(case)
    if control is None:
        rows = [json.loads(line) for line in raw.splitlines()]
        outputs = [row.get('Output', '').strip() for row in rows
                   if row.get('Test') == ROOT and 'ORDINARY_REMAINING_FIFTY ' in row.get('Output', '')]
        if len(outputs) != 1 or outputs[0].split('ORDINARY_REMAINING_FIFTY ', 1)[1] != witness(case).split('ORDINARY_REMAINING_FIFTY ', 1)[1]:
            raise ValueError('Original remaining graph/cipher/position/fifty witness changed')
    return base.require_events(raw, status, base.LIBBOX, (ROOT,), dict(control, cases=(ROOT,)) if control else None)

def checked_projection(source, mobile, owner, table, peer_table):
    for template, relative in PROJECTIONS:
        a, b = source/'mobile/chain'/template, mobile/relative
        if table.get(template) != relative or a.is_symlink() or b.is_symlink() or a.read_bytes() != b.read_bytes():
            raise ValueError('Original remaining native projection changed: '+template)
    template, relative = PEER_PROJECTION
    a, b = source/'mobile/desktop'/template, owner/relative
    if peer_table.get(template) != relative or a.is_symlink() or b.is_symlink() or a.read_bytes() != b.read_bytes():
        raise ValueError('Original remaining encrypted peer projection changed')

def validate_compiled(base, run, compiler, mobile, peer, client, work, flags, env):
    identities = (base.COMMON.image_identity(peer), base.COMMON.image_identity(client))
    def unchanged():
        if identities != (base.COMMON.image_identity(peer), base.COMMON.image_identity(client)):
            raise ValueError('Original remaining compiled images changed')
    records = []
    unchanged()
    for case in CASES:
        status, raw = run(name(case), [compiler, 'tool', 'test2json', '-t', '-p', base.LIBBOX, client,
            '-test.run=^'+ROOT+'$', '-test.count=1', '-test.timeout=180s', '-test.v'], mobile, 190,
            environment(env, case, peer))
        records.append(dict(graph=case[0], mode=case[1], count=case[2], position=case[3], method=case[4],
                            **events(base, raw, status, case)))
        unchanged()
    original = mobile/CONTROL['path']
    changed = base.mutate(CONTROL, original.read_text())
    replacement, overlay = work/(CONTROL['name']+'.go'), work/(CONTROL['name']+'.json')
    replacement.write_text(changed)
    overlay.write_text(json.dumps({'Replace': {str(original): str(replacement)}}))
    status, raw = run(CONTROL['name'], [compiler, 'test', *flags, '-json', '-overlay='+str(overlay),
        '-run=^'+ROOT+'$', '-count=1', '-timeout=180s', './experimental/libbox'], mobile, 600,
        environment(env, CASES[1], peer))
    control = dict(name=CONTROL['name'], original_sha256=hashlib.sha256(original.read_bytes()).hexdigest(),
        mutation_sha256=hashlib.sha256(changed.encode()).hexdigest(), **events(base, raw, status, CASES[1], CONTROL))
    unchanged()
    return dict(ordinary_remaining_fifty_records=records, ordinary_remaining_fifty_control=control,
        ordinary_remaining_fifty_native_borrow_accepted=True,
        ordinary_remaining_fifty_scope='actual WG/AWG with HY2-final at counts2/3/8 and imported SS2022-middle across three ciphers, including all WG3 positions; no physical OS/device or shipping-host acceptance')
