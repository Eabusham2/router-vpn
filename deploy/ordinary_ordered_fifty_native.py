#!/usr/bin/env python3
"""Add ordinary captured 2–8-node evidence after the unchanged typed CONNECT gate."""
import hashlib
import json

ROOT = 'TestRouterNodeChainOrdinaryEncryptedOrderedFifty'
# Separate processes keep the original per-request and peer bounds. The 8-node
# interior case proves an actual cumulative prefix, not merely count labels.
CASES = (('wg', 2, 1), ('wg', 8, 3), ('awg2-fast', 2, 0), ('awg2-strong', 8, 7)) + tuple(('wg', 8, p) for p in range(8) if p != 3)
PROJECTIONS = (
 ('latency.go.tmpl', 'experimental/libbox/routervpn_node_chain_latency.go'),
 ('latency_test.go.tmpl', 'experimental/libbox/routervpn_node_chain_latency_test.go'),
 ('latency_native_test.go.tmpl', 'experimental/libbox/routervpn_node_chain_latency_native_test.go'),
)
CONTROLS = (
 dict(name='ordinary-fifty-original-service', path=PROJECTIONS[0][1],
      before='service == nil || service != measurement.service', after='service == nil', witness='foreign ordinary owner admitted'),
 dict(name='ordinary-fifty-original-plan', path=PROJECTIONS[0][1],
      before='m == nil || m.self != m || m.chain == nil', after='m == nil || m.chain == nil', witness='foreign ordinary owner admitted'),
 dict(name='ordinary-fifty-original-server', path=PROJECTIONS[0][1],
      before='instance == nil || m.server != server || m.healthyContext(ctx) != nil', after='instance == nil || m.healthyContext(ctx) != nil', witness='foreign ordinary owner admitted',
      additional=(("m.instance != instance || m.server != server || m.measurement.Load() != service", "m.instance != instance || m.measurement.Load() != service"),)),
 dict(name='ordinary-fifty-original-saved', path='experimental/libbox/routervpn_ordered_latency.go',
      before='return m.service.SavedJSON(nodeID)', after='return "" // causal missing original saved identity', witness='ordinary native saved identity changed'),
 dict(name='ordinary-fifty-borrowed-close', path='experimental/libbox/routervpn/hopmeasure/ordered_latency.go',
      before='\to.closed = true\n\top := o.operation', after='\ts.closed = true // causal retirement of original borrowed service\n\to.closed = true\n\top := o.operation', witness='ordinary Retest lost original borrowed service'),
)

def name(case):
    if case not in CASES:
        raise ValueError('Uncaptured ordinary fifty case')
    return 'ordinary-fifty-%s-%d-%d' % case

def witness(case):
    return 'ORDINARY_FIFTY_NODE mode=%s count=%d position=%d samples=50' % case

def events(base, raw, status, case, control=None):
    name(case)
    if control is None:
        rows = [json.loads(line) for line in raw.splitlines()]
        observed = [row.get('Output', '').strip() for row in rows
                    if row.get('Test') == ROOT and 'ORDINARY_FIFTY_NODE ' in row.get('Output', '')]
        # Go test prepends the source filename/line to a t.Log witness.
        if len(observed) != 1 or observed[0].split('ORDINARY_FIFTY_NODE ', 1)[1] != witness(case).split('ORDINARY_FIFTY_NODE ', 1)[1]:
            raise ValueError('Original ordinary count/position/fifty witness changed')
    selected = dict(control, cases=(ROOT,)) if control else None
    return base.require_events(raw, status, base.LIBBOX, (ROOT,), selected)

def mutation(base, control, text):
    text = base.mutate(control, text)
    for before, after in control.get('additional', ()):
        text = base.mutate(dict(name=control['name'], before=before, after=after), text)
    return text

def checked_projection(source, mobile, owner, table, peer_table):
    for template, relative in PROJECTIONS:
        a, b = source/'mobile/chain'/template, mobile/relative
        if table.get(template) != relative or a.is_symlink() or b.is_symlink() or a.read_bytes() != b.read_bytes():
            raise ValueError('Original ordinary latency projection changed: '+template)
    template = 'node_chain_fifty_peer_test.go.tmpl'
    relative = 'protocol/routervpnamnezia/routervpn_desktop_node_chain_fifty_peer_test.go'
    a, b = source/'mobile/desktop'/template, owner/relative
    if peer_table.get(template) != relative or a.is_symlink() or b.is_symlink() or a.read_bytes() != b.read_bytes():
        raise ValueError('Original ordinary encrypted peer projection changed')

def validate_compiled(base, run, compiler, mobile, peer, client, work, flags, env):
    identities = (base.COMMON.image_identity(peer), base.COMMON.image_identity(client))
    def unchanged():
        if identities != (base.COMMON.image_identity(peer), base.COMMON.image_identity(client)):
            raise ValueError('Original ordinary compiled images changed')
    def environment(case):
        mode, count, position = case
        return dict(env, ROUTERVPN_ORDINARY_FIFTY_PEER=str(peer), ROUTERVPN_ORDINARY_FIFTY_MODE=mode,
                    ROUTERVPN_ORDINARY_FIFTY_COUNT=str(count), ROUTERVPN_ORDINARY_FIFTY_POSITION=str(position),
                    GODEBUG='x509usefallbackroots=1')
    records, controls = [], []
    unchanged()
    for case in CASES:
        status, raw = run(name(case), [compiler, 'tool', 'test2json', '-t', '-p', base.LIBBOX, client,
            '-test.run=^'+ROOT+'$', '-test.count=1', '-test.timeout=180s', '-test.v'], mobile, 190, environment(case))
        records.append(dict(mode=case[0], count=case[1], position=case[2], **events(base, raw, status, case)))
        unchanged()
    for control in CONTROLS:
        original = mobile/control['path']
        changed = mutation(base, control, original.read_text())
        replacement, overlay = work/(control['name']+'.go'), work/(control['name']+'.json')
        replacement.write_text(changed)
        overlay.write_text(json.dumps({'Replace': {str(original): str(replacement)}}))
        status, raw = run(control['name'], [compiler, 'test', *flags, '-json', '-overlay='+str(overlay),
            '-run=^'+ROOT+'$', '-count=1', '-timeout=180s', './experimental/libbox'], mobile, 600, environment(CASES[0]))
        controls.append(dict(name=control['name'], original_sha256=hashlib.sha256(original.read_bytes()).hexdigest(),
            mutation_sha256=hashlib.sha256(changed.encode()).hexdigest(), **events(base, raw, status, CASES[0], control)))
        unchanged()
    return dict(ordinary_ordered_fifty_records=records, ordinary_ordered_fifty_controls=controls,
        ordinary_ordered_fifty_native_borrow_accepted=True,
        ordinary_ordered_fifty_scope='captured WG/AWG prefixes with SS2022 final, counts2/8 and every WG8 position; no HY2/imported-middle or physical-device acceptance')
