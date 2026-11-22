#!/usr/bin/env python3
"""Project original HTTP/runtime fixtures under an explicit component-test tag.

No production capture, receipt or runtime body is replaced. The copied native
transport/worker fixtures remain doubles; the real shared runtime and HTTP50
facade are the subject of the separate desktop mailbox component gate.
"""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
TAG = 'routervpn_execution_latency_component'
TARGET = 'experimental/libbox/routervpn/mobilemultihop/routervpn_desktop_latency_fixture.go'
RUNTIME = 'internal/mobilemultihop/node_chain_execution_runtime_test.go'
IMPORTED_RUNTIME = 'internal/mobilemultihop/node_chain_multiple_imported_execution_runtime_test.go'
SOCKS_RUNTIME = 'internal/mobilemultihop/node_chain_socks_execution_runtime_test.go'
LATENCY = 'internal/mobilemultihop/node_chain_execution_latency_test.go'
THROUGHPUT = 'internal/mobilemultihop/node_chain_execution_measurement_test.go'
TEMPLATE = 'mobile/desktop_test/selected_latency_fixture.go.tmpl'
NAMES = ('nodeChainExecutionRuntimeWorker', 'nodeChainExecutionRuntimeRunner',
         'nodeChainExecutionRuntimeEngine', 'nodeChainExecutionRuntimeFixture',
         'nodeChainExecutionRuntimeTLS')


def inputs():
    return [Path(__file__).resolve(), *(ROOT / name for name in (RUNTIME, IMPORTED_RUNTIME, SOCKS_RUNTIME, LATENCY, THROUGHPUT, TEMPLATE))]


def declarations(text):
    starts = list(re.finditer(r'^(?:func|type|var|const) ', text, re.M))
    return [text[m.start():starts[i + 1].start() if i + 1 < len(starts) else len(text)].rstrip()
            for i, m in enumerate(starts)]


def one(decls, prefix):
    values = [v for v in decls if v.startswith(prefix)]
    if len(values) != 1:
        raise ValueError('original selected-latency fixture anchor changed: ' + prefix)
    return values[0]


def copies():
    for path in inputs():
        if path.is_symlink() or not path.is_file():
            raise ValueError('selected-latency original fixture missing or linked')
    runtime = declarations((ROOT / RUNTIME).read_text())
    latency = declarations((ROOT / LATENCY).read_text())
    selected = []
    for value in runtime:
        signature = value.split('\n', 1)[0]
        if signature.startswith('func Test'):
            continue
        if any(signature.startswith('type ' + name + ' ') or
               signature.startswith('func ' + name + '(') or
               re.match(r'func \(\w+ \*' + name + r'\) ', signature)
               for name in NAMES):
            selected.append(value)
    if len(selected) != 23:
        raise ValueError('original selected-latency fixture declaration inventory changed: ' + str(len(selected)))
    wrapper_constructor = one(runtime, 'func newNodeChainExecutionRuntimeFixtureFromPreparation(')
    delegation = '\treturn newNodeChainExecutionRuntimeFixtureFromPreparationTTL(t, source, prep, 15)'
    if wrapper_constructor.count(delegation) != 1:
        raise ValueError('original runtime fixture default lifetime delegation changed')
    constructor = one(runtime, 'func newNodeChainExecutionRuntimeFixtureFromPreparationTTL(')
    lifetime = 'TTLSeconds: ttlSeconds'
    if constructor.count(lifetime) != 1:
        raise ValueError('original runtime fixture manager lifetime changed')

    anchor = '\te := &nodeChainExecutionRuntimeEngine{'
    if constructor.count(anchor) != 1:
        raise ValueError('original runtime fixture construction changed')
    # An existing physical desktop projection is the original authority. Reuse
    # the original HTTP/Manager/worker construction body after source binding,
    # avoiding reconstruction as a plain preparation that would lose its TUN.
    constructor = '''func desktopLatencyNewFixture(t *testing.T, projection *NodeChainExecutionProjection, ttlSeconds int) *nodeChainExecutionRuntimeFixture {
 t.Helper()
 policy, source := projection.policy, projection.policy.source
 var err error
''' + constructor[constructor.index(anchor):]
    selected.append(constructor)
    socks = declarations((ROOT / SOCKS_RUNTIME).read_text())
    selected.append(one(socks, 'func (e *nodeChainExecutionRuntimeEngine) ObserveSOCKSExecutionContext('))
    imported = declarations((ROOT / IMPORTED_RUNTIME).read_text())
    for prefix in ('func (e *nodeChainExecutionRuntimeEngine) ObserveMultipleImportedExecutionContext(',
                   'func (e *nodeChainExecutionRuntimeEngine) MultipleImportedExecutionRetiredContext(',
                   'func multipleImportedExecutionPublicFixtures('):
        selected.append(one(imported, prefix))
    # Use the peer already captured by the caller's actual paired source.
    before = 'peer := netip.MustParseAddr("10.80.0.2")'
    body = '\n\n'.join(selected)
    if body.count(before) != 1:
        raise ValueError('original runtime fixture peer changed')
    body = body.replace(before, 'peer := netip.MustParseAddr(f.engine.projection.policy.source.Request.Peer)', 1)
    body += '\n\n' + one(latency, 'func executionFiftyHTTP(')
    throughput = declarations((ROOT / THROUGHPUT).read_text())
    for prefix in ('type nodeChainThroughputBytes ', 'func nodeChainExecutionMeasurementHTTP('):
        body += '\n\n' + one(throughput, prefix)
    for name in (*NAMES, 'executionFiftyHTTP', 'multipleImportedExecutionPublicFixtures'):
        body = re.sub(r'\b' + name + r'\b', 'desktopLatencyOriginal' + name[0].upper() + name[1:], body)
    head = '''//go:build routervpn_execution_latency_component

package mobilemultihop

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/tls"
 "crypto/x509"
 "encoding/json"
 "errors"
 "io"
 "math/big"
 "net"
 "net/http"
 "net/http/httptest"
 "net/netip"
 "strings"
 "strconv"
 "sync"
 "sync/atomic"
 "testing"
 "time"
 "github.com/sagernet/sing-box/experimental/libbox/routervpn/multihoprelay"
)

// TEST ONLY: original HTTP/Manager/runtime fixture bodies. Native transport,
// remote worker completion and TUN readback are explicit component doubles.
'''
    wrapper = (ROOT / TEMPLATE).read_text()
    marker = '// BEGIN EXPORTED COMPONENT FIXTURE\n'
    if wrapper.count(marker) != 1:
        raise ValueError('selected-latency component wrapper boundary changed')
    return {TARGET: (head + body + '\n\n' + wrapper.split(marker, 1)[1]).encode()}
