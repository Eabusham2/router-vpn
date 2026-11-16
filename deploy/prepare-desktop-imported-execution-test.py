#!/usr/bin/env python3
"""Project the original relay IPC/retirement owner into native test peers only.

The Darwin test launcher and HTTP administration fixture are separate seams.
Neither this projection nor those seams grant production server authority.
"""
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
TARGET = 'protocol/routervpnamnezia/routervpn_imported_execution_process_test.go'
SOURCES = ('cmd/router-agent/multihop_node_chain_process.go',
           'cmd/router-agent/multihop_tor_process.go', 'cmd/router-agent/relay_root.go',
           'cmd/router-agent/multihop_node_chain_lease.go')


def inputs():
    return [Path(__file__).resolve(), *(ROOT/name for name in SOURCES)]


def between(text, start, end):
    if text.count(start) != 1 or text.count(end) != 1:
        raise ValueError('Original relay process projection anchor changed')
    first, last = text.index(start), text.index(end)
    if last <= first:
        raise ValueError('Original relay process projection reversed')
    return text[first:last]


def copies():
    values=[]
    for path in inputs()[1:]:
        if path.is_symlink() or not path.is_file():
            raise ValueError('Original relay process source is missing or linked')
        values.append(path.read_text())
    process, tor, root, lease=values
    start='type relayNodeChainProcess struct {'
    if process.count(start)!=1:
        raise ValueError('Original ordered relay owner is ambiguous')
    body=between(process,'func captureRelayNodeChainImage(path string)', 'func (r *relayNodeChainExecRunner) source(')
    body+='\n'+process[process.index(start):]
    body+='\n'+between(tor,'func torIPCNonce() (string, error) {','func (p *relayTorProcess) lock(')
    body+='\n'+between(root,'func validRelayRootName(name string) bool {','func renameRelayRootFile(')
    start='func removeRelayRootContents(root *os.Root) error {'
    if root.count(start)!=1:
        raise ValueError('Original rooted cleanup is ambiguous')
    body+='\n'+root[root.index(start):]
    body+='\n'+lease[lease.index('func (s *server) multihopNodeChainLease('):].replace('(s *server)', '(s *importedExecutionAdmin)')
    for before,after in (('captureRelayNodeChainImage','captureImportedExecutionImage'),('newRelayNodeChainProcess','newImportedExecutionProcess'),
                         ('relayNodeChainProcess','importedExecutionProcess'),
                         ('torIPCNonce','importedExecutionNonce'),
                         ('validRelayRootName','importedExecutionRootName'),
                         ('removeRelayRootContents','importedExecutionRemoveRoot')):
        body=body.replace(before,after)
    head='''//go:build (linux && !android) || (darwin && routervpn_darwin_node_chain)

package routervpnamnezia

import (
 "bufio"
 "context"
 "crypto/rand"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "io"
 "os"
 "os/exec"
 "net/http"
 "net/netip"
 "strings"
 "sync"
 "sync/atomic"
 "time"
 "github.com/sagernet/sing-box/experimental/libbox/routervpn/multihoprelay"
)

// Exact shipping relay IPC, sequence, original-source and joined-retirement
// bodies, with test-package identifier renaming only. Direct Darwin test image
// launch and HTTP administration are deliberately outside this owner.
'''
    native_lease = lease.replace('package main', 'package routervpnamnezia', 1).replace('"router-vpn/internal/multihoprelay"', '"github.com/sagernet/sing-box/experimental/libbox/routervpn/multihoprelay"').replace('(s *server)', '(s *nativeImportedAdmin)').replace('multihopNodeChainLeasePath', 'nativeImportedLeasePath')
    return {TARGET:(head+body).encode(),
            'protocol/routervpnamnezia/routervpn_imported_execution_native_lease_linux_test.go':
            ('//go:build linux && !android\n\n// Exact shipping lease handler; distinct fixture authentication receiver.\n'+native_lease).encode()}
