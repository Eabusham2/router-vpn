#!/usr/bin/env python3
"""Exercise complete MAX with actual scoped Windows WFP and the real Rust ABI.

The retained separate peer executes the original MAX reference graph. Client
permits and socket ownership use the actual shipping Windows factories; TUN is
an explicit harmless boundary. Normal execution uses unchanged shipping
admission and a separately compiled exact-four-family closed control.
--prospective retains the closed-source prerequisite before public activation.
"""
from pathlib import Path
from contextlib import contextmanager
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'deploy' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MAX = load('windows_complete_max_graph', 'test_desktop_node_max.py')
WPQ = load('windows_complete_max_native', 'test_windows_node_pq.py')
NODE, REFERENCE, WFP = MAX.NODE, MAX.REFERENCE, WPQ.WFP
PREDICATE = WPQ.PREDICATE
PEER = 'protocol/routervpnpq/node_max_peer_windows_test.go'
PEER_TEMPLATE = 'mobile/desktop/node_max_peer_windows_test.go.tmpl'
PREFIX = WPQ.PREFIX
UDP_CONTROL = ROOT / 'deploy' / 'fixtures' / 'windows-max-control'
UDP_OBSERVATION = 'TestWindowsMAXUDPObservation'
UDP_CASES = ('drop', 'denied', 'delivered', 'delivered-without-echo', 'deadline-error',
             'reset-error', 'short', 'write-error', 'late-receipt', 'positive-error',
             'foreign-local', 'foreign-remote', 'cancelled')
TAGS = REFERENCE.TAGS + ',routervpn_windows_node_composition'
MODES = tuple(mode for modes in MAX.FAMILIES.values() for mode in modes)
LAYERS = MAX.LAYERS
CLOSED = 'TestRouterVPNDesktopNodeWindowsMAXCapabilityClosed'
OPEN = 'TestRouterVPNDesktopNodeWindowsMAXCapabilityOpen'
MARKERS = 'TestRouterVPNDesktopNodeWindowsMAXMarkers'
MARKER_CASES = ('bounded-input', 'unarmed-and-wrong-owner', 'encrypted-fragments', 'exact-armed-stream', 'marker-and-authentication', 'packet-authentication', 'reference-failure-channel', 'retained-reference-readback', 'key-epoch-barrier', 'retained-middle-idle')
STARTUP_RECORDS = MAX.STARTUP_RECORDS
PORT_PAIR, PORT_PAIR_CASES = MAX.PORT_PAIR, MAX.PORT_PAIR_CASES
EXECUTION_SUITES = ('quic', 'tls', 'succession', 'ownership-controls-1', 'ownership-controls-2')
SUCCESSION = 'TestRouterVPNDesktopNodeWindowsMAXSuccession'
FOREIGN = 'TestRouterVPNDesktopNodeWindowsMAXForeignPredecessor'
PROSPECTIVE_BEFORE = '\tswitch mode {\n'
PROSPECTIVE_AFTER = PROSPECTIVE_BEFORE + '\tcase "max-quic-wg", "max-quic-awg", "max-tls-wg", "max-tls-awg":\n\t\treturn true\n'
JOIN_FAILURES = (*MAX.JOIN_FAILURES, *WPQ.CLEANUP_DIAGNOSTICS, 'captured Node Box did not join',
    'actual Windows PQ owner did not join', 'owned MAX reference did not join',
    'MAX reference ignored its owned input EOF', 'MAX reference retained its unjoined process',
    'MAX failed credential startup did not join', 'MAX cancelled native credential trial did not join',
    'exact PQ test-owned deny did not retire', 'rejected MAX successor did not join')


def checked_sources(source):
    source, records = MAX.checked_sources(Path(source))
    actual, native = WPQ.checked_sources(source)
    if source != actual:
        raise ValueError('MAX and native WFP changed the captured core identity')
    for name, digest in native.items():
        if name in records and records[name] != digest:
            raise ValueError('MAX and Windows PQ disagree on an owned source record')
        records[name] = digest
    path = ROOT / PEER_TEMPLATE
    if NODE.PREP.PEER_TEMPLATES.get(path.name) != PEER or path.is_symlink() or not path.read_bytes().startswith(PREFIX):
        raise ValueError('Complete MAX WFP lost its exact native/CGO/test-only mapping')
    # Key generation executes this exact private-root helper before exposing
    # any KEM material. Bind it and its executable acceptance/preparation
    # tests to the native evidence, not only the Python invocation wrapper.
    for relative in (PEER_TEMPLATE, 'deploy/test_windows_node_max.py', 'deploy/test_windows_node_max_runner.py',
                     'deploy/fixtures/windows-max-control/udp_observation.go',
                     'deploy/fixtures/windows-max-control/udp_observation_test.go',
                     'client/Protect-RouterVPN-Windows-PrivateRoot.ps1', 'client/test-windows-private-acl.ps1',
                     'deploy/build_pq_reference_fixture.py', 'deploy/test_pq_reference_preparation.py',
                     'deploy/windows_build_owner.py', 'deploy/test_windows_build_owner.py'):
        records['windows-max/' + relative] = MAX.regular_digest(ROOT / relative)
    return source, records


class MAXCommandOwner:
    """Retain each exact command tree until its native job has fully joined."""
    def __init__(self):
        self.retired = True

    def run(self, command, *, cwd, env, timeout):
        if not self.retired:
            raise RuntimeError('Windows MAX cannot replace an unjoined native command')
        arguments = [str(value) for value in command]
        self.retired = False
        try:
            result = REFERENCE.BUILD.BUILD_OWNER.run(arguments, cwd=cwd, env=env, timeout=timeout)
        except subprocess.CalledProcessError as error:
            if error.cmd != arguments:
                raise
            # This exception is emitted only after the original job and
            # bootstrap joined. Preserve its nonzero status for causal verdicts.
            self.retired = True
            return error.returncode, (error.stdout + error.stderr).decode('utf-8', errors='replace')
        except subprocess.TimeoutExpired as error:
            # A timeout from the bootstrap's own join has different argv and
            # must retain every source/key/image workspace, even after exit.
            if error.cmd == arguments:
                self.retired = True
            raise
        if result.args != arguments:
            raise RuntimeError('Windows MAX native completion changed its original command')
        self.retired = True
        return result.returncode, (result.stdout + result.stderr).decode('utf-8', errors='replace')

    @contextmanager
    def preparation(self):
        if not self.retired:
            raise RuntimeError('Windows MAX cannot prepare over an unjoined command')
        # Existing preparation helpers own their native commands separately.
        # Keep their exact exception/status/deadline semantics, but do not let an
        # unknown join failure authorize deletion of this enclosing source tree.
        self.retired = False
        yield
        self.retired = True

    @contextmanager
    def workspace(self, prefix):
        directory = Path(tempfile.mkdtemp(prefix=prefix))
        original = directory.lstat()
        try:
            yield directory
        finally:
            # A failed native join is not authority to delete files that an
            # original descendant may still use. No automatic finalizer retries.
            if self.retired:
                prepare_workspace_retirement(directory, original)
                shutil.rmtree(directory)


def prepare_workspace_retirement(directory, original):
    """Normalize owned read-only files before the single destructive cleanup.

    Git marks its Windows pack/index files read-only. Unlike TemporaryDirectory,
    plain rmtree does not clear that attribute. This runs only after the original
    command tree joined; it neither retries unlink nor tolerates a sharing error.
    Refuse replacements and reparse paths before changing any file attribute.
    """
    def current(path, captured):
        actual = path.lstat()
        if not os.path.samestat(actual, captured):
            raise RuntimeError('Windows MAX workspace entry was replaced before retirement')
        if stat.S_ISLNK(actual.st_mode) or getattr(actual, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise RuntimeError('Windows MAX workspace retirement refuses reparse paths')
        if not (stat.S_ISREG(actual.st_mode) or stat.S_ISDIR(actual.st_mode)):
            raise RuntimeError('Windows MAX workspace retirement refuses special files')
        return actual

    entries = []
    def capture(path, captured):
        actual = current(path, captured)
        entries.append((path, actual))
        if stat.S_ISDIR(actual.st_mode):
            with os.scandir(path) as children:
                for child in children:
                    # Windows DirEntry.stat caches enumeration data with zero
                    # inode/device/link fields. Capture the real no-follow
                    # identity, exactly as the later replacement checks do.
                    child_path = Path(child.path)
                    capture(child_path, child_path.lstat())
            current(path, actual)
        elif getattr(actual, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_READONLY and actual.st_nlink != 1:
            raise RuntimeError('Windows MAX read-only workspace file has a foreign hard link')

    capture(directory, original)
    captured_paths = dict(entries)
    def current_path(path):
        parent = directory
        actual = current(parent, original)
        for name in path.relative_to(directory).parts:
            parent = parent / name
            actual = current(parent, captured_paths[parent])
        return actual

    for path, captured in entries:
        actual = current_path(path)
        if stat.S_ISREG(actual.st_mode) and getattr(actual, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_READONLY:
            # Windows chmod only changes READONLY. Preserve all other mode bits,
            # and leave directories and already writable files unchanged.
            path.chmod(actual.st_mode | stat.S_IWRITE)
            current_path(path)
    for path, _ in entries:
        current_path(path)


def observation_contract(compiler, source, captured, race, files, parent, cases):
    """Compile cold tooling separately from the original 30-second verdict."""
    records = {Path(path): MAX.regular_digest(Path(path)) for path in files}
    workspace = Path(tempfile.mkdtemp(prefix='routervpn-windows-max-observation-'))
    binary = workspace / 'observation.test.exe'
    retired = True

    def owned(command, timeout):
        nonlocal retired
        retired = False
        try:
            result = REFERENCE.BUILD.BUILD_OWNER.run(command, cwd=source, env=captured, timeout=timeout)
        except Exception as error:
            arguments = [str(value) for value in command]
            if isinstance(error, (subprocess.CalledProcessError, subprocess.TimeoutExpired)) and error.cmd == arguments:
                # Only original-command outcomes imply the retained Job and
                # bootstrap joined. A timeout joining the bootstrap itself
                # has different argv and cannot release this workspace.
                retired = True
                raise
            # A cleanup exception must not hide the initial deadline failure.
            # Keep its unproved workspace; no PID lookup grants its removal.
            seen, previous, expired = set(), error, None
            while previous is not None and id(previous) not in seen:
                seen.add(id(previous))
                if isinstance(previous, subprocess.TimeoutExpired):
                    expired = previous
                previous = previous.__cause__ or previous.__context__
            if expired is not None and expired is not error:
                # communicate reports the retained bootstrap argv until its
                # cleanup succeeds. Preserve that first real timeout too.
                raise ExceptionGroup('Windows MAX observation timeout with unproved owned cleanup',
                                     [expired, error]) from None
            raise
        retired = True
        return result

    try:
        # The same bounded cold compilation used for native helper fixtures;
        # no compile/link work consumes the real test's execution deadline.
        owned([compiler, 'test', '-c', '-mod=readonly', *race, '-o', binary, *files], 180)
        if {path: MAX.regular_digest(path) for path in records} != records:
            raise ValueError('Windows MAX observation sources changed during compilation')
        digest = MAX.regular_digest(binary)
        result = owned([binary, '-test.run=^' + parent + '$', '-test.count=1',
                        '-test.timeout=30s', '-test.v'], 45)
        output = (result.stdout + result.stderr).decode('utf-8', errors='replace')
        print(output, end='' if output.endswith('\n') else '\n', flush=True)
        MAX.required_output(result.returncode, output, parent, cases)
        if MAX.regular_digest(binary) != digest or {path: MAX.regular_digest(path) for path in records} != records:
            raise ValueError('Windows MAX observation changed its exact executable or source during execution')
    finally:
        if retired:
            shutil.rmtree(workspace)


def prospective_predicate(raw):
    if ('func DesktopNodePhysicalGraphSupported(mode, startLayer string) bool {' not in raw or
            any('"' + mode + '"' in raw for mode in MODES)):
        raise ValueError('Prospective complete MAX lost its exact closed four-family source')
    return WFP.BOOT.IDENTITY.replace_once(raw, PROSPECTIVE_BEFORE, PROSPECTIVE_AFTER)


def closed_predicate(raw):
    return WPQ.closed_admission(raw, MODES)


def native_parent(parent):
    before = 'TestRouterVPNDesktopNodeCompleteMAX'
    if not parent.startswith(before):
        raise ValueError('MAX native control has an unrelated graph parent')
    return 'TestRouterVPNDesktopNodeWindowsMAX' + parent[len(before):]


def ordinary_witness(protocol):
    return 'MAX native ordinary ' + protocol + ' socket denied by captured WFP'


INVALID_ORDINARY = 'MAX native ordinary control invalid'


def handshake_witness(protocol):
    return 'MAX native captured ' + protocol + ' handshake rejected before ready'


# Only deliberate socket-bypass compilations receive this observer. It never
# creates a socket grant or returns a different dial/I/O result. TCP requires
# native WSAEACCES. UDP may instead prove non-delivery of a fresh nonce through
# this same connection, using its independently owned peer. Both require fresh
# identical BFE/isolated-owner readbacks; a bare timeout is never evidence.
ORDINARY_OBSERVER = r'''//go:build windows && routervpn_windows_node_composition

package mobiletor

import (
    "context"
    "errors"
    "net"
    "net/netip"
    "sync"
    "sync/atomic"
    "syscall"
    "time"
)

// Bounded diagnostics are not rejection evidence. The exact native denial or
// independent UDP delivery observation must also retain its native policy.
var desktopMAXControlDiagnosticCount atomic.Uint32
var desktopMAXControlInvalidSeen atomic.Bool
var desktopMAXControlUDP struct {
    sync.Mutex
    observe func(context.Context, net.Conn, netip.AddrPort) error
}

func DesktopWindowsMAXControlSetUDPObserver(observe func(context.Context, net.Conn, netip.AddrPort) error) error {
    desktopMAXControlUDP.Lock()
    defer desktopMAXControlUDP.Unlock()
    if observe == nil || desktopMAXControlUDP.observe != nil {
        return errors.New("MAX ordinary UDP observer cannot replace its captured reference")
    }
    desktopMAXControlUDP.observe = observe
    return nil
}

func desktopMAXControlInvalid(stage string, err error) {
    // An earlier valid witness cannot conceal a later leak or failed readback.
    if !desktopMAXControlInvalidSeen.Swap(true) {
        println("MAX native ordinary control invalid", stage)
    }
    desktopMAXControlDiagnostic(stage, "udp", err)
}

func desktopMAXControlObserveUDP(ctx context.Context, connection net.Conn, before DesktopWindowsNodeCompositionReadback, remote netip.AddrPort) {
    desktopMAXControlUDP.Lock()
    defer desktopMAXControlUDP.Unlock()
    if desktopMAXControlUDP.observe == nil {
        desktopMAXControlInvalid("missing-independent-reference", nil)
        return
    }
    if err := desktopMAXControlUDP.observe(ctx, connection, remote); err != nil {
        desktopMAXControlInvalid("independent-delivery-proof-failed", err)
        return
    }
    after, current := desktopMAXControlSnapshot(ctx, "udp", remote)
    if !current || before.Target != after.Target || before.Capture != after.Capture || before.Owner != after.Owner {
        desktopMAXControlInvalid("delivery-readback-rejected", nil)
        return
    }
    println("MAX native ordinary udp socket denied by captured WFP")
}

func desktopMAXControlDiagnostic(stage, network string, err error, fields ...int) {
    if desktopMAXControlDiagnosticCount.Add(1) > 16 {
        return
    }
    var errno syscall.Errno
    _ = errors.As(err, &errno)
    var timeout net.Error
    timedOut := errors.As(err, &timeout) && timeout.Timeout()
    println("MAX native ordinary control stage", stage, "network", network,
        "error", err != nil, "errno", uint64(errno), "timeout", timedOut)
    for index, value := range fields {
        println("MAX native ordinary control field", stage, index, value)
    }
}

func desktopMAXControlSnapshot(ctx context.Context, network string, remote netip.AddrPort) (DesktopWindowsNodeCompositionReadback, bool) {
    if ctx == nil || ctx.Err() != nil || network != "tcp" && network != "udp" || !remote.IsValid() || remote.Port() == 0 {
        desktopMAXControlDiagnostic("captured-input-rejected", network, nil)
        return DesktopWindowsNodeCompositionReadback{}, false
    }
    proof, cancel := context.WithTimeout(ctx, 2*time.Second)
    defer cancel()
    snapshot, err := DesktopWindowsNodeCompositionSnapshot(proof)
    if err != nil || snapshot.Closed || snapshot.Target.Validate() != nil || snapshot.Owner.Kind != "windows-isolated-token" || !snapshot.Options.RetainBaselineForHandoff || len(snapshot.Grants) != 0 || len(snapshot.Options.PrivateDestinations) != 1 || snapshot.Options.PrivateDestinations[0] != (DesktopWindowsSocketDestination{Network: network, Address: remote}) {
        reason := "native-readback-error"
        switch {
        case err != nil:
        case snapshot.Closed:
            reason = "native-owner-closed"
        case snapshot.Target.Validate() != nil:
            reason = "native-target-invalid"
        case snapshot.Owner.Kind != "windows-isolated-token":
            reason = "native-owner-kind"
        case !snapshot.Options.RetainBaselineForHandoff:
            reason = "native-baseline-not-retained"
        case len(snapshot.Grants) != 0:
            reason = "native-owner-has-grants"
        case len(snapshot.Options.PrivateDestinations) != 1:
            reason = "native-private-tuple-count"
        default:
            reason = "native-private-tuple-changed"
        }
        desktopMAXControlDiagnostic(reason, network, err, len(snapshot.Grants), len(snapshot.Options.PrivateDestinations))
        return snapshot, false
    }
    desktopWindowsNodeComposition.Lock()
    policy := desktopWindowsNodeComposition.owner
    desktopWindowsNodeComposition.Unlock()
    current := policy != nil && policy.Current(snapshot.Capture, snapshot.Owner)
    if !current {
        desktopMAXControlDiagnostic("captured-policy-not-current", network, nil)
    }
    return snapshot, current
}

func desktopMAXControlDenied(ctx context.Context, before DesktopWindowsNodeCompositionReadback, network string, remote netip.AddrPort, err error) {
    if !errors.Is(err, syscall.Errno(10013)) {
        return
    }
    after, current := desktopMAXControlSnapshot(ctx, network, remote)
    if !current || before.Target != after.Target || before.Capture != after.Capture || before.Owner != after.Owner {
        desktopMAXControlDiagnostic("denial-readback-rejected", network, err)
        if network == "udp" {
            desktopMAXControlInvalid("denial-readback-rejected", err)
        }
        return
    }
    if network == "tcp" {
        println("MAX native ordinary tcp socket denied by captured WFP")
    } else {
        println("MAX native ordinary udp socket denied by captured WFP")
    }
}

type desktopMAXControlConn struct {
    net.Conn
    ctx context.Context
    before DesktopWindowsNodeCompositionReadback
    network string
    remote netip.AddrPort
}

func (c *desktopMAXControlConn) Write(body []byte) (int, error) {
    count, err := c.Conn.Write(body)
    desktopMAXControlDiagnostic("ordinary-write", c.network, err, count)
    desktopMAXControlDenied(c.ctx, c.before, c.network, c.remote, err)
    return count, err
}

func (c *desktopMAXControlConn) Read(body []byte) (int, error) {
    count, err := c.Conn.Read(body)
    // Read errors are diagnostic only. They cannot satisfy the unchanged
    // outbound socket/delivery rejection witness.
    if err != nil {
        desktopMAXControlDiagnostic("ordinary-read", c.network, err, count)
    }
    return count, err
}

func DesktopWindowsMAXControlDial(ctx context.Context, network, address string, dial func() (net.Conn, error)) (net.Conn, error) {
    remote, parseErr := netip.ParseAddrPort(address)
    before, current := desktopMAXControlSnapshot(ctx, network, remote)
    connection, err := dial()
    desktopMAXControlDiagnostic("ordinary-dial", network, err)
    if network == "udp" && (parseErr != nil || !current) {
        desktopMAXControlInvalid("udp-captured-input-rejected", parseErr)
    }
    if parseErr == nil && current {
        desktopMAXControlDenied(ctx, before, network, remote, err)
        if connection != nil {
            if network == "udp" && err == nil {
                desktopMAXControlObserveUDP(ctx, connection, before, remote)
            }
            connection = &desktopMAXControlConn{Conn: connection, ctx: ctx, before: before, network: network, remote: remote}
        } else if network == "udp" && !errors.Is(err, syscall.Errno(10013)) {
            desktopMAXControlInvalid("udp-dial-lost-captured-socket", err)
        }
    }
    return connection, err
}
'''


def late_handshake_control(selected, protocol):
    raw = selected[4]
    boundary = '\tif closed || !allowed || owner == nil || !owner.Current() {\n'
    if raw.count(boundary) != 1:
        raise ValueError('MAX native control lost its precise late-handshake mutation')
    observer = ('\tif !closed && allowed && owner != nil && owner.SocketCurrent() && !owner.Current() && base == ' + json.dumps(protocol) + ' {\n'
                '\t\tsnapshot, err := mobiletor.DesktopWindowsNodeCompositionSnapshot(ctx)\n'
                '\t\tif err == nil && !snapshot.Closed && snapshot.Target.Validate() == nil && snapshot.Capture == owner.brokerCapture() && snapshot.Owner.Kind == "windows-isolated-token" {\n'
                '\t\t\tprintln(' + json.dumps(handshake_witness(protocol)) + ')\n\t\t}\n\t}\n')
    return (*selected[:4], raw.replace(boundary, observer + boundary))


def observed_control_sources(source, mutation):
    label, _, _, _, _, replacement = mutation
    if replacement is None:
        return {}
    sources = MAX.control_sources(source, label, *replacement)
    protocol = {'uncaptured-outer-tcp': 'tcp', 'uncaptured-outer-udp': 'udp'}.get(label)
    if protocol is None:
        return sources
    relative, raw = replacement
    if protocol == 'tcp':
        before = 'conn, err := (&net.Dialer{}).DialContext(cctx, N.NetworkTCP, b.server.String())'
        after = 'conn, err := nodeMAXOrdinaryDial(cctx, N.NetworkTCP, b.server.String())'
        helper = '''//go:build windows && routervpn_windows_node_composition

package routervpnxray

import (
    "context"
    "net"
    "github.com/sagernet/sing-box/routervpn/mobiletor"
)

func nodeMAXOrdinaryDial(ctx context.Context, network, address string) (net.Conn, error) {
    return mobiletor.DesktopWindowsMAXControlDial(ctx, network, address, func() (net.Conn, error) {
        return (&net.Dialer{}).DialContext(ctx, network, address)
    })
}
'''
    else:
        before = 'Dialer:             func() N.Dialer { _ = outboundDialer; return N.SystemDialer }(),'
        after = 'Dialer:             func() N.Dialer { _ = outboundDialer; return nodeMAXOrdinaryDialer{N.SystemDialer} }(),'
        helper = '''//go:build windows && routervpn_windows_node_composition

package hysteria2

import (
    "context"
    "net"
    "github.com/sagernet/sing-box/routervpn/mobiletor"
    M "github.com/sagernet/sing/common/metadata"
    N "github.com/sagernet/sing/common/network"
)

type nodeMAXOrdinaryDialer struct { N.Dialer }

func (d nodeMAXOrdinaryDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
    return mobiletor.DesktopWindowsMAXControlDial(ctx, network, destination.String(), func() (net.Conn, error) {
        return d.Dialer.DialContext(ctx, network, destination)
    })
}
'''
    sources[relative] = WFP.BOOT.IDENTITY.replace_once(raw, before, after)
    if protocol == 'udp':
        if mutation[1:3] != ('TestRouterVPNDesktopNodeWindowsMAXQUIC', 'max-quic-wg/off'):
            raise ValueError('Ordinary UDP observer escaped its one captured MAX case')
        peer = (source / PEER).read_text(encoding='utf-8')
        boundary = '\t\t\t\tf := nodeMAXWFPBox(t, peer.original(t, "always"), nil, true)\n\t\t\t\tf.start(t)'
        observed = '''\t\t\t\tf := nodeMAXWFPBox(t, peer.original(t, "always"), nil, true)
                if err := mobiletor.DesktopWindowsMAXControlSetUDPObserver(func(ctx context.Context, connection net.Conn, remote netip.AddrPort) error {
                    peer.mu.Lock()
                    defer peer.mu.Unlock()
                    if peer.request.Mode != "max-quic-wg" || peer.request.Layer != "" || peer.request.Fault != "" || peer.source.Protocol != "udp" || peer.source.Physical != remote.String() || peer.source.digest() != peer.reply.SourceSHA256 {
                        return errors.New("ordinary UDP observer replaced its original MAX reference")
                    }
                    return nodeMAXWFPObserveOrdinaryUDP(ctx, connection, peer.local, remote, func(ctx context.Context, action, nonce string) (int64, error) {
                        reply, err := peer.observeLocked(ctx, action+" "+nonce)
                        if err != nil || reply.Probe != nonce || reply.ProbeCount < 0 {
                            return 0, errors.Join(err, errors.New("ordinary UDP observer lost its independent private nonce"))
                        }
                        return reply.ProbeCount, nil
                    })
                }); err != nil {
                    t.Fatal(err)
                }
                f.start(t)'''
        sources[PEER] = WFP.BOOT.IDENTITY.replace_once(peer, boundary, observed)
        helper_path = 'protocol/routervpnpq/node_max_udp_control_test.go'
        if (source / helper_path).exists() or (source / helper_path).is_symlink():
            raise ValueError('MAX native observer would replace an unowned source')
        sources[helper_path] = PREFIX.decode().split('package ', 1)[0] + (UDP_CONTROL / 'udp_observation.go').read_text(encoding='utf-8')
    for path, contents in (
            ('routervpn/mobiletor/desktop_socket_windows_max_control_overlay.go', ORDINARY_OBSERVER),
            (str(Path(relative).parent / 'routervpn_max_wfp_control_overlay.go'), helper)):
        if (source / path).exists() or (source / path).is_symlink():
            raise ValueError('MAX native observer would replace an unowned source')
        sources[path] = contents
    return sources


def mutations(source):
    result = []
    for label, relative, parent, case, witness, replacement in MAX.mutations(source):
        if label.startswith('uncaptured-outer-'):
            witness = ordinary_witness(label.removeprefix('uncaptured-outer-'))
        elif label == 'cached-selected-dns':
            witness = 'actual WFP complete MAX cached or bypassed selected DNS'
        elif label.startswith('valid-'):
            witness = 'actual WFP MAX accepted the substituted authenticated layer credential'
        result.append((label, native_parent(parent), case, witness, None, (relative, replacement)))
    kernel = WFP.mutants(source)
    for family, mode in (('TLS', 'max-tls-wg'), ('QUIC', 'max-quic-wg')):
        parent = 'TestRouterVPNDesktopNodeWindowsMAX' + family
        protocol = 'tcp' if family == 'TLS' else 'udp'
        for label, selected, group, case, witness in (
            ('legacy-max-adoption-' + family.lower(), kernel[0], FOREIGN, mode,
             'foreign MAX predecessor reached captured native admission'),
            ('late-max-handshake-' + family.lower(), late_handshake_control(kernel[1], protocol), parent, mode + '/off',
             handshake_witness(protocol)),
            ('ordinary-max-' + ('tcp' if family == 'TLS' else 'udp') + '-deny', kernel[2], parent, mode + '/off',
             'independent peer marker receipt'),
        ):
            result.append((label, group, case, witness, selected, None))
    relative = 'protocol/routervpnpq/node_max_peer_test.go'
    raw = (source / relative).read_text(encoding='utf-8')
    before = 'secret, int64(nodeMAXReferenceLifetime/time.Second), nodeMAXMiddleHandler{s, tcpRoutes}, nil)'
    after = 'secret, 10, nodeMAXMiddleHandler{s, tcpRoutes}, nil)'
    replacement = WFP.BOOT.IDENTITY.replace_once(raw, before, after)
    result.append(('expired-reference-association', MARKERS, 'retained-middle-idle',
                   'MAX retained authenticated middle changed its owned UDP association',
                   None, (relative, replacement)))
    return tuple(result)


def overlay(source, directory, *, prospective, mutation=None, closed=False):
    if closed and (prospective or mutation is not None):
        raise ValueError('Closed MAX admission control cannot alter native execution controls')
    if mutation is not None and mutation not in mutations(source):
        raise ValueError('MAX mutation is not one of its exact compiled controls')
    selected = mutation[4] if mutation is not None else None
    result = WFP.overlay(source, directory, selected)
    value = json.loads(result.read_text(encoding='utf-8'))
    mapping = value['Replace']

    def add(relative, raw, name):
        actual = source / relative
        if Path(relative).is_absolute() or '..' in Path(relative).parts or str(actual) in mapping:
            raise ValueError('MAX overlay overlaps native ownership or escapes its captured source')
        path = directory / (name + '.go')
        path.write_text(raw, encoding='utf-8')
        mapping[str(actual)] = str(path)

    if prospective:
        add(PREDICATE, prospective_predicate((source / PREDICATE).read_text(encoding='utf-8')), 'prospective-max-predicate')
    if closed:
        add(PREDICATE, closed_predicate((source / PREDICATE).read_text(encoding='utf-8')), 'closed-max-predicate')
    if mutation is not None and mutation[5] is not None:
        sources = observed_control_sources(source, mutation)
        for index, (relative, raw) in enumerate(sorted(sources.items())):
            add(relative, raw, 'max-native-negative-' + str(index))
    result.write_text(json.dumps(value, sort_keys=True), encoding='utf-8')
    return result


def overlay_source_hashes(source, overlay_path):
    value = json.loads(overlay_path.read_text(encoding='utf-8'))
    if set(value) != {'Replace'} or not isinstance(value['Replace'], dict) or not value['Replace']:
        raise ValueError('Windows MAX lost its exact compiled overlay')
    records = {}
    for original, replacement in value['Replace'].items():
        relative = Path(original).relative_to(source)
        path = Path(replacement)
        if '..' in relative.parts or path.parent != overlay_path.parent:
            raise ValueError('Windows MAX compiled overlay escaped its captured workspace')
        records[relative.as_posix()] = MAX.regular_digest(path)
    return records


def bounded_failure_output(output, limit=16384):
    """Keep initial failure and terminal stacks; never use this as verdict input."""
    if not isinstance(output, str) or not isinstance(limit, int) or limit < 128:
        raise ValueError('Invalid bounded native diagnostic')
    # Redact complete sensitive records before slicing; a long configuration or
    # a wrapped private PEM must not expose a suffix after a truncation boundary.
    output = re.sub(r'-----BEGIN[^\n]*PRIVATE KEY-----.*?-----END[^\n]*PRIVATE KEY-----',
                    '[private key omitted]', output, flags=re.DOTALL)
    sensitive = re.compile(r'password|private[_ -]?key|api[_ -]?token|authorization|protocol[_ ]?files|sing-box\.json|cert\.pem|["\'](?:config|secret|token)["\']\s*[:=]', re.IGNORECASE)
    output = ''.join('[private native diagnostic record omitted]\n' if sensitive.search(line) else
                     re.sub(r'([a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s@]+@', r'\1[credentials omitted]@', line)
                     for line in output.splitlines(keepends=True))
    raw = output.encode('utf-8')
    if len(raw) <= limit:
        return output
    marker = b'\n... [middle native diagnostic omitted] ...\n'
    head = (limit - len(marker)) // 2
    tail = limit - len(marker) - head
    return raw[:head].decode('utf-8', errors='ignore') + marker.decode() + raw[-tail:].decode('utf-8', errors='ignore')


def rejected_output(status, output, parent, case, witness):
    output = output.replace('\r\n', '\n')
    if INVALID_ORDINARY in output:
        raise ValueError('Windows MAX control invalidated its captured delivery evidence')
    invalid = ('fatal:', 'testing: warning:', *JOIN_FAILURES)
    if any(value.casefold() in output.casefold() for value in invalid):
        raise ValueError('Windows MAX control failed its owned cleanup')
    if len(re.findall(r'^\s*--- FAIL:.*$', output, re.MULTILINE)) != 2 or re.search(r'^FAIL$', output, re.MULTILINE) is None:
        raise ValueError('Windows MAX control omitted its exact final executable failure')
    MAX.rejected_output(status, output, parent, case, witness)


def repository_identity(expected_sha=None):
    def git(*arguments):
        return subprocess.check_output(['git', *arguments], cwd=ROOT, text=True).strip()
    commit = git('rev-parse', '--verify', 'HEAD^{commit}')
    tree = git('rev-parse', '--verify', 'HEAD^{tree}')
    changes = git('status', '--porcelain', '--untracked-files=all')
    if expected_sha is not None and (re.fullmatch('[0-9a-f]{40}', expected_sha) is None or commit != expected_sha or changes):
        raise ValueError('Authoritative Windows MAX requires the exact clean repository commit')
    return {'commit': commit, 'tree': tree, 'clean': not bool(changes),
            'status_sha256': hashlib.sha256(changes.encode('utf-8')).hexdigest()}


def execution_plan(suite, changes):
    if suite not in ('complete', *EXECUTION_SUITES):
        raise ValueError('Unknown complete MAX execution suite: ' + suite)
    if len({item[0] for item in changes}) != len(changes):
        raise ValueError('Complete MAX execution inventory contains duplicate controls')
    families = tuple(MAX.FAMILIES) if suite == 'complete' else tuple(family for family in MAX.FAMILIES if family.lower() == suite)
    selected = changes if suite == 'complete' else ()
    if suite.startswith('ownership-controls-'):
        midpoint = (len(changes) + 1) // 2
        selected = changes[:midpoint] if suite.endswith('-1') else changes[midpoint:]
    return families, suite in ('complete', 'succession'), suite in ('complete', 'ownership-controls-1'), selected


def execute(source, pq, cache, go='go', *, prospective=False, env=None, receipt_path=None, expected_sha=None, suite='complete', command_owner=None):
    if platform.system() != 'Windows' or not WFP.BOOT.IDENTITY.ctypes.windll.shell32.IsUserAnAdmin():
        raise ValueError('Complete MAX WFP requires actual elevated Windows')
    command_owner = MAXCommandOwner() if command_owner is None else command_owner
    receipt_path = WPQ.new_receipt_path(receipt_path)
    repository = repository_identity(expected_sha)
    source, before = checked_sources(Path(source))
    # Every selected suite repeats the captured native prerequisites below.
    # Only the long workload inventory is partitioned; default execution keeps
    # the entire original gate in one process.
    execution_plan(suite, ())
    compiler, captured, architecture = NODE.selected_compiler(go, source, dict(os.environ if env is None else env))
    target = captured['GOOS'] + '/' + architecture
    if target not in ('windows/amd64', 'windows/arm64') or captured.get('CGO_ENABLED', '1') != '1':
        raise ValueError('Complete MAX WFP requires matching-host Windows and the real CGO ABI')
    predicate = (source / PREDICATE).read_text(encoding='utf-8')
    (prospective_predicate if prospective else closed_predicate)(predicate)
    pq, cache = Path(pq).absolute(), Path(cache).absolute()
    native = REFERENCE.BUILD.PQ.verify(pq, target)
    captured['CGO_ENABLED'] = '1'
    captured['CGO_LDFLAGS'] = shlex.join(['-static', '-L' + str(pq), *native['native_static_libs']])
    for name in ('ROUTERVPN_NODE_MAX_WFP_REFERENCE_CHILD', 'ROUTERVPN_NODE_PQ_WFP_REFERENCE_CHILD', 'ROUTERVPN_NODE_WFP_REFERENCE_CHILD'):
        captured.pop(name, None)
    race = ['-race'] if architecture == 'amd64' else []
    tools = MAX.tool_receipts(source, compiler, captured, target, cache)
    dependencies = MAX.dependency_receipt(source, compiler, captured)
    status, output = command_owner.run([compiler, 'mod', 'verify'], cwd=source, env=captured, timeout=300)
    if status:
        raise ValueError('Windows MAX checksum verification failed:\n' + output[-8192:])
    packet = REFERENCE.BUILD.POLICY.AMNEZIA
    packet.TIMERS.verify(source, compiler, env=captured)
    observation_contract(compiler, source, captured, race,
                         (WFP.RESOURCES / 'socket_peer.go', WFP.RESOURCES / 'socket_peer_test.go'),
                         'TestWindowsNodeObserverTransportPeer', ())
    observation_contract(compiler, source, captured, race,
                         (UDP_CONTROL / 'udp_observation.go', UDP_CONTROL / 'udp_observation_test.go'),
                         UDP_OBSERVATION, UDP_CASES)
    with command_owner.workspace('routervpn-windows-complete-max-' + suite + '-') as directory:
        workspace = Path(directory)
        keys = workspace / 'private' / 'keys'
        REFERENCE.generate_keys(target, cache, keys)
        key_records = REFERENCE.key_files(keys)
        key_generator = cache / REFERENCE.BUILD.PQ.TARGETS[target] / 'release/examples/native_keys.exe'
        generator_digest = MAX.regular_digest(key_generator)
        captured['ROUTERVPN_PQ_TEST_KEYS'] = str(keys)
        relay, relay_digest = NODE.build_layer_reference(compiler, workspace, captured, race)
        xray, xray_digest, xray_source, xray_records = NODE.build_xray_reference(compiler, source, workspace, captured, race)
        build = [compiler, 'test', '-c', '-p=1', '-mod=readonly', '-tags=' + TAGS, *race, '-ldflags=-checklinkname=0']
        controls, suites = [], []
        with REFERENCE.test_sources(source):
            families, run_succession, run_foreign, selected_controls = execution_plan(suite, mutations(source))
            compiled_overlays = {}

            def compile_in(name, prospective, mutation=None, closed=False):
                owned = workspace / name
                owned.mkdir()
                selected = overlay(source, owned, prospective=prospective, mutation=mutation, closed=closed)
                before_overlay = overlay_source_hashes(source, selected)
                binary = owned / 'complete-max-native.test.exe'
                status, output = command_owner.run([*build, '-overlay=' + str(selected), '-o', binary, './protocol/routervpnpq'], cwd=source, env=captured, timeout=600)
                if status:
                    raise ValueError('Windows MAX compilation failed: ' + name + '\n' + output[-32768:])
                if overlay_source_hashes(source, selected) != before_overlay:
                    raise ValueError('Windows MAX overlay changed during native compilation: ' + name)
                compiled_overlays[name] = before_overlay
                return binary

            def run_suite(binary, parent, cases, timeout):
                digest = MAX.regular_digest(binary)
                name = binary.parent.name
                mapping = binary.parent / 'overlay.json'
                if overlay_source_hashes(source, mapping) != compiled_overlays[name]:
                    raise ValueError('Windows MAX overlay changed before native execution: ' + name)
                status, output = command_owner.run([binary, '-test.run=^' + parent + '$', '-test.count=1', '-test.timeout=' + str(timeout) + 's', '-test.v'],
                                          cwd=source, env=captured, timeout=timeout + 15)
                print(output, end='' if output.endswith('\n') else '\n', flush=True)
                MAX.required_output(status, output, parent, cases)
                if MAX.regular_digest(binary) != digest:
                    raise ValueError('Windows MAX executable changed during native execution')
                if overlay_source_hashes(source, mapping) != compiled_overlays[name]:
                    raise ValueError('Windows MAX overlay changed during native execution: ' + name)
                record = {'parent': parent, 'cases': cases, 'binary_sha256': digest,
                          'source_overlay_sha256': compiled_overlays[name],
                          'output_sha256': hashlib.sha256(output.encode('utf-8')).hexdigest()}
                suites.append(record)
                return record

            closed_name = 'unmodified-closed-capability' if prospective else 'shipping-closed-capability'
            closed = compile_in(closed_name, False, closed=not prospective)
            closed_control = run_suite(closed, CLOSED, MODES, 600)
            closed.unlink()
            if closed.exists() or closed.is_symlink():
                raise ValueError('Windows MAX closed-admission executable did not retire')
            binary = compile_in('native-composition', prospective)
            digest = MAX.regular_digest(binary)
            run_suite(binary, OPEN, (), 15)
            run_suite(binary, MARKERS, MARKER_CASES, 30)
            status, output = command_owner.run([binary, '-test.run=^Test(RealPinnedFactory|RealFactory|RealPQTraffic)|^(' + STARTUP_RECORDS + '|' + PORT_PAIR + ')$', '-test.v', '-test.count=1', '-test.timeout=120s'],
                                      cwd=source, env=captured, timeout=135)
            print(output, end='' if output.endswith('\n') else '\n', flush=True)
            for parent in MAX.PQ.NATIVE_CASES:
                MAX.required_output(status, output, parent, ('v2', 'v3') if parent == 'TestRealPinnedFactoryExchangeAndRekey' else ())
            MAX.required_output(status, output, STARTUP_RECORDS, ())
            MAX.required_output(status, output, PORT_PAIR, PORT_PAIR_CASES)
            startup_record_output = hashlib.sha256(output.encode('utf-8')).hexdigest()
            for family in families:
                for suffix, cases, timeout in (('', MAX.TRAFFIC[family], 600), ('Credentials', MAX.CREDENTIALS[family], 1800)):
                    run_suite(binary, 'TestRouterVPNDesktopNodeWindowsMAX' + family + suffix, cases, timeout)
            # Twelve reversals each build, prove and retire three owned graphs.
            # Actual AMD64 exhausted 2400s only 14s into the final reversal.
            # Allow the measured full sequence and cleanup; every individual
            # peer lifetime, startup, I/O and retirement bound is unchanged.
            if run_succession:
                run_suite(binary, SUCCESSION, tuple(mode + '/' + layer for mode in MODES for layer in LAYERS), 3000)
            if run_foreign:
                run_suite(binary, FOREIGN, MODES, 600)
            for mutation in selected_controls:
                name, parent, case, witness, _, replacement = mutation
                negative = compile_in(name, prospective, mutation)
                negative_digest = MAX.regular_digest(negative)
                if overlay_source_hashes(source, negative.parent / 'overlay.json') != compiled_overlays[name]:
                    raise ValueError('Windows MAX control overlay changed before execution')
                status, output = command_owner.run([negative, '-test.run=' + MAX.selector(parent, case), '-test.count=1', '-test.timeout=90s', '-test.v'],
                                          cwd=source, env=captured, timeout=105)
                try:
                    rejected_output(status, output, parent, case, witness)
                except ValueError as error:
                    raise ValueError(str(error) + ': ' + name + '\n' + bounded_failure_output(output)) from error
                if MAX.regular_digest(negative) != negative_digest:
                    raise ValueError('Windows MAX control executable changed')
                if overlay_source_hashes(source, negative.parent / 'overlay.json') != compiled_overlays[name]:
                    raise ValueError('Windows MAX control overlay changed during execution')
                controls.append({'name': name, 'parent': parent, 'case': case, 'witness': witness,
                                 'binary_sha256': negative_digest, 'exit_status': status,
                                 'source': replacement[0] if replacement else mutation[4][1],
                                 'replacement_sha256': hashlib.sha256((replacement[1] if replacement else mutation[4][4]).encode()).hexdigest(),
                                 'source_overlay_sha256': compiled_overlays[name],
                                 'output_sha256': hashlib.sha256(output.encode()).hexdigest()})
                negative.unlink()
                print('Rejected actual Windows complete MAX control: ' + name + ' output_sha256=' + controls[-1]['output_sha256'], flush=True)
            if MAX.regular_digest(binary) != digest or REFERENCE.key_files(keys) != key_records or MAX.regular_digest(key_generator) != generator_digest or MAX.regular_digest(relay) != relay_digest or MAX.regular_digest(xray) != xray_digest or NODE.xray_reference_sources(xray_source) != xray_records:
                raise ValueError('Windows MAX keys, reference executables or source changed')
        if checked_sources(source)[1] != before or REFERENCE.BUILD.PQ.verify(pq, target) != native or MAX.tool_receipts(source, compiler, captured, target, cache) != tools or MAX.dependency_receipt(source, compiler, captured) != dependencies:
            raise ValueError('Windows MAX captured source, archive or tool identity changed')
        result = {'schema': 2, 'target': target, 'source': before, 'repository': repository,
                  'execution_suite': suite, 'complete_inventory_proved': suite == 'complete',
                  'receipt_kind': 'complete-max' if suite == 'complete' else 'complete-max-required-suite',
                  'required_execution_suites': EXECUTION_SUITES,
                  'native_pq': native, 'tools': tools,
                  'prepared_quic_dependencies': dependencies, 'test_binary_sha256': digest,
                  'relay_sha256': relay_digest, 'xray_sha256': xray_digest,
                  'xray_pin': NODE.PREP.RELAY.XRAY.XRAY_PIN, 'xray_source': xray_records,
                  'key_generator_sha256': generator_digest, 'fresh_independent_keypairs': 3,
                  'prospective': prospective, 'current_closed_admission_proved': prospective,
                  'closed_admission_control': closed_control,
                  'closed_admission_source': 'unmodified' if prospective else 'exact-family-removed',
                  'prospective_predicate': {'before': PROSPECTIVE_BEFORE, 'after': PROSPECTIVE_AFTER} if prospective else None,
                  'traffic_cases': {family: MAX.TRAFFIC[family] for family in families},
                  'credential_cases': {family: MAX.CREDENTIALS[family] for family in families},
                  'succession_cases': tuple(mode + '/' + layer for mode in MODES for layer in LAYERS) if run_succession else (),
                  'foreign_predecessor_cases': MODES if run_foreign else (), 'native_abi_cases': MAX.PQ.NATIVE_CASES,
                  'startup_record_case': STARTUP_RECORDS, 'startup_record_output_sha256': startup_record_output,
                  'port_pair_case': PORT_PAIR, 'port_pair_subcases': PORT_PAIR_CASES, 'port_pair_output_sha256': startup_record_output,
                  'suites': suites, 'compiled_negative_controls': controls,
                  'native_firewall': 'actual-appid-scoped-wfp', 'native_socket_source': 'actual-isolated-token',
                  'tun': 'modeled', 'public_admission': 'separate' if prospective else 'shipping-predicate', 'device_acceptance': 'separate'}
    if workspace.exists() or workspace.is_symlink():
        raise ValueError('Windows MAX retained its disposable private workspace')
    if repository_identity(expected_sha) != repository:
        raise ValueError('Windows MAX repository identity changed before final acknowledgment')
    result['private_key_workspace_removed'] = True
    WPQ.publish_receipt(receipt_path, result, workspace)
    if suite == 'complete':
        print('Actual Windows WFP, complete four-family MAX, 12 Start Layer paths, 48 credential cases, native rekey, selected Home DNS, joined reversal and compiled controls passed; TUN, public host and device acceptance remain separate.', flush=True)
    else:
        print('Actual Windows MAX required suite passed: ' + suite + '; every required suite at this source and target remains necessary for complete inventory evidence.', flush=True)
    return result


def standalone(go='go', *, prospective=False, receipt_path=None, expected_sha=None, suite='complete'):
    if platform.system() != 'Windows' or not WFP.BOOT.IDENTITY.ctypes.windll.shell32.IsUserAnAdmin():
        raise ValueError('Standalone complete MAX requires actual elevated Windows')
    compiler, captured, architecture = NODE.selected_compiler(go, ROOT, dict(os.environ))
    target = 'windows/' + architecture
    if captured.get('CGO_ENABLED', '1') != '1':
        raise ValueError('Standalone MAX cannot disable its native cryptographic ABI')
    receipt_path = WPQ.new_receipt_path(receipt_path)
    captured['CGO_ENABLED'] = '1'
    native = REFERENCE.BUILD
    previous = dict(os.environ)
    execution_plan(suite, ())
    command_owner = MAXCommandOwner()
    with command_owner.workspace('routervpn-windows-max-core-' + suite + '-') as directory:
        workspace = Path(directory)
        source, xray, pq, cache = (workspace / name for name in ('core', 'xray', 'pq', 'cargo-cache-' + suite))
        try:
            os.environ.clear()
            os.environ.update(captured)
            with command_owner.preparation():
                native.checkout(source, 'https://github.com/SagerNet/sing-box.git', native.PIN)
                native.checkout(xray, 'https://github.com/XTLS/Xray-core.git', native.POLICY.XRAY.XRAY_PIN)
                native.pristine(source, native.PIN)
                native.pristine(xray, native.POLICY.XRAY.XRAY_PIN)
                native.PQ.build(target, pq, cache)
                native.POLICY.prepare_native(source, xray)
                native.PERFORMANCE.prepare(source)
                native.OPENVPN.prepare(source)
                native.EXTERNAL.prepare(source, go=str(compiler), env=captured)
                native.BUFFERS.prepare(source)
                native.run([compiler, 'mod', 'tidy'], cwd=source, env=captured)
                native.run([compiler, 'mod', 'verify'], cwd=source, env=captured)
                native.POLICY.AMNEZIA.verify(source)
            result = execute(source, pq, cache, str(compiler), prospective=prospective, env=captured, expected_sha=expected_sha, suite=suite, command_owner=command_owner)
        finally:
            os.environ.clear()
            os.environ.update(previous)
    if repository_identity(expected_sha) != result['repository']:
        raise ValueError('Standalone Windows MAX source changed before cleanup acknowledgment')
    result['standalone_source_workspace_removed'] = True
    WPQ.publish_receipt(receipt_path, result, workspace)
    return result


if __name__ == '__main__':
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path, nargs='?')
    parser.add_argument('pq', type=Path, nargs='?')
    parser.add_argument('--cache', type=Path, default=ROOT / 'dist/.native-pq-cache')
    parser.add_argument('--go', default='go')
    parser.add_argument('--prospective', action='store_true')
    parser.add_argument('--standalone', action='store_true')
    parser.add_argument('--receipt', type=Path)
    parser.add_argument('--sha', help='require this exact clean repository commit for authoritative evidence')
    parser.add_argument('--suite', choices=('complete', *EXECUTION_SUITES), default='complete')
    arguments = parser.parse_args()
    if arguments.standalone:
        if arguments.source is not None or arguments.pq is not None:
            parser.error('--standalone owns its exact source and native archive')
        standalone(arguments.go, prospective=arguments.prospective, receipt_path=arguments.receipt, expected_sha=arguments.sha, suite=arguments.suite)
    else:
        if arguments.source is None or arguments.pq is None:
            parser.error('an exact prepared source and native PQ archive are required')
        execute(arguments.source, arguments.pq, arguments.cache, arguments.go,
                prospective=arguments.prospective, receipt_path=arguments.receipt, expected_sha=arguments.sha, suite=arguments.suite)
