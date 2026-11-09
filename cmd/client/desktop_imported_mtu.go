package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/nativeopenvpn"
)

// The imported entry and paired final already share one native Box/TUN. This
// adapter measures that exact interface with the shared authenticated private
// protocol; a SOCKS lane or an ordinary LAN socket cannot supply these results.
type desktopImportedMTUOwner struct {
	mu          sync.Mutex
	launch      *desktopNodeLaunch
	runtime     *nativeMultihopRuntime
	current     func(context.Context) error
	dial        func(context.Context, string, string, desktopNodeMTURecord, func(context.Context) error) (net.Conn, error)
	policy      mobilemtu.Profile
	config      string
	record      desktopNodeMTURecord
	openVPN     nativeopenvpn.PacketObservation
	kernel      *desktopNodeMTUOwner
	operation   context.Context
	mailboxHeld bool
	originalMTU int
	committed   atomic.Bool
	connections sync.Map
	sockets     atomic.Int64
}

func desktopImportedMTURuntime(ctx context.Context, a *app) (*nativeMultihopRuntime, bool, error) {
	raw, found := nativeMultihopOwners.Load(a)
	if !found {
		return nil, false, nil
	}
	owner, ok := raw.(*nativeMultihopRuntime)
	if !ok || owner == nil || owner.selection.Native == nil || !owner.selection.Native.imported {
		return nil, false, nil
	}
	if owner.launch == nil || !owner.launch.importedEntry || owner.graph.Execution != "local" || !owner.graph.ImportedEntry ||
		owner.selection.Control.ID != owner.selection.Exit.ID || owner.selection.Exit.External != nil || owner.selection.Exit.NodeKind == "external" {
		return nil, true, errors.New("imported MTU lost its retained entry and paired final")
	}
	if err := desktopImportedMTURuntimeCurrent(ctx, a, owner); err != nil {
		return nil, true, err
	}
	return owner, true, nil
}

func desktopImportedMTURuntimeCurrent(ctx context.Context, a *app, expected *nativeMultihopRuntime) error {
	if ctx == nil || expected == nil || expected.launch == nil {
		return errors.New("imported MTU has no original caller or runtime")
	}
	cleanup, _ := mobilemtu.OperationCleanupOnly(ctx)
	if !cleanup {
		held, err := mtuSuspendedContext(ctx, a)
		_, temporary := speedLabTemporaryOwners.Load(a)
		if err != nil || held || temporary || speedLabTemporaryPersistenceSuppressed(a) {
			return errors.Join(err, errors.New("imported MTU path is held by its connection or temporary measurement transition"))
		}
	}
	graph, found := getActiveMultihopGraph(a)
	if !found || !sameMTUMultihopGraph(graph, expected.graph) {
		return errors.New("imported MTU graph was replaced")
	}
	actual, err := capturedNativeMultihopRuntimeContext(ctx, a, expected.launch.command, graph)
	if err != nil || actual != expected {
		return errors.Join(err, errors.New("imported MTU source or network generation changed"))
	}
	if desktopNodeProcessExited(expected.launch) {
		return errors.New("imported MTU original profiles or process retired")
	}
	if err := mobilemtu.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	connected := a.cmd == expected.launch.command && a.profiles.SelectedID == expected.selection.Control.ID && (!a.closing || cleanup)
	for _, profile := range []common.RouterProfile{expected.selection.Control, expected.selection.Entry, expected.selection.Exit} {
		actual, found := a.profileByIDLocked(profile.ID)
		connected = connected && found && mtuProfileSnapshotToken(actual) == mtuProfileSnapshotToken(profile)
	}
	connected = connected && (cleanup || a.state.Connected && a.state.Phase == "connected" && a.state.RouterID == graph.ExitID && a.state.RuntimeMode == graph.ExitMode && a.state.Base == graph.Base)
	a.mu.Unlock()
	if !connected {
		return errors.New("imported MTU requires the connected, proved original path")
	}
	return ctx.Err()
}

func newDesktopImportedMTUOwner(ctx context.Context, a *app, runtime *nativeMultihopRuntime, policy mobilemtu.Profile) (*desktopImportedMTUOwner, error) {
	if err := desktopImportedMTURuntimeCurrent(ctx, a, runtime); err != nil {
		return nil, err
	}
	if err := a.observeImportedOpenVPN(ctx, runtime.selection, runtime.launch.command); err != nil {
		return nil, err
	}
	launch := runtime.launch
	raw, err := readDesktopRuntimeFileContext(ctx, launch, "sing-box.json", 4<<20)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != launch.configSHA256 {
		return nil, errors.New("imported MTU compiled source was replaced")
	}
	if launch.ownedNode != nil && launch.ownedNode.imported != nil {
		if err := validateDesktopOwnedImportedConfigContext(ctx, launch, raw); err != nil {
			return nil, err
		}
	}
	record, err := readDesktopNodeMTUContext(ctx, launch)
	if err != nil || record.Active || record.Failure != "" {
		return nil, errors.Join(err, errors.New("imported MTU requires its stable native reader"))
	}
	owner := &desktopImportedMTUOwner{launch: launch, runtime: runtime, policy: policy, config: string(raw), record: record,
		current: func(call context.Context) error { return desktopImportedMTURuntimeCurrent(call, a, runtime) }, dial: dialDesktopImportedMTUSocket}
	if launch.importedOpenVPN != nil {
		original := launch.importedOpenVPN
		if err := mobilemtu.LockContext(ctx, &original.mu); err != nil {
			return nil, err
		}
		if original.original == nil || original.retired.Load() {
			original.mu.Unlock()
			return nil, errors.New("imported MTU has no original authenticated OpenVPN packet connection")
		}
		owner.openVPN = *original.original
		original.mu.Unlock()
	}
	if _, err := owner.CaptureContext(ctx); err != nil {
		return nil, err
	}
	return owner, nil
}

func (o *desktopImportedMTUOwner) state(record desktopNodeMTURecord) mobilemtu.State {
	return mobilemtu.State{Session: record.Session, Path: record.Path + "/" + o.runtime.network,
		Interface: fmt.Sprintf("%s/%d/%d", record.Interface, record.Index, record.Reader), MTU: record.MTU}
}

func sameDesktopImportedMTURecord(first, second desktopNodeMTURecord) bool {
	first.Heartbeat, second.Heartbeat = 0, 0
	first.NetworkReceipt, second.NetworkReceipt = "", ""
	first.OpenVPN, second.OpenVPN = nativeopenvpn.PacketObservation{}, nativeopenvpn.PacketObservation{}
	return first == second
}

func (o *desktopImportedMTUOwner) readLocked(ctx context.Context) (desktopNodeMTURecord, error) {
	if o.current == nil {
		return desktopNodeMTURecord{}, errors.New("imported MTU lost its captured path validator")
	}
	if err := o.current(ctx); err != nil {
		return desktopNodeMTURecord{}, err
	}
	expected := o.record
	if o.kernel != nil {
		if err := mobilemtu.LockContext(ctx, &o.kernel.mu); err != nil {
			return desktopNodeMTURecord{}, err
		}
		pending := o.kernel.pending != nil
		expected = o.kernel.record
		o.kernel.mu.Unlock()
		if pending {
			return desktopNodeMTURecord{}, errors.New("original imported MTU command is still draining")
		}
	}
	record, err := readDesktopNodeMTUContext(ctx, o.launch)
	if err != nil || !sameDesktopImportedMTURecord(record, expected) || record.Failure != "" {
		return record, errors.Join(err, errors.New("imported MTU captured reader or lease changed"))
	}
	if err := o.packetRecordCurrent(record); err != nil {
		return record, err
	}
	if err := o.current(ctx); err != nil {
		return record, err
	}
	return record, ctx.Err()
}

func (o *desktopImportedMTUOwner) packetRecordCurrent(record desktopNodeMTURecord) error {
	if o.launch.importedOpenVPN != nil {
		// The native command loop reobserves the original tuple after the exact
		// TUN/network receipt. It never borrows a saved endpoint declaration.
		if o.launch.importedOpenVPN.retired.Load() || o.openVPN.Validate() != nil || record.OpenVPN != o.openVPN {
			return errors.New("imported MTU OpenVPN packet generation or capacity changed")
		}
	} else if record.OpenVPN != (nativeopenvpn.PacketObservation{}) {
		return errors.New("imported MTU reader substituted an unrelated OpenVPN observation")
	}
	return nil
}

func (o *desktopImportedMTUOwner) cleanupCurrent(ctx context.Context) error {
	if err := o.current(ctx); err != nil {
		return err
	}
	// A pending command may have advanced the exact reader. The kernel owner
	// drains that command below, but it cannot borrow another session, graph,
	// physical path or authenticated OpenVPN generation to authorize rollback.
	record, err := readDesktopNodeMTUContext(ctx, o.launch)
	if err != nil || record.Path != o.record.Path || record.Config != o.record.Config || record.Session != o.record.Session {
		return errors.Join(err, errors.New("imported MTU cleanup lost its original native path"))
	}
	return errors.Join(o.packetRecordCurrent(record), ctx.Err())
}

func (o *desktopImportedMTUOwner) Capture() (mobilemtu.State, error) {
	return mobilemtu.State{}, errors.New("imported MTU requires its original bounded caller")
}

func (o *desktopImportedMTUOwner) CaptureContext(ctx context.Context) (mobilemtu.State, error) {
	if err := mobilemtu.LockContext(ctx, &o.mu); err != nil {
		return mobilemtu.State{}, err
	}
	defer o.mu.Unlock()
	record, err := o.readLocked(ctx)
	return o.state(record), err
}

func (o *desktopImportedMTUOwner) prepare(ctx context.Context, request string) (failure error) {
	cleanup, err := mobilemtu.OperationCleanupOnly(ctx)
	if err != nil || cleanup || !mobilemtu.SameOperationContext(ctx, ctx) || !desktopMTURequestPattern.MatchString(request) {
		return errors.Join(err, errors.New("imported MTU admission has no original work authority"))
	}
	if err := mobilemtu.LockContext(ctx, &o.mu); err != nil {
		return err
	}
	defer o.mu.Unlock()
	if o.mailboxHeld || o.sockets.Load() != 0 {
		return errors.New("imported MTU previous run has not joined")
	}
	record, err := o.readLocked(ctx)
	if err != nil || record.Active {
		return errors.Join(err, errors.New("imported MTU cannot capture another lease"))
	}
	if err := mobilemtu.LockContext(ctx, &o.launch.importedDNSMu); err != nil {
		return err
	}
	o.mailboxHeld, o.operation, o.originalMTU = true, ctx, record.MTU
	o.committed.Store(false)
	// This same mutex excludes ordinary selected-DNS/OpenVPN mailbox callers
	// until the retained native lease has actually committed or rolled back.
	family := 4
	if sink, err := netip.ParseAddr(o.policy.Sink); err == nil && sink.Is6() {
		family = 6
	}
	opened, err := openDesktopNodeMTUOwnerContext(ctx, o.launch, mtuLiveSnapshot{Interface: record.Interface, Family: family, OriginalMTU: record.MTU}, request)
	if opened != nil {
		o.kernel = opened.(*desktopNodeMTUOwner)
	}
	if err == nil {
		_, err = o.readLocked(ctx)
	}
	if err != nil {
		cleanup, cleanupErr := mobilemtu.OperationCleanupContext(ctx)
		if cleanupErr == nil {
			cleanupErr = o.closeLocked(cleanup)
		}
		return errors.Join(err, cleanupErr)
	}
	return nil
}

func (o *desktopImportedMTUOwner) ChangeMTU(ctx context.Context, expected mobilemtu.State, mtu int) (mobilemtu.State, error) {
	if err := mobilemtu.LockContext(ctx, &o.mu); err != nil {
		return mobilemtu.State{}, err
	}
	defer o.mu.Unlock()
	if !o.mailboxHeld || o.kernel == nil || !mobilemtu.SameOperationContext(ctx, o.operation) || o.sockets.Load() != 0 {
		return mobilemtu.State{}, errors.New("imported MTU mutation has no exclusive original operation")
	}
	cleanup, err := mobilemtu.OperationCleanupOnly(ctx)
	if err != nil || cleanup && mtu != o.originalMTU {
		return mobilemtu.State{}, errors.Join(err, errors.New("imported MTU cleanup changed its original target"))
	}
	record, err := o.readLocked(ctx)
	if err != nil || o.state(record) != expected {
		return o.state(record), errors.Join(err, errors.New("imported MTU mutation replaced its captured reader"))
	}
	if cleanup && record.Restored && !record.Active && record.MTU == o.originalMTU {
		return expected, nil
	}
	state, err := o.kernel.ReadContext(ctx)
	if err != nil {
		return expected, err
	}
	_, changeErr := o.kernel.ChangeContext(ctx, state, mtu)
	after, readErr := o.readLocked(ctx)
	return o.state(after), errors.Join(changeErr, readErr)
}

func (o *desktopImportedMTUOwner) RollbackStateContext(ctx context.Context, expected mobilemtu.State) (mobilemtu.State, error) {
	if err := mobilemtu.LockContext(ctx, &o.mu); err != nil {
		return mobilemtu.State{}, err
	}
	defer o.mu.Unlock()
	cleanup, err := mobilemtu.OperationCleanupOnly(ctx)
	if err != nil || !cleanup || !mobilemtu.SameOperationContext(ctx, o.operation) || o.kernel == nil ||
		expected.Session != o.record.Session || expected.Path != o.state(o.record).Path {
		return mobilemtu.State{}, errors.Join(err, errors.New("imported MTU rollback lost its original operation"))
	}
	o.closeSockets()
	if err := o.cleanupCurrent(ctx); err != nil {
		return mobilemtu.State{}, err
	}
	if _, err := o.kernel.RestoreContext(ctx); err != nil {
		return mobilemtu.State{}, err
	}
	record, err := o.readLocked(ctx)
	return o.state(record), err
}

func (o *desktopImportedMTUOwner) FinalizedRollbackContext(ctx context.Context, expected mobilemtu.State) (mobilemtu.State, error) {
	if err := mobilemtu.LockContext(ctx, &o.mu); err != nil {
		return mobilemtu.State{}, err
	}
	defer o.mu.Unlock()
	cleanup, err := mobilemtu.OperationCleanupOnly(ctx)
	if err != nil || !cleanup || !mobilemtu.SameOperationContext(ctx, o.operation) || o.kernel == nil || o.mailboxHeld || o.committed.Load() {
		return mobilemtu.State{}, errors.Join(err, errors.New("imported MTU final rollback was not joined by its original owner"))
	}
	state, restored, err := o.kernel.CleanupRestoredContext(ctx)
	if err != nil || !restored || state.MTU != o.originalMTU {
		return mobilemtu.State{}, errors.Join(err, errors.New("imported MTU final rollback lacks its exact native receipt"))
	}
	record, err := o.readLocked(ctx)
	actual := o.state(record)
	if err != nil || actual.Session != expected.Session || actual.Path != expected.Path || actual.MTU != expected.MTU || record.MTU != o.originalMTU {
		return mobilemtu.State{}, errors.Join(err, errors.New("imported MTU final rollback changed its original session, path or MTU"))
	}
	return actual, nil
}

func (o *desktopImportedMTUOwner) closeSockets() {
	o.connections.Range(func(key, _ any) bool { _ = key.(*desktopImportedMTUConn).Close(); return true })
}

func (o *desktopImportedMTUOwner) closeLocked(ctx context.Context) error {
	o.closeSockets()
	if o.kernel != nil {
		// A replacement app/session cannot authorize rollback. A checked stop
		// receipt from the original child may retire that exact stale owner.
		if err := o.cleanupCurrent(ctx); err != nil {
			closed, closeErr := readDesktopNodeStoppedContext(ctx, o.launch)
			if closeErr != nil || !closed {
				return errors.Join(err, closeErr)
			}
		}
		if err := o.kernel.CloseContext(ctx); err != nil {
			return err
		}
		if err := mobilemtu.LockContext(ctx, &o.kernel.mu); err != nil {
			return err
		}
		o.record = o.kernel.record
		o.kernel.mu.Unlock()
	}
	if o.sockets.Load() != 0 {
		return errors.New("imported MTU sockets did not join original close")
	}
	if o.mailboxHeld {
		o.mailboxHeld = false
		o.launch.importedDNSMu.Unlock()
	}
	return ctx.Err()
}

func (o *desktopImportedMTUOwner) finish(ctx context.Context, measured bool) error {
	if err := mobilemtu.LockContext(ctx, &o.mu); err != nil {
		return err
	}
	defer o.mu.Unlock()
	if o.kernel == nil || !mobilemtu.SameOperationContext(ctx, o.operation) {
		return errors.New("imported MTU finalization lost its original lease")
	}
	if !measured {
		return errors.New("imported MTU winner lacks fresh authenticated measurements")
	}
	if _, err := o.readLocked(ctx); err != nil {
		return err
	}
	if err := o.kernel.commitWithValidationContext(ctx, func(call context.Context) error {
		if err := o.current(call); err != nil {
			return err
		}
		// kernel.mu is already held here; use its exact acknowledged record
		// without reacquiring it or any ordinary observation mailbox.
		actual, err := readDesktopNodeMTUContext(call, o.launch)
		if err != nil || !sameDesktopImportedMTURecord(actual, o.kernel.record) || actual.Active || actual.Failure != "" ||
			o.launch.importedOpenVPN != nil && (actual.OpenVPN != o.openVPN || o.launch.importedOpenVPN.retired.Load()) {
			return errors.Join(err, errors.New("imported MTU commit lost exact native readback"))
		}
		return o.current(call)
	}); err != nil {
		return err
	}
	o.committed.Store(true)
	return nil
}

func (o *desktopImportedMTUOwner) DialThroughTunnel(ctx context.Context, expected mobilemtu.State, network, address string) (net.Conn, error) {
	if err := mobilemtu.LockContext(ctx, &o.mu); err != nil {
		return nil, err
	}
	defer o.mu.Unlock()
	cleanup, err := mobilemtu.OperationCleanupOnly(ctx)
	if err != nil || cleanup || !o.mailboxHeld || !mobilemtu.SameOperationContext(ctx, o.operation) {
		return nil, errors.Join(err, errors.New("imported MTU probe has no original work authority"))
	}
	host, port, err := net.SplitHostPort(address)
	ip, parseErr := netip.ParseAddr(host)
	if err != nil || parseErr != nil || ip.Zone() != "" || ip.Is4In6() || !ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return nil, errors.New("imported MTU probe destination is not its paired private literal")
	}
	api, err := url.Parse(o.policy.API)
	if err != nil {
		return nil, err
	}
	if network == "tcp" && (host != api.Hostname() || port != api.Port()) || network == "udp" && (host != o.policy.Sink || port != strconv.Itoa(mobilemtu.ProbePort)) || network != "tcp" && network != "udp" {
		return nil, errors.New("imported MTU cannot probe an uncaptured destination or transport")
	}
	record, err := o.readLocked(ctx)
	if err != nil || o.state(record) != expected || !record.Active {
		return nil, errors.Join(err, errors.New("imported MTU probe lost its exact active reader"))
	}
	family := "4"
	if ip.Is6() {
		family = "6"
	}
	current := func(call context.Context) error {
		actual, err := o.readLocked(call)
		if err != nil || o.state(actual) != expected {
			return errors.Join(err, errors.New("imported MTU socket changed its captured reader"))
		}
		return nil
	}
	if o.dial == nil {
		return nil, errors.New("imported MTU lost its retained native socket adapter")
	}
	connection, err := o.dial(ctx, network+family, address, record, current)
	if err != nil {
		if connection != nil {
			_ = connection.Close()
		}
		return nil, err
	}
	if connection == nil {
		return nil, errors.New("imported MTU native socket adapter returned no connection")
	}
	if err := current(ctx); err != nil {
		_ = connection.Close()
		return nil, err
	}
	owned := &desktopImportedMTUConn{Conn: connection, owner: o}
	o.connections.Store(owned, true)
	o.sockets.Add(1)
	context.AfterFunc(ctx, func() { _ = owned.Close() })
	return owned, nil
}

func dialDesktopImportedMTUSocket(ctx context.Context, network, address string, record desktopNodeMTURecord, current func(context.Context) error) (net.Conn, error) {
	dialer := net.Dialer{ControlContext: func(call context.Context, socketNetwork, _ string, raw syscall.RawConn) error {
		return bindDesktopImportedMTUSocket(call, socketNetwork, raw, record, current)
	}}
	return dialer.DialContext(ctx, network, address)
}

type desktopImportedMTUConn struct {
	net.Conn
	owner *desktopImportedMTUOwner
	once  sync.Once
	err   error
}

func (c *desktopImportedMTUConn) Close() error {
	c.once.Do(func() { c.err = c.Conn.Close(); c.owner.connections.Delete(c); c.owner.sockets.Add(-1) })
	return c.err
}

func desktopImportedMTUAutomatic(policy string, jumbo bool) bool {
	return strings.EqualFold(strings.TrimSpace(policy), "auto") && !jumbo
}

func desktopImportedMTUCleanupDeadline(ctx context.Context) (time.Time, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return time.Time{}, errors.New("imported MTU cleanup lost its one captured deadline")
	}
	return deadline, ctx.Err()
}

var _ mobilemtu.Owner = (*desktopImportedMTUOwner)(nil)
var _ mobilemtu.ContextOwner = (*desktopImportedMTUOwner)(nil)
var _ mobilemtu.RollbackOwner = (*desktopImportedMTUOwner)(nil)
var _ mobilemtu.FinalizationRollbackOwner = (*desktopImportedMTUOwner)(nil)
