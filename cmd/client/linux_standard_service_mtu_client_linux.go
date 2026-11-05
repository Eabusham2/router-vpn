//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/standardengine"
)

// This adapter retains the installed launch and its original controller observer.
// A new service response never creates a replacement capture or connection intent.
type linuxStandardServiceMTUOwner struct {
	run                              atomic.Pointer[linuxStandardMTUClientRun]
	launch                           *linuxStandardServiceLaunch
	connection                       context.Context
	activation                       *linuxStandardServiceMonitor
	config, authority, path, exitRaw string
	pending                          *linuxStandardServiceMTURequest
	pendingRejected                  *linuxStandardServiceMTURejected
	sockets                          atomic.Int32
	retained                         bool
}

func newLinuxStandardServiceMTUOwner(ctx context.Context, launch *linuxStandardServiceLaunch) (*linuxStandardServiceMTUOwner, error) {
	if launch == nil {
		return nil, errors.New("standard MTU has no installed service owner")
	}
	if err := mobilemtu.LockContext(ctx, &launch.mu); err != nil {
		return nil, err
	}
	defer launch.mu.Unlock()
	if launch.mtuOwner != nil {
		if run := launch.mtuOwner.run.Load(); run != nil && !run.closed.Load() {
			return nil, errors.New("standard MTU prior run has not joined closure")
		}
	}
	if launch.mtuOwner != nil && (launch.mtuOwner.pending != nil || launch.mtuOwner.sockets.Load() != 0) {
		return nil, errors.New("standard MTU prior operation still owns native work")
	}
	if launch.mtuExit == nil || !launch.dnsProved || launch.prepared == nil || launch.prepared.requestEpoch == nil {
		return nil, errors.New("standard MTU lacks its original proved exit")
	}
	if err := mobilemtu.LockContext(ctx, &launch.app.mu); err != nil {
		return nil, err
	}
	connection := launch.app.connectionContext
	profile, found := launch.app.profileByIDLocked(launch.request.ProfileID)
	launch.app.mu.Unlock()
	rawMonitor, exists := linuxStandardServiceMonitors.Load(launch)
	activation, ok := rawMonitor.(*linuxStandardServiceMonitor)
	if !exists || !ok || activation == nil || activation.owner != launch || activation.ctx == nil || activation.ctx.Err() != nil || activation.operation == nil || connection != nil && connection != activation.operation {
		return nil, errors.New("standard MTU lost its original successful activation")
	}
	connection = activation.operation
	if !found || profile.MTUPolicy != "auto" {
		return nil, errors.New("standard MTU requires the original Auto profile")
	}
	raw, err := standardengine.ReadSealed(launch.prepared.config, standardengine.MaxConfig)
	if err != nil {
		return nil, err
	}
	source := standardengine.SHA256([]byte(launch.mtuExitRaw))
	authority, err := json.Marshal(map[string]any{"schema": 1, "id": launch.mtuExit.ID, "source_sha256": source, "expected_public_ip": launch.mtuExit.ExpectedPublicIP, "mtu_policy": profile.MTUPolicy, "jumbo_tun": profile.JumboTUN})
	if err != nil {
		return nil, err
	}
	owner := &linuxStandardServiceMTUOwner{launch: launch, connection: connection, activation: activation, config: string(raw), authority: string(authority), exitRaw: launch.mtuExitRaw,
		path: standardengine.SHA256([]byte(launch.request.ConfigSHA256 + ":" + launch.request.NetworkID + ":" + source + ":" + launch.request.ProfileSHA256))}
	if _, err := owner.currentLocked(ctx); err != nil {
		return nil, err
	}
	response, err := owner.rpcLocked(ctx, "mtu-capture", &linuxStandardServiceMTURequest{})
	if err != nil {
		return nil, err
	}
	n := launch.prepared.requestEpoch
	if response.CaptureSHA256 != standardengine.SHA256(n.startup.Capture) || response.Current != n.mtuBinding || response.Ready != n.mtuReceipt {
		return nil, errors.New("standard MTU capture differs between original observers")
	}
	launch.mtuOwner = owner
	owner.retained = true
	return owner, nil
}

func (o *linuxStandardServiceMTUOwner) rpcLocked(ctx context.Context, action string, mtu *linuxStandardServiceMTURequest) (*linuxStandardServiceMTUResponse, error) {
	request := linuxStandardServiceRequest{Schema: 1, Session: o.launch.request.Session, Action: action}
	wire := *mtu
	if action != "mtu-begin" && action != "mtu-capture" && action != "mtu-resolve" {
		wire.MTU = 0
		wire.CleanupOnly = false
		if wire.Reservation != nil {
			wire.ID = ""
			wire.Expected = nil
			wire.DeadlineNS = 0
		}
	}
	request.MTU = &wire
	exchange := o.launch.exchange
	if exchange == nil {
		exchange = func(ctx context.Context, r linuxStandardServiceRequest, f *os.File, before func()) (linuxStandardServiceResponse, error) {
			return linuxStandardServiceRPC(ctx, o.launch.image, o.launch.prepared.namespaceInfo, &o.launch.peer, r, f, before)
		}
	}
	response, err := exchange(ctx, request, nil, nil)
	if err != nil {
		return nil, err
	}
	if response.authenticatedPeer == nil || response.authenticatedPeer != o.launch.peer || response.MTU == nil || response.Protection != nil || response.Startup != nil {
		return nil, errors.New("standard MTU response lost original service authority")
	}
	if err := o.launch.peer.Current(ctx); err != nil {
		return nil, err
	}
	if response.MTU.ObservationError != "" && !mtu.Retiring {
		return nil, errors.New(response.MTU.ObservationError)
	}
	return response.MTU, nil
}

func (o *linuxStandardServiceMTUOwner) intentLocked(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		if ctx != nil {
			return ctx.Err()
		}
		return errors.New("standard MTU has no caller")
	}
	if o == nil || o.launch == nil || o.connection == nil || o.activation == nil || o.activation.ctx == nil || o.activation.ctx.Err() != nil {
		return errors.New("standard MTU original connection ended")
	}
	if o.retained && o.launch.mtuOwner != o {
		return errors.New("standard MTU measurement owner was replaced")
	}
	currentMonitor, monitored := linuxStandardServiceMonitors.Load(o.launch)
	if !monitored || currentMonitor != o.activation || o.activation.operation != o.connection {
		return errors.New("standard MTU original activation was replaced")
	}
	actual, exists := linuxStandardServiceOwners.Load(o.launch.app)
	if err := mobilemtu.LockContext(ctx, &o.launch.app.mu); err != nil {
		return err
	}
	currentIntent := exists && actual == o.launch && o.launch.app.cmd == o.launch.Command() && (o.launch.app.connectionContext == nil || o.launch.app.connectionContext == o.connection) && o.launch.app.connectionCancelIntent != o.connection
	o.launch.app.mu.Unlock()
	if !currentIntent {
		return errors.New("standard MTU original connection was replaced")
	}
	current, err := standardExitByID(o.launch.mtuExit.ID)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(current)
	if err != nil {
		return err
	}
	if string(raw) != o.exitRaw {
		return errors.New("standard MTU original exit was edited")
	}
	if err := mobilemtu.LockContext(ctx, &o.launch.app.mu); err != nil {
		return err
	}
	connected := o.launch.app.state.Connected && o.launch.app.state.Phase == "connected" && o.launch.app.state.RouterID == o.launch.request.RouterID
	o.launch.app.mu.Unlock()
	if !connected {
		return errors.New("standard MTU original session is no longer connected")
	}
	return nil
}
func (o *linuxStandardServiceMTUOwner) currentLocked(ctx context.Context) (mobilemtu.State, error) {
	if run := o.run.Load(); run != nil && !run.closed.Load() {
		if failure := run.failure.Load(); failure != nil {
			return mobilemtu.State{}, failure.err
		}
		if mobilemtu.SameOperationContext(ctx, run.operation) {
			cleanup, e := mobilemtu.OperationCleanupOnly(ctx)
			if e != nil {
				return mobilemtu.State{}, e
			}
			if !cleanup {
				if _, e = o.requireRunWorkLocked(ctx, false); e != nil {
					return mobilemtu.State{}, e
				}
			}
		}
	}
	if err := o.intentLocked(ctx); err != nil {
		return mobilemtu.State{}, err
	}
	n := o.launch.prepared.requestEpoch
	if err := n.current(ctx, true); err != nil {
		return mobilemtu.State{}, err
	}
	receipt, err := desktopnetwork.ParseDesktopNetworkReceipt(n.mtuReceipt)
	if err != nil {
		return mobilemtu.State{}, err
	}
	return mobilemtu.State{Session: o.launch.request.Session, Path: o.path, Interface: fmt.Sprintf("%s:%d:%s", receipt.Name, receipt.Index, receipt.Incarnation), MTU: receipt.MTU}, nil
}
func (o *linuxStandardServiceMTUOwner) requireStateLocked(ctx context.Context, expected mobilemtu.State) (desktopnetwork.DesktopNetworkReceipt, error) {
	current, err := o.currentLocked(ctx)
	if err != nil {
		return desktopnetwork.DesktopNetworkReceipt{}, err
	}
	if current != expected {
		return desktopnetwork.DesktopNetworkReceipt{}, errors.New("standard MTU changed its actual original reader")
	}
	return desktopnetwork.ParseDesktopNetworkReceipt(o.launch.prepared.requestEpoch.mtuReceipt)
}
func (o *linuxStandardServiceMTUOwner) Capture() (mobilemtu.State, error) {
	return mobilemtu.State{}, errors.New("standard MTU capture requires original caller context")
}
func (o *linuxStandardServiceMTUOwner) CaptureContext(ctx context.Context) (mobilemtu.State, error) {
	if err := mobilemtu.LockContext(ctx, &o.launch.mu); err != nil {
		return mobilemtu.State{}, err
	}
	defer o.launch.mu.Unlock()
	return o.currentLocked(ctx)
}
func (o *linuxStandardServiceMTUOwner) RollbackStateContext(ctx context.Context, expected mobilemtu.State) (mobilemtu.State, error) {
	if err := mobilemtu.LockContext(ctx, &o.launch.mu); err != nil {
		return mobilemtu.State{}, err
	}
	defer o.launch.mu.Unlock()
	if o.pending != nil {
		if _, err := o.finishLocked(ctx, true); err != nil {
			return mobilemtu.State{}, err
		}
	}
	current, err := o.currentLocked(ctx)
	if err != nil {
		return current, err
	}
	if current.Session != expected.Session || current.Path != expected.Path {
		return mobilemtu.State{}, errors.New("standard MTU rollback lost original path")
	}
	return current, nil
}
func (o *linuxStandardServiceMTUOwner) ChangeMTU(ctx context.Context, expected mobilemtu.State, mtu int) (mobilemtu.State, error) {
	if err := mobilemtu.LockContext(ctx, &o.launch.mu); err != nil {
		return mobilemtu.State{}, err
	}
	defer o.launch.mu.Unlock()
	if _, err := o.requireStateLocked(ctx, expected); err != nil {
		return mobilemtu.State{}, err
	}
	if o.sockets.Load() != 0 {
		return mobilemtu.State{}, errors.New("standard MTU still owns unjoined measurement sockets")
	}
	if mtu < 1280 || mtu > 9000 {
		return mobilemtu.State{}, errors.New("standard MTU candidate outside native bounds")
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return mobilemtu.State{}, errors.New("standard MTU requires bounded original operation")
	}
	cleanupOnly, err := mobilemtu.OperationCleanupOnly(ctx)
	if err != nil {
		return mobilemtu.State{}, err
	}
	run, err := o.requireRunWorkLocked(ctx, cleanupOnly)
	if err != nil {
		return mobilemtu.State{}, err
	}
	if cleanupOnly && mtu != run.wire.OriginalMTU {
		return mobilemtu.State{}, errors.New("standard MTU cleanup changed captured original restore MTU")
	}
	if mtu == expected.MTU {
		return expected, ctx.Err() // Fresh actual readback above; no native mutation.
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return mobilemtu.State{}, err
	}
	n := o.launch.prepared.requestEpoch
	key := standardengine.OperationKey{CaptureSHA256: standardengine.SHA256(n.startup.Capture), ID: hex.EncodeToString(nonce[:]), DeadlineNS: deadline.Add(-time.Millisecond).UnixNano(), Original: n.mtuBinding}
	if err := n.beginMTU(ctx, key); err != nil {
		cleanup := ctx
		if ctx.Err() != nil {
			if original, cleanupErr := mobilemtu.OperationCleanupContext(ctx); cleanupErr == nil {
				cleanup = original
			}
		}
		return mobilemtu.State{}, errors.Join(err, n.abandonUnsentMTU(cleanup, key))
	}
	o.pending = &linuxStandardServiceMTURequest{ID: key.ID, MTU: mtu, DeadlineNS: key.DeadlineNS, Expected: &key.Original, Run: &run.wire, CleanupOnly: cleanupOnly}
	response, beginErr := o.rpcLocked(ctx, "mtu-begin", o.pending)
	if beginErr == nil && response.Rejected != nil {
		err := o.rejectLocked(ctx, response, false)
		if o.pending == nil {
			return mobilemtu.State{}, err
		}
		beginErr = err
	} else if beginErr == nil {
		beginErr = o.bindCommandLocked(response.Command)
	}
	work := ctx
	cancelled := false
	if beginErr != nil || ctx.Err() != nil {
		cleanup, err := mobilemtu.OperationCleanupContext(ctx)
		if err != nil {
			return mobilemtu.State{}, errors.Join(beginErr, err)
		}
		work = cleanup
		cancelled = true
	}
	state, err := o.finishLocked(work, cancelled)
	if err != nil && ctx.Err() != nil && !cancelled {
		cleanup, cleanupErr := mobilemtu.OperationCleanupContext(ctx)
		if cleanupErr != nil {
			return state, errors.Join(err, cleanupErr)
		}
		state, err = o.finishLocked(cleanup, true)
	}
	return state, errors.Join(beginErr, ctx.Err(), err)
}
func (o *linuxStandardServiceMTUOwner) bindCommandLocked(command *standardengine.OperationCommand) error {
	if command == nil || o.pending == nil || command.MTU != o.pending.MTU {
		return errors.New("standard MTU service omitted original command")
	}
	k := command.Reservation.Key
	if k.ID != o.pending.ID || k.DeadlineNS != o.pending.DeadlineNS || o.pending.Expected == nil || k.Original != *o.pending.Expected {
		return errors.New("standard MTU service changed original command")
	}
	if err := o.launch.prepared.requestEpoch.bindMTU(k); err != nil {
		return err
	}
	reservation := command.Reservation
	o.pending.Reservation = &reservation
	return nil
}
func (o *linuxStandardServiceMTUOwner) finishLocked(ctx context.Context, cancelled bool) (mobilemtu.State, error) {
	return o.finishOperationLocked(ctx, cancelled, false)
}

// An explicit Stop can retry only the retained failed native cleanup. This does
// not authorize another candidate, a measurement, or a renewed work deadline.
func (o *linuxStandardServiceMTUOwner) finishStopLocked(ctx context.Context) (mobilemtu.State, error) {
	return o.finishOperationLocked(ctx, true, true)
}
func (o *linuxStandardServiceMTUOwner) finishOperationLocked(ctx context.Context, cancelled, explicitStop bool) (mobilemtu.State, error) {
	cleanupSent := false
	followup := func() *linuxStandardServiceMTURequest {
		request := *o.pending
		request.Retiring = explicitStop
		request.CleanupOnly = false
		return &request
	}
	if o.pending == nil {
		return o.currentLocked(ctx)
	}
	if cancelled {
		response, err := o.rpcLocked(ctx, "mtu-cancel", followup())
		if err != nil {
			return mobilemtu.State{}, err
		}
		if response.Rejected != nil {
			return mobilemtu.State{}, o.rejectLocked(ctx, response, explicitStop)
		}
	}
	for {
		response, err := o.rpcLocked(ctx, "mtu-status", followup())
		if err != nil {
			return mobilemtu.State{}, err
		}
		if response.Rejected != nil {
			return mobilemtu.State{}, o.rejectLocked(ctx, response, explicitStop)
		}
		if response.Command != nil {
			if err := o.bindCommandLocked(response.Command); err != nil {
				return mobilemtu.State{}, err
			}
		}
		if response.Pending && explicitStop && !cleanupSent && response.Result != nil && response.Result.WorkerJoined && response.Result.Pending && o.pending.Reservation != nil {
			if _, err := o.rpcLocked(ctx, "mtu-cleanup", followup()); err != nil {
				return mobilemtu.State{}, err
			}
			cleanupSent = true
		}
		if response.Pending {
			timer := time.NewTimer(20 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return mobilemtu.State{}, ctx.Err()
			case <-timer.C:
			}
			continue
		}
		if response.Command == nil || response.Result == nil || o.pending.Reservation == nil {
			return mobilemtu.State{}, errors.New("standard MTU result lost its native reservation")
		}
		report := standardengine.OperationReport{Command: *response.Command, Result: *response.Result}
		if o.pending.Run != nil {
			sum, e := o.pending.Run.SHA256()
			if e != nil || report.Result.RunSHA256 != sum || report.Result.CleanupOnly != o.pending.CleanupOnly {
				return mobilemtu.State{}, errors.New("standard MTU result changed original run authority")
			}
		}
		for role := standardengine.OperationRole(0); role < standardengine.OperationReaders; role++ {
			for phase := standardengine.ReadyEvidence; phase <= standardengine.RetirementEvidence; phase++ {
				mask := report.Result.ReadyMask
				if phase == standardengine.RetirementEvidence {
					mask = report.Result.RetirementMask
				}
				if mask&(1<<role) == 0 {
					continue
				}
				request := *followup()
				request.Digest, request.Role, request.Phase = report.Result.Digest, role, phase
				binding, raw, err := o.readEvidenceLocked(ctx, &request)
				if err != nil {
					return mobilemtu.State{}, err
				}
				if report.Readers[role] == nil {
					report.Readers[role] = &standardengine.OperationReaderEvidence{Binding: binding}
				} else if report.Readers[role].Binding != binding {
					return mobilemtu.State{}, errors.New("standard MTU evidence reader changed")
				}
				if phase == standardengine.ReadyEvidence {
					report.Readers[role].Ready = raw
				} else {
					report.Readers[role].Retirement = raw
				}
			}
		}
		n := o.launch.prepared.requestEpoch
		if explicitStop {
			if err := n.retireMTUForStop(ctx, report); err != nil {
				return mobilemtu.State{}, err
			}
			o.pending = nil
			return mobilemtu.State{}, nil
		}
		if err := n.endMTU(ctx, report); err != nil {
			return mobilemtu.State{}, err
		}
		ack := *o.pending
		ack.Digest = report.Result.Digest
		settled, err := o.rpcLocked(ctx, "mtu-ack", &ack)
		if err != nil {
			return mobilemtu.State{}, err
		}
		if !settled.Settled {
			return mobilemtu.State{}, errors.New("standard MTU original observers have not settled")
		}
		settleErr := n.settledMTU(ctx, report.Command.Reservation.Key, report.Result.Digest)
		if n.mtuTransition == nil {
			o.pending = nil
		}
		if settleErr != nil {
			return mobilemtu.State{}, settleErr
		}
		state, err := o.currentLocked(ctx)
		if report.Result.Failed {
			err = errors.Join(err, errors.New("standard native MTU candidate failed and joined rollback"))
		}
		return state, err
	}
}

func (o *linuxStandardServiceMTUOwner) rejectLocked(ctx context.Context, response *linuxStandardServiceMTUResponse, retiring bool) error {
	n := o.launch.prepared.requestEpoch
	if response == nil || response.Rejected == nil || o.pending == nil || response.Pending || response.Command != nil || response.Result != nil ||
		response.CaptureSHA256 != standardengine.SHA256(n.startup.Capture) || response.Current != n.mtuBinding || response.Ready != n.mtuReceipt ||
		response.Rejected.ID != o.pending.ID || response.Rejected.DeadlineNS != o.pending.DeadlineNS || o.pending.Expected == nil || response.Rejected.Expected != *o.pending.Expected || response.Rejected.Reason == "" || len(response.Rejected.Reason) > 2048 {
		return errors.New("standard MTU rejection lost its definitively unsubmitted original intent")
	}
	var err error
	if retiring {
		err = n.retireRejectedMTUForStop(ctx, *response.Rejected)
		if n.mtuTransition == nil {
			o.pending = nil
			o.pendingRejected = nil
		}
		if err != nil {
			return err
		}
	} else {
		if o.pendingRejected == nil {
			if err = n.rejectMTU(ctx, *response.Rejected); err != nil {
				return err
			}
			copy := *response.Rejected
			o.pendingRejected = &copy
		} else if *o.pendingRejected != *response.Rejected {
			return errors.New("standard MTU rejection changed after controller completion")
		}
		if err = n.sources(ctx); err != nil {
			return err
		}
		ack := *o.pending
		ack.CleanupOnly = false
		settled, err := o.rpcLocked(ctx, "mtu-reject-ack", &ack)
		if err != nil {
			return err
		}
		if !settled.Settled || settled.Rejected == nil || *settled.Rejected != *o.pendingRejected {
			return errors.New("standard MTU unsubmitted observers have not settled")
		}
		o.pending = nil
		o.pendingRejected = nil
	}

	return errors.New(response.Rejected.Reason)
}

// Chunks retain the exact raw byte sequence; JSON base64 avoids UTF-8 boundary
// rewriting. Every bounded part is tied to the same joined report and binding.
func (o *linuxStandardServiceMTUOwner) readEvidenceLocked(ctx context.Context, request *linuxStandardServiceMTURequest) (standardengine.ReaderBinding, []byte, error) {
	var binding standardengine.ReaderBinding
	var raw []byte
	size := 0
	limit := 48 << 10
	if request.Phase == standardengine.ReadyEvidence {
		limit = 16 << 10
	}
	for {
		part := *request
		part.Offset = len(raw)
		response, err := o.rpcLocked(ctx, "mtu-evidence", &part)
		if err != nil {
			return binding, nil, err
		}
		if response.Binding == nil || response.Result == nil || response.Result.Digest != request.Digest || response.Command == nil || request.Reservation == nil || response.Command.Reservation != *request.Reservation || response.Pending || response.Rejected != nil || response.Ready != "" ||
			response.EvidenceSize <= 0 || response.EvidenceSize > limit || len(response.Evidence) == 0 || len(response.Evidence) > linuxStandardServiceMTUEvidencePart || response.NextOffset != len(raw)+len(response.Evidence) || response.NextOffset > response.EvidenceSize {
			return binding, nil, errors.New("standard MTU evidence chunk lost its original bounded report")
		}
		if len(raw) == 0 {
			binding = *response.Binding
			size = response.EvidenceSize
		} else if binding != *response.Binding || size != response.EvidenceSize {
			return binding, nil, errors.New("standard MTU evidence changed between original chunks")
		}
		if response.NextOffset < size && len(response.Evidence) != linuxStandardServiceMTUEvidencePart {
			return binding, nil, errors.New("standard MTU evidence shortened an intermediate chunk")
		}
		raw = append(raw, response.Evidence...)
		if len(raw) == size {
			return binding, raw, nil
		}
	}
}

// Read-only views use the original successful activation even after the Connect
// request has finished. Fixed/Jumbo status does not create an optimizer owner.
func captureLinuxStandardServiceMTUReadback(ctx context.Context, launch *linuxStandardServiceLaunch) (mobilemtu.State, common.RouterProfile, context.Context, error) {
	if launch == nil {
		return mobilemtu.State{}, common.RouterProfile{}, nil, errors.New("standard MTU readback has no original launch")
	}
	if err := mobilemtu.LockContext(ctx, &launch.mu); err != nil {
		return mobilemtu.State{}, common.RouterProfile{}, nil, err
	}
	defer launch.mu.Unlock()
	state, profile, activation, err := captureLinuxStandardServiceMTUReadbackLocked(ctx, launch)
	if err != nil {
		return state, profile, nil, err
	}
	return state, profile, activation.ctx, nil
}
func linuxStandardServiceMTUActivationContext(ctx context.Context, launch *linuxStandardServiceLaunch) (context.Context, error) {
	if launch == nil {
		return nil, errors.New("standard MTU lifetime has no original launch")
	}
	if err := mobilemtu.LockContext(ctx, &launch.mu); err != nil {
		return nil, err
	}
	defer launch.mu.Unlock()
	_, _, activation, err := captureLinuxStandardServiceMTUReadbackLocked(ctx, launch)
	if err != nil {
		return nil, err
	}
	return activation.ctx, nil
}
func captureLinuxStandardServiceMTUReadbackLocked(ctx context.Context, launch *linuxStandardServiceLaunch) (mobilemtu.State, common.RouterProfile, *linuxStandardServiceMonitor, error) {
	bad := errors.New("standard MTU readback lost its original proved activation")
	var profile common.RouterProfile
	if launch.prepared == nil || launch.prepared.requestEpoch == nil || launch.mtuExit == nil || !launch.dnsProved {
		return mobilemtu.State{}, profile, nil, bad
	}
	raw, exists := linuxStandardServiceMonitors.Load(launch)
	activation, ok := raw.(*linuxStandardServiceMonitor)
	if !exists || !ok || activation == nil || activation.owner != launch || activation.operation == nil || activation.ctx == nil || activation.ctx.Err() != nil {
		return mobilemtu.State{}, profile, nil, bad
	}
	source := standardengine.SHA256([]byte(launch.mtuExitRaw))
	owner := &linuxStandardServiceMTUOwner{launch: launch, connection: activation.operation, activation: activation, exitRaw: launch.mtuExitRaw, path: standardengine.SHA256([]byte(launch.request.ConfigSHA256 + ":" + launch.request.NetworkID + ":" + source + ":" + launch.request.ProfileSHA256))}
	state, err := owner.currentLocked(ctx)
	if err != nil {
		return mobilemtu.State{}, profile, nil, err
	}
	if err := mobilemtu.LockContext(ctx, &launch.app.mu); err != nil {
		return mobilemtu.State{}, profile, nil, err
	}
	captured, found := launch.app.profileByIDLocked(launch.request.ProfileID)
	encoded, encodeErr := json.Marshal(captured)
	launch.app.mu.Unlock()
	if !found || encodeErr != nil || json.Unmarshal(encoded, &profile) != nil {
		return mobilemtu.State{}, profile, nil, bad
	}
	if err := ctx.Err(); err != nil {
		return mobilemtu.State{}, profile, nil, err
	}
	return state, profile, activation, nil
}
