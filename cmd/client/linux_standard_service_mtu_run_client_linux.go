//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/standardengine"
	"sync/atomic"
	"time"
)

type linuxStandardMTURunFailure struct{ err error }
type linuxStandardMTUClientRun struct {
	peer             *linuxStandardServicePeer
	image, namespace os.FileInfo
	session          string
	exchange         func(context.Context, linuxStandardServiceRequest, *os.File, func()) (linuxStandardServiceResponse, error)

	wire            standardengine.OperationRun
	operation       context.Context
	epoch           *linuxStandardRequestEpoch
	failure         atomic.Pointer[linuxStandardMTURunFailure]
	closed          atomic.Bool
	cleanupDeadline atomic.Int64
}

func (o *linuxStandardServiceMTUOwner) beginRunContext(ctx context.Context) error {
	if o == nil || o.launch == nil {
		return errors.New("standard MTU run has no original owner")
	}
	if err := mobilemtu.LockContext(ctx, &o.launch.mu); err != nil {
		return err
	}
	defer o.launch.mu.Unlock()
	if prior := o.run.Load(); prior != nil && !prior.closed.Load() {
		return errors.New("standard MTU retains an unclosed original run")
	}
	if _, err := o.currentLocked(ctx); err != nil {
		return err
	}
	if o.pending != nil || o.sockets.Load() != 0 {
		return errors.New("standard MTU run preceded original work join")
	}
	n := o.launch.prepared.requestEpoch
	if n == nil || n.startup == nil || n.mtuTransition != nil {
		return errors.New("standard MTU run has no settled original controller observer")
	}
	if err := n.current(ctx, true); err != nil {
		return err
	}
	before, err := desktopnetwork.ParseDesktopNetworkReceipt(n.mtuReceipt)
	if err != nil {
		return err
	}
	response, err := o.rpcLocked(ctx, "mtu-capture", &linuxStandardServiceMTURequest{})
	if err != nil {
		return err
	}
	if response.CaptureSHA256 != standardengine.SHA256(n.startup.Capture) || response.Current != n.mtuBinding || response.Ready != n.mtuReceipt {
		return errors.New("standard MTU run capture differs between original observers")
	}
	deadline, err := mobilemtu.OperationWorkDeadline(ctx)
	if err != nil {
		return err
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	run := &linuxStandardMTUClientRun{operation: ctx, epoch: n, wire: standardengine.OperationRun{CaptureSHA256: response.CaptureSHA256, ID: hex.EncodeToString(nonce[:]), WorkDeadlineNS: deadline.UnixNano(), CleanupBudgetNS: int64(standardengine.OperationRunCleanupLimit), Original: n.mtuBinding, OriginalMTU: before.MTU}}
	run.captureTransport(o.launch)
	o.run.Store(run)
	response, err = run.rpc(ctx, "mtu-run-begin")
	if err == nil {
		err = verifyLinuxStandardMTURunResponse(run, response, false)
	}
	if err == nil && (response.RunState != standardengine.OperationRunOpen || response.CleanupDeadlineNS != 0) {
		err = errors.New("standard MTU admission returned a closed or cleaning run")
	}
	if err != nil {
		// A lost acknowledgement may still own a real run. Accept only a draining
		// generation: every work observation rejects this failure, while the core's
		// finalizer still owns the original token and can fence a delayed Begin.
		run.failure.Store(&linuxStandardMTURunFailure{err: err})
	}
	return nil
}

func verifyLinuxStandardMTURunResponse(run *linuxStandardMTUClientRun, response *linuxStandardServiceMTUResponse, closing bool) error {
	if run == nil || response == nil || response.Run == nil || *response.Run != run.wire || response.RunState > standardengine.OperationRunClosed {
		return errors.New("standard MTU response changed original run")
	}
	if !response.RunRetained && (!closing || response.RunState != standardengine.OperationRunClosed) {
		return errors.New("standard MTU service did not retain original run")
	}
	if response.CleanupDeadlineNS != 0 {
		for {
			old := run.cleanupDeadline.Load()
			if old != 0 && old != response.CleanupDeadlineNS {
				return errors.New("standard MTU cleanup clock was renewed")
			}
			if old == response.CleanupDeadlineNS || run.cleanupDeadline.CompareAndSwap(0, response.CleanupDeadlineNS) {
				break
			}
		}
	}
	return nil
}

// This callback deliberately does not acquire launch.mu: ChangeMTU may already
// hold that gate when cancellation first needs the same shared cleanup clock.
func (o *linuxStandardServiceMTUOwner) cleanupDeadlineContext(ctx context.Context) (time.Time, error) {
	run := o.run.Load()
	if run == nil || run.closed.Load() || !mobilemtu.SameOperationContext(ctx, run.operation) {
		return time.Time{}, errors.New("standard MTU cleanup lost original operation token")
	}
	response, err := run.rpc(ctx, "mtu-run-cleanup")
	if err == nil {
		err = verifyLinuxStandardMTURunResponse(run, response, true)
	}
	if err != nil {
		return time.Time{}, err
	}
	if response.RunState == standardengine.OperationRunClosed {
		run.closed.Store(true)
		return time.Time{}, errors.New("standard MTU run already closed without cleanup work")
	}
	if o.run.Load() != run || run.closed.Load() || response.RunState != standardengine.OperationRunOpen && response.RunState != standardengine.OperationRunClosing || response.CleanupDeadlineNS <= 0 {
		return time.Time{}, errors.New("standard MTU cleanup changed original retained clock")
	}
	return time.Unix(0, response.CleanupDeadlineNS), ctx.Err()
}

func (o *linuxStandardServiceMTUOwner) finishRunContext(original context.Context) error {
	run := o.run.Load()
	if run == nil {
		return nil
	}
	if run.closed.Load() {
		return nil
	}
	if !mobilemtu.SameOperationContext(original, run.operation) {
		return errors.New("standard MTU finalizer lost original operation token")
	}
	ctx := original
	if ctx.Err() != nil {
		var err error
		ctx, err = mobilemtu.OperationCleanupContext(original)
		if err != nil {
			if run.closed.Load() {
				return nil
			}
			return err
		}
	}
	// An expired work read may be retried only with this run's remaining clock.
	for {
		err := o.closeRunAttempt(ctx, run)
		if err == nil {
			return nil
		}
		if ctx == original && original.Err() != nil {
			cleanup, e := mobilemtu.OperationCleanupContext(original)
			if e != nil {
				if run.closed.Load() {
					return nil
				}
				return errors.Join(err, e)
			}
			ctx = cleanup
			continue
		}
		return err
	}
}

func (o *linuxStandardServiceMTUOwner) closeRunAttempt(ctx context.Context, run *linuxStandardMTUClientRun) error {
	if deadline := run.cleanupDeadline.Load(); deadline != 0 {
		bound, cancel := context.WithDeadline(ctx, time.Unix(0, deadline))
		defer cancel()
		ctx = bound
	}

	if err := mobilemtu.LockContext(ctx, &o.launch.mu); err != nil {
		return err
	}
	defer o.launch.mu.Unlock()
	if o.run.Load() != run || run.closed.Load() || o.pending != nil || o.sockets.Load() != 0 {
		return errors.New("standard MTU closure still owns original native work")
	}
	n := o.launch.prepared.requestEpoch
	if n == nil || n != run.epoch || n.mtuTransition != nil {
		return errors.New("standard MTU closure preceded original controller completion")
	}
	for {
		response, err := run.rpc(ctx, "mtu-run-close")
		if err != nil {
			return err
		}
		if err = verifyLinuxStandardMTURunResponse(run, response, true); err != nil {
			return err
		}
		if deadline := run.cleanupDeadline.Load(); deadline != 0 {
			bound, cancel := context.WithDeadline(ctx, time.Unix(0, deadline))
			defer cancel()
			ctx = bound
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if response.RunState == standardengine.OperationRunClosed {
			if o.run.Load() != run {
				return errors.New("standard MTU closure replaced original run")
			}
			run.closed.Store(true)
			return nil
		}
		if response.RunState != standardengine.OperationRunClosing {
			return errors.New("standard MTU child did not accept original closure")
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (o *linuxStandardServiceMTUOwner) requireRunWorkLocked(ctx context.Context, cleanup bool) (*linuxStandardMTUClientRun, error) {
	run := o.run.Load()
	if run == nil || run.closed.Load() || !mobilemtu.SameOperationContext(ctx, run.operation) {
		return nil, errors.New("standard MTU mutation has no original shared run")
	}
	if failed := run.failure.Load(); failed != nil {
		return nil, failed.err
	}
	response, err := run.rpc(ctx, "mtu-run-status")
	if err == nil {
		err = verifyLinuxStandardMTURunResponse(run, response, false)
	}
	if err != nil {
		return nil, err
	}
	if response.RunState != standardengine.OperationRunOpen || !cleanup && response.CleanupDeadlineNS != 0 {
		return nil, errors.New("standard MTU work cannot resume after original cleanup")
	}
	return run, ctx.Err()
}

// RunOperationContext is the captured explicit-operation counterpart to UI
// Retest. Read-only capture does not call it. The callback and finalizer share
// exactly the same original work token and FD11 cleanup clock.
func (o *linuxStandardServiceMTUOwner) RunOperationContext(parent context.Context, request string, work func(context.Context) error) (failure error) {
	if work == nil || request == "" {
		return errors.New("standard MTU operation omitted captured work")
	}
	ctx, finish, err := mobilemtu.WithOperationContextProvider(parent, standardengine.OperationRunWorkLimit, standardengine.OperationRunCleanupLimit, o.cleanupDeadlineContext)
	if err != nil {
		return err
	}
	defer finish()
	if err = o.beginRunContext(ctx); err != nil {
		return err
	}
	defer func() { failure = errors.Join(failure, o.finishRunContext(ctx), ctx.Err()) }()
	if run := o.run.Load(); run != nil {
		if failed := run.failure.Load(); failed != nil {
			return failed.err
		}
	}
	return errors.Join(work(ctx), ctx.Err())
}

func (r *linuxStandardMTUClientRun) captureTransport(o *linuxStandardServiceLaunch) {
	r.peer, r.image, r.namespace, r.session, r.exchange = o.peer, o.image, o.prepared.namespaceInfo, o.request.Session, o.exchange
}

// The cleanup callback cannot borrow launch.mu or a pointer to launch.peer:
// original Stop can close that peer after joining the UI. This immutable
// capture never follows a replacement pointer and RPC uses a local peer slot.
func (r *linuxStandardMTUClientRun) rpc(ctx context.Context, action string) (*linuxStandardServiceMTUResponse, error) {
	if r.peer == nil {
		return nil, errors.New("standard MTU run lost original authenticated peer")
	}
	request := linuxStandardServiceRequest{Schema: 1, Session: r.session, Action: action, MTU: &linuxStandardServiceMTURequest{Run: &r.wire}}
	var response linuxStandardServiceResponse
	var err error
	if r.exchange != nil {
		response, err = r.exchange(ctx, request, nil, nil)
	} else {
		peer := r.peer
		response, err = linuxStandardServiceRPC(ctx, r.image, r.namespace, &peer, request, nil, nil)
		if peer != r.peer {
			err = errors.Join(err, errors.New("standard MTU run replaced original peer"))
		}
	}
	if err != nil {
		return nil, err
	}
	if response.authenticatedPeer != r.peer || response.MTU == nil || response.Protection != nil || response.Startup != nil || response.MTU.ObservationError != "" {
		return nil, errors.New("standard MTU run response lost original service authority")
	}
	if err = r.peer.Current(ctx); err != nil {
		return nil, err
	}
	return response.MTU, nil
}
