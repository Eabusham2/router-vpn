package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"router-vpn/internal/mobilemtu"
)

type desktopImportedMTUUI struct {
	mu         sync.Mutex
	a          *app
	runtime    *nativeMultihopRuntime
	owner      *desktopImportedMTUOwner
	controller *mobilemtu.Controller
	cache      *desktopImportedMTUCache
	identity   mtuViewIdentity
	operation  *mtuViewOperation
	running    bool
}

var desktopImportedMTUUIs sync.Map // One retained original controller per app.

func getDesktopImportedMTUUI(ctx context.Context, a *app, runtime *nativeMultihopRuntime) (*desktopImportedMTUUI, error) {
	if raw, found := desktopImportedMTUUIs.Load(a); found {
		previous := raw.(*desktopImportedMTUUI)
		if previous.runtime == runtime {
			if err := previous.owner.current(ctx); err != nil {
				return nil, err
			}
			return previous, nil
		}
		if err := previous.releaseObserved(ctx); err != nil {
			return nil, err
		}
	}
	profile := runtime.selection.Exit
	raw, policy, err := readDesktopImportedMTUPolicyContext(ctx, runtime.selection)
	if err != nil {
		return nil, err
	}
	if !policy.Automatic || policy.Jumbo {
		return nil, errors.New("choose compatible Auto MTU without shared Jumbo on the captured entry and final before Retest")
	}
	owner, err := newDesktopImportedMTUOwner(ctx, a, runtime, policy)
	if err != nil {
		return nil, err
	}
	u := &desktopImportedMTUUI{a: a, runtime: runtime, owner: owner, identity: mtuViewIdentity{Session: runtime.launch.mtuSession, Profile: profile.ID, Native: true}}
	u.cache = &desktopImportedMTUCache{ui: u}
	u.controller, err = mobilemtu.NewContext(ctx, owner, owner.config, raw, u.cache)
	if err != nil {
		return nil, err
	}
	if err := owner.current(ctx); err != nil {
		return nil, err
	}
	desktopImportedMTUUIs.Store(a, u)
	return u, nil
}

func desktopImportedMTUStatusContext(ctx context.Context, controller *mobilemtu.Controller) (mobilemtu.Status, error) {
	raw, err := controller.StatusJSONContext(ctx)
	if err != nil {
		return mobilemtu.Status{}, err
	}
	var status mobilemtu.Status
	err = decodeRelayControlJSON([]byte(raw), &status)
	return status, err
}

func (a *app) retestDesktopImportedMTU(w http.ResponseWriter, r *http.Request, request mtuViewRequest) bool {
	runtime, handled, err := desktopImportedMTURuntime(r.Context(), a)
	if !handled {
		return false
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return true
	}
	u, err := getDesktopImportedMTUUI(r.Context(), a, runtime)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return true
	}
	ctx, operation, err := beginMTUViewOperation(a, r.Context(), request, u.identity)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return true
	}
	writer := &mtuViewResponse{ResponseWriter: w, operation: operation}
	defer writer.finish()
	status, err := u.run(ctx, operation)
	if err != nil {
		http.Error(writer, "Imported path MTU: "+err.Error(), http.StatusConflict)
		return true
	}
	writer.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{"ok": true, "effective_mtu": status.EffectiveMTU, "effective_mtu_source": status.Source, "result": status,
		"note": "Authenticated private-node packet-size replies and transferred-byte upload/download through this retained native TUN; the entry endpoint, selected final, DNS and graph envelope remain captured."})
	return true
}

func (u *desktopImportedMTUUI) run(parent context.Context, operation *mtuViewOperation) (result mobilemtu.Status, failure error) {
	if err := mobilemtu.LockContext(parent, &u.mu); err != nil {
		return result, err
	}
	if u.running {
		u.mu.Unlock()
		return result, errors.New("original imported MTU operation is still running")
	}
	if err := u.owner.current(parent); err != nil {
		u.mu.Unlock()
		return result, err
	}
	if err := mobilemtu.LockContext(parent, &u.owner.mu); err != nil {
		u.mu.Unlock()
		return result, err
	}
	pending := u.owner.mailboxHeld || u.owner.sockets.Load() != 0 || !u.owner.committed.Load() && u.cache.written != ""
	if !pending {
		// A new request cannot borrow the previous run's accepted-commit bit
		// while its own native admission is waiting or has been cancelled.
		u.owner.committed.Store(false)
	}
	u.owner.mu.Unlock()
	if pending {
		u.mu.Unlock()
		return result, errors.New("original imported MTU native or historical rollback remains unresolved")
	}
	u.running, u.operation = true, operation
	u.cache.written = ""
	u.mu.Unlock()
	operation.mu.Lock()
	operation.cancelCaptured = func(call context.Context) error {
		if err := call.Err(); err != nil {
			return err
		}
		if u.owner.committed.Load() {
			return mobilemtu.ErrOperationCommitted
		}
		return nil
	}
	operation.mu.Unlock()
	defer func() {
		u.mu.Lock()
		u.running = false
		u.mu.Unlock()
		operation.mu.Lock()
		operation.status = result
		operation.mu.Unlock()
	}()
	finalize := func(original context.Context) error {
		cleanup, err := mobilemtu.OperationCleanupContext(original)
		if err != nil {
			return err
		}
		// Reading completion after cancellation grants cleanup only. Commit
		// still receives the unrenewed original work context below.
		status, statusErr := desktopImportedMTUStatusContext(cleanup, u.controller)
		var commitErr error
		if statusErr == nil && status.Measured && original.Err() == nil {
			commitErr = u.owner.finish(original, true)
		} else if status.Measured {
			commitErr = errors.Join(statusErr, original.Err())
		}
		var durableErr error
		if !u.owner.committed.Load() {
			durableErr = u.cache.restore(cleanup)
		}
		if lockErr := mobilemtu.LockContext(cleanup, &u.owner.mu); lockErr != nil {
			return errors.Join(commitErr, statusErr, durableErr, lockErr)
		}
		closeErr := u.owner.closeLocked(cleanup)
		u.owner.mu.Unlock()
		return errors.Join(commitErr, statusErr, durableErr, closeErr)
	}
	failure = u.controller.RunContextWithCleanupProvider(parent, parent, operation.request, !operation.automatic,
		desktopImportedMTUCleanupDeadline, func(ctx context.Context) error { return u.owner.prepare(ctx, operation.request) }, finalize)
	// This observation cannot submit a candidate, renew cleanup, or commit.
	observe, stop := context.WithTimeout(context.WithoutCancel(parent), 2*time.Second)
	defer stop()
	status, err := desktopImportedMTUStatusContext(observe, u.controller)
	if err == nil {
		result = status
	} else {
		failure = errors.Join(failure, err)
	}
	if result.Request != operation.request {
		result = mobilemtu.Status{Request: operation.request, Phase: "failed", Complete: true, Source: "unmeasured", Candidates: []mobilemtu.Candidate{}}
	}
	if err := mobilemtu.LockContext(observe, &u.owner.mu); err != nil {
		operation.mu.Lock()
		operation.cleanupPending = true
		operation.mu.Unlock()
		return result, errors.Join(failure, err)
	}
	pending = u.owner.mailboxHeld || u.owner.sockets.Load() != 0
	kernel := u.owner.kernel
	u.owner.mu.Unlock()
	if kernel != nil {
		if restored, ok, err := kernel.CleanupRestoredContext(observe); err != nil {
			failure = errors.Join(failure, err)
		} else if ok {
			live, freshErr := u.owner.CaptureContext(observe)
			if freshErr == nil && live.MTU == restored.MTU {
				result.Restored, result.EffectiveMTU, result.Source = true, restored.MTU, "restored-captured-interface"
			} else {
				result.Restored, result.EffectiveMTU, result.Source = false, 0, "unavailable-stale-owner"
				failure = errors.Join(failure, freshErr, errors.New("imported MTU rollback has no fresh original-path observation"))
			}
		}
	}
	if pending {
		operation.mu.Lock()
		operation.cleanupPending = true
		operation.mu.Unlock()
		failure = errors.Join(failure, errors.New("original imported MTU cleanup remains pending"))
	}
	if failure != nil || !u.owner.committed.Load() {
		result.Measured = false
		return result, errors.Join(failure, errors.New("imported MTU did not retain a measured native commit"))
	}
	live, err := u.owner.CaptureContext(observe)
	if err != nil || !result.Measured || !result.Complete || result.Running || result.EffectiveMTU != live.MTU {
		result.Measured = false
		return result, errors.Join(err, errors.New("imported MTU result lost its exact final readback"))
	}
	if raw, found := routerNodeAutomaticMTUs.Load(u.a); found {
		automatic := raw.(*routerNodeAutomaticMTU)
		automatic.mu.Lock()
		if automatic.command == u.runtime.launch.command {
			automatic.completed, automatic.attempted, automatic.resume = true, true, false
		}
		automatic.mu.Unlock()
	}
	return result, nil
}

// After the original cleanup allowance expires, a later transition can only
// consume an already restored lease or checked original child retirement. It
// cannot renew that allowance and issue another mutation.
func (u *desktopImportedMTUUI) releaseObserved(ctx context.Context) error {
	if err := mobilemtu.LockContext(ctx, &u.mu); err != nil {
		return err
	}
	defer u.mu.Unlock()
	if u.running {
		return errors.New("captured imported MTU worker has not joined")
	}
	o := u.owner
	if err := mobilemtu.LockContext(ctx, &o.mu); err != nil {
		return err
	}
	defer o.mu.Unlock()
	if !o.mailboxHeld {
		return nil
	}
	if o.kernel == nil {
		return errors.New("pending imported MTU omitted its retained native owner")
	}
	if err := mobilemtu.LockContext(ctx, &o.kernel.mu); err != nil {
		return err
	}
	defer o.kernel.mu.Unlock()
	// CloseContext records retirement only after verifying this exact native
	// child's stop receipt. Workspace cleanup may remove that already-checked
	// file before this later read-only release; neither flag alone suffices.
	closed := o.kernel.closed && o.kernel.runtimeRetired
	if !closed {
		var err error
		closed, err = readDesktopNodeStoppedContext(ctx, o.launch)
		if err != nil {
			return err
		}
	}
	if closed {
		o.kernel.closed, o.kernel.runtimeRetired, o.kernel.pending = true, true, nil
		o.kernel.discardCommitRevert()
	} else if !o.kernel.closed {
		record, err := readDesktopNodeMTUContext(ctx, o.launch)
		if err != nil {
			return err
		}
		restored, err := o.kernel.acceptExpiredRestorationContext(ctx, record)
		if err != nil || !restored {
			return errors.Join(err, errors.New("imported MTU original cleanup remains unresolved"))
		}
		o.kernel.closed = true
	}
	// A checked closed lease permits releasing only its own mailbox. Reporting
	// restored additionally needs fresh native and original-path observations;
	// the retained numeric value cannot attest to a currently live interface.
	restored := false
	if !closed {
		actual, readErr := readDesktopNodeMTUContext(ctx, o.launch)
		restored = readErr == nil && sameDesktopImportedMTURecord(actual, o.kernel.record) && actual.Restored && !actual.Active &&
			actual.MTU == o.originalMTU && o.packetRecordCurrent(actual) == nil && o.current(ctx) == nil
	}
	o.record = o.kernel.record
	o.mailboxHeld = false
	o.launch.importedDNSMu.Unlock()
	if u.operation != nil {
		u.operation.mu.Lock()
		u.operation.cleanupPending = false
		u.operation.status.Running, u.operation.status.Complete, u.operation.status.Measured = false, true, false
		u.operation.status.Restored = restored
		if u.operation.status.Restored {
			u.operation.status.EffectiveMTU, u.operation.status.Source, u.operation.status.Phase = o.record.MTU, "restored-captured-interface", "restored"
		} else {
			u.operation.status.EffectiveMTU, u.operation.status.Source, u.operation.status.Phase = 0, "unavailable-stale-owner", "failed"
		}
		u.operation.mu.Unlock()
	}
	return ctx.Err()
}

func closeDesktopImportedMTUForHold(ctx context.Context, a *app) error {
	if raw, found := desktopImportedMTUUIs.Load(a); found {
		return raw.(*desktopImportedMTUUI).releaseObserved(ctx)
	}
	return nil
}

func (a *app) writeDesktopImportedMTUViewStatus(w http.ResponseWriter, r *http.Request, request, session string) bool {
	runtime, handled, err := desktopImportedMTURuntime(r.Context(), a)
	if !handled {
		return false
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return true
	}
	identity := mtuViewIdentity{Session: runtime.launch.mtuSession, Profile: runtime.selection.Exit.ID, Native: true}
	if session != "" && session != identity.Session {
		http.Error(w, "imported MTU connection was replaced", http.StatusConflict)
		return true
	}
	_, policy, err := readDesktopImportedMTUPolicyContext(r.Context(), runtime.selection)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return true
	}
	live, err := readDesktopNodeMTUContext(r.Context(), runtime.launch)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return true
	}
	status := mobilemtu.Status{Phase: "idle", EffectiveMTU: live.MTU, Source: "live-captured-interface", Candidates: []mobilemtu.Candidate{}}
	requested := false
	if raw, found := desktopImportedMTUUIs.Load(a); found {
		u := raw.(*desktopImportedMTUUI)
		if u.runtime == runtime {
			if err := mobilemtu.LockContext(r.Context(), &u.mu); err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return true
			}
			running, operation := u.running, u.operation
			u.mu.Unlock()
			if operation != nil {
				requested = true
				if running {
					status, err = desktopImportedMTUStatusContext(r.Context(), u.controller)
				} else {
					if err := mobilemtu.LockContext(r.Context(), &operation.mu); err != nil {
						http.Error(w, err.Error(), http.StatusConflict)
						return true
					}
					status = operation.status
					operation.mu.Unlock()
				}
				if !running && status.Measured {
					current, currentErr := u.owner.CaptureContext(r.Context())
					if currentErr != nil || live.Active || live.Failure != "" || current.MTU != status.EffectiveMTU || current.MTU != live.MTU {
						http.Error(w, "imported MTU result lost its original current reader", http.StatusConflict)
						return true
					}
				}
				if err != nil {
					http.Error(w, err.Error(), http.StatusConflict)
					return true
				}
				status.Request = operation.request
				if running {
					status.Running, status.Complete, status.Measured, status.EffectiveMTU, status.Source = true, false, false, live.MTU, "live-captured-interface"
				}
			}
		}
	}
	if request != "" && request != status.Request {
		http.Error(w, "imported MTU request has not started or was replaced", http.StatusNotFound)
		return true
	}
	if err := desktopImportedMTURuntimeCurrent(r.Context(), a, runtime); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return true
	}
	writeMTUViewStatus(w, identity, requested, false, policy.Automatic && !policy.Jumbo, status)
	return true
}

func (a *app) startDesktopImportedAutomaticMTU() bool {
	raw, found := nativeMultihopOwners.Load(a)
	runtime, ok := raw.(*nativeMultihopRuntime)
	if !found || !ok || runtime == nil || runtime.selection.Native == nil || !runtime.selection.Native.imported {
		return false
	}
	if runtime.launch == nil {
		return true
	}
	profile := runtime.selection.Exit
	// This read-only eligibility check cannot begin a measurement. The worker
	// below still proves the same live runtime before public Retest admission.
	_, policy, err := readDesktopImportedMTUPolicyContext(context.Background(), runtime.selection)
	if err != nil || !policy.Automatic || policy.Jumbo || mtuSuspended(a) {
		return true
	}
	command := runtime.launch.command
	raw, _ = routerNodeAutomaticMTUs.LoadOrStore(a, &routerNodeAutomaticMTU{command: command})
	automatic := raw.(*routerNodeAutomaticMTU)
	automatic.mu.Lock()
	if automatic.command != command {
		automatic.command, automatic.waiting, automatic.attempted, automatic.completed, automatic.resume = command, false, false, false, false
	}
	if automatic.waiting || automatic.attempted {
		if automatic.waiting && !automatic.attempted {
			automatic.resume = true
		}
		automatic.mu.Unlock()
		return true
	}
	automatic.waiting, automatic.resume = true, false
	automatic.mu.Unlock()
	go func() {
		defer func() {
			automatic.mu.Lock()
			resume := automatic.command == command && automatic.resume && !automatic.completed
			if automatic.command == command {
				automatic.waiting = false
			}
			automatic.mu.Unlock()
			if resume && !mtuSuspended(a) && a.ownsConnectionRuntime(command) {
				a.startRouterNodeAutomaticMTU()
			}
		}()
		ready, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		ticker := time.NewTicker(25 * time.Millisecond)
		defer ticker.Stop()
		for {
			if !a.ownsConnectionRuntime(command) {
				return
			}
			if mtuSuspended(a) {
				automatic.resumeAfterHold(command)
				return
			}
			if a.operationMu.TryLock() {
				a.operationMu.Unlock()
				break
			}
			select {
			case <-ready.Done():
				return
			case <-ticker.C:
			}
		}
		if err := desktopImportedMTURuntimeCurrent(ready, a, runtime); err != nil {
			return
		}
		automatic.mu.Lock()
		if automatic.command != command || automatic.attempted {
			automatic.mu.Unlock()
			return
		}
		automatic.attempted = true
		automatic.mu.Unlock()
		encoded, _ := json.Marshal(mtuViewRequest{Session: runtime.launch.mtuSession, Profile: profile.ID})
		attempt := &mtuAutomaticAttempt{}
		ctx := context.WithValue(context.Background(), mtuAutomaticContextKey{}, attempt)
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, "/api/mtu/retest", bytes.NewReader(encoded))
		if err != nil {
			return
		}
		a.retestMTU(&mtuAutomaticResponse{header: make(http.Header)}, request)
		if !attempt.accepted.Load() && attempt.retry.Load() {
			automatic.mu.Lock()
			if automatic.command == command {
				automatic.attempted, automatic.resume = false, true
			}
			automatic.mu.Unlock()
		}
	}()
	return true
}
