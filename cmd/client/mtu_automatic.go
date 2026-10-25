package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type mtuAutomaticContextKey struct{}

type mtuAutomaticAttempt struct {
	accepted atomic.Bool
	retry    atomic.Bool
}

type mtuAutomaticResult struct{ accepted, retry bool }

func retryHeldAutomaticMTU(ctx context.Context) {
	if attempt, ok := ctx.Value(mtuAutomaticContextKey{}).(*mtuAutomaticAttempt); ok {
		attempt.retry.Store(true)
	}
}

type routerNodeAutomaticMTU struct {
	mu        sync.Mutex
	command   *exec.Cmd
	waiting   bool
	attempted bool
	resume    bool
}

var routerNodeAutomaticMTUs sync.Map

func resetRouterNodeAutomaticMTU(a *app) {
	if raw, found := routerNodeAutomaticMTUs.Load(a); found {
		owner := raw.(*routerNodeAutomaticMTU)
		owner.mu.Lock()
		owner.attempted = false
		owner.resume = true
		owner.mu.Unlock()
	}
}

func (a *app) startRouterNodeAutomaticMTU() {
	a.startRouterNodeAutomaticMTUWithRun(a.runRouterNodeAutomaticMTU)
}

func (a *app) runRouterNodeAutomaticMTU(snapshot mtuRetestSnapshot) mtuAutomaticResult {
	encoded, _ := json.Marshal(mtuViewRequest{Session: snapshot.SessionID, Profile: snapshot.Profile.ID})
	attempt := &mtuAutomaticAttempt{}
	ctx := context.WithValue(context.Background(), mtuAutomaticContextKey{}, attempt)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "/api/mtu/retest", bytes.NewReader(encoded))
	if err != nil {
		return mtuAutomaticResult{}
	}
	// Retest publishes its bounded, captured status before returning. A hold
	// that wins before publication is a deferred attempt, not a completed one.
	a.retestMTU(&mtuAutomaticResponse{header: make(http.Header)}, request)
	return mtuAutomaticResult{accepted: attempt.accepted.Load(), retry: attempt.retry.Load()}
}

func (owner *routerNodeAutomaticMTU) finish(a *app, command *exec.Cmd, run func(mtuRetestSnapshot) mtuAutomaticResult) {
	owner.mu.Lock()
	resume := false
	if owner.command == command {
		owner.waiting = false
		resume = owner.resume
	}
	owner.mu.Unlock()
	if resume && !mtuSuspended(a) && a.ownsConnectionRuntime(command) {
		a.startRouterNodeAutomaticMTUWithRun(run)
	}
}

func (owner *routerNodeAutomaticMTU) resumeAfterHold(command *exec.Cmd) {
	owner.mu.Lock()
	if owner.command == command && !owner.attempted {
		owner.resume = true
	}
	owner.mu.Unlock()
}

func (a *app) startRouterNodeAutomaticMTUWithRun(run func(mtuRetestSnapshot) mtuAutomaticResult) {
	a.mu.Lock()
	command := a.cmd
	profileID := a.profiles.SelectedID
	if a.state.Mode == "multihop" || a.state.LogicalMode == "multihop" {
		profileID = a.state.RouterID
	}
	profile, found := a.profileByIDLocked(profileID)
	eligible := found && command != nil && a.state.Connected && a.state.Phase == "connected" && strings.EqualFold(profile.MTUPolicy, "auto") && profile.External == nil && profile.NodeKind != "external"
	a.mu.Unlock()
	if !eligible || run == nil || mtuSuspended(a) {
		return
	}
	raw, _ := routerNodeAutomaticMTUs.LoadOrStore(a, &routerNodeAutomaticMTU{command: command})
	owner := raw.(*routerNodeAutomaticMTU)
	owner.mu.Lock()
	if owner.command != command {
		owner.command, owner.waiting, owner.attempted, owner.resume = command, false, false, false
	}
	if owner.waiting {
		// A hold can release before the old waiting worker runs its defer.
		// Preserve this request so that defer can schedule the captured path.
		if !owner.attempted {
			owner.resume = true
		}
		owner.mu.Unlock()
		return
	}
	if owner.attempted {
		owner.mu.Unlock()
		return
	}
	owner.waiting = true
	owner.resume = false
	owner.mu.Unlock()
	go func() {
		defer owner.finish(a, command, run)
		deadline := time.NewTimer(30 * time.Second)
		defer deadline.Stop()
		ticker := time.NewTicker(25 * time.Millisecond)
		defer ticker.Stop()
		for {
			if !a.ownsConnectionRuntime(command) {
				return
			}
			if mtuSuspended(a) {
				owner.resumeAfterHold(command)
				return
			}
			if a.operationMu.TryLock() {
				a.operationMu.Unlock()
				tracker := sessionTrackerFor(a)
				tracker.observe(tracker.capture())
				snapshot, err := captureMTURetestSnapshot(a)
				if mtuSuspended(a) {
					owner.resumeAfterHold(command)
					return
				}
				if err != nil || !a.ownsConnectionRuntime(command) {
					return
				}
				owner.mu.Lock()
				if owner.command != command || owner.attempted {
					owner.mu.Unlock()
					return
				}
				owner.attempted = true
				owner.mu.Unlock()
				result := run(snapshot)
				if !result.accepted && result.retry {
					owner.mu.Lock()
					if owner.command == command {
						owner.attempted, owner.resume = false, true
					}
					owner.mu.Unlock()
				}
				return
			}
			select {
			case <-deadline.C:
				return
			case <-ticker.C:
			}
		}
	}()
}

type mtuAutomaticResponse struct{ header http.Header }

func (w *mtuAutomaticResponse) Header() http.Header          { return w.header }
func (*mtuAutomaticResponse) WriteHeader(int)                {}
func (*mtuAutomaticResponse) Write(data []byte) (int, error) { return len(data), nil }
