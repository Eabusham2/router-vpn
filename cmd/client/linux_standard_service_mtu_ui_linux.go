//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemtu"
)

type linuxStandardMTUController interface {
	Requested() bool
	RunContext(context.Context, string, bool) error
	StatusJSONContext(context.Context) (string, error)
	CloseContext(context.Context) error
}

// One controller retains its frozen source and evolving verified configuration
// for every Retest on this launch. Reconstructing after a winner would confuse
// the startup TUN MTU with the current reader and change the cache path key.
type linuxStandardServiceMTUUI struct {
	mu                                 sync.Mutex
	launch                             *linuxStandardServiceLaunch
	owner                              *linuxStandardServiceMTUOwner
	controller                         linuxStandardMTUController
	identity                           mtuViewIdentity
	path                               string
	lifetime                           context.Context
	active                             *mtuViewOperation
	cancel                             context.CancelFunc
	done                               chan struct{}
	stopped, running, completed        bool
	autoWaiting, autoAttempted, resume bool
	autoCancel                         context.CancelFunc
	autoDone                           chan struct{}
	activation                         *linuxStandardServiceMonitor
	profileToken                       string
}

var linuxStandardServiceMTUUIs sync.Map // Original launch -> original controller.

func linuxStandardMTULaunch(a *app) (*linuxStandardServiceLaunch, bool, error) {
	raw, found := linuxStandardServiceOwners.Load(a)
	if !found {
		return nil, false, nil
	}
	launch, ok := raw.(*linuxStandardServiceLaunch)
	if !ok || launch == nil || launch.app != a {
		return nil, true, errors.New("MTU lost its installed service capture")
	}
	return launch, true, nil
}
func (u *linuxStandardServiceMTUUI) current(ctx context.Context) (mobilemtu.State, common.RouterProfile, error) {
	live, profile, lifetime, err := captureLinuxStandardServiceMTUReadback(ctx, u.launch)
	if err != nil {
		return live, profile, err
	}
	if lifetime != u.lifetime || live.Session != u.identity.Session || profile.ID != u.identity.Profile || live.Path != u.path {
		return live, profile, errors.New("MTU result belongs to another service capture")
	}
	return live, profile, ctx.Err()
}
func getLinuxStandardServiceMTUUI(ctx context.Context, launch *linuxStandardServiceLaunch) (*linuxStandardServiceMTUUI, error) {
	live, profile, lifetime, err := captureLinuxStandardServiceMTUReadback(ctx, launch)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(profile.MTUPolicy, "auto") || profile.JumboTUN {
		return nil, errors.New("choose Auto MTU without Jumbo before Retest")
	}
	fresh := &linuxStandardServiceMTUUI{launch: launch, identity: mtuViewIdentity{Session: live.Session, Profile: profile.ID, Native: true}, path: live.Path, lifetime: lifetime}
	raw, _ := linuxStandardServiceMTUUIs.LoadOrStore(launch, fresh)
	u := raw.(*linuxStandardServiceMTUUI)
	if err := mobilemtu.LockContext(ctx, &u.mu); err != nil {
		return nil, err
	}
	defer u.mu.Unlock()
	if u.stopped {
		return nil, errors.New("MTU original controller is stopping")
	}
	if _, _, err := u.current(ctx); err != nil {
		return nil, err
	}
	if u.controller != nil {
		return u, nil
	}
	owner, err := newLinuxStandardServiceMTUOwner(ctx, launch)
	if err != nil {
		return nil, err
	}
	if err := mobilemtu.LockContext(ctx, &launch.app.mu); err != nil {
		return nil, err
	}
	directory := filepath.Dir(launch.app.cfg.ProfilesFile)
	launch.app.mu.Unlock()
	cache, err := openLinuxStandardMTUCache(ctx, directory)
	if err != nil {
		return nil, err
	}
	controller, err := mobilemtu.NewExternalContext(ctx, owner, owner.config, owner.authority, cache)
	if err != nil {
		return nil, err
	}
	u.owner, u.controller = owner, controller
	u.activation = owner.activation
	u.profileToken, err = linuxStandardProfileDigest(profile)
	if err != nil {
		return nil, err
	}
	return u, nil
}
func readLinuxStandardMTUStatus(ctx context.Context, controller linuxStandardMTUController) (mobilemtu.Status, error) {
	raw, err := controller.StatusJSONContext(ctx)
	if err != nil {
		return mobilemtu.Status{}, err
	}
	var status mobilemtu.Status
	if err := decodeRelayControlJSON([]byte(raw), &status); err != nil {
		return status, err
	}
	return status, nil
}

func (a *app) retestPlatformServiceMTU(w http.ResponseWriter, r *http.Request, request mtuViewRequest) bool {
	launch, handled, err := linuxStandardMTULaunch(a)
	if !handled {
		return false
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return true
	}
	u, err := getLinuxStandardServiceMTUUI(r.Context(), launch)
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
	force := !operation.automatic
	result, err := u.run(ctx, operation, force)
	if err != nil {
		http.Error(writer, "Native service MTU Retest: "+err.Error(), http.StatusConflict)
		return true
	}
	writer.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{"ok": true, "effective_mtu": result.EffectiveMTU, "effective_mtu_source": result.Source, "result": result, "note": "Selected-path HTTPS response and transferred-byte throughput through the original service TUN; the reported value is verified interface MTU, not authenticated UDP path MTU."})
	return true
}
func (u *linuxStandardServiceMTUUI) run(parent context.Context, operation *mtuViewOperation, force bool) (result mobilemtu.Status, failure error) {
	if err := mobilemtu.LockContext(parent, &u.mu); err != nil {
		return result, err
	}
	if u.stopped || u.running || u.controller == nil {
		u.mu.Unlock()
		return result, errors.New("original service MTU operation is busy or retired")
	}
	if _, _, err := u.current(parent); err != nil {
		u.mu.Unlock()
		return result, err
	}
	if u.owner != nil {
		if err := u.owner.PrepareRetestContext(parent); err != nil {
			u.mu.Unlock()
			return result, err
		}
	}
	ctx, cancel := context.WithCancel(parent)
	stopLifetime := context.AfterFunc(u.lifetime, cancel)
	done := make(chan struct{})
	u.running, u.active, u.cancel, u.done = true, operation, cancel, done
	if operation.automatic {
		u.autoAttempted = true
	}
	u.mu.Unlock()
	defer func() {
		stopLifetime()
		cancel()
		u.mu.Lock()
		u.running = false
		u.cancel = nil
		if failure != nil {
			result.Measured = false
		}
		operation.mu.Lock()
		operation.status = result
		if operation.cleanupPending {
			operation.status.Running = true
			operation.status.Complete = false
			operation.status.Measured = false
			operation.status.Phase = "cleanup-pending"
		}
		operation.mu.Unlock()
		if result.Measured && failure == nil {
			u.completed = true
		}
		if operation.automatic && parent.Err() != nil && !u.completed {
			u.autoAttempted = false
		}
		resume := u.resume && !u.stopped && !u.completed && !u.autoAttempted
		u.resume = false
		close(done)
		u.mu.Unlock()
		if resume {
			u.resumeAutomatic()
		}
	}()
	failure = u.controller.RunContext(ctx, operation.request, force)
	// The synchronous worker has joined. A separate bounded observation can
	// report its rollback after the HTTP caller leaves, but cannot admit a winner.
	observation, finish := context.WithTimeout(context.WithoutCancel(parent), 2*time.Second)
	defer finish()
	status, statusErr := readLinuxStandardMTUStatus(observation, u.controller)
	live, _, liveErr := u.current(observation)
	if statusErr == nil && liveErr == nil && status.EffectiveMTU == live.MTU {
		result = status
		if result.Request != operation.request {
			result = mobilemtu.Status{Request: operation.request, Phase: "failed", Complete: true, EffectiveMTU: live.MTU, Source: "live-captured-interface", Candidates: []mobilemtu.Candidate{}}
		}
	} else {
		failure = errors.Join(failure, statusErr, liveErr, errors.New("MTU result lacks original live readback"))
	}
	if u.owner != nil {
		if err := mobilemtu.LockContext(observation, &u.launch.mu); err != nil {
			failure = errors.Join(failure, err)
			operation.mu.Lock()
			operation.cleanupPending = true
			operation.mu.Unlock()
		} else {
			pending := u.owner.pending != nil || u.owner.sockets.Load() != 0
			u.launch.mu.Unlock()
			if pending {
				operation.mu.Lock()
				operation.cleanupPending = true
				operation.mu.Unlock()
				failure = errors.Join(failure, errors.New("original MTU cleanup is still pending"))
			}
		}
	}
	if failure != nil {
		return result, failure
	}
	if err := parent.Err(); err != nil {
		return result, err
	}
	if !result.Complete || result.Running || !result.Measured || result.Request != operation.request {
		return result, errors.New("MTU operation ended without fresh measured evidence")
	}
	return result, nil
}

func (a *app) writeLinuxStandardServiceMTUViewStatus(w http.ResponseWriter, r *http.Request, request, session string) bool {
	launch, handled, err := linuxStandardMTULaunch(a)
	if !handled {
		return false
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return true
	}
	if a.writeLinuxStandardServiceMTUPending(w, r, launch, request, session) {
		return true
	}
	live, profile, lifetime, err := captureLinuxStandardServiceMTUReadback(r.Context(), launch)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return true
	}
	identity := mtuViewIdentity{Session: live.Session, Profile: profile.ID, Native: true}
	if session != "" && session != identity.Session {
		http.Error(w, "MTU connection was replaced", http.StatusConflict)
		return true
	}
	automatic := strings.EqualFold(profile.MTUPolicy, "auto") && !profile.JumboTUN
	status := mobilemtu.Status{Phase: "idle", EffectiveMTU: live.MTU, Source: "live-captured-interface", Candidates: []mobilemtu.Candidate{}}
	requested := false
	if raw, ok := linuxStandardServiceMTUUIs.Load(launch); ok {
		u := raw.(*linuxStandardServiceMTUUI)
		if err := mobilemtu.LockContext(r.Context(), &u.mu); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return true
		}
		controller, operation, running, stopped := u.controller, u.active, u.running, u.stopped
		matches := u.identity == identity && u.path == live.Path && u.lifetime == lifetime
		u.mu.Unlock()
		if !matches || stopped {
			http.Error(w, "MTU view belongs to a retired service capture", http.StatusConflict)
			return true
		}
		if controller != nil && operation != nil {
			if running {
				status, err = readLinuxStandardMTUStatus(r.Context(), controller)
			} else {
				if lockErr := mobilemtu.LockContext(r.Context(), &operation.mu); lockErr != nil {
					http.Error(w, lockErr.Error(), http.StatusConflict)
					return true
				}
				status = operation.status
				operation.mu.Unlock()
			}
			if err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return true
			}
			if status.Request == "" {
				status.Request = operation.request
			}
			requested = true
			if running {
				status.Running, status.Complete, status.Measured = true, false, false
				status.EffectiveMTU, status.Source = live.MTU, "live-captured-interface"
			} else if status.EffectiveMTU != live.MTU {
				http.Error(w, "MTU result no longer matches the original live reader", http.StatusConflict)
				return true
			}
		}
	}
	if request != "" && request != status.Request {
		http.Error(w, "MTU request has not started or was replaced", http.StatusNotFound)
		return true
	}
	// Recheck both immutable capture and actual reader after reading worker state.
	after, afterProfile, afterLifetime, err := captureLinuxStandardServiceMTUReadback(r.Context(), launch)
	if err != nil || after != live || afterProfile.ID != profile.ID || afterLifetime != lifetime {
		http.Error(w, "MTU service changed during status observation", http.StatusConflict)
		return true
	}
	writeMTUViewStatus(w, identity, requested, false, automatic, status)
	return true
}

func stopLinuxStandardServiceMTUUI(ctx context.Context, launch *linuxStandardServiceLaunch) error {
	raw, ok := linuxStandardServiceMTUUIs.Load(launch)
	if !ok {
		return nil
	}
	u := raw.(*linuxStandardServiceMTUUI)
	if launch == nil || launch.app == nil || u.launch != launch {
		return errors.New("MTU Stop lost original service capture")
	}
	if err := mobilemtu.LockContext(ctx, &launch.app.mu); err != nil {
		return err
	}
	actual, exists := linuxStandardServiceOwners.Load(launch.app)
	valid := exists && actual == launch && launch.app.cmd == launch.Command()
	launch.app.mu.Unlock()
	if !valid {
		return errors.New("MTU Stop belongs to a replacement service")
	}
	if err := mobilemtu.LockContext(ctx, &u.mu); err != nil {
		return err
	}
	u.stopped = true
	if u.autoCancel != nil {
		u.autoCancel()
	}
	if u.cancel != nil {
		u.cancel()
	}
	done, autoDone, controller := u.done, u.autoDone, u.controller
	u.mu.Unlock()
	if autoDone != nil {
		select {
		case <-autoDone:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if controller != nil {
		if err := controller.CloseContext(ctx); err != nil {
			return err
		}
	}
	linuxStandardServiceMTUUIs.CompareAndDelete(launch, u)
	return nil
}

func (a *app) startPlatformServiceAutomaticMTU() bool {
	launch, handled, err := linuxStandardMTULaunch(a)
	if !handled {
		return false
	}
	if err != nil {
		return true
	}
	admission, finish := context.WithTimeout(context.Background(), 4*time.Second)
	defer finish()
	u, err := getLinuxStandardServiceMTUUI(admission, launch)
	if err != nil {
		return true
	}
	u.startAutomatic(admission)
	return true
}

// Delayed resume belongs to this exact UI owner. It must never reconstruct a
// controller after Stop has joined and removed that owner's registry entry.
func (u *linuxStandardServiceMTUUI) resumeAutomatic() {
	admission, finish := context.WithTimeout(context.Background(), 4*time.Second)
	defer finish()
	u.startAutomatic(admission)
}

func (u *linuxStandardServiceMTUUI) startAutomatic(admission context.Context) {
	a := u.launch.app
	if err := mobilemtu.LockContext(admission, &u.mu); err != nil {
		return
	}
	original, retained := linuxStandardServiceMTUUIs.Load(u.launch)
	if !retained || original != u || u.stopped || u.completed || u.autoAttempted || u.lifetime == nil || u.lifetime.Err() != nil {
		u.mu.Unlock()
		return
	}
	if u.autoWaiting || u.running {
		u.resume = true
		u.mu.Unlock()
		return
	}
	autoContext, cancel := context.WithCancel(u.lifetime)
	ctx, finishAdmission := context.WithTimeout(autoContext, 30*time.Second)
	autoDone := make(chan struct{})
	u.autoWaiting, u.autoCancel, u.autoDone = true, cancel, autoDone
	u.mu.Unlock()
	go func() {
		attempt := &mtuAutomaticAttempt{}
		defer func() {
			finishAdmission()
			cancel()
			u.mu.Lock()
			u.autoWaiting = false
			u.autoCancel = nil
			close(autoDone)
			resume := u.resume && !u.stopped && !u.completed && !u.autoAttempted
			u.resume = false
			u.mu.Unlock()
			if resume {
				u.resumeAutomatic()
			}
		}()
		ticker := time.NewTicker(25 * time.Millisecond)
		defer ticker.Stop()
		for {
			if ctx.Err() != nil {
				return
			}
			suspended, err := mtuSuspendedContext(ctx, a)
			if err != nil {
				return
			}
			if suspended {
				return
			}
			if a.operationMu.TryLock() {
				a.operationMu.Unlock()
				break
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
		// Waiting admission has its own bound; the accepted measurement inherits
		// the original activation lifetime and the ordinary Retest work budget.
		if ctx.Err() != nil {
			return
		}
		parent := context.WithValue(autoContext, mtuAutomaticContextKey{}, attempt)
		body, _ := json.Marshal(mtuViewRequest{Session: u.identity.Session, Profile: u.identity.Profile})
		request, err := http.NewRequestWithContext(parent, http.MethodPost, "/api/mtu/retest", bytes.NewReader(body))
		if err != nil {
			return
		}
		a.retestMTU(&mtuAutomaticResponse{header: make(http.Header)}, request)
	}()
	return
}

// During native replacement the launch mutex and epoch transition belong to the
// original worker. Progress remains readable from that worker's captured view;
// it deliberately publishes no current interface MTU or completed measurement.
func (a *app) writeLinuxStandardServiceMTUPending(w http.ResponseWriter, r *http.Request, launch *linuxStandardServiceLaunch, request, session string) bool {
	raw, ok := linuxStandardServiceMTUUIs.Load(launch)
	if !ok {
		return false
	}
	u := raw.(*linuxStandardServiceMTUUI)
	if err := mobilemtu.LockContext(r.Context(), &u.mu); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return true
	}
	running, operation, controller := u.running, u.active, u.controller
	identity, activation, token, stopped := u.identity, u.activation, u.profileToken, u.stopped
	u.mu.Unlock()
	if !running || operation == nil || controller == nil {
		return false
	}
	if session != "" && session != identity.Session || request != "" && request != operation.request {
		http.Error(w, "MTU request belongs to another captured operation", http.StatusConflict)
		return true
	}
	check := func() error {
		current, exists := linuxStandardServiceMonitors.Load(launch)
		if stopped || activation == nil || !exists || current != activation || activation.ctx == nil || activation.ctx.Err() != nil {
			return errors.New("MTU activation retired")
		}
		if err := mobilemtu.LockContext(r.Context(), &a.mu); err != nil {
			return err
		}
		actual, owned := linuxStandardServiceOwners.Load(a)
		profile, found := a.profileByIDLocked(identity.Profile)
		digest, digestErr := linuxStandardProfileDigest(profile)
		valid := owned && actual == launch && a.cmd == launch.Command() && found && digestErr == nil && digest == token &&
			a.state.Connected && a.state.Phase == "connected" &&
			(a.connectionContext == nil || a.connectionContext == activation.operation) && a.connectionCancelIntent != activation.operation
		a.mu.Unlock()
		if !valid {
			return errors.New("MTU progress belongs to a replaced connection or profile")
		}
		if err := mobilemtu.LockContext(r.Context(), &u.mu); err != nil {
			return err
		}
		valid = !u.stopped && u.running && u.active == operation && u.controller == controller && u.activation == activation
		u.mu.Unlock()
		if !valid {
			return errors.New("MTU progress operation was replaced or completed")
		}
		return r.Context().Err()
	}
	if err := check(); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return true
	}
	status, err := readLinuxStandardMTUStatus(r.Context(), controller)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return true
	}
	if err := check(); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return true
	}
	if status.Request != operation.request {
		status = mobilemtu.Status{Request: operation.request, Phase: "preparing", Candidates: []mobilemtu.Candidate{}}
	}
	status.Running, status.Complete, status.Measured, status.Restored = true, false, false, false
	status.EffectiveMTU, status.Source = 0, "unmeasured"
	writeMTUViewStatus(w, identity, true, false, true, status)
	return true
}
