package main

import (
	"context"
	"errors"
	"sync"
	"time"
)

// A Speed Lab transaction can stop and restore several connections. Nested
// stops share its already-drained MTU hold instead of locking it a second time.
type mtuSuspension struct {
	mu      sync.Mutex
	users   int
	ready   chan struct{}
	held    bool
	failure error
}

var mtuSuspensions sync.Map

func mtuSuspensionFor(a *app) *mtuSuspension {
	value, _ := mtuSuspensions.LoadOrStore(a, &mtuSuspension{})
	return value.(*mtuSuspension)
}

func mtuSuspended(a *app) bool {
	if a.controllerClosing() {
		return true
	}
	value, found := mtuSuspensions.Load(a)
	if !found {
		return false
	}
	suspension := value.(*mtuSuspension)
	suspension.mu.Lock()
	defer suspension.mu.Unlock()
	return suspension.users > 0
}

func cancelCapturedMTU(a *app) {
	if raw, exists := mtuViewSlots.Load(a); exists {
		slot := raw.(*mtuViewSlot)
		slot.mu.Lock()
		operation := slot.current
		slot.mu.Unlock()
		if operation != nil {
			operation.mu.Lock()
			if operation.status.Running && operation.cancel != nil {
				operation.status.Phase = "canceling"
				operation.cancel()
				if operation.automatic {
					resetRouterNodeAutomaticMTU(a)
				}
			}
			operation.mu.Unlock()
		}
	}
	if launch := desktopExternalMTULaunch(a); launch != nil {
		owner := desktopMeasurementMTUSession(launch)
		if owner != nil {
			owner.mu.Lock()
			if owner.cancel != nil {
				if owner.activeAutomatic {
					owner.automatic = false
				}
				owner.cancel()
			}
			owner.mu.Unlock()
		}
	}
}

func (a *app) holdCapturedMTU(ctx context.Context) (func(), error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("MTU hold was canceled before capture")
	}
	suspension := mtuSuspensionFor(a)
	suspension.mu.Lock()
	first := suspension.users == 0
	if first {
		suspension.ready, suspension.failure = make(chan struct{}), nil
	}
	suspension.users++
	ready := suspension.ready
	suspension.mu.Unlock()
	var once sync.Once
	release := func() {
		once.Do(func() {
			suspension.mu.Lock()
			if suspension.ready != ready || suspension.users <= 0 {
				suspension.mu.Unlock()
				return
			}
			suspension.users--
			last := suspension.users == 0
			if last {
				if suspension.held {
					mtuRetestLockFor(a).Unlock()
				}
				suspension.held, suspension.ready = false, nil
			}
			suspension.mu.Unlock()
			if last {
				if launch := desktopExternalMTULaunch(a); launch != nil {
					a.startDesktopExternalAutomaticMTU(launch)
				} else {
					a.startRouterNodeAutomaticMTU()
				}
			}
		})
	}
	if first {
		lock := mtuRetestLockFor(a)
		drainBudget := 15 * time.Second
		if launch := desktopExternalMTULaunch(a); launch != nil && launch.tor != nil {
			drainBudget = 45 * time.Second // Tor's checked late-cancel rollback is bounded to 30s.
		}
		deadline := time.NewTimer(drainBudget)
		defer deadline.Stop()
		ticker := time.NewTicker(25 * time.Millisecond)
		defer ticker.Stop()
		var failure error
	drain:
		for {
			cancelCapturedMTU(a)
			if lock.TryLock() {
				if raw, exists := mtuLiveOwners.Load(a); exists {
					failure = raw.(*mtuLiveOwner).Close()
				}
				if failure != nil {
					lock.Unlock()
				} else {
					suspension.mu.Lock()
					suspension.held = true
					suspension.mu.Unlock()
				}
				break
			}
			select {
			case <-ctx.Done():
				failure = ctx.Err()
				break drain
			case <-deadline.C:
				failure = errors.New("captured MTU cancellation has not drained; connection retained")
				break drain
			case <-ticker.C:
			}
		}
		suspension.mu.Lock()
		suspension.failure = failure
		close(ready)
		suspension.mu.Unlock()
	}
	select {
	case <-ctx.Done():
		release()
		return nil, ctx.Err()
	case <-ready:
	}
	suspension.mu.Lock()
	failure := suspension.failure
	suspension.mu.Unlock()
	if failure != nil {
		release()
		return nil, failure
	}
	return release, nil
}
