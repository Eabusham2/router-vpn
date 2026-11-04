package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"sync"
	"time"

	"router-vpn/internal/mobiletor"
)

// Monitor owns no Stop authority until it holds the ordinary operation lock
// for this exact command. It ends its watch before calling Stop so shutdown
// can join the same watch without waiting on itself.
func (owner *desktopWindowsExternalRuntime) Monitor(parent context.Context) error {
	if err := owner.enter(parent); err != nil {
		return err
	}
	defer func() { owner.gate <- struct{}{} }()
	if err := owner.current(true); err != nil {
		return err
	}
	owner.mu.Lock()
	if !owner.activated || owner.proof == nil || owner.monitorDone != nil {
		owner.mu.Unlock()
		return errors.New("native external monitor has no unused proved activation")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	owner.monitorCancel, owner.monitorDone = cancel, done
	owner.mu.Unlock()
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		var once sync.Once
		end := func() { once.Do(func() { ticker.Stop(); cancel(); close(done) }) }
		defer end()
		a, launch := owner.app, owner.launch
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			if !a.ownsConnectionRuntime(launch.command) {
				return
			}
			if _, err := a.readDesktopExternalProof(launch); err == nil {
				continue
			}
			release, current := a.claimRuntimeMonitorOperation(launch.command)
			if !current {
				return
			}
			if release == nil {
				continue
			}
			if !a.ownsConnectionRuntime(launch.command) {
				release()
				return
			}
			if _, err := a.readDesktopExternalProof(launch); err == nil {
				release()
				continue
			}
			end()
			invalidateDesktopDNSResults(a)
			err := a.stopModeWithIntent(true)
			message := "captured native external source or network retired; exact protection is held"
			if err != nil {
				message += "; " + err.Error()
			}
			a.mu.Lock()
			// A late monitor cannot relabel a replacement's presentation.
			if a.cmd == launch.command || a.cmd == nil && a.state.RouterID == launch.profileID {
				a.state.Connected, a.state.Phase, a.state.LastError = false, "failed", message
			}
			a.mu.Unlock()
			sessionTrackerFor(a).markRequestFailure(message)
			release()
			return
		}
	}()
	return nil
}

func (owner *desktopWindowsExternalRuntime) stopMonitor(ctx context.Context) error {
	if owner == nil || ctx == nil {
		return errors.New("native external monitor has no original retirement owner")
	}
	owner.mu.Lock()
	cancel, done := owner.monitorCancel, owner.monitorDone
	owner.mu.Unlock()
	if done == nil {
		return nil
	}
	if cancel == nil {
		return errors.New("native external monitor lost its original cancellation")
	}
	cancel()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}

// Give the actual command its existing private stop mailbox before joining its
// retained Job. The bounded grace period is not retirement evidence: a killed
// or unresponsive child still needs its drained journal and exact BFE outcome.
func (owner *desktopWindowsExternalRuntime) requestStop(ctx context.Context, process desktopNodeProcess) error {
	if process == nil || !process.Started() {
		return nil
	}
	if closed, err := readDesktopExternalStopped(owner.launch); err != nil || closed {
		return err
	}
	if process.Alive() != nil {
		return nil
	}
	request, err := json.Marshal(desktopExternalStop{Schema: 1, SessionID: owner.launch.external.session, SourceSHA256: owner.launch.external.expected.SourceSHA256})
	if err != nil {
		return err
	}
	if err = writeDesktopRuntimeFile(owner.launch, "stop.json", request, true); err != nil {
		return err
	}
	grace, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if closed, err := readDesktopExternalStopped(owner.launch); err != nil || closed {
			return err
		}
		if process.Alive() != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-grace.Done():
			return nil // The actual retained Job must still join below.
		case <-owner.ProcessDone():
			return nil
		case <-ticker.C:
		}
	}
}

// closeRuntime retains the registry after retirement. Explicit Disconnect may
// still need to release On-connect protection; failure there must retry this
// same owner rather than fall through an unrelated helper command.
func (owner *desktopWindowsExternalRuntime) closeRuntime(ctx context.Context) error {
	if err := owner.enter(ctx); err != nil {
		return err
	}
	defer func() { owner.gate <- struct{}{} }()
	if err := owner.stopMonitor(ctx); err != nil {
		return err
	}
	if owner.app == nil || owner.launch == nil || owner.launch.ownedNode != nil || owner.launch.external == nil ||
		owner.launch.external.windows != owner || owner.launch.external.retained != owner || owner.policy == nil || owner.launch.external.physical != owner.policy {
		return errors.New("native external retirement lost its original typed owner")
	}
	owner.mu.Lock()
	process, attempt, slot, retired, closed, entered := owner.process, owner.attempt, owner.slot, owner.retired, owner.closed, owner.startEntered
	owner.retiring = true
	owner.mu.Unlock()
	if closed {
		return ctx.Err()
	}
	owner.app.mu.Lock()
	if owner.published && owner.app.cmd == owner.launch.command {
		owner.app.state.Connected, owner.app.state.Phase = false, "stopping"
	}
	owner.app.mu.Unlock()
	if !retired {
		if attempt == nil && process == nil && !entered {
			// Staging never entered a native constructor or protection transfer.
			// This releases only our private files, even if the old path remains.
		} else {
			if attempt == nil || slot == nil || attempt.launch != owner.launch || attempt.external != owner.policy || attempt.policy != nil {
				return errors.New("native external retirement lost its captured protection attempt")
			}
			join := func(caller context.Context) error {
				if process == nil {
					if entered {
						return errors.New("entered external constructor lost its actual partial process owner")
					}
					return nil
				}
				if err := process.Close(caller); err != nil {
					return err
				}
				if process.Started() {
					done := owner.ProcessDone()
					if done == nil {
						return errors.New("native external child lost its joined exit observer")
					}
					select {
					case <-caller.Done():
						return caller.Err()
					case <-done:
					}
				}
				return caller.Err()
			}
			stopErr := owner.requestStop(ctx, process)
			// Failed or forged mailbox data cannot keep this exact child alive.
			// It is still retained as an error after native join, never normalized.
			if err := join(ctx); err != nil || stopErr != nil {
				return errors.Join(stopErr, err)
			}
			owner.app.mu.Lock()
			sameSlot := owner.app.nodeProtection == slot
			owner.app.mu.Unlock()
			if !sameSlot {
				return errors.New("native external retirement cannot settle a replacement protection slot")
			}
			raw, err := readDesktopRuntimeFile(owner.launch, "external-protection-retired.json", mobiletor.DesktopProtectionTransferRecordLimit)
			if err == nil {
				stopped, stopErr := readDesktopExternalStopped(owner.launch)
				if stopErr != nil || !stopped {
					return errors.Join(stopErr, errors.New("native external retirement omitted its exact stopped acknowledgement"))
				}
				record, parseErr := mobiletor.ParseDesktopProtectionRetirementRecord(raw, attempt.transfer)
				if parseErr != nil {
					return parseErr
				}
				err = slot.finish(ctx, attempt, record, join)
			} else if errors.Is(err, os.ErrNotExist) {
				if _, ok := process.(desktopNodeJournalAdmission); ok {
					err = slot.finishJournalWithoutReceipt(ctx, attempt, join)
				} else if !entered && process == nil {
					err = slot.abandonUnchanged(ctx, attempt, join)
				} else {
					err = errors.New("native external retirement lost its authenticated journal outcome")
				}
			}
			if err != nil {
				return err
			}
		}
		owner.mu.Lock()
		owner.retired, owner.proof = true, nil
		owner.mu.Unlock()
	}
	if owner.stageDirectory != "" && (owner.launch.directory != owner.stageDirectory || owner.launch.directoryRoot == nil) {
		return errors.New("native external private staging still has an uncaptured workspace; ownership retained")
	}
	if err := cleanupDesktopNodeLaunch(owner.launch); err != nil {
		return err
	}
	owner.mu.Lock()
	owner.closed = true
	owner.mu.Unlock()
	return ctx.Err()
}

func (owner *desktopWindowsExternalRuntime) finishRetirement(ctx context.Context) error {
	if err := owner.enter(ctx); err != nil {
		return err
	}
	defer func() { owner.gate <- struct{}{} }()
	owner.mu.Lock()
	closed, retired, published, finished := owner.closed, owner.retired, owner.published, owner.finished
	owner.mu.Unlock()
	if finished {
		return nil
	}
	if !closed || !retired {
		return errors.New("native external retirement still owns its original private workspace")
	}
	a, launch := owner.app, owner.launch
	if published {
		a.mu.Lock()
		if current, ok := desktopExternalRetainedLaunches.Load(a); !ok || current != launch ||
			a.cmd != nil && a.cmd != launch.command {
			a.mu.Unlock()
			return errors.New("native external retirement cannot publish over another runtime")
		}
		if !desktopExternalRetainedLaunches.CompareAndDelete(a, launch) {
			a.mu.Unlock()
			return errors.New("native external retirement lost its retained registry entry")
		}
		coverCancel := a.daitaCancel
		a.daitaCancel, a.cmd = nil, nil
		a.state.Connected, a.state.Mode, a.state.LogicalMode, a.state.RuntimeMode, a.state.Base = false, "off", "", "", ""
		a.state.Phase, a.state.LastError = "off", ""
		a.mu.Unlock()
		if coverCancel != nil {
			coverCancel()
		}
		clearActiveDNSRuntimeConfig(a)
		invalidateDesktopDNSResults(a)
		clearActiveMultihopGraph(a)
	}
	clear(launch.config)
	clear(launch.metadata)
	launch.external.mu.Lock()
	clear(launch.external.source)
	clear(launch.external.capture)
	launch.external.mu.Unlock()
	desktopWindowsExternalPreparations.CompareAndDelete(owner, a)
	owner.mu.Lock()
	owner.finished = true
	owner.mu.Unlock()
	return nil
}

func (owner *desktopWindowsExternalRuntime) Close(ctx context.Context) error {
	if owner == nil {
		return nil
	}
	if err := owner.closeRuntime(ctx); err != nil {
		return err
	}
	return owner.finishRetirement(ctx)
}

func (a *app) retryDesktopWindowsExternalPreparations() error {
	var failures []error
	desktopWindowsExternalPreparations.Range(func(key, value any) bool {
		owner, ok := key.(*desktopWindowsExternalRuntime)
		if !ok || value != a || owner == nil {
			return true
		}
		owner.mu.Lock()
		published := owner.published
		owner.mu.Unlock()
		if published {
			return true
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		failures = append(failures, owner.Close(ctx))
		cancel()
		return true
	})
	return errors.Join(failures...)
}

type desktopRetainedStopCapture interface {
	Retire(context.Context, *exec.Cmd, bool) error
}

type desktopWindowsExternalStopCapture struct {
	owner     *desktopWindowsExternalRuntime
	command   *exec.Cmd
	operation context.Context
}

func (a *app) captureDesktopRetainedStop() (desktopRetainedStopCapture, error) {
	if captured, err := captureLegacyStandardExitStop(a); captured != nil || err != nil {
		return captured, err
	}
	if raw, exists := desktopExternalRetainedLaunches.Load(a); exists {
		launch, ok := raw.(*desktopNodeLaunch)
		if !ok || launch == nil || launch.external == nil {
			return nil, errors.New("native Stop lost its retained external launch")
		}
		if original, ok := launch.external.retained.(interface {
			CaptureStop() (desktopRetainedStopCapture, error)
		}); ok {
			return original.CaptureStop()
		}
		if owner := launch.external.windows; owner != nil {
			a.mu.Lock()
			captured := &desktopWindowsExternalStopCapture{owner: owner, command: a.cmd, operation: a.connectionContext}
			a.mu.Unlock()
			return captured, captured.current(false)
		}
	}
	// A typed nil pointer must not become a non-nil interface on legacy paths.
	captured, err := a.captureDesktopNodeStop()
	if captured == nil {
		return nil, err
	}
	return captured, err
}

func (captured *desktopWindowsExternalStopCapture) current(retired bool) error {
	if captured == nil || captured.owner == nil || captured.owner.app == nil || captured.owner.launch == nil {
		return errors.New("native external Stop has no original owner")
	}
	owner, a := captured.owner, captured.owner.app
	owner.mu.Lock()
	slot, published, closed := owner.slot, owner.published, owner.closed
	owner.mu.Unlock()
	a.mu.Lock()
	defer a.mu.Unlock()
	if !published || a.connectionContext != captured.operation || a.cmd != captured.command ||
		a.cmd != nil && a.cmd != owner.launch.command || slot == nil || a.nodeProtection != slot && !retired {
		return errors.New("native external Stop belongs to a replacement application or command")
	}
	if captured.command == nil && !closed {
		return errors.New("native external Stop cannot infer an unjoined child's absence")
	}
	if raw, exists := desktopExternalRetainedLaunches.Load(a); !exists || raw != owner.launch {
		return errors.New("native external Stop lost its original registry entry")
	}
	if _, exists := desktopNodeOwners.Load(a); exists {
		return errors.New("native external Stop cannot share a legacy owner")
	}
	return nil
}

func (captured *desktopWindowsExternalStopCapture) Retire(ctx context.Context, command *exec.Cmd, disconnect bool) (failure error) {
	defer func() {
		if failure != nil && captured != nil && captured.owner != nil {
			a := captured.owner.app
			a.mu.Lock()
			if a.connectionContext == captured.operation && a.cmd == captured.command {
				a.state.Connected, a.state.Phase, a.state.LastError = false, "failed", failure.Error()
			}
			a.mu.Unlock()
		}
	}()
	if command != captured.command {
		return errors.New("native external Stop changed its MTU-held command")
	}
	if err := captured.current(false); err != nil {
		return err
	}
	owner := captured.owner
	if err := owner.closeRuntime(ctx); err != nil {
		return err
	}
	if err := captured.current(false); err != nil {
		return err
	}
	if disconnect {
		if err := owner.app.releaseCapturedDesktopNodeProtection(owner.slot); err != nil {
			return err
		}
	}
	if err := captured.current(true); err != nil {
		return err
	}
	return owner.finishRetirement(ctx)
}
