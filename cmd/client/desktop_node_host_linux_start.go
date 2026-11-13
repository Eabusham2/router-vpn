//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"time"

	"router-vpn/internal/desktopnetwork"
)

// Start requires the caller to retain operationMu and to have already joined
// the previous connection. It publishes only Starting. The child's selected
// DNS/TUN readiness and the authenticated Router proof are separate gates.
func (h *desktopLinuxNodeHost) Start(ctx context.Context, journal *desktopLinuxNodeJournal, predecessor *desktopLinuxNodeTransaction) error {
	return h.startWithVerifier(ctx, journal, predecessor, os.Environ(), verifyBundledNativeContext)
}

// Only package metadata verification is modeled by the private native fixture.
// Installed image pins, actual process creation, inherited original handshake,
// durable journal and native source admission always use the shipping owners.
func (h *desktopLinuxNodeHost) startWithVerifier(ctx context.Context, journal *desktopLinuxNodeJournal,
	predecessor *desktopLinuxNodeTransaction, environment []string, verify func(context.Context, string) (string, error)) error {
	if h != nil && h.launch != nil && h.launch.external != nil {
		var err error
		ctx, err = captureDesktopNativeStartup(ctx, h.launch)
		if err != nil {
			return err
		}
		environment, err = desktopNativeStartupEnvironment(ctx, h.launch, environment)
		if err != nil {
			return err
		}
	}
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	arguments, capture, err := h.argumentsLocked(ctx)
	if err != nil {
		return err
	}
	if h.startEntered || h.process != nil || h.transaction != nil || h.launch.command != nil || verify == nil ||
		journal == nil || !sameDesktopLinuxParentCapture(journal.parent, h.parent) {
		return errors.New("Linux Node start lost its unused original prepared host and journal")
	}
	if predecessor != nil && (predecessor.journal != journal || !sameDesktopLinuxParentCapture(predecessor.parent, h.parent)) {
		return errors.New("Linux Node start cannot acquire another controller's predecessor")
	}
	if err := h.unoccupied(ctx); err != nil {
		return err
	}
	checkpoint, err := journal.Snapshot(ctx)
	if err != nil || checkpoint.Incomplete || checkpoint.Record.Phase != "settled" || checkpoint.Record.Committed.Engine != nil ||
		checkpoint.Record.Controller != h.parent.record {
		return errors.Join(err, errors.New("Linux Node start requires its original settled engine-free journal"))
	}
	if err := h.current(ctx); err != nil {
		return err
	}
	h.startEntered, h.started = true, time.Now()
	h.process, err = startDesktopLinuxNodeProcessWithVerifier(ctx, h.parent, arguments, environment, h.launch.directory, capture, verify)
	if h.process != nil && h.process.Started() {
		h.launch.command = h.process.command
		if h.external != nil {
			h.launch.external.started = h.started
			desktopExternalRetainedLaunches.Store(h.parent.app, h.launch)
		}
	}
	if err != nil {
		return err // This host and original parent retain every partial owner.
	}
	if h.process == nil || !h.process.Started() || h.launch.command == nil {
		return errors.New("Linux Node start returned no original created command")
	}
	if err := h.publishStarting(ctx); err != nil {
		return err
	}
	if h.candidatePrefix != nil {
		h.transaction, err = newDesktopLinuxCandidatePrefixTransaction(ctx, h, journal, predecessor)
	} else if h.chain != nil {
		h.transaction, err = newDesktopLinuxNodeChainTransaction(ctx, h, journal, predecessor)
	} else if h.imported != nil {
		h.transaction, err = newDesktopLinuxImportedTransaction(ctx, h, journal, predecessor)
	} else if h.external != nil {
		h.transaction, err = newDesktopLinuxExternalTransactionContext(ctx, h, journal, predecessor)
	} else {
		h.transaction, err = newDesktopLinuxNodeTransaction(h.operation, h.parent, journal, h.process, h.policy, predecessor)
	}
	if err != nil {
		return err
	}
	// Cancellation refuses creation/admission through the original callbacks.
	// Keep a separate bounded dialogue so that refusal can reach the child and
	// its exact partial source can participate in subsequent joined teardown.
	dialogue, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	stopParent := context.AfterFunc(h.parent.lifetime, cancel)
	defer func() { stopParent(); cancel() }()
	if err := h.transaction.ServePreparation(dialogue); err != nil {
		return err
	}
	return h.runningLocked(ctx)
}

func (h *desktopLinuxNodeHost) unoccupied(ctx context.Context) error {
	if err := h.current(ctx); err != nil {
		return err
	}
	a := h.parent.app
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	defer a.mu.Unlock()
	if a.cmd != nil || a.state.Connected {
		return errors.New("Linux Node start cannot replace an unjoined active connection")
	}
	if _, exists := desktopNodeOwners.Load(a); exists {
		return errors.New("Linux Node start cannot replace another retained native workspace")
	}
	return a.checkCapturedConnectionOperationLocked(h.operation)
}

func (h *desktopLinuxNodeHost) publishStarting(ctx context.Context) error {
	if err := h.current(ctx); err != nil {
		return err
	}
	a := h.parent.app
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	defer a.mu.Unlock()
	profile, exists := a.profileByIDLocked(desktopExternalPathProfileID(h.launch))
	if h.external != nil {
		if err := h.externalSourcesLocked(a); err != nil {
			return err
		}
	}
	if h.imported != nil {
		owner := h.launch.importedPlatform.(*desktopLinuxImportedConnection)
		if err := owner.capture.sources.currentLocked(a, true); err != nil {
			return err
		}
	}
	if h.candidatePrefix != nil {
		if h.launch.candidatePrefix == nil || h.launch.candidatePrefix.capture == nil {
			return errors.New("prefix publication lost original captured sources")
		}
		if err := h.launch.candidatePrefix.capture.sources.currentLocked(a); err != nil {
			return err
		}
		if _, err := orderedCandidateLaunchPurposeLocked(a, h.launch); err != nil {
			return err
		}
	}
	if h.chain != nil {
		if err := h.launch.chain.platform.capture.sources.currentLocked(a); err != nil {
			return err
		}
	}
	if a.checkCapturedConnectionOperationLocked(h.operation) != nil || !exists || a.cmd != nil || a.state.Connected ||
		desktopOwnedNodeProfileToken(profile) != h.revision ||
		[3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled} != h.savedOptions ||
		[3]bool{a.state.DAITA, a.state.Jumbo, a.state.Socks} != h.options {
		return errors.New("Linux Node publication lost its original request, node or empty connection slot")
	}
	if _, exists := desktopNodeOwners.Load(a); exists {
		return errors.New("Linux Node publication cannot replace another native workspace")
	}
	a.cmd = h.launch.command
	a.state.Connected, a.state.Phase, a.state.LastError = false, "starting", ""
	a.state.Mode, a.state.RuntimeMode, a.state.RouterID = h.launch.mode, h.launch.mode, desktopExternalPathProfileID(h.launch)
	a.state.LogicalMode, a.state.Base = "", ""
	a.state.DAITA, a.state.Jumbo, a.state.Socks = h.options[0], h.options[1], h.options[2]
	if h.chain != nil {
		a.state.Mode, a.state.LogicalMode, a.state.Base = "multihop", "multihop", h.launch.chain.selection.Base
	}
	if h.candidatePrefix != nil {
		a.state.Mode, a.state.LogicalMode, a.state.Base = "multihop", "multihop", h.launch.candidatePrefix.selection.Base
	}
	if h.imported != nil {
		owner := h.launch.importedPlatform.(*desktopLinuxImportedConnection)
		a.state.Mode, a.state.LogicalMode, a.state.Base = "multihop", "multihop", owner.selection.Base
		if temporary := owner.capture.sources.temporary; temporary != nil {
			temporary.runtime = h.launch.command
		}
	}
	return nil
}

func (h *desktopLinuxNodeHost) runningLocked(ctx context.Context) error {
	if err := h.current(ctx); err != nil {
		return err
	}
	if h.process == nil || h.launch.command != h.process.command || !h.process.Started() || h.transaction == nil || h.started.IsZero() {
		return errors.New("Linux Node has no retained original running transaction")
	}
	t := h.transaction
	if err := t.enter(ctx); err != nil {
		return err
	}
	defer func() { t.gate <- struct{}{} }()
	if t.process != h.process || t.policy != h.policy || t.external != h.external || t.imported != h.imported || t.chain != h.chain || t.candidatePrefix != h.candidatePrefix || t.selection != h.selection || !t.complete || !t.served || !t.admitted ||
		!t.nativeCommitted || t.stopRequested.Load() || t.retiring || t.retirement != nil || t.closed || t.retired || t.pending != nil {
		return errors.New("Linux Node lost its original admitted source and durable transaction")
	}
	if h.activation == nil {
		if err := t.accepted(ctx); err != nil {
			return err
		}
	} else if err := h.activation.matches(h); err != nil {
		return err
	}
	if err := t.checkHead(ctx); err != nil {
		return err
	}
	return t.control.CurrentContext(ctx)
}

// Retire always joins the exact created child and settles its original journal.
// Temporary operations retain the closed predecessor. Ordinary disconnect may
// release On-connect; Always remains closed under the original transaction.
func (h *desktopLinuxNodeHost) Retire(ctx context.Context, disconnect bool) error {
	if err := h.stopMonitorBeforeRetirement(ctx); err != nil {
		return err
	}
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	h.closing = true
	return h.retireLocked(ctx, disconnect)
}

func (h *desktopLinuxNodeHost) retireLocked(ctx context.Context, disconnect bool) error {
	if h.mtu != nil {
		if err := h.mtu.closeLocked(ctx); err != nil {
			// A naturally closing graph may already be waiting for this
			// parent's retirement ACK and can no longer serve rollback. Keep
			// the exact lease while joining only its original transaction;
			// failed mailbox cleanup is never a discharge receipt.
			if currentErr := h.mtu.cleanupCurrentLocked(ctx); currentErr != nil {
				return errors.Join(err, currentErr)
			}
		}
	}
	h.revokeActivationLocked()
	if h.process == nil {
		if h.launch != nil && h.launch.command != nil {
			return errors.New("Linux prepared host cannot discard an entered native command")
		}
		return nil
	}
	if h.launch == nil || h.process.Started() && h.launch.command != h.process.command {
		return errors.New("Linux host retirement lost its original launched command")
	}
	if t := h.transaction; t != nil {
		if t.process != h.process || !sameDesktopLinuxParentCapture(t.parent, h.parent) {
			return errors.New("Linux host retirement substituted another transaction")
		}
		if err := t.enter(ctx); err != nil {
			return err
		}
		complete, closed := t.complete, t.closed && t.released
		t.gate <- struct{}{}
		if !closed {
			if !complete {
				if err := t.Close(ctx); err != nil {
					return err
				}
			} else {
				if err := t.Retire(ctx); err != nil {
					return err
				}
				if h.mtu != nil {
					if err := h.mtu.finishRetirementLocked(ctx); err != nil {
						return err
					}
				}
				if disconnect {
					if err := t.ReleaseOnDisconnect(ctx); err != nil {
						return err
					}
				}
			}
		}
		if h.mtu != nil {
			if err := h.mtu.finishRetirementLocked(ctx); err != nil {
				return err
			}
		}
		if err := t.enter(ctx); err != nil {
			return err
		}
		joined := !t.complete && t.closed && t.released || t.complete && t.retired && t.engineJoined && t.pending == nil
		canClose := !t.closed && joined && t.successor == nil &&
			(t.superseded || !t.nativeCommitted || t.head.Record.Committed.Target == nil)
		t.gate <- struct{}{}
		if !joined {
			return errors.New("Linux host retirement preceded its original settled engine join")
		}
		if canClose {
			if err := t.Close(ctx); err != nil {
				return err
			}
		}
	} else if err := h.process.Close(ctx); err != nil {
		return err
	}
	if h.process.Started() {
		select {
		case <-h.process.joined:
		default:
			return errors.New("Linux host retirement preceded its original Cmd.Wait")
		}
		if h.process.command.ProcessState == nil {
			return errors.New("Linux host retirement has no original command exit")
		}
	}
	if h.importedMTU != nil {
		if err := h.finishImportedMTURetirementLocked(ctx); err != nil {
			return err
		}
	}
	// A newer connection may already own the app. Retire the old resources,
	// but only clear presentation state if this exact original command remains.
	a := h.parent.app
	a.mu.Lock()
	if h.launch.command != nil && a.cmd == h.launch.command {
		if a.state.RouterID != desktopExternalPathProfileID(h.launch) || a.state.RuntimeMode != h.launch.mode {
			a.mu.Unlock()
			return errors.New("Linux host retirement cannot change a replacement presentation")
		}
		a.cmd = nil
		a.state.Connected, a.state.Mode, a.state.RuntimeMode, a.state.Phase = false, "off", "", "off"
	}
	a.mu.Unlock()
	return nil
}
