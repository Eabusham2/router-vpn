//go:build windows

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"os"
	"strconv"
	"sync"
	"time"

	"router-vpn/internal/windowscontroller"
	"router-vpn/internal/windowsprotection"
)

type desktopNodeWindowsJournalProcess struct {
	*desktopNodeProcessOwner
	server     *windowsprotection.JournalCommitServer
	capture    windowsprotection.JournalCommitCapture
	controller *windowsOwnedController
	app        *app
	launch     *desktopNodeLaunch
	child      *windowscontroller.GUIChild
	image      *windowscontroller.Image
	digest     string
	mu         sync.Mutex
	closeGate  chan struct{}
	outcome    windowsprotection.JournalRecord
	joined     bool
}

func startDesktopOwnedNodeJournalProcess(ctx context.Context, a *app, launch *desktopNodeLaunch,
	arguments, environment []string, directory string) (_ desktopNodeProcess, failure error) {
	if a == nil || launch == nil || launch.ownedNode == nil || launch.ownedNode.slot == nil || launch.ownedNode.attempt == nil ||
		ctx == nil || ctx.Err() != nil || !a.desktopOwnedNodeCurrent(launch, false) {
		return nil, errors.New("native journal launch has no captured application attempt")
	}
	controller := windowsOwnedCapture.Load()
	if err := currentDesktopNodeController(controller); err != nil {
		return nil, err
	}
	journal, captured, err := captureDesktopNodeJournal(ctx, controller, launch)
	if err != nil {
		return nil, err
	}
	owner := &desktopNodeWindowsJournalProcess{controller: controller, app: a, launch: launch, capture: captured, outcome: captured.Head, closeGate: make(chan struct{}, 1)}
	owner.closeGate <- struct{}{}
	defer func() {
		if failure != nil {
			retire, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			failure = errors.Join(failure, owner.Close(retire))
		}
	}()
	current := func() error {
		if !a.desktopOwnedNodeCurrent(launch, false) {
			return errors.New("native journal launch belongs to a replaced application attempt")
		}
		return currentDesktopNodeController(controller)
	}
	owner.server, err = windowsprotection.NewJournalCommitServer(ctx, journal, captured, current)
	if err != nil {
		return owner, err
	}
	raw, err := windowsprotection.CanonicalJournalCommitCapture(captured)
	if err == nil {
		sum := sha256.Sum256(raw)
		owner.digest = hex.EncodeToString(sum[:])
		err = writeDesktopRuntimeFile(launch, "node-journal-capture.json", raw, false)
	}
	if err != nil {
		return owner, err
	}
	process, err := startDesktopOwnedNodeProcessWithJournal(ctx, arguments, environment, directory, owner)
	if process == nil {
		return owner, err // Even validation before child creation retains the server.
	}
	return process, err
}

// Capture uses the already retained original desktop/Data handles. A complete
// journal from this controller may reopen; another controller's checkpoint is
// retained but cannot be appended or silently adopted on this startup path.
func captureDesktopNodeJournal(ctx context.Context, controller *windowsOwnedController, launch *desktopNodeLaunch) (*windowsprotection.ProtectionJournal, windowsprotection.JournalCommitCapture, error) {
	var empty windowsprotection.JournalCommitCapture
	owned := launch.ownedNode
	slot := owned.slot
	slot.mu.Lock()
	defer slot.mu.Unlock()
	if slot.active != owned.attempt || len(controller.directories) != 1 || controller.parent == nil ||
		!windowsOwnedSamePath(controller.directories[0].Name(), controller.dataRoot) {
		return nil, empty, errors.New("native journal lost its retained original Data directory")
	}
	if slot.journal == nil {
		store, err := windowsprotection.OpenProtectionJournal(ctx, controller.parent, controller.directories[0])
		if errors.Is(err, os.ErrNotExist) {
			if store != nil {
				if closeErr := store.Close(); closeErr != nil {
					slot.journal = store
					return nil, empty, errors.Join(err, closeErr)
				}
			}
			store, err = windowsprotection.CreateProtectionJournal(ctx, controller.parent, controller.directories[0])
		}
		if store != nil {
			slot.journal = store // Preserve partial native capture even on failure.
		}
		if err != nil {
			return nil, empty, err
		}
	}
	store, ok := slot.journal.(*windowsprotection.ProtectionJournal)
	if !ok || store == nil {
		return nil, empty, errors.New("native journal has another storage owner")
	}
	selection, err := store.Snapshot(ctx)
	if err != nil || selection.Incomplete || selection.Record.Phase != "settled" || selection.Record.Committed.Engine != nil ||
		selection.Record.Sequence > math.MaxUint64-3 {
		return nil, empty, errors.Join(err, errors.New("native journal requires checked recovery before another launch"))
	}
	meta := owned.policy.Metadata()
	captured := windowsprotection.JournalCommitCapture{Schema: windowsprotection.JournalCommitSchema, Kind: windowsprotection.JournalCommitCaptureKind,
		Head: selection.Record, ProfileID: meta.ProfileID, ProfileRevision: owned.profileToken, Transfer: owned.attempt.transfer}
	if err := captured.Validate(); err != nil {
		return nil, empty, err
	}
	return store, captured, nil
}

func (owner *desktopNodeWindowsJournalProcess) launchArguments(parent uint64, arguments []string) ([]string, error) {
	if owner == nil || owner.server == nil || parent == 0 || owner.digest == "" || owner.controller == nil || owner.controller.selfImage == nil {
		return nil, errors.New("native journal child has no inherited parent or exact rendezvous")
	}
	if err := currentDesktopNodeController(owner.controller); err != nil {
		return nil, err
	}
	pipe := owner.server.PipeName()
	if pipe == "" {
		return nil, errors.New("native journal child lost its parent channel")
	}
	return append(append([]string(nil), arguments...), "--journal-parent-handle", strconv.FormatUint(parent, 10),
		"--journal-parent-image", owner.controller.selfImage.Path(), "--journal-pipe", pipe, "--journal-capture-sha256", owner.digest), nil
}

func (owner *desktopNodeWindowsJournalProcess) remember(record windowsprotection.JournalRecord) error {
	if record.Validate() != nil {
		return nil // No durable result was returned; DrainAttempt keeps the exact pending append.
	}
	copy, err := copyDesktopNodeJournalRecord(record)
	if err != nil {
		return err
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if copy.JournalID != owner.outcome.JournalID || copy.Controller != owner.outcome.Controller {
		return errors.New("native journal result changed its retained creator")
	}
	if copy.Sequence >= owner.outcome.Sequence {
		owner.outcome = copy
	}
	return nil
}

func (owner *desktopNodeWindowsJournalProcess) AdmitProtection(ctx context.Context) error {
	if owner == nil || owner.server == nil || owner.child == nil || owner.image == nil || ctx == nil || ctx.Err() != nil {
		return errors.New("native journal admission has no created child")
	}
	intent, err := owner.server.Receive(owner.child, owner.image)
	rememberErr := owner.remember(intent)
	if err != nil || rememberErr != nil {
		return errors.Join(err, rememberErr)
	}
	current := func() bool { return ctx.Err() == nil && owner.app.desktopOwnedNodeCurrent(owner.launch, true) }
	record, err := owner.server.Admit(ctx, func(ctx context.Context, durable windowsprotection.JournalRecord) error {
		return owner.launch.ownedNode.slot.captureJournalPrepared(ctx, owner.launch.ownedNode.attempt, durable, current)
	})
	return errors.Join(err, owner.remember(record))
}

func (owner *desktopNodeWindowsJournalProcess) Started() bool {
	return owner != nil && owner.desktopNodeProcessOwner != nil && owner.desktopNodeProcessOwner.Started()
}

func (owner *desktopNodeWindowsJournalProcess) Alive() error {
	if owner == nil || owner.desktopNodeProcessOwner == nil {
		return errors.New("native journal child was not created")
	}
	return owner.desktopNodeProcessOwner.Alive()
}

func (owner *desktopNodeWindowsJournalProcess) Wait(ctx context.Context) (uint32, error) {
	if owner == nil || owner.desktopNodeProcessOwner == nil {
		return 0, errors.New("native journal child has no exit owner")
	}
	return owner.desktopNodeProcessOwner.Wait(ctx)
}

func (owner *desktopNodeWindowsJournalProcess) Close(ctx context.Context) error {
	if owner == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("native journal retirement requires a bounded caller")
	}
	if owner.closeGate == nil {
		return errors.New("native journal retirement lost its serialized owner")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-owner.closeGate:
	}
	defer func() { owner.closeGate <- struct{}{} }()
	owner.mu.Lock()
	joined := owner.joined
	owner.mu.Unlock()
	if joined {
		return nil
	}
	if owner.server != nil {
		if err := owner.server.Close(ctx); err != nil {
			return err
		}
	}
	if owner.desktopNodeProcessOwner != nil {
		if err := owner.desktopNodeProcessOwner.Close(ctx); err != nil {
			return err
		}
	}
	if owner.server != nil {
		record, err := owner.server.DrainAttempt(ctx)
		if rememberErr := owner.remember(record); err != nil || rememberErr != nil {
			return errors.Join(err, rememberErr)
		}
	}
	owner.mu.Lock()
	owner.joined = true
	owner.mu.Unlock()
	return ctx.Err()
}

func (owner *desktopNodeWindowsJournalProcess) JournalOutcome() (windowsprotection.JournalRecord, error) {
	if owner == nil {
		return windowsprotection.JournalRecord{}, errors.New("native journal outcome has no captured child")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if !owner.joined {
		return windowsprotection.JournalRecord{}, errors.New("native journal outcome preceded its checked channel and child join")
	}
	return copyDesktopNodeJournalRecord(owner.outcome)
}
