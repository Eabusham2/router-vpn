//go:build windows

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
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
	slot       *desktopNodeProtectionSlot
	attempt    *desktopNodeProtectionAttempt
	current    func(bool) bool
	external   bool
}

func startDesktopOwnedNodeJournalProcess(ctx context.Context, a *app, launch *desktopNodeLaunch,
	arguments, environment []string, directory string) (desktopNodeProcess, error) {
	return startDesktopProtectedJournalProcess(ctx, a, launch, arguments, environment, directory, false)
}

func startDesktopOwnedExternalJournalProcess(ctx context.Context, a *app, launch *desktopNodeLaunch,
	arguments, environment []string, directory string) (desktopNodeProcess, error) {
	return startDesktopProtectedJournalProcess(ctx, a, launch, arguments, environment, directory, true)
}

func startDesktopProtectedJournalProcess(ctx context.Context, a *app, launch *desktopNodeLaunch,
	arguments, environment []string, directory string, external bool) (_ desktopNodeProcess, failure error) {
	if a == nil || launch == nil || ctx == nil {
		return nil, errors.New("native journal launch has no captured application attempt")
	}
	var slot *desktopNodeProtectionSlot
	var attempt *desktopNodeProtectionAttempt
	var revision, captureName string
	var current func(bool) bool
	var owner *desktopNodeWindowsJournalProcess
	if external {
		if launch.ownedNode != nil || launch.external == nil || launch.external.windows == nil {
			return nil, errors.New("native external journal lost its typed host")
		}
		owned := launch.external.windows
		owned.mu.Lock()
		slot, attempt = owned.slot, owned.attempt
		owned.mu.Unlock()
		revision, captureName = owned.profileToken, "external-journal-capture.json"
		current = func(required bool) bool { return owned.current(required) == nil }
		if attempt == nil || attempt.external != owned.policy || attempt.policy != nil || attempt.imported != nil {
			return nil, errors.New("native external journal lost its exact policy selection")
		}
	} else {
		if launch.ownedNode == nil || launch.external != nil {
			return nil, errors.New("native Router journal lost its typed host")
		}
		owned := launch.ownedNode
		slot, attempt, revision, captureName = owned.slot, owned.attempt, owned.profileToken, "node-journal-capture.json"
		current = func(required bool) bool { return a.desktopOwnedNodeCurrent(launch, required) }
		if !attempt.matchesOwned(owned) {
			return nil, errors.New("native Router journal lost its exact policy selection")
		}
	}
	if slot == nil || attempt == nil || attempt.launch != launch {
		return nil, errors.New("native journal launch changed its original attempt")
	}
	if external {
		// Once the app has entered this constructor, every failure returns a real
		// retirement owner. Before a channel/child exists its only outcome is the
		// exact settled head captured by beginExternal, never an inferred absence.
		slot.mu.Lock()
		if slot.active != attempt || attempt.initialJournal == nil {
			slot.mu.Unlock()
			return nil, errors.New("native external journal omitted its original settled checkpoint")
		}
		initial, initialErr := copyDesktopNodeJournalRecord(*attempt.initialJournal)
		slot.mu.Unlock()
		if initialErr != nil {
			return nil, initialErr
		}
		owner = &desktopNodeWindowsJournalProcess{app: a, launch: launch, outcome: initial, closeGate: make(chan struct{}, 1), slot: slot, attempt: attempt, current: current, external: true}
		owner.closeGate <- struct{}{}
	}
	defer func() {
		if failure != nil && owner != nil {
			retire, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			failure = errors.Join(failure, owner.Close(retire))
		}
	}()
	if ctx.Err() != nil || !current(false) {
		err := errors.Join(ctx.Err(), errors.New("native journal launch changed its original attempt"))
		if owner != nil {
			return owner, err
		}
		return nil, err
	}
	var controller *windowsOwnedController
	if external {
		controller, _ = launch.external.windows.host.capture.retainedController.(*windowsOwnedController)
	} else if launch.ownedNode.imported != nil {
		if launch.ownedNode.host != nil {
			controller, _ = launch.ownedNode.host.capture.retainedController.(*windowsOwnedController)
		}
	} else {
		controller = windowsOwnedCapture.Load()
	}
	if err := currentDesktopNodeController(controller); err != nil {
		if owner != nil {
			return owner, err
		}
		return nil, err
	}
	journal, captured, err := captureDesktopProtectionJournal(ctx, controller, slot, attempt, revision)
	if err != nil {
		if owner != nil {
			return owner, err
		}
		return nil, err
	}
	if owner == nil {
		owner = &desktopNodeWindowsJournalProcess{app: a, launch: launch, closeGate: make(chan struct{}, 1), slot: slot, attempt: attempt, current: current}
		owner.closeGate <- struct{}{}
	}
	owner.controller, owner.capture, owner.outcome = controller, captured, captured.Head
	currentJournal := func() error {
		if !current(false) {
			return errors.New("native journal launch belongs to a replaced application attempt")
		}
		return currentDesktopNodeController(controller)
	}
	owner.server, err = windowsprotection.NewJournalCommitServer(ctx, journal, captured, currentJournal)
	if err != nil {
		return owner, err
	}
	raw, err := windowsprotection.CanonicalJournalCommitCapture(captured)
	if err == nil {
		sum := sha256.Sum256(raw)
		owner.digest = hex.EncodeToString(sum[:])
		err = writeDesktopRuntimeFile(launch, captureName, raw, false)
	}
	if err != nil {
		return owner, err
	}
	process, err := startDesktopProtectedProcessWithJournal(ctx, arguments, environment, directory, owner, external)
	if process == nil {
		return owner, err // Even validation before child creation retains the server.
	}
	return process, err
}

// Startup initializes/reconciles the journal before slot.begin can capture its
// predecessor. Launch only consumes that retained checked owner; it never
// creates a store after selecting a nil expectation or adopts a decoded head.
func captureDesktopProtectionJournal(ctx context.Context, controller *windowsOwnedController, slot *desktopNodeProtectionSlot, attempt *desktopNodeProtectionAttempt, revision string) (*windowsprotection.ProtectionJournal, windowsprotection.JournalCommitCapture, error) {
	var empty windowsprotection.JournalCommitCapture
	if controller == nil || slot == nil || attempt == nil {
		return nil, empty, errors.New("native journal has no original captured slot")
	}
	slot.mu.Lock()
	defer slot.mu.Unlock()
	if slot.active != attempt || attempt.profileRevision != revision || len(controller.directories) != 1 || controller.parent == nil ||
		!windowsOwnedSamePath(controller.directories[0].Name(), controller.dataRoot) {
		return nil, empty, errors.New("native journal lost its retained original Data directory")
	}
	if slot.journal == nil {
		return nil, empty, errors.New("native journal launch preceded checked startup initialization")
	}
	if slot.recovery == nil || !slot.recovery.ready {
		return nil, empty, errors.New("native journal launch still has unresolved startup recovery")
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
	selected, selectedErr := attempt.selection()
	if selectedErr != nil {
		return nil, empty, selectedErr
	}
	captured := windowsprotection.JournalCommitCapture{Schema: windowsprotection.JournalCommitSchema, Kind: windowsprotection.JournalCommitCaptureKind,
		Head: selection.Record, ProfileID: selected.profileID, ProfileRevision: attempt.profileRevision, Transfer: attempt.transfer}
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
	current := func() bool { return ctx.Err() == nil && owner.current != nil && owner.current(true) }
	record, err := owner.server.Admit(ctx, func(ctx context.Context, durable windowsprotection.JournalRecord) error {
		return owner.slot.captureJournalPrepared(ctx, owner.attempt, durable, current)
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

func (owner *desktopNodeWindowsJournalProcess) AliveContext(ctx context.Context) error {
	if owner == nil || owner.desktopNodeProcessOwner == nil {
		return errors.New("native journal child was not created")
	}
	return owner.desktopNodeProcessOwner.AliveContext(ctx)
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
