package main

import (
	"bytes"
	"context"
	"errors"
	"math"
	"time"

	"router-vpn/internal/windowsprotection"
)

type desktopNodeJournalRecovery interface {
	Run(context.Context) (windowsprotection.JournalRecoveryResult, error)
	Close(context.Context) error
}

// Production constructs these callbacks from the retained Windows bootstrap,
// original desktop/Data handles and native ProtectionJournal. No imported
// profile, UI field or serialized receipt supplies a recovery capability.
type desktopNodeRecoveryBackend struct {
	controller windowsprotection.Controller
	current    func() error
	open       func(context.Context) (desktopNodeProtectionJournal, error)
	create     func(context.Context) (desktopNodeProtectionJournal, error)
	begin      func(context.Context, desktopNodeProtectionJournal) (desktopNodeJournalRecovery, error)
}

type desktopNodeRecoveryState struct {
	backend        desktopNodeRecoveryBackend
	opened         bool
	head           *windowsprotection.JournalSelection
	owner          desktopNodeJournalRecovery
	result         *windowsprotection.JournalRecoveryResult
	proved         bool
	ownerClosed    bool
	ready          bool
	closing        bool
	failure        error
	absenceClosing bool // joined before a fresh namespace proof on retry
}

type desktopNodeRecoveryOperation struct {
	context context.Context
	cancel  context.CancelFunc
}

// Recovery may run before beginConnectionTransaction publishes a connection
// context. Give that work its own captured cancellation owner so Disconnect and
// terminal shutdown can cancel it before waiting for operationMu.
func (a *app) captureDesktopNodeRecoveryOperation(parent context.Context, slot *desktopNodeProtectionSlot) (*desktopNodeRecoveryOperation, func(), error) {
	if parent == nil || parent.Err() != nil {
		return nil, nil, errors.New("startup recovery has no current caller")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.nodeProtection != slot || a.nodeRecovery != nil || a.controllerClosingLocked() {
		return nil, nil, errors.New("startup recovery belongs to an active or replaced operation")
	}
	ctx, cancel := context.WithCancel(parent)
	operation := &desktopNodeRecoveryOperation{context: ctx, cancel: cancel}
	a.nodeRecovery = operation
	finish := func() {
		cancel()
		a.mu.Lock()
		if a.nodeRecovery == operation {
			a.nodeRecovery = nil
		}
		a.mu.Unlock()
	}
	return operation, finish, nil
}

func (a *app) cancelDesktopNodeRecovery() {
	a.mu.Lock()
	operation := a.nodeRecovery
	a.mu.Unlock()
	if operation != nil {
		operation.cancel()
	}
}

func exactDesktopNodeJournalSelection(selection windowsprotection.JournalSelection) error {
	raw, err := windowsprotection.CanonicalJournalRecord(selection.Record)
	digest, hashErr := windowsprotection.JournalRecordSHA256(raw)
	if err != nil || hashErr != nil || selection.Incomplete || selection.Slot < 0 || selection.Slot > 1 ||
		uint64(selection.Slot) != (selection.Record.Sequence-1)%2 || digest != selection.SHA256 {
		return errors.Join(err, hashErr, errors.New("native startup recovery lost its exact complete journal selection"))
	}
	return nil
}

func copyDesktopNodeJournalSelection(selection windowsprotection.JournalSelection) (windowsprotection.JournalSelection, error) {
	if err := exactDesktopNodeJournalSelection(selection); err != nil {
		return windowsprotection.JournalSelection{}, err
	}
	copy, err := copyDesktopNodeJournalRecord(selection.Record)
	selection.Record = copy
	return selection, err
}

func (a *app) ensureDesktopNodeRecovery(ctx context.Context, slot *desktopNodeProtectionSlot) error {
	return a.ensureDesktopNodeRecoveryMode(ctx, slot, false)
}

func (a *app) ensureDesktopNodeJournalForStart(ctx context.Context, slot *desktopNodeProtectionSlot) error {
	return a.ensureDesktopNodeRecoveryMode(ctx, slot, true)
}

func (a *app) ensureDesktopNodeRecoveryMode(ctx context.Context, slot *desktopNodeProtectionSlot, requireJournal bool) error {
	if a == nil || slot == nil || ctx == nil || ctx.Err() != nil {
		return errors.New("native startup recovery has no captured application slot")
	}
	a.mu.Lock()
	selected, profiles := a.profiles.SelectedID, a.cfg.ProfilesFile
	current := a.nodeProtection == slot && !a.controllerClosingLocked()
	a.mu.Unlock()
	if !current {
		return errors.New("native startup recovery belongs to a replaced application")
	}
	guard := func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		return ctx.Err() == nil && a.nodeProtection == slot && a.profiles.SelectedID == selected &&
			a.cfg.ProfilesFile == profiles && !a.controllerClosingLocked()
	}
	return slot.initializeRecoveryWithJournal(ctx, selected, profiles, guard, requireJournal)
}

func (s *desktopNodeProtectionSlot) initializeRecovery(ctx context.Context, selectedID, profiles string, current func() bool) (failure error) {
	return s.initializeRecoveryWithJournal(ctx, selectedID, profiles, current, false)
}

func (s *desktopNodeProtectionSlot) initializeRecoveryWithJournal(ctx context.Context, selectedID, profiles string, current func() bool, requireJournal bool) (failure error) {
	if s == nil || ctx == nil || ctx.Err() != nil || current == nil || !current() {
		return errors.New("native startup recovery lost its captured operation")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.backend.bootstrap == nil {
		return nil // explicit modeled/pre-captured test backends have no native store
	}
	if s.recovery != nil && s.recovery.ready {
		if !requireJournal || s.journal != nil {
			return nil
		}
		if !s.known || s.target != nil || s.active != nil || s.retirement != nil || s.off != nil || s.journalClosing {
			return errors.New("native journal creation cannot replace an existing protection owner")
		}
		// Read-only startup absence is not a durable launch authority. Reopen
		// the exact namespace and materialize before capturing a predecessor.
		s.known, s.recovery.ready, s.recovery.opened = false, false, false
		s.recovery.head = nil
	}
	if s.active != nil || s.retirement != nil || s.off != nil || s.journalClosing || s.known || s.target != nil || s.backend.read == nil {
		return errors.New("startup recovery cannot replace an active, retiring or already captured slot")
	}
	if s.recovery == nil {
		s.recovery = &desktopNodeRecoveryState{}
	}
	r := s.recovery
	defer func() { r.failure = failure }()
	if r.backend.current == nil {
		backend, err := s.backend.bootstrap(ctx, profiles)
		if err != nil {
			return err
		}
		if backend.controller.Validate() != nil || backend.current == nil || backend.open == nil || backend.begin == nil {
			return errors.New("startup recovery has no complete native bootstrap owner")
		}
		r.backend = backend
	}
	if r.closing {
		return errors.New("startup recovery is joining its terminal owner")
	}
	check := func() error {
		if ctx.Err() != nil || !current() {
			return errors.Join(ctx.Err(), errors.New("startup recovery lost its application generation"))
		}
		return r.backend.current()
	}
	if err := check(); err != nil {
		return err
	}
	initialAbsence, err := s.openRecoveryJournalLocked(ctx, check, requireJournal)
	if err != nil {
		return err
	}
	if initialAbsence {
		s.known, r.ready = true, true
		return nil
	}
	if r.head == nil {
		selection, err := s.journal.Snapshot(ctx)
		if err != nil {
			return err
		}
		captured, err := copyDesktopNodeJournalSelection(selection)
		if err != nil {
			return err
		}
		r.head = &captured
	}
	if r.head.Record.Controller == r.backend.controller {
		// A fresh empty journal can belong to this controller. A nonempty or
		// unresolved same-controller record without its original operation is
		// not a substitute for the opaque handover owner and its BFE proof.
		if r.head.Record.Phase != "settled" || r.head.Record.Committed.Target != nil || r.head.Record.Committed.Engine != nil {
			return errors.New("startup recovery cannot adopt a nonempty same-controller record without its original owner")
		}
		if err := s.backend.read(ctx, nil); err != nil {
			return err
		}
		if err := check(); err != nil {
			return err
		}
		s.known, r.ready = true, true
		return nil
	}
	if r.owner == nil {
		owner, err := r.backend.begin(ctx, s.journal)
		if owner != nil {
			r.owner = owner
		}
		if err != nil || owner == nil {
			return errors.Join(err, errors.New("startup recovery has no checked native handover owner"))
		}
	}
	if !r.proved {
		result, err := r.owner.Run(ctx)
		if result.Selection.Record.Validate() != nil {
			return errors.Join(err, errors.New("native startup handover has no current complete result"))
		}
		copy, copyErr := copyDesktopNodeJournalSelection(result.Selection)
		if copyErr != nil || windowsprotection.CheckJournalRecoveryTransition(r.head.Record, copy.Record) != nil ||
			copy.Record.Controller != r.backend.controller || copy.Record.Adoption == nil ||
			!sameDesktopNodeRecoveryState(result.Observed, copy.Record.Adoption.Observed) ||
			r.result != nil && !sameDesktopNodeJournalSelection(r.result.Selection, copy) {
			return errors.Join(err, copyErr, errors.New("native startup handover changed its captured journal or observed outcome"))
		}
		result.Selection, result.Observed = copy, copy.Record.Adoption.Observed
		r.result = &result // a result with error preserves evidence, never admission
		if err != nil {
			return errors.Join(err, errors.New("native startup recovery has not joined its process and BFE proof"))
		}
		r.proved = true
	}
	if !r.ownerClosed {
		if err := r.owner.Close(ctx); err != nil {
			return err
		}
		r.ownerClosed = true
	}
	selection, err := s.journal.Snapshot(ctx)
	if err != nil || !sameDesktopNodeJournalSelection(selection, r.result.Selection) {
		return errors.Join(err, errors.New("startup recovery changed after its acknowledged native handover"))
	}
	if err := s.backend.read(ctx, r.result.Observed.Target); err != nil {
		return err
	}
	if err := check(); err != nil {
		return err
	}
	if err := s.hydrateRecoveryLocked(selectedID, *r.result, r.owner); err != nil {
		return err
	}
	r.ready = true
	return nil
}

func sameDesktopNodeRecoveryState(a, b windowsprotection.JournalState) bool {
	return a.ProfileID == b.ProfileID && a.ProfileRevision == b.ProfileRevision && a.Engine == nil && b.Engine == nil &&
		(a.Target == nil && b.Target == nil || a.Target != nil && b.Target != nil && *a.Target == *b.Target)
}

func sameDesktopNodeJournalSelection(a, b windowsprotection.JournalSelection) bool {
	if exactDesktopNodeJournalSelection(a) != nil || exactDesktopNodeJournalSelection(b) != nil || a.SHA256 != b.SHA256 || a.Slot != b.Slot {
		return false
	}
	left, leftErr := windowsprotection.CanonicalJournalRecord(a.Record)
	right, rightErr := windowsprotection.CanonicalJournalRecord(b.Record)
	return leftErr == nil && rightErr == nil && bytes.Equal(left, right)
}

func (s *desktopNodeProtectionSlot) hydrateRecoveryLocked(selectedID string, result windowsprotection.JournalRecoveryResult, joined desktopNodeJournalRecovery) error {
	record := result.Selection.Record
	if exactDesktopNodeJournalSelection(result.Selection) != nil || joined == nil || record.Adoption == nil ||
		!sameDesktopNodeRecoveryState(record.Adoption.Observed, result.Observed) || s.generation == math.MaxUint64 {
		return errors.New("startup hydration has no exact joined native recovery receipt")
	}
	state := result.Observed
	if record.Phase == "intent" {
		if record.Intent == nil || record.Intent.Action != "off" || record.Committed.Target == nil || record.Committed.Engine != nil ||
			!desktopNodeProcessHex(record.Committed.ProfileRevision, 32) {
			return errors.New("startup recovery has an unsupported unresolved native intent")
		}
		state = record.Committed // logical owner remains until captured Off is saved
	} else if record.Phase != "settled" || !sameDesktopNodeRecoveryState(record.Committed, state) {
		return errors.New("startup recovery lost its exact settled source binding")
	}
	if state.Target != nil && !desktopNodeProcessHex(state.ProfileRevision, 32) {
		return errors.New("startup recovery source has no durably captured profile revision")
	}
	var pending *desktopNodeProtectionOff
	if record.Phase == "intent" {
		var err error
		pending, err = s.recoveredJournalOffLocked(selectedID, result, joined)
		if err != nil {
			return err
		}
	}
	s.generation++
	s.known, s.target, s.profileRevision = true, copyDesktopNodeProtectionTarget(state.Target), state.ProfileRevision
	if state.Target != nil {
		s.binding = desktopNodeProtectionBinding{ProfileID: state.ProfileID, SourceSHA256: state.Target.Capture.SourceSHA256}
	} else {
		s.binding = desktopNodeProtectionBinding{}
	}
	s.off = pending
	if pending != nil {
		pending.generation, pending.binding = s.generation, s.binding
		pending.token = s.viewLocked().token(pending.profileRevision)
	}
	return nil
}

func (s *desktopNodeProtectionSlot) recoveryPending() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.backend.bootstrap != nil && (s.recovery == nil || !s.recovery.ready)
}

// initializeDesktopNodeRecoveryWith runs before the listener can schedule any
// startup connection. An empty initialized journal is closed before dropping
// its slot, so it cannot swallow a later independent engine's cleanup.
func (a *app) initializeDesktopNodeRecoveryWith(ctx context.Context, backend desktopNodeProtectionBackend) error {
	if a == nil || ctx == nil || ctx.Err() != nil || backend.bootstrap == nil {
		return errors.New("startup recovery requires its native application bootstrap")
	}
	a.operationMu.Lock()
	defer a.operationMu.Unlock()
	a.mu.Lock()
	if a.nodeProtection == nil {
		a.nodeProtection = &desktopNodeProtectionSlot{backend: backend}
	}
	slot := a.nodeProtection
	a.mu.Unlock()
	return a.resumeDesktopNodeStartupRecovery(ctx, slot)
}

// The caller holds operationMu (startup, connection admission or settings).
func (a *app) resumeDesktopNodeStartupRecovery(ctx context.Context, slot *desktopNodeProtectionSlot) error {
	operation, finish, err := a.captureDesktopNodeRecoveryOperation(ctx, slot)
	if err != nil {
		return err
	}
	defer finish()
	ctx = operation.context
	if err := a.ensureDesktopNodeRecovery(ctx, slot); err != nil {
		return err
	}
	if pending := slot.pendingOff(); pending != nil {
		_, err := a.resumeDesktopProtectionOff(ctx, slot, pending, false)
		return err
	}
	slot.mu.Lock()
	empty := slot.known && slot.target == nil && slot.active == nil && slot.retirement == nil && slot.off == nil
	err = nil
	if empty {
		err = slot.closeEmptyJournalLocked(ctx)
	}
	slot.mu.Unlock()
	if err != nil {
		return err
	}
	if empty && slot.provedEmpty() {
		a.mu.Lock()
		if a.nodeProtection == slot {
			a.nodeProtection = nil
		}
		a.mu.Unlock()
	}
	return nil
}

// Terminal shutdown joins only resources owned by an unresolved startup or
// recovered Off operation. It leaves the durable intent and native policy for
// the next controller to reconcile; no absence/removal receipt is invented.
func (a *app) closeTerminalDesktopNodeRecovery() (bool, error) {
	a.mu.Lock()
	slot, closing := a.nodeProtection, a.controllerClosingLocked()
	unused := a.cmd == nil && !a.state.Connected
	a.mu.Unlock()
	if slot == nil || !closing || !unused {
		return false, nil
	}
	slot.mu.Lock()
	defer slot.mu.Unlock()
	r := slot.recovery
	if slot.active != nil || slot.retirement != nil || r == nil || r.ready && (slot.off == nil || !slot.off.recovered) {
		return false, nil
	}
	r.closing = true
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if slot.off != nil && slot.off.owner != nil && slot.off.owner != r.owner {
		if err := slot.off.owner.Close(ctx); err != nil {
			return true, err
		}
	}
	if r.owner != nil {
		if err := r.owner.Close(ctx); err != nil {
			return true, err
		}
	}
	if slot.journal != nil {
		if err := slot.journal.Close(); err != nil {
			return true, err
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.nodeProtection != slot || !a.controllerClosingLocked() || a.cmd != nil || a.state.Connected {
		return true, errors.New("terminal startup recovery join belongs to a replaced application")
	}
	a.nodeProtection = nil
	return true, nil
}
