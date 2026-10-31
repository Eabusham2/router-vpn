package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"

	"router-vpn/internal/common"
	"router-vpn/internal/mobiletor"
	"router-vpn/internal/windowsprotection"
)

// Application initialization, owned-slot adoption, HTTP retry, profile writes,
// readback and journal transitions are real here. Only native process/BFE
// observation and protected journal I/O are modeled; their Windows gates run
// separately against actual kernel handles and the shipping BFE observer.
type desktopRecoveryFixture struct {
	*desktopDurableOffFixture
	initial       windowsprotection.JournalRecord
	controller    windowsprotection.Controller
	store         *desktopRecoveryStore
	recovery      *desktopRecoveryNative
	backend       desktopNodeProtectionBackend
	matched       int
	opens, begins int
	openErr       error
	currentErr    error
	bootstrapErr  error
	removeCalls   int
	barriers      int
}

type desktopRecoveryStore struct {
	fixture *desktopRecoveryFixture
	base    *desktopNodeJournalFixtureStore
}

func (s *desktopRecoveryStore) Snapshot(ctx context.Context) (windowsprotection.JournalSelection, error) {
	selection, err := s.base.Snapshot(ctx)
	if err == nil {
		selection.Slot = int((selection.Record.Sequence - 1) % 2)
	}
	return selection, err
}

func (s *desktopRecoveryStore) Append(ctx context.Context, digest string, next windowsprotection.JournalRecord) (windowsprotection.JournalSelection, error) {
	f := s.fixture
	if s.base.head.Phase == "intent" && s.base.head.Intent.Action == "off" && next.Phase == "settled" {
		capture := f.slot.off
		if capture == nil || !capture.profileWritten.Load() || !capture.profileSaved.Load() || !capture.joined ||
			!capture.absenceProved || !capture.removed || f.kernel.target != nil {
			f.t.Fatal("recovered Off settled before the real saved-profile acknowledgment and joined absence")
		}
		raw, err := readPrivateRegular(f.a.cfg.ProfilesFile, maxPrivateStoreBytes)
		var saved common.RouterProfileStore
		if err != nil || json.Unmarshal(raw, &saved) != nil || saved.SelectedID != capture.capturedSelection() {
			f.t.Fatal("recovered Off settlement changed the actual selected private store", err)
		}
		proved := false
		for _, profile := range saved.Profiles {
			proved = proved || profile.ID == capture.profileID && profileStartupSettingsToken(profile) == capture.resultRevision && profile.KillSwitchPolicy == "off"
		}
		if !proved {
			f.t.Fatal("recovered Off settled without its exact result on disk")
		}
		f.events = append(f.events, "saved-profile-ack")
	}
	selection, err := s.base.Append(ctx, digest, next)
	if selection.Record.Sequence != 0 {
		selection.Slot = int((selection.Record.Sequence - 1) % 2)
	}
	return selection, err
}

func (s *desktopRecoveryStore) Close() error {
	s.fixture.events = append(s.fixture.events, "journal-close")
	return s.base.Close()
}

type desktopRecoveryNative struct {
	fixture      *desktopRecoveryFixture
	err          error
	closeErr     error
	writeOnError bool
	runs, closes int
	change       func(*windowsprotection.JournalRecoveryResult)
	entered      chan struct{}
	resume       chan struct{}
	waitContext  bool
	cancelled    error
}

func (owner *desktopRecoveryNative) Run(ctx context.Context) (windowsprotection.JournalRecoveryResult, error) {
	f := owner.fixture
	owner.runs++
	f.events = append(f.events, "checked-native-recovery")
	if owner.entered != nil {
		close(owner.entered)
		if owner.waitContext {
			<-ctx.Done()
			owner.cancelled = ctx.Err()
		} else {
			<-owner.resume
		}
	}
	if ctx.Err() != nil || owner.err != nil && !owner.writeOnError {
		return windowsprotection.JournalRecoveryResult{}, errors.Join(ctx.Err(), owner.err)
	}
	previous := f.initial
	candidates, err := windowsprotection.JournalRecoveryCandidates(previous)
	if err != nil || f.matched < 0 || f.matched >= len(candidates) {
		return windowsprotection.JournalRecoveryResult{}, errors.New("fixture native recovery has no recorded outcome")
	}
	observed := candidates[f.matched]
	observed.Engine = nil
	if !reflect.DeepEqual(observed.Target, f.kernel.target) || f.kernel.locked {
		return windowsprotection.JournalRecoveryResult{}, errors.New("fixture BFE differs from its exact recorded candidate")
	}
	next, _ := copyDesktopNodeJournalRecord(previous)
	raw, _ := windowsprotection.CanonicalJournalRecord(previous)
	digest, _ := windowsprotection.JournalRecordSHA256(raw)
	next.Sequence++
	next.PreviousSHA256, next.Controller = digest, f.controller
	next.Adoption = &windowsprotection.JournalAdoption{Sequence: next.Sequence, PreviousSHA256: digest, PreviousController: previous.Controller,
		Controller: f.controller, RequestID: strings.Repeat("e", 32), CandidateIndex: f.matched, Observed: observed}
	if previous.Phase != "intent" || previous.Intent.Action != "off" {
		next.Phase, next.Intent, next.Committed = "settled", nil, observed
	}
	if err := windowsprotection.CheckJournalRecoveryTransition(previous, next); err != nil {
		return windowsprotection.JournalRecoveryResult{}, err
	}
	f.store.base.head, _ = copyDesktopNodeJournalRecord(next)
	selection, err := f.store.Snapshot(ctx)
	result := windowsprotection.JournalRecoveryResult{Selection: selection, Observed: observed}
	if owner.change != nil {
		owner.change(&result)
	}
	return result, errors.Join(err, owner.err, ctx.Err())
}

func (owner *desktopRecoveryNative) Close(ctx context.Context) error {
	owner.closes++
	owner.fixture.events = append(owner.fixture.events, "recovery-close")
	return errors.Join(owner.closeErr, ctx.Err())
}

type desktopRecoveryOffNative struct {
	fixture *desktopRecoveryFixture
	native  *desktopProtectionOffFixtureOwner
	barrier mobiletor.DesktopWindowsProtectionCommitBarrier
}

func (owner *desktopRecoveryOffNative) Close(ctx context.Context) error {
	f := owner.fixture
	if !owner.native.closed {
		f.barriers++
		if err := owner.barrier(ctx, mobiletor.DesktopWindowsProtectionCommit{Action: "off", Previous: &owner.native.target}); err != nil {
			return err
		}
		head := f.store.base.head
		if head.Phase != "intent" || head.Intent == nil || head.Intent.RequestID != f.initial.Intent.RequestID ||
			head.Intent.ProfileRevision != f.initial.Intent.ProfileRevision || head.Intent.ResultProfileRevision != f.initial.Intent.ResultProfileRevision {
			f.t.Fatal("restart removal replaced the original accepted Off intent")
		}
		f.events = append(f.events, "retained-intent-barrier")
	}
	return owner.native.Close(ctx)
}

func newDesktopRecoveryFixture(t *testing.T, pendingOff, absent bool) *desktopRecoveryFixture {
	t.Helper()
	old := newDesktopDurableOffFixture(t, "always")
	// The accepted UI request belongs to an actual loaded/saved application
	// profile. Its revision may differ from the earlier retained source's
	// revision; neither one may be inferred from the other during restart.
	if err := old.a.loadProfiles(); err != nil {
		t.Fatal(err)
	}
	old.profile = cloneRouterProfile(old.a.profiles.Profiles[0])
	if err := old.a.persistProfiles(); err != nil {
		t.Fatal(err)
	}
	f := &desktopRecoveryFixture{desktopDurableOffFixture: old}
	head, _ := copyDesktopNodeJournalRecord(old.store.base.head)
	if pendingOff {
		capture := old.capture(t)
		journal, err := old.slot.captureJournalOffLocked(context.Background(), capture)
		if err != nil {
			t.Fatal(err)
		}
		head, _ = copyDesktopNodeJournalRecord(journal.intent)
		if absent {
			f.matched = 1
			f.kernel.target = nil
		}
	}
	f.initial, _ = copyDesktopNodeJournalRecord(head)
	f.controller = head.Controller
	f.controller.PID, f.controller.StartTimeUTCTicks = 303, f.controller.StartTimeUTCTicks+1000
	f.store = &desktopRecoveryStore{fixture: f, base: &desktopNodeJournalFixtureStore{head: head}}
	f.recovery = &desktopRecoveryNative{fixture: f}
	backend := old.slot.backend
	backend.bootstrap = func(ctx context.Context, profiles string) (desktopNodeRecoveryBackend, error) {
		if ctx.Err() != nil || profiles != f.a.cfg.ProfilesFile || f.bootstrapErr != nil {
			return desktopNodeRecoveryBackend{}, errors.Join(ctx.Err(), f.bootstrapErr, errors.New("fixture bootstrap rejected its profile root"))
		}
		return desktopNodeRecoveryBackend{controller: f.controller, current: func() error { return f.currentErr },
			open: func(context.Context) (desktopNodeProtectionJournal, error) { f.opens++; return f.store, f.openErr },
			begin: func(_ context.Context, store desktopNodeProtectionJournal) (desktopNodeJournalRecovery, error) {
				f.begins++
				if store != f.store {
					return nil, errors.New("fixture substituted a native store")
				}
				return f.recovery, nil
			}}, nil
	}
	backend.recoverWithBarrier = func(ctx context.Context, target mobiletor.DesktopWindowsProtectionTarget, barrier mobiletor.DesktopWindowsProtectionCommitBarrier) (desktopNodeProtectionRelease, error) {
		f.removeCalls++
		if ctx.Err() != nil || f.kernel.locked || f.kernel.target == nil || *f.kernel.target != target {
			return nil, errors.New("fixture recovered Off substituted its native target")
		}
		native := &desktopProtectionOffFixtureOwner{fixture: f.desktopProtectionOffFixture, target: target, armed: true}
		f.kernel.locked = true
		return &desktopRecoveryOffNative{fixture: f, native: native, barrier: barrier}, nil
	}
	f.backend = backend
	f.slot = &desktopNodeProtectionSlot{backend: backend}
	f.a.nodeProtection = f.slot
	f.events = nil
	return f
}

func (f *desktopRecoveryFixture) initialize() error {
	return f.a.initializeDesktopNodeRecoveryWith(context.Background(), f.backend)
}

func desktopRecoveryHoldSavedProfile(t *testing.T, path string) os.FileInfo {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	})
	info, err := file.Stat() // Captures native identity now, not a later pathname lookup.
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func TestDesktopNodeRecoveryRetainsAlwaysBeforeSuccessor(t *testing.T) {
	f := newDesktopRecoveryFixture(t, false, false)
	f.a.profiles.Profiles[0].DNSHost = "192.0.2.80" // Today's saved UI profile is distinct from the old running source.
	if err := f.a.persistProfiles(); err != nil {
		t.Fatal(err)
	}
	f.a.profiles = common.RouterProfileStore{}
	if err := f.a.loadProfiles(); err != nil {
		t.Fatal(err)
	}
	if err := f.initialize(); err != nil {
		t.Fatal(err)
	}
	if !f.slot.known || f.slot.target == nil || *f.slot.target != f.target || f.slot.profileRevision != f.initial.Committed.ProfileRevision ||
		f.slot.binding.ProfileID != f.initial.Committed.ProfileID || f.slot.binding.SourceSHA256 != f.target.Capture.SourceSHA256 ||
		f.slot.active != nil || f.a.state.Connected || f.recovery.runs != 1 || f.recovery.closes != 1 {
		t.Fatal("startup did not adopt the exact joined Always owner independently of today's selected profile")
	}
	launch := &desktopNodeLaunch{ownedNode: &desktopOwnedNodeRuntime{profileToken: desktopOwnedNodeProfileToken(f.a.profiles.Profiles[0])}}
	attempt, err := f.slot.begin(context.Background(), launch, desktopNodeProtectionPolicy(t, "2", "always", 0))
	if err != nil || attempt.transfer.Predecessor == nil || *attempt.transfer.Predecessor != f.target {
		t.Fatal("next actual source lost its checked restart predecessor", err)
	}
}

func TestDesktopNodeRecoveryPendingOffOriginalAndSavedResult(t *testing.T) {
	for _, mode := range []string{"retained-original", "absent-original", "absent-result"} {
		t.Run(mode, func(t *testing.T) {
			f := newDesktopRecoveryFixture(t, true, mode != "retained-original")
			other := cloneRouterProfile(f.profile)
			other.ID, other.Name, other.APIToken = "other-node", "Other node", "other-node-private-reference"
			f.a.profiles.Profiles = append(f.a.profiles.Profiles, other)
			f.a.profiles.SelectedID = other.ID
			if mode == "absent-result" {
				updated, err := profileProtectionOffResult(f.profile)
				if err != nil {
					t.Fatal(err)
				}
				f.a.profiles.Profiles[0] = updated
			}
			if err := f.a.persistProfiles(); err != nil {
				t.Fatal(err)
			}
			f.a.profiles = common.RouterProfileStore{}
			if err := f.a.loadProfiles(); err != nil {
				t.Fatal(err)
			}
			var before os.FileInfo
			if mode == "absent-result" {
				before = desktopRecoveryHoldSavedProfile(t, f.a.cfg.ProfilesFile)
			}
			if err := f.initialize(); err != nil {
				t.Fatal("recovered Off did not finish its exact accepted transaction", err)
			}
			after, err := os.Stat(f.a.cfg.ProfilesFile)
			if err != nil {
				t.Fatal(err)
			}
			if f.a.nodeProtection != nil || f.slot.target != nil || f.slot.off != nil || f.kernel.target != nil || f.kernel.locked ||
				f.a.profiles.SelectedID != other.ID || !reflect.DeepEqual(f.a.profiles.Profiles[1], other) ||
				profileStartupSettingsToken(f.a.profiles.Profiles[0]) != f.initial.Intent.ResultProfileRevision ||
				f.store.base.head.Phase != "settled" || f.store.base.head.Committed.Target != nil || f.store.base.closes != 1 {
				t.Fatal("restart Off lost saved result, unrelated credentials, startup selection or joined native state")
			}
			if mode == "absent-result" && !os.SameFile(before, after) {
				t.Fatal("restart rewrote an already published exact Off result")
			}
			wantRemoval := 0
			if mode == "retained-original" {
				wantRemoval = 1
			}
			if f.removeCalls != wantRemoval || f.barriers != wantRemoval || f.store.base.writes != 1 {
				t.Fatal("recovery repeated native removal or invented a second Off intent", f.removeCalls, f.barriers, f.store.base.writes)
			}
		})
	}
}

func TestDesktopNodeRecoveryOffRetriesActualSavedResult(t *testing.T) {
	f := newDesktopRecoveryFixture(t, true, false)
	f.store.base.failWrite = true
	if err := f.initialize(); err == nil || f.slot.off == nil || !f.slot.off.profileWritten.Load() || !f.slot.off.profileSaved.Load() ||
		f.store.base.pending == nil || f.kernel.target != nil {
		t.Fatal("failed recovered settlement lost its actual saved result and native absence")
	}
	before := desktopRecoveryHoldSavedProfile(t, f.a.cfg.ProfilesFile)
	pending, _ := windowsprotection.CanonicalJournalRecord(*f.store.base.pending)
	f.store.base.failWrite = false
	if err := f.initialize(); err != nil {
		t.Fatal("same recovered Off could not retry its exact pending settlement", err)
	}
	after, err := os.Stat(f.a.cfg.ProfilesFile)
	actual, _ := windowsprotection.CanonicalJournalRecord(f.store.base.head)
	if err != nil || !os.SameFile(before, after) || !bytes.Equal(pending, actual) || f.removeCalls != 1 || f.recovery.runs != 1 {
		t.Fatal("recovered settlement retry resaved the profile or replaced its native operation", err)
	}
}

func TestDesktopNodeRecoveryRejectsUnprovedReceiptAndChangedProfile(t *testing.T) {
	for _, fault := range []string{"process-proof", "durable-with-error", "wrong-observed-source", "wrong-controller", "changed-profile", "private-store-mismatch"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopRecoveryFixture(t, true, false)
			original, err := os.ReadFile(f.a.cfg.ProfilesFile)
			if err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "process-proof":
				f.recovery.err = errors.New("old source still owns its native engine")
			case "durable-with-error":
				f.recovery.err, f.recovery.writeOnError = errors.New("native snapshot proof was lost after durable append"), true
			case "wrong-observed-source":
				f.recovery.change = func(r *windowsprotection.JournalRecoveryResult) { r.Observed.ProfileRevision = strings.Repeat("f", 64) }
			case "wrong-controller":
				f.recovery.change = func(r *windowsprotection.JournalRecoveryResult) { r.Selection.Record.Controller.PID++ }
			case "changed-profile":
				f.a.profiles.Profiles[0].APIToken = "new-private-credential-reference"
				if err := f.a.persistProfiles(); err != nil {
					t.Fatal(err)
				}
				original, _ = os.ReadFile(f.a.cfg.ProfilesFile)
			case "private-store-mismatch":
				if err := atomicWritePrivate(f.a.cfg.ProfilesFile, []byte("{}\n")); err != nil {
					t.Fatal(err)
				}
				original = []byte("{}\n")
			}
			if err := f.initialize(); err == nil || f.a.state.Connected || f.removeCalls != 0 || f.store.base.writes != 0 {
				t.Fatal("unproved recovery or changed accepted profile reached native removal or saved settlement")
			}
			actual, err := os.ReadFile(f.a.cfg.ProfilesFile)
			if err != nil || !bytes.Equal(actual, original) || f.kernel.target == nil || *f.kernel.target != f.target {
				t.Fatal("failed recovery altered a replacement profile or retained native target", err)
			}
		})
	}
}

func TestDesktopNodeRecoveryAdmissionRetriesAndHTTPPendingOff(t *testing.T) {
	f := newDesktopRecoveryFixture(t, true, true)
	f.recovery.err = errors.New("old controller is still joining")
	if err := f.initialize(); err == nil {
		t.Fatal("fixture unresolved startup unexpectedly succeeded")
	}
	if !f.slot.recoveryPending() || f.slot.known {
		t.Fatal("failed startup fabricated an adopted slot")
	}
	f.recovery.err = nil
	f.a.operationMu.Lock()
	err := f.a.guardDesktopProtectionOffPending()
	f.a.operationMu.Unlock()
	if err != nil || f.a.nodeProtection != nil || profileStartupSettingsToken(f.a.profiles.Profiles[0]) != f.initial.Intent.ResultProfileRevision {
		t.Fatal("connection admission failed to resume the exact old accepted Off first", err)
	}

	f = newDesktopRecoveryFixture(t, true, false)
	other := cloneRouterProfile(f.profile)
	other.ID, other.Name = "selected-other", "Selected other"
	f.a.profiles.Profiles = append(f.a.profiles.Profiles, other)
	f.a.profiles.SelectedID = other.ID
	if err := f.a.persistProfiles(); err != nil {
		t.Fatal(err)
	}
	f.store.base.failWrite = true
	if err := f.initialize(); err == nil || f.slot.off == nil || !f.slot.off.recovered {
		t.Fatal("fixture recovered Off did not retain its pending actual settlement")
	}
	f.store.base.failWrite = false
	token := ownedProtectionGet(t, f.a)
	response := postProtectionForTest(f.a, bytes.NewReader(ownedProtectionBody(t, token, "off")))
	if response.Code != http.StatusOK || f.a.profiles.SelectedID != other.ID || f.a.nodeProtection != nil || !reflect.DeepEqual(f.a.profiles.Profiles[1], other) {
		t.Fatal("HTTP Off retry lost the accepted source or changed startup selection", response.Code, response.Body.String())
	}
	var result profileProtectionSettings
	if json.Unmarshal(response.Body.Bytes(), &result) != nil || result.ProfileID != other.ID {
		t.Fatal("HTTP recovered-Off result presented another node as selected")
	}
}

func TestDesktopNodeRecoveryEmptyStartupClosesStore(t *testing.T) {
	for _, sameController := range []bool{false, true} {
		f := newDesktopRecoveryFixture(t, false, false)
		head := windowsprotection.JournalRecord{Schema: 1, Kind: windowsprotection.JournalRecordKind, JournalID: strings.Repeat("a", 32),
			Sequence: 1, Controller: f.initial.Controller, Phase: "settled"}
		if sameController {
			head.Controller = f.controller
		}
		f.initial, f.store.base.head, f.kernel.target = head, head, nil
		if err := f.initialize(); err != nil || f.a.nodeProtection != nil || f.store.base.closes != 1 {
			t.Fatal("empty startup left a slot that could swallow another engine's cleanup", err)
		}
		if sameController && f.recovery.runs != 0 || !sameController && f.recovery.runs != 1 {
			t.Fatal("empty startup did not distinguish initial creation from checked restart")
		}
	}
}

func TestDesktopNodeRecoveryTerminalShutdownPreservesUnknownPolicy(t *testing.T) {
	for _, fault := range []string{"bootstrap", "partial-open", "native-proof", "profile-changed"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopRecoveryFixture(t, true, false)
			switch fault {
			case "bootstrap":
				f.bootstrapErr = errors.New("retired desktop bootstrap")
			case "partial-open":
				f.openErr = errors.New("incomplete protected journal capture")
			case "native-proof":
				f.recovery.err = errors.New("unrecognized actual BFE state")
			case "profile-changed":
				f.a.profiles.Profiles[0].APIToken = "replacement-credential"
			}
			if err := f.initialize(); err == nil {
				t.Fatal("fixture should retain unresolved startup")
			}
			if handled, err := f.a.closeTerminalDesktopNodeRecovery(); handled || err != nil {
				t.Fatal("ordinary disconnect abandoned unresolved startup authority")
			}
			before, _ := windowsprotection.CanonicalJournalRecord(f.store.base.head)
			opened := f.slot.journal != nil
			f.a.closing = true
			if handled, err := f.a.closeTerminalDesktopNodeRecovery(); !handled || err != nil || f.a.nodeProtection != nil {
				t.Fatal("terminal controller could not join its own startup resources", err)
			}
			after, _ := windowsprotection.CanonicalJournalRecord(f.store.base.head)
			if !bytes.Equal(before, after) || f.kernel.target == nil || *f.kernel.target != f.target || f.removeCalls != 0 || f.store.base.writes != 0 {
				t.Fatal("terminal recovery join invented native removal or erased durable evidence")
			}
			if opened && f.store.base.closes != 1 {
				t.Fatal("terminal recovery dropped its slot before joining the original protected store")
			}
		})
	}
}

func TestDesktopNodeRecoveryCancellationKeepsReplacement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newDesktopRecoveryFixture(t, false, false)
		f.recovery.entered, f.recovery.resume = make(chan struct{}), make(chan struct{})
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- f.a.ensureDesktopNodeRecovery(ctx, f.slot) }()
		<-f.recovery.entered
		replacement := &desktopNodeProtectionSlot{known: true}
		f.a.mu.Lock()
		f.a.nodeProtection = replacement
		f.a.mu.Unlock()
		cancel()
		close(f.recovery.resume)
		if err := <-done; err == nil || f.slot.known || f.a.nodeProtection != replacement || replacement.journal != nil {
			t.Fatal("cancelled old recovery changed the replacement application owner")
		}
	})
}

func TestDesktopNodeRecoveryRequiresJoinedInitializationBeforeBegin(t *testing.T) {
	for _, state := range []string{"not-initialized", "unproved", "same-controller-nonempty"} {
		t.Run(state, func(t *testing.T) {
			f := newDesktopRecoveryFixture(t, false, false)
			switch state {
			case "not-initialized":
				f.kernel.target = nil // Even native absence cannot replace journal initialization.
			case "unproved":
				f.recovery.err = errors.New("native process proof pending")
				if err := f.initialize(); err == nil {
					t.Fatal("unproved native fixture was admitted")
				}
			case "same-controller-nonempty":
				f.store.base.head.Controller = f.controller
				if err := f.initialize(); err == nil {
					t.Fatal("decoded same-controller target substituted for its original opaque owner")
				}
			}
			launch := &desktopNodeLaunch{ownedNode: &desktopOwnedNodeRuntime{profileToken: desktopOwnedNodeProfileToken(f.profile)}}
			if _, err := f.slot.begin(context.Background(), launch, desktopNodeProtectionPolicy(t, "2", "always", 0)); err == nil || f.slot.active != nil {
				t.Fatal("native successor entered before checked startup recovery joined")
			}
		})
	}
}

func TestDesktopNodeRecoveryPartialOpenAndNativeCloseRemainOwned(t *testing.T) {
	t.Run("partial-open", func(t *testing.T) {
		f := newDesktopRecoveryFixture(t, false, false)
		f.openErr = errors.New("native protected slot opened only partially")
		f.store.base.failClose = true
		if err := f.initialize(); err == nil || f.slot.journal != f.store || f.begins != 0 {
			t.Fatal("failed native open discarded its partial protected owner")
		}
		f.openErr = nil
		if err := f.initialize(); err == nil || f.opens != 1 || f.slot.journal != f.store {
			t.Fatal("failed partial close reopened another protected journal")
		}
		f.store.base.failClose = false
		if err := f.initialize(); err != nil || f.opens != 2 || f.begins != 1 || !f.slot.known {
			t.Fatal("joined partial-open retry failed its captured protected store", err)
		}
	})
	t.Run("native-close", func(t *testing.T) {
		f := newDesktopRecoveryFixture(t, false, false)
		f.recovery.closeErr = errors.New("native proof cleanup is unresolved")
		if err := f.initialize(); err == nil || f.slot.known || f.slot.recovery == nil || !f.slot.recovery.proved {
			t.Fatal("native recovery cleanup failure admitted a successor owner")
		}
		f.recovery.closeErr = nil // Explicit model-only recoverable cleanup.
		if err := f.initialize(); err != nil || !f.slot.known || f.recovery.runs != 1 || f.recovery.closes != 2 {
			t.Fatal("cleanup retry replayed the native adoption instead of joining its owner", err)
		}
	})
}

func TestDesktopNodeRecoveryUncertainResultCannotBeReplaced(t *testing.T) {
	for _, fault := range []string{"empty-result", "changed-request", "changed-outcome"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopRecoveryFixture(t, true, false)
			f.recovery.err, f.recovery.writeOnError = errors.New("native snapshot lost after adoption"), true
			if err := f.initialize(); err == nil || f.slot.recovery.result == nil || f.slot.known {
				t.Fatal("uncertain durable adoption was lost or admitted")
			}
			f.recovery.err = nil
			f.recovery.change = func(result *windowsprotection.JournalRecoveryResult) {
				switch fault {
				case "empty-result":
					*result = windowsprotection.JournalRecoveryResult{}
				case "changed-request":
					result.Selection.Record.Adoption.RequestID = strings.Repeat("d", 32)
				case "changed-outcome":
					result.Observed = windowsprotection.JournalState{}
					result.Selection.Record.Adoption.Observed = result.Observed
					result.Selection.Record.Adoption.CandidateIndex = 1
				}
				if fault != "empty-result" {
					raw, _ := windowsprotection.CanonicalJournalRecord(result.Selection.Record)
					result.Selection.SHA256, _ = windowsprotection.JournalRecordSHA256(raw)
					f.store.base.head, _ = copyDesktopNodeJournalRecord(result.Selection.Record)
				}
			}
			if err := f.initialize(); err == nil || f.slot.known || f.slot.off != nil || f.removeCalls != 0 {
				t.Fatal("uncertain restart result was replaced or reused without a current exact native receipt")
			}
		})
	}
}

func TestDesktopNodeRecoveryHTTPDoesNotReuseUnknownOwnerToken(t *testing.T) {
	f := newDesktopRecoveryFixture(t, false, false)
	f.recovery.err = errors.New("native owner remains unresolved")
	if err := f.initialize(); err == nil {
		t.Fatal("fixture expected unresolved native startup")
	}
	value := ownedProtectionGet(t, f.a)
	if value.ProtectionStatus != "recovery-pending" || value.EffectivePolicy != "unknown" {
		t.Fatal("unknown startup protection was presented as ordinary saved policy")
	}
	body := ownedProtectionBody(t, value, "off")
	response := postProtectionForTest(f.a, bytes.NewReader(body))
	if response.Code != http.StatusServiceUnavailable || f.removeCalls != 0 || f.slot.known {
		t.Fatal("unproved startup token authorized a new protection change", response.Code)
	}
	f.recovery.err = nil
	response = postProtectionForTest(f.a, bytes.NewReader(body))
	if response.Code != http.StatusConflict || !f.slot.known || f.removeCalls != 0 || f.slot.off != nil || f.a.profiles.Profiles[0].KillSwitchPolicy != "always" {
		t.Fatal("completed startup recovery silently reused its old unknown-owner UI token", response.Code)
	}
	refreshed := ownedProtectionGet(t, f.a)
	if refreshed.ProfileToken == value.ProfileToken || refreshed.EffectivePolicy != "always" {
		t.Fatal("checked startup recovery did not refresh the actual retained-owner revision")
	}
}

func TestDesktopNodeRecoveryAdmissionCancellation(t *testing.T) {
	for _, cancelBy := range []string{"disconnect", "shutdown", "request", "cancel-operation"} {
		t.Run(cancelBy, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newDesktopRecoveryFixture(t, false, false)
				f.recovery.entered, f.recovery.waitContext = make(chan struct{}), true
				requestCtx, cancelRequest := context.WithCancel(context.Background())
				defer cancelRequest()
				done := make(chan error, 1)
				go func() {
					if cancelBy == "request" {
						release, err := f.a.beginMutationOperation(httptest.NewRequest(http.MethodPost, "/api/profile/settings", nil).WithContext(requestCtx))
						if release != nil {
							release()
						}
						done <- err
						return
					}
					_, release, err := f.a.beginConnectionTransaction()
					if release != nil {
						release()
					}
					done <- err
				}()
				<-f.recovery.entered
				switch cancelBy {
				case "disconnect":
					response := httptest.NewRecorder()
					f.a.disconnect(response, httptest.NewRequest(http.MethodPost, "/api/disconnect", nil))
					if response.Code < 400 || f.a.nodeProtection != f.slot || f.kernel.target == nil {
						t.Fatal("manual Disconnect invented release of unproved startup protection")
					}
				case "shutdown":
					shutdown := newControllerShutdown(f.a, strings.Repeat("c", 32))
					shutdown.begin()
					<-shutdown.done
					if f.a.nodeProtection != nil || f.store.base.closes != 1 || f.kernel.target == nil {
						t.Fatal("shutdown did not join cancelled startup recovery while preserving recorded protection")
					}
				case "request":
					cancelRequest()
				case "cancel-operation":
					f.a.mu.Lock()
					operation := f.a.nodeRecovery
					f.a.mu.Unlock()
					if operation == nil {
						t.Fatal("admission recovery did not publish its captured cancellation owner")
					}
					// This is the real Disconnect/shutdown cancellation seam, before
					// either path waits for operationMu. Check it synchronously and
					// release the test-owned operation on failure, so the negative
					// control proves this boundary without a timeout/deadlock panic.
					f.a.cancelConnectionOperation()
					if !errors.Is(operation.context.Err(), context.Canceled) {
						operation.cancel()
						<-done
						t.Fatal("admission recovery ignored captured cancellation or installed a connection owner")
					}
				}
				if err := <-done; err == nil || !errors.Is(f.recovery.cancelled, context.Canceled) ||
					f.a.nodeRecovery != nil || f.a.connectionContext != nil || f.a.state.Connected || f.slot.known || f.slot.active != nil {
					t.Fatal("admission recovery ignored captured cancellation or installed a connection owner", err, f.recovery.cancelled)
				}
			})
		})
	}
}

func TestDesktopNodeRecoveryOldCompletionKeepsNewOperation(t *testing.T) {
	f := newDesktopRecoveryFixture(t, false, false)
	old, finish, err := f.a.captureDesktopNodeRecoveryOperation(context.Background(), f.slot)
	if err != nil {
		t.Fatal(err)
	}
	newContext, cancelNew := context.WithCancel(context.Background())
	defer cancelNew()
	connection, cancelConnection := context.WithCancel(context.Background())
	defer cancelConnection()
	replacement := &desktopNodeRecoveryOperation{context: newContext, cancel: cancelNew}
	f.a.mu.Lock()
	f.a.nodeRecovery, f.a.connectionContext, f.a.connectionCancel = replacement, connection, cancelConnection
	f.a.mu.Unlock()
	old.cancel()
	finish()
	if f.a.nodeRecovery != replacement || newContext.Err() != nil || connection.Err() != nil {
		t.Fatal("old recovery completion cancelled or removed its replacement operation")
	}
}
