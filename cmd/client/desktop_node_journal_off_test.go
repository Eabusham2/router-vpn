package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobiletor"
	"router-vpn/internal/windowsprotection"
)

// The real HTTP operation, slot, canonical journal transitions and private
// profile publication/readback compose here. Only protected journal I/O and
// the native BFE/process boundary are explicit models.
type desktopDurableOffFixture struct {
	*desktopProtectionOffFixture
	t                *testing.T
	store            *desktopNodeReleaseStore
	events           []string
	original         []byte
	change           func(*mobiletor.DesktopWindowsProtectionCommit)
	skipBarrier      bool
	beforeSettlement func()
}

type desktopDurableOffStore struct {
	*desktopNodeReleaseStore
	fixture *desktopDurableOffFixture
}

func (s *desktopDurableOffStore) Append(ctx context.Context, previous string, next windowsprotection.JournalRecord) (windowsprotection.JournalSelection, error) {
	if next.Phase == "settled" {
		f := s.fixture
		capture := f.slot.off // Application slot lock is already held.
		if capture == nil || !capture.profileWritten.Load() || !capture.profileSaved.Load() || !capture.joined ||
			!capture.removed || !capture.absenceProved || f.kernel.target != nil {
			f.t.Fatal("explicit Off settled before joined absence and saved-profile acknowledgment")
		}
		raw, err := os.ReadFile(f.a.cfg.ProfilesFile)
		var saved common.RouterProfileStore
		if err != nil || json.Unmarshal(raw, &saved) != nil || saved.SelectedID != capture.profileID ||
			profileStartupSettingsToken(saved.Profiles[0]) != capture.resultRevision {
			f.t.Fatal("explicit Off settled without its actual saved result")
		}
		f.events = append(f.events, "saved-profile")
		if f.beforeSettlement != nil {
			f.beforeSettlement()
		}
	}
	return s.desktopNodeReleaseStore.Append(ctx, previous, next)
}

type desktopDurableOffNative struct {
	fixture *desktopDurableOffFixture
	native  *desktopProtectionOffFixtureOwner
	barrier mobiletor.DesktopWindowsProtectionCommitBarrier
}

func (n *desktopDurableOffNative) Close(ctx context.Context) error {
	f := n.fixture
	f.events = append(f.events, "native-close")
	if n.native.armed && !n.native.closed && ctx.Err() == nil {
		change := mobiletor.DesktopWindowsProtectionCommit{Action: "off", Previous: copyDesktopNodeProtectionTarget(&n.native.target)}
		if f.change != nil {
			f.change(&change)
		}
		if !f.skipBarrier {
			if err := n.barrier(ctx, change); err != nil {
				return err
			}
			capture := f.slot.off
			head := f.store.base.head
			if capture == nil || head.Phase != "intent" || head.Intent == nil || head.Intent.Action != "off" ||
				head.Intent.ProfileRevision != capture.profileRevision || head.Intent.ResultProfileRevision != capture.resultRevision ||
				head.Committed.Target == nil || *head.Committed.Target != f.target || f.store.base.pending != nil {
				f.t.Fatal("explicit Off removed protection before its durable intent")
			}
			raw, err := os.ReadFile(f.a.cfg.ProfilesFile)
			if err == nil && !bytes.Equal(raw, f.original) || capture.profileWritten.Load() {
				f.t.Fatal("explicit Off saved its result before native removal and independent absence")
			}
		}
	}
	wasClosed := n.native.closed
	if err := n.native.Close(ctx); err != nil {
		return err
	}
	if n.native.armed && !wasClosed {
		f.events = append(f.events, "kernel-removed")
	}
	return nil
}

func newDesktopDurableOffFixture(t *testing.T, policy string) *desktopDurableOffFixture {
	t.Helper()
	f := &desktopDurableOffFixture{desktopProtectionOffFixture: newDesktopProtectionOffPolicyFixture(t, policy), t: t}
	controller := windowsprotection.Controller{PID: 101, StartTimeUTCTicks: 638000000000000000, SID: "S-1-5-21-100-200-300-1001", AuthenticationID: 123, SessionID: 2}
	head := windowsprotection.JournalRecord{Schema: 1, Kind: windowsprotection.JournalRecordKind, JournalID: strings.Repeat("a", 32), Sequence: 1, Controller: controller, Phase: "settled"}
	capture := windowsprotection.JournalCommitCapture{Schema: 1, Kind: windowsprotection.JournalCommitCaptureKind,
		Head: head, ProfileID: f.profile.ID, ProfileRevision: f.slot.profileRevision, Transfer: f.attempt.transfer}
	raw, err := windowsprotection.CanonicalJournalCommitCapture(capture)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := windowsprotection.JournalCommitCaptureSHA256(raw)
	engine := controller
	engine.PID++
	engine.StartTimeUTCTicks++
	intent, err := windowsprotection.DeriveJournalCommitIntent(capture, windowsprotection.JournalCommitRequest{Schema: 1,
		Kind: windowsprotection.JournalCommitRequestKind, CaptureSHA256: digest, Nonce: strings.Repeat("b", 64), Candidate: f.target}, engine)
	if err != nil {
		t.Fatal(err)
	}
	live, err := windowsprotection.DeriveJournalAdmissionSettlement(intent)
	if err != nil {
		t.Fatal(err)
	}
	head, _ = copyDesktopNodeJournalRecord(live)
	raw, _ = windowsprotection.CanonicalJournalRecord(live)
	head.PreviousSHA256, _ = windowsprotection.JournalRecordSHA256(raw)
	head.Sequence++
	head.Committed.Engine = nil
	if err := windowsprotection.CheckJournalTransition(live, head); err != nil {
		t.Fatal(err)
	}
	f.store = &desktopNodeReleaseStore{base: &desktopNodeJournalFixtureStore{head: head}, events: &f.events}
	f.slot.journal = &desktopDurableOffStore{desktopNodeReleaseStore: f.store, fixture: f}
	f.original, err = os.ReadFile(f.a.cfg.ProfilesFile)
	if err != nil {
		t.Fatal(err)
	}
	read := f.slot.backend.read
	f.slot.backend.read = func(ctx context.Context, target *mobiletor.DesktopWindowsProtectionTarget) error {
		name := "read-target"
		if target == nil {
			name = "read-absence"
		}
		f.events = append(f.events, name)
		return read(ctx, target)
	}
	recover := f.slot.backend.recover
	f.slot.backend.recoverWithBarrier = func(ctx context.Context, target mobiletor.DesktopWindowsProtectionTarget, barrier mobiletor.DesktopWindowsProtectionCommitBarrier) (desktopNodeProtectionRelease, error) {
		f.events = append(f.events, "construct")
		owner, err := recover(ctx, target)
		if owner == nil {
			return nil, err
		}
		return &desktopDurableOffNative{fixture: f, native: owner.(*desktopProtectionOffFixtureOwner), barrier: barrier}, err
	}
	f.slot.backend.recover = func(context.Context, mobiletor.DesktopWindowsProtectionTarget) (desktopNodeProtectionRelease, error) {
		t.Fatal("durable Off used callback-free native removal")
		return nil, nil
	}
	return f
}

func (f *desktopDurableOffFixture) post(t *testing.T, token profileProtectionSettings) int {
	t.Helper()
	return postProtectionForTest(f.a, bytes.NewReader(ownedProtectionBody(t, token, "off"))).Code
}

func (f *desktopDurableOffFixture) finished(t *testing.T) {
	t.Helper()
	if f.a.nodeProtection != nil || f.slot.off != nil || f.slot.journal != nil || f.slot.target != nil || !f.slot.provedEmpty() ||
		f.kernel.target != nil || f.kernel.locked || f.store.base.head.Phase != "settled" || f.store.base.head.Committed.Target != nil ||
		f.store.base.pending != nil || f.store.base.closes == 0 || f.a.profiles.Profiles[0].KillSwitchPolicy != "off" {
		t.Fatal("durable Off did not finish its exact saved and closed transaction")
	}
}

func TestDesktopNodeJournalOffOrdersRemovalSaveAndSettlement(t *testing.T) {
	for _, policy := range []string{"always", "on-connect"} {
		t.Run(policy, func(t *testing.T) {
			f := newDesktopDurableOffFixture(t, policy)
			before := cloneRouterProfileStore(f.a.profiles)
			capture := ownedProtectionGet(t, f.a)
			if code := f.post(t, capture); code != http.StatusOK {
				t.Fatal("durable Off failed its actual HTTP transaction", code)
			}
			f.finished(t)
			want := []string{"read-target", "construct", "native-close", "append-intent", "flushed-intent", "kernel-removed", "read-absence", "saved-profile", "append-settled", "flushed-settled", "store-close"}
			if !reflect.DeepEqual(f.events, want) {
				t.Fatal("durable Off reordered intent, removal, profile publication or settlement", f.events)
			}
			before.Profiles[0].KillSwitchPolicy, before.Profiles[0].KillSwitch = "off", false
			if !reflect.DeepEqual(f.a.profiles, before) {
				t.Fatal("durable Off changed private node settings beyond its accepted preference")
			}
			if f.post(t, capture) != http.StatusConflict || f.calls != 1 {
				t.Fatal("consumed Off token authorized another native removal")
			}
		})
	}
}

func TestDesktopNodeJournalOffRetainsIntentUntilProfileSave(t *testing.T) {
	f := newDesktopDurableOffFixture(t, "always")
	path := f.a.cfg.ProfilesFile
	f.a.cfg.ProfilesFile = t.TempDir()
	token := ownedProtectionGet(t, f.a)
	if code := f.post(t, token); code != http.StatusInternalServerError {
		t.Fatal("fixture did not retain failed actual profile publication", code)
	}
	capture := f.slot.pendingOff()
	if capture == nil || !capture.removed || capture.profileWritten.Load() || capture.profileSaved.Load() ||
		f.store.base.head.Phase != "intent" || f.store.base.writes != 1 || f.store.base.closes != 0 || f.slot.provedEmpty() {
		t.Fatal("Off erased its unsaved intent or its exact native owner")
	}
	owner := capture.owner
	if err := f.slot.finishOffSave(context.Background(), capture, func() bool { return true }); err == nil {
		t.Fatal("unacknowledged profile save settled durable Off")
	}
	f.a.cfg.ProfilesFile = path
	if f.post(t, token) != http.StatusOK || capture.owner != owner || f.calls != 1 {
		t.Fatal("unsaved Off retry repeated native removal")
	}
	f.finished(t)
}

func TestDesktopNodeJournalOffSavedResultRetryKeepsTokenAndOwner(t *testing.T) {
	for _, fault := range []string{"settlement", "cancelled-before-settlement", "cancelled-settlement", "close", "cancelled-close"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopDurableOffFixture(t, "always")
			token := ownedProtectionGet(t, f.a)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch fault {
			case "settlement":
				f.store.failPhase = "settled"
			case "cancelled-settlement":
				f.store.cancelPhase, f.store.cancel = "settled", cancel
			case "cancelled-before-settlement":
				f.beforeSettlement = cancel
			case "close":
				f.store.base.failClose = true
			case "cancelled-close":
				f.store.cancelPhase, f.store.cancel = "close", cancel
			}
			capture := f.capture(t)
			if _, err := f.a.resumeDesktopProtectionOff(ctx, f.slot, capture, false); err == nil {
				t.Fatal("fixture did not retain its failed finalization")
			}
			owner := capture.owner
			if !capture.profileWritten.Load() || !capture.profileSaved.Load() || f.a.profiles.Profiles[0].KillSwitchPolicy != "off" ||
				capture.profileRevision == capture.resultRevision || f.slot.provedEmpty() {
				t.Fatal("saved Off lost its exact original/result transition")
			}
			status := ownedProtectionGet(t, f.a)
			if status.ProfileToken != token.ProfileToken || status.KillSwitchPolicy != "off" || status.EffectivePolicy != "off" ||
				status.ProtectionStatus != "off-pending" || !strings.Contains(status.Message, "preference is saved") {
				t.Fatal("saved-result retry lost its pending UI token or truthful state")
			}
			saved, err := os.ReadFile(f.a.cfg.ProfilesFile)
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(f.a.cfg.ProfilesFile)
			if err != nil {
				t.Fatal(err)
			}
			f.store.failPhase, f.store.cancelPhase, f.store.base.failClose = "", "", false
			f.beforeSettlement = nil
			if f.post(t, token) != http.StatusOK {
				t.Fatal("saved-result retry did not finish captured Off")
			}
			f.finished(t)
			after, _ := os.ReadFile(f.a.cfg.ProfilesFile)
			current, _ := os.Stat(f.a.cfg.ProfilesFile)
			if f.calls != 1 || capture.owner != owner || f.owners[0].closes != 1 || !bytes.Equal(saved, after) || !os.SameFile(info, current) {
				t.Fatal("saved-result retry resaved the profile or reconstructed native removal")
			}
		})
	}
}

func TestDesktopNodeJournalOffSavedReadbackRetainsExactOwner(t *testing.T) {
	for _, fault := range []string{"store-bytes", "result", "path", "missing"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopDurableOffFixture(t, "always")
			token := ownedProtectionGet(t, f.a)
			f.store.failPhase = "settled"
			if f.post(t, token) != http.StatusServiceUnavailable {
				t.Fatal("fixture did not retain a saved unsettled Off")
			}
			capture := f.slot.pendingOff()
			owner := capture.owner
			path := f.a.cfg.ProfilesFile
			saved, _ := os.ReadFile(path)
			var changed common.RouterProfileStore
			if err := json.Unmarshal(saved, &changed); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "store-bytes":
				changed.Profiles[0].UseCount++
			case "result":
				changed.Profiles[0].DNSHost = "203.0.113.53"
			case "path":
				f.a.cfg.ProfilesFile = path + ".replacement"
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			if fault == "store-bytes" || fault == "result" {
				raw, err := json.MarshalIndent(changed, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				if err := atomicWritePrivate(path, append(raw, '\n')); err != nil {
					t.Fatal(err)
				}
			}
			f.store.failPhase = ""
			if f.post(t, token) < 400 || f.slot.pendingOff() != capture || capture.owner != owner || f.calls != 1 || f.slot.provedEmpty() {
				t.Fatal("saved Off accepted a replacement private profile store")
			}
			f.a.cfg.ProfilesFile = path
			if err := atomicWritePrivate(path, saved); err != nil {
				t.Fatal(err)
			}
			if f.post(t, token) != http.StatusOK {
				t.Fatal("restored exact saved bytes could not finish retained Off")
			}
			f.finished(t)
		})
	}
}

func TestDesktopNodeJournalOffRejectsReplacementRevision(t *testing.T) {
	for _, fault := range []string{"credential", "dns", "old-revision", "result-revision", "source-revision", "generation", "target", "store"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopDurableOffFixture(t, "always")
			token := ownedProtectionGet(t, f.a)
			f.store.failPhase = "settled"
			if f.post(t, token) != http.StatusServiceUnavailable {
				t.Fatal("fixture did not reach saved-result retry")
			}
			capture := f.slot.pendingOff()
			owner := capture.owner
			f.store.failPhase = ""
			switch fault {
			case "credential":
				f.a.profiles.Profiles[0].APIToken = "another-private-token"
			case "dns":
				f.a.profiles.Profiles[0].DNSHost = "203.0.113.53"
			case "old-revision":
				f.a.profiles.Profiles[0] = f.profile
			case "result-revision":
				capture.resultRevision = strings.Repeat("e", 64)
			case "source-revision":
				f.slot.profileRevision = strings.Repeat("e", 64)
			case "generation":
				f.slot.generation++
			case "target":
				f.slot.target.BaselineSHA256 = strings.Repeat("f", 64)
			case "store":
				f.slot.journal = &desktopNodeJournalFixtureStore{head: f.store.base.head}
			}
			if f.post(t, token) < 400 || f.slot.pendingOff() != capture || capture.owner != owner || f.calls != 1 || f.store.base.closes != 0 {
				t.Fatal("pending Off token adopted a change outside its exact old-to-result revision")
			}
		})
	}
}

func TestDesktopNodeJournalOffRejectsUncapturedDurability(t *testing.T) {
	for _, fault := range []string{"source", "engine", "profile", "target", "sequence", "incomplete", "read", "barrier"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopDurableOffFixture(t, "always")
			switch fault {
			case "source":
				f.slot.profileRevision = ""
			case "engine":
				engine := f.store.base.head.Controller
				engine.PID++
				f.store.base.head.Committed.Engine = &engine
			case "profile":
				f.store.base.head.Committed.ProfileID = "other-node"
			case "target":
				f.store.base.head.Committed.Target.BaselineSHA256 = strings.Repeat("d", 64)
			case "sequence":
				f.store.base.head.Sequence = math.MaxUint64 - 1
			case "incomplete":
				f.store.base.incomplete = true
			case "read":
				f.store.base.failRead = true
			case "barrier":
				f.slot.backend.recoverWithBarrier = nil
			}
			if f.post(t, ownedProtectionGet(t, f.a)) < 400 || f.calls != 0 || f.kernel.target == nil || f.store.base.writes != 0 {
				t.Fatal("uncaptured journal state acquired explicit Off removal")
			}
		})
	}
}

func TestDesktopNodeJournalOffRejectsSubstitutedBarrier(t *testing.T) {
	for _, fault := range []string{"release", "target", "candidate", "missing", "skip"} {
		t.Run(fault, func(t *testing.T) {
			policy := "always"
			if fault == "release" {
				policy = "on-connect" // A valid normal removal still cannot replace explicit Off.
			}
			f := newDesktopDurableOffFixture(t, policy)
			f.skipBarrier = fault == "skip"
			f.change = func(change *mobiletor.DesktopWindowsProtectionCommit) {
				switch fault {
				case "release":
					change.Action = "release"
				case "target":
					change.Previous.BaselineSHA256 = strings.Repeat("d", 64)
				case "candidate":
					change.Candidate = copyDesktopNodeProtectionTarget(&f.target)
				case "missing":
					change.Previous = nil
				}
			}
			if f.post(t, ownedProtectionGet(t, f.a)) < 400 || f.store.base.writes != 0 || f.store.base.closes != 0 || f.a.profiles.Profiles[0].KillSwitchPolicy != policy {
				t.Fatal("substituted explicit Off callback reached persistence or completion")
			}
		})
	}
}

func TestDesktopNodeJournalOffRetriesNativeAndIntentFailures(t *testing.T) {
	for _, fault := range []string{"intent-flush", "partial", "native-close", "absence", "cancelled-constructor"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopDurableOffFixture(t, "always")
			capture := f.capture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch fault {
			case "intent-flush":
				f.store.failPhase = "intent"
			case "partial":
				f.partial = true
			case "native-close":
				f.closeFail = true
			case "absence":
				f.afterMake = func() { f.kernel.readFail = true }
			case "cancelled-constructor":
				f.afterMake = cancel
			}
			if _, err := f.a.resumeDesktopProtectionOff(ctx, f.slot, capture, false); err == nil || capture.owner == nil || capture.profileWritten.Load() {
				t.Fatal("failed native Off forgot its owner or saved early")
			}
			intent, _ := copyDesktopNodeJournalRecord(capture.journal.intent)
			owner := capture.owner
			f.store.failPhase, f.partial, f.closeFail, f.kernel.readFail, f.afterMake = "", false, false, false, nil
			if _, err := f.a.resumeDesktopProtectionOff(context.Background(), f.slot, capture, false); err != nil {
				t.Fatal("exact pending Off could not retry", err)
			}
			f.finished(t)
			if !reflect.DeepEqual(intent, capture.journal.intent) || fault != "partial" && (f.calls != 1 || capture.owner != owner) || fault == "partial" && f.calls != 2 {
				t.Fatal("durable Off retry changed its intent or native operation")
			}
		})
	}
}

func TestDesktopNodeJournalOffDoesNotPublishBeforeNativeProof(t *testing.T) {
	f := newDesktopDurableOffFixture(t, "always")
	capture := f.capture(t)
	if _, err := f.a.persistCapturedProtectionOff(context.Background(), f.slot, capture, false); !errors.Is(err, errDesktopProtectionOffUnsaved) || capture.profileWritten.Load() {
		t.Fatal("profile publication bypassed native removal and absence")
	}
	if raw, err := os.ReadFile(f.a.cfg.ProfilesFile); err != nil || !bytes.Equal(raw, f.original) {
		t.Fatal("unproved Off modified the saved source")
	}
}

func TestDesktopNodeJournalOffHTTPReportsActualSavedPendingResult(t *testing.T) {
	f := newDesktopDurableOffFixture(t, "always")
	token := ownedProtectionGet(t, f.a)
	f.store.failPhase = "settled"
	w := postProtectionForTest(f.a, bytes.NewReader(ownedProtectionBody(t, token, "off")))
	var response profileProtectionSettings
	if w.Code != http.StatusServiceUnavailable || json.Unmarshal(w.Body.Bytes(), &response) != nil ||
		response.KillSwitchPolicy != "off" || response.EffectivePolicy != "off" || response.ProtectionStatus != "off-pending" ||
		response.ProfileToken != token.ProfileToken || !strings.Contains(response.Message, "preference is saved") {
		t.Fatal("saved Off HTTP failure reported the original preference or lost its exact retry token")
	}
	f.store.failPhase = ""
	if f.post(t, response) != http.StatusOK {
		t.Fatal("returned saved-result token could not finish pending Off")
	}
	f.finished(t)
}

func TestDesktopNodeJournalOffJoinsLateNativeBarrier(t *testing.T) {
	f := newDesktopDurableOffFixture(t, "always")
	capture := f.capture(t)
	constructor := f.slot.backend.recoverWithBarrier
	native := &desktopNodeLateReleaseNative{gate: make(chan struct{}, 1), entered: make(chan struct{}, 3), done: make(chan struct{}, 3)}
	native.gate <- struct{}{}
	f.slot.backend.recoverWithBarrier = func(ctx context.Context, target mobiletor.DesktopWindowsProtectionTarget, barrier mobiletor.DesktopWindowsProtectionCommitBarrier) (desktopNodeProtectionRelease, error) {
		owner, err := constructor(ctx, target, barrier)
		native.native = owner
		return native, err
	}
	entered, resume := make(chan struct{}), make(chan struct{})
	var once sync.Once
	f.store.beforeAppend = func() { once.Do(func() { close(entered); <-resume }) }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := f.a.resumeDesktopProtectionOff(ctx, f.slot, capture, false); done <- err }()
	<-entered
	<-native.entered
	cancel()
	if err := <-done; err == nil || capture.owner != native || f.kernel.target == nil || capture.profileWritten.Load() {
		t.Fatal("cancelled Off detached its still-entered native barrier")
	}
	retry, cancelRetry := context.WithCancel(context.Background())
	defer cancelRetry()
	go func() { _, err := f.a.resumeDesktopProtectionOff(retry, f.slot, capture, false); done <- err }()
	<-native.entered
	cancelRetry()
	if err := <-done; err == nil || capture.owner != native || f.calls != 1 {
		t.Fatal("pending native barrier authorized another Off owner")
	}
	close(resume)
	<-native.done
	if f.store.base.writes != 0 || f.kernel.target == nil || capture.journal.acknowledged.Load() {
		t.Fatal("late cancelled Off barrier gained removal acknowledgment")
	}
	if _, err := f.a.resumeDesktopProtectionOff(context.Background(), f.slot, capture, false); err != nil {
		t.Fatal("joined late Off could not resume its exact owner", err)
	}
	<-native.done
	f.finished(t)
	if capture.owner != native || f.calls != 1 {
		t.Fatal("late Off completion replaced its original native operation")
	}
}
