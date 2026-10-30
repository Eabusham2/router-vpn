package main

import (
	"context"
	"errors"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"

	"router-vpn/internal/mobiletor"
	"router-vpn/internal/windowsprotection"
)

// The application slot, journal transitions and callback order are real. The
// native store and kernel are explicit models; separate Windows gates execute
// the actual protected files, WFP constructors and process composition.
type desktopNodeReleaseStore struct {
	base         *desktopNodeJournalFixtureStore
	events       *[]string
	failPhase    string
	cancelPhase  string
	cancel       context.CancelFunc
	beforeAppend func()
}

func (s *desktopNodeReleaseStore) Snapshot(ctx context.Context) (windowsprotection.JournalSelection, error) {
	return s.base.Snapshot(ctx)
}

func (s *desktopNodeReleaseStore) Append(ctx context.Context, previous string, next windowsprotection.JournalRecord) (windowsprotection.JournalSelection, error) {
	if s.beforeAppend != nil {
		s.beforeAppend()
	}
	*s.events = append(*s.events, "append-"+next.Phase)
	s.base.failWrite = s.failPhase == next.Phase
	result, err := s.base.Append(ctx, previous, next)
	if err == nil {
		*s.events = append(*s.events, "flushed-"+next.Phase)
		if s.cancelPhase == next.Phase && s.cancel != nil {
			s.cancel()
			err = context.Canceled
		}
	}
	return result, err
}

func (s *desktopNodeReleaseStore) Close() error {
	*s.events = append(*s.events, "store-close")
	err := s.base.Close()
	if err == nil && s.cancelPhase == "close" && s.cancel != nil {
		s.cancel()
	}
	return err
}

type desktopNodeDurableReleaseFixture struct {
	t               *testing.T
	slot            *desktopNodeProtectionSlot
	kernel          *desktopNodeProtectionFixture
	store           *desktopNodeReleaseStore
	target          mobiletor.DesktopWindowsProtectionTarget
	before          windowsprotection.JournalRecord
	revision        string
	events          []string
	constructors    int
	nativeCloses    int
	partialNext     bool
	prepareFailure  bool
	partialJoinFail bool
	commitFailure   bool
	beforeCloseFail bool
	cancelConstruct context.CancelFunc
	cancelClose     context.CancelFunc
	change          func(*mobiletor.DesktopWindowsProtectionCommit)
	skipBarrier     bool
}

type desktopNodeDurableReleaseNative struct {
	fixture *desktopNodeDurableReleaseFixture
	barrier mobiletor.DesktopWindowsProtectionCommitBarrier
	armed   bool
	closed  bool
}

func (n *desktopNodeDurableReleaseNative) Close(ctx context.Context) error {
	f := n.fixture
	f.nativeCloses++
	f.events = append(f.events, "native-close")
	if err := ctx.Err(); err != nil {
		return err
	}
	if n.closed {
		return nil
	}
	if !n.armed {
		if f.partialJoinFail {
			return errors.New("fixture partial native owner is still entered")
		}
		f.kernel.locked, n.closed = false, true
		return nil
	}
	if f.beforeCloseFail {
		return errors.New("fixture native cleanup has not reached its transaction")
	}
	if f.kernel.target == nil || *f.kernel.target != f.target || !f.kernel.locked {
		return errors.New("fixture native owner lost its captured locked target")
	}
	if f.target.Policy == "on-connect" {
		change := mobiletor.DesktopWindowsProtectionCommit{Action: "release", Previous: copyDesktopNodeProtectionTarget(&f.target)}
		if f.change != nil {
			f.change(&change)
		}
		if !f.skipBarrier {
			if err := n.barrier(ctx, change); err != nil {
				return err
			}
			head := f.store.base.head
			if head.Phase != "intent" || head.Intent == nil || head.Intent.Action != "release" ||
				head.Intent.ProfileRevision != f.revision || head.Intent.ResultProfileRevision != f.revision ||
				head.Committed.Target == nil || *head.Committed.Target != f.target || f.store.base.pending != nil {
				f.t.Fatal("native removal preceded its exact durable intent")
			}
		}
		if f.commitFailure {
			return errors.New("fixture native transaction did not commit")
		}
		f.kernel.target = nil
		f.events = append(f.events, "kernel-removed")
	}
	f.kernel.locked, n.closed = false, true
	if f.cancelClose != nil {
		f.cancelClose()
	}
	return nil
}

func newDesktopNodeDurableReleaseFixture(t *testing.T, policy string) *desktopNodeDurableReleaseFixture {
	t.Helper()
	slot, attempt, kernel, store, process := desktopNodeJournalPolicyFixture(t, true, policy)
	revision := attempt.launch.ownedNode.profileToken
	if err := slot.finish(context.Background(), attempt, desktopNodeProtectionRetired(attempt, kernel.target),
		func(context.Context) error { process.closed = true; kernel.locked = false; return nil }); err != nil {
		t.Fatal(err)
	}
	f := &desktopNodeDurableReleaseFixture{t: t, slot: slot, kernel: kernel, target: *kernel.target, revision: revision}
	f.before, _ = copyDesktopNodeJournalRecord(store.head)
	store.writes = 0
	f.store = &desktopNodeReleaseStore{base: store, events: &f.events}
	slot.journal = f.store
	read := slot.backend.read
	slot.backend.read = func(ctx context.Context, target *mobiletor.DesktopWindowsProtectionTarget) error {
		name := "read-target"
		if target == nil {
			name = "read-absence"
		}
		f.events = append(f.events, name)
		return read(ctx, target)
	}
	slot.backend.releaseWithBarrier = func(ctx context.Context, target mobiletor.DesktopWindowsProtectionTarget, barrier mobiletor.DesktopWindowsProtectionCommitBarrier) (desktopNodeProtectionRelease, error) {
		f.constructors++
		f.events = append(f.events, "construct")
		if ctx.Err() != nil || target != f.target || barrier == nil || kernel.locked {
			return nil, errors.New("fixture constructor changed its exact captured release")
		}
		if f.prepareFailure {
			return nil, errors.New("fixture rejected native preparation before ownership")
		}
		native := &desktopNodeDurableReleaseNative{fixture: f, barrier: barrier, armed: !f.partialNext}
		kernel.locked = true
		if f.partialNext {
			f.partialNext = false
			return native, errors.New("fixture native constructor retained an unarmed owner")
		}
		if f.cancelConstruct != nil {
			f.cancelConstruct()
		}
		return native, nil
	}
	return f
}

func (f *desktopNodeDurableReleaseFixture) requireFinished(t *testing.T) {
	t.Helper()
	if f.slot.retirement != nil || f.slot.active != nil || f.kernel.locked || f.kernel.releases != 0 {
		t.Fatal("durable release did not finish its exact native operation")
	}
	if f.target.Policy == "always" {
		if !reflect.DeepEqual(f.slot.target, &f.target) || !reflect.DeepEqual(f.kernel.target, &f.target) ||
			f.slot.journal != f.store || f.slot.profileRevision != f.revision || f.store.base.writes != 0 ||
			f.store.base.closes != 0 || !reflect.DeepEqual(f.before, f.store.base.head) {
			t.Fatal("normal durable release removed or rewrote retained Always")
		}
		return
	}
	if f.slot.target != nil || f.kernel.target != nil || f.slot.journal != nil || f.slot.profileRevision != "" ||
		f.store.base.head.Phase != "settled" || f.store.base.head.Committed.Target != nil || f.store.base.pending != nil ||
		!f.slot.provedEmpty() || f.store.base.closes == 0 {
		t.Fatal("durable release did not finish its exact settlement and journal close")
	}
}

func TestDesktopNodeJournalReleaseOrdersDurabilityAndPreservesAlways(t *testing.T) {
	for _, policy := range []string{"on-connect", "always"} {
		t.Run(policy, func(t *testing.T) {
			f := newDesktopNodeDurableReleaseFixture(t, policy)
			if f.slot.profileRevision != f.revision {
				t.Fatal("release lost the joined attempt's actual captured profile revision")
			}
			if err := f.slot.release(context.Background()); err != nil {
				t.Fatal("durable release did not finish its captured transaction", err)
			}
			f.requireFinished(t)
			if f.constructors != 1 || f.nativeCloses != 1 {
				t.Fatal("release replaced its exact native owner")
			}
			if policy == "on-connect" {
				want := []string{"read-target", "construct", "native-close", "append-intent", "flushed-intent", "kernel-removed", "read-absence", "append-settled", "flushed-settled", "store-close"}
				if !reflect.DeepEqual(f.events, want) {
					t.Fatal("durable release reordered native mutation, journal flush or cleanup", f.events)
				}
			}
		})
	}
}

func TestDesktopNodeJournalReleaseRetriesExactIntentFlush(t *testing.T) {
	for _, late := range []bool{false, true} {
		t.Run(map[bool]string{false: "failed-flush", true: "cancelled-after-flush"}[late], func(t *testing.T) {
			f := newDesktopNodeDurableReleaseFixture(t, "on-connect")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if late {
				f.store.cancelPhase, f.store.cancel = "intent", cancel
			} else {
				f.store.failPhase = "intent"
			}
			if err := f.slot.release(ctx); err == nil || f.slot.retirement == nil || f.kernel.target == nil || f.store.base.closes != 0 {
				t.Fatal("failed durable intent permitted native removal or lost its owner", err)
			}
			capture := f.slot.retirement.(*desktopNodeJournalRelease)
			intent, _ := copyDesktopNodeJournalRecord(capture.intent)
			f.store.failPhase, f.store.cancelPhase = "", ""
			if err := f.slot.release(context.Background()); err != nil {
				t.Fatal("same captured intent could not finish its retry", err)
			}
			f.requireFinished(t)
			if f.constructors != 1 || !reflect.DeepEqual(capture.intent, intent) ||
				late && f.store.base.writes != 2 || !late && f.store.base.writes != 3 {
				t.Fatal("release retried another intent or duplicated its acknowledged append")
			}
		})
	}
}

func TestDesktopNodeJournalReleaseRetriesAfterNativeRemoval(t *testing.T) {
	for _, fault := range []string{"readback", "failed-settlement", "cancelled-settlement", "close", "cancelled-close", "cancelled-native-close"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopNodeDurableReleaseFixture(t, "on-connect")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			read := f.slot.backend.read
			if fault == "readback" {
				f.slot.backend.read = func(ctx context.Context, target *mobiletor.DesktopWindowsProtectionTarget) error {
					if target == nil {
						return errors.New("fixture absence readback failed")
					}
					return read(ctx, target)
				}
			}
			switch fault {
			case "failed-settlement":
				f.store.failPhase = "settled"
			case "cancelled-settlement":
				f.store.cancelPhase, f.store.cancel = "settled", cancel
			case "close":
				f.store.base.failClose = true
			case "cancelled-close":
				f.store.cancelPhase, f.store.cancel = "close", cancel
			case "cancelled-native-close":
				f.cancelClose = cancel
			}
			if err := f.slot.release(ctx); err == nil || f.kernel.target != nil || f.slot.target == nil ||
				f.slot.retirement == nil || f.slot.provedEmpty() {
				t.Fatal("unfinished durable removal discarded its exact transaction", err)
			}
			capture := f.slot.retirement
			f.slot.backend.read = read
			f.store.failPhase, f.store.cancelPhase = "", ""
			f.store.base.failClose = false
			f.cancelClose = nil
			if fault == "close" || fault == "cancelled-close" {
				f.store.base.failRead = true // Never reopen or read partially closed journal handles.
			}
			if err := f.slot.release(context.Background()); err != nil {
				t.Fatal("same removed owner could not finish durable settlement and close", err)
			}
			f.requireFinished(t)
			if f.constructors != 1 || f.nativeCloses != 1 || capture.(*desktopNodeJournalRelease).native == nil {
				t.Fatal("post-removal retry reconstructed or reclosed the native removal")
			}
		})
	}
}

func TestDesktopNodeJournalReleaseRetriesPartialNativeOwner(t *testing.T) {
	for _, policy := range []string{"on-connect", "always"} {
		t.Run(policy, func(t *testing.T) {
			f := newDesktopNodeDurableReleaseFixture(t, policy)
			f.partialNext = true
			if err := f.slot.release(context.Background()); err == nil || f.slot.retirement == nil || f.store.base.writes != 0 || !f.kernel.locked {
				t.Fatal("failed native preparation lost its exact partial owner")
			}
			capture := f.slot.retirement.(*desktopNodeJournalRelease)
			native := capture.native
			f.partialJoinFail = true
			if err := f.slot.release(context.Background()); err == nil || capture.native != native || f.constructors != 1 {
				t.Fatal("unjoined partial release reached another constructor")
			}
			f.partialJoinFail, f.kernel.readFail = false, true
			if err := f.slot.release(context.Background()); err == nil || capture.native != native || f.constructors != 1 || f.kernel.locked {
				t.Fatal("partial release skipped its independently unchanged target")
			}
			f.kernel.readFail = false
			if err := f.slot.release(context.Background()); err != nil {
				t.Fatal(err)
			}
			f.requireFinished(t)
			if f.constructors != 2 || capture.native == native {
				t.Fatal("joined partial owner did not lead to one fresh exact preparation")
			}
		})
	}
}

func TestDesktopNodeJournalReleaseRetainsArmedOwnerAndIntent(t *testing.T) {
	for _, fault := range []string{"late-constructor-cancel", "native-commit"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopNodeDurableReleaseFixture(t, "on-connect")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if fault == "late-constructor-cancel" {
				f.cancelConstruct = cancel
			} else {
				f.commitFailure = true
			}
			if err := f.slot.release(ctx); err == nil || f.slot.retirement == nil || f.kernel.target == nil {
				t.Fatal("cancelled native release lost its armed owner or assumed removal")
			}
			capture := f.slot.retirement.(*desktopNodeJournalRelease)
			native := capture.native
			f.cancelConstruct, f.commitFailure = nil, false
			if err := f.slot.release(context.Background()); err != nil {
				t.Fatal(err)
			}
			f.requireFinished(t)
			if f.constructors != 1 || capture.native != native || f.store.base.writes != 2 {
				t.Fatal("armed release replaced its native owner or durable intent")
			}
		})
	}
}

func TestDesktopNodeJournalReleaseRejectsUncapturedState(t *testing.T) {
	for _, fault := range []string{"missing-revision", "invalid-revision", "foreign-profile", "foreign-source", "foreign-target", "live-engine", "intent", "incomplete", "read", "sequence", "generation", "barrier"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopNodeDurableReleaseFixture(t, "on-connect")
			switch fault {
			case "missing-revision":
				f.slot.profileRevision = ""
			case "invalid-revision":
				f.slot.profileRevision = strings.Repeat("F", 64)
			case "foreign-profile":
				f.slot.binding.ProfileID += "other"
			case "foreign-source":
				f.slot.binding.SourceSHA256 = strings.Repeat("9", 64)
			case "foreign-target":
				f.store.base.head.Committed.Target.BaselineSHA256 = strings.Repeat("9", 64)
			case "live-engine":
				engine := f.store.base.head.Controller
				engine.PID++
				f.store.base.head.Committed.Engine = &engine
			case "intent":
				f.store.base.head.Phase = "intent"
			case "incomplete":
				f.store.base.incomplete = true
			case "read":
				f.store.base.failRead = true
			case "sequence":
				f.store.base.head.Sequence = math.MaxUint64 - 1
			case "generation":
				f.slot.generation = math.MaxUint64
			case "barrier":
				f.slot.backend.releaseWithBarrier = nil
			}
			if err := f.slot.release(context.Background()); err == nil || f.constructors != 0 || f.store.base.writes != 0 || f.kernel.target == nil || f.slot.retirement != nil {
				t.Fatal("uncaptured durable state acquired native release", fault, err)
			}
		})
	}
}

func TestDesktopNodeJournalReleaseRejectsReplacementDuringRetry(t *testing.T) {
	for _, fault := range []string{"target", "profile", "revision", "generation", "store", "controller", "journal-head"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopNodeDurableReleaseFixture(t, "on-connect")
			f.prepareFailure = true
			if err := f.slot.release(context.Background()); err == nil || f.slot.retirement == nil {
				t.Fatal("fixture did not retain its captured preparation")
			}
			capture := f.slot.retirement
			f.prepareFailure = false
			switch fault {
			case "target":
				f.slot.target.BaselineSHA256 = strings.Repeat("9", 64)
			case "profile":
				f.slot.binding.ProfileID += "other"
			case "revision":
				f.slot.profileRevision = strings.Repeat("9", 64)
			case "generation":
				f.slot.generation++
			case "store":
				f.slot.journal = &desktopNodeJournalFixtureStore{head: f.before}
			case "controller":
				f.store.base.head.Controller.PID++
			case "journal-head":
				f.store.base.head.Sequence += 2
			}
			if err := f.slot.release(context.Background()); err == nil || f.slot.retirement != capture || f.constructors != 1 || f.store.base.writes != 0 || f.kernel.target == nil {
				t.Fatal("durable retry adopted a replaced application or journal owner", fault, err)
			}
		})
	}
}

func TestDesktopNodeJournalReleaseRejectsSubstitutedNativeBarrier(t *testing.T) {
	for _, fault := range []string{"off", "target", "candidate", "missing-target"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopNodeDurableReleaseFixture(t, "on-connect")
			f.change = func(change *mobiletor.DesktopWindowsProtectionCommit) {
				switch fault {
				case "off":
					change.Action = "off"
				case "target":
					change.Previous.BaselineSHA256 = strings.Repeat("9", 64)
				case "candidate":
					change.Candidate = copyDesktopNodeProtectionTarget(&f.target)
				case "missing-target":
					change.Previous = nil
				}
			}
			if err := f.slot.release(context.Background()); err == nil || f.store.base.writes != 0 || f.kernel.target == nil || f.slot.retirement == nil {
				t.Fatal("substituted native callback gained durable removal permission", fault, err)
			}
		})
	}
}

func TestDesktopNodeJournalReleaseRequiresActualBarrierAcknowledgment(t *testing.T) {
	f := newDesktopNodeDurableReleaseFixture(t, "on-connect")
	f.skipBarrier = true
	if err := f.slot.release(context.Background()); err == nil || f.slot.retirement == nil || f.slot.target == nil || f.store.base.writes != 0 || f.store.base.closes != 0 {
		t.Fatal("callback-free removal received durable settlement or application completion", err)
	}
}

func TestDesktopNodeJournalReleaseKeepsSeparateOffGate(t *testing.T) {
	f := newDesktopNodeDurableReleaseFixture(t, "always")
	f.slot.backend.recover = func(context.Context, mobiletor.DesktopWindowsProtectionTarget) (desktopNodeProtectionRelease, error) {
		t.Fatal("durable normal release enabled callback-free explicit Off")
		return nil, nil
	}
	if err := f.slot.release(context.Background()); err != nil {
		t.Fatal(err)
	}
	capture, err := f.slot.captureOff(context.Background(), f.slot.binding.ProfileID, f.revision, f.revision, f.slot.view().token(f.revision))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.slot.applyOff(context.Background(), capture, func() bool { return true }); err == nil || f.store.base.writes != 0 || f.kernel.target == nil {
		t.Fatal("normal release silently authorized durable Off without its distinct native barrier")
	}
}

// Windows policy calls retain entered native work after a caller times out.
// This wrapper models that explicit scheduling boundary around the same real
// application barrier; no delayed worker may release or replace its capture.
type desktopNodeLateReleaseNative struct {
	native  desktopNodeProtectionRelease
	gate    chan struct{}
	entered chan struct{}
	done    chan struct{}
}

func (n *desktopNodeLateReleaseNative) Close(ctx context.Context) error {
	n.entered <- struct{}{}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-n.gate:
	}
	result := make(chan error, 1)
	go func() {
		err := n.native.Close(ctx)
		n.gate <- struct{}{}
		result <- err
		n.done <- struct{}{}
	}()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestDesktopNodeJournalReleaseJoinsLateNativeBarrier(t *testing.T) {
	f := newDesktopNodeDurableReleaseFixture(t, "on-connect")
	constructor := f.slot.backend.releaseWithBarrier
	native := &desktopNodeLateReleaseNative{gate: make(chan struct{}, 1), entered: make(chan struct{}, 3), done: make(chan struct{}, 3)}
	native.gate <- struct{}{}
	f.slot.backend.releaseWithBarrier = func(ctx context.Context, target mobiletor.DesktopWindowsProtectionTarget, barrier mobiletor.DesktopWindowsProtectionCommitBarrier) (desktopNodeProtectionRelease, error) {
		owner, err := constructor(ctx, target, barrier)
		native.native = owner
		return native, err
	}
	entered, resume := make(chan struct{}), make(chan struct{})
	var once sync.Once
	f.store.beforeAppend = func() { once.Do(func() { close(entered); <-resume }) }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- f.slot.release(ctx) }()
	<-entered
	<-native.entered
	cancel()
	if err := <-result; err == nil || f.slot.retirement == nil || f.kernel.target == nil || !f.kernel.locked {
		t.Fatal("cancelled release detached its still-entered native barrier", err)
	}
	capture := f.slot.retirement
	retry, cancelRetry := context.WithCancel(context.Background())
	defer cancelRetry()
	go func() { result <- f.slot.release(retry) }()
	<-native.entered
	cancelRetry()
	if err := <-result; err == nil || f.slot.retirement != capture || f.constructors != 1 {
		t.Fatal("unjoined native barrier let another retry replace its owner", err)
	}
	close(resume)
	<-native.done
	if f.store.base.writes != 0 || f.store.base.head.Phase != "settled" || f.kernel.target == nil {
		t.Fatal("late cancelled barrier acknowledged a durable removal")
	}
	if err := f.slot.release(context.Background()); err != nil {
		t.Fatal("joined cancelled native barrier could not retry its exact release", err)
	}
	<-native.done
	f.requireFinished(t)
	if f.constructors != 1 || f.nativeCloses != 2 || capture.(*desktopNodeJournalRelease).native != native {
		t.Fatal("late-barrier recovery replaced its captured native transaction")
	}
}
