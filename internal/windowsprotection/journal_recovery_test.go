package windowsprotection

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"

	"router-vpn/internal/mobiletor"
)

type journalRecoveryModel struct {
	t              *testing.T
	head           JournalSelection
	previous       JournalRecord
	owner          *JournalRecovery
	observer       *journalRecoveryModelObservation
	events         []string
	bodies         [][]byte
	pending        []byte
	verifyErr      error
	retireErr      error
	appendErr      error
	writeThenError bool
	falseReceipt   bool
	closeFailures  int
	finishFailures int
	retired        bool
	closed         bool
	finished       int
	appendEntered  chan struct{}
	appendRelease  chan struct{}
}

func (model *journalRecoveryModel) verify(context.Context) error {
	model.events = append(model.events, "verify")
	return model.verifyErr
}

func (model *journalRecoveryModel) retire(context.Context) error {
	model.events = append(model.events, "retire")
	if model.retireErr != nil {
		return model.retireErr
	}
	model.retired = true
	return nil
}

func (model *journalRecoveryModel) append(ctx context.Context, next JournalRecord) (JournalSelection, error) {
	model.events = append(model.events, "append")
	if !model.retired || !model.observer.reading {
		return JournalSelection{}, errors.New("append preceded process retirement or escaped the native snapshot")
	}
	if err := CheckJournalRecoveryTransition(model.previous, next); err != nil {
		return JournalSelection{}, err
	}
	body := journalTestBody(model.t, next)
	if model.pending != nil && !bytes.Equal(body, model.pending) {
		return JournalSelection{}, errors.New("model received changed pending adoption bytes")
	}
	model.pending = append([]byte(nil), body...)
	model.bodies = append(model.bodies, append([]byte(nil), body...))
	if model.appendEntered != nil {
		close(model.appendEntered)
		<-model.appendRelease
	}
	if model.appendErr != nil && !model.writeThenError {
		return JournalSelection{}, model.appendErr
	}
	model.head = journalRecoverySelection(model.t, next)
	if model.falseReceipt {
		wrong := cloneJournalSelection(model.head)
		wrong.SHA256 = strings.Repeat("1", 64)
		return wrong, model.appendErr
	}
	return cloneJournalSelection(model.head), errors.Join(model.appendErr, ctx.Err())
}

func (model *journalRecoveryModel) close() error {
	model.events = append(model.events, "process-close")
	if model.closeFailures > 0 {
		model.closeFailures--
		return errors.New("injected retained process close failure")
	}
	model.closed = true
	return nil
}

func (model *journalRecoveryModel) finish(context.Context, *JournalRecovery) error {
	model.events = append(model.events, "finish")
	if !model.retired || !model.closed || !model.observer.closed || model.owner.durable == nil {
		return errors.New("finish preceded a joined observed durable handover")
	}
	if model.finishFailures > 0 {
		model.finishFailures--
		return errors.New("injected final readback failure")
	}
	model.finished++
	return nil
}

type journalRecoveryModelObservation struct {
	model         *journalRecoveryModel
	callback      func(context.Context, int) error
	matched       int
	readErr       error
	proofLost     bool
	endFailures   int
	closeFailures int
	skipCallback  bool
	reading       bool
	acked         bool
	closed        bool
	proofs        int
}

func (observer *journalRecoveryModelObservation) Run(ctx context.Context) error {
	model := observer.model
	model.events = append(model.events, "observe")
	if observer.proofLost {
		return errors.New("sticky loss of the observed native snapshot")
	}
	if observer.acked {
		return nil
	}
	observer.proofs++
	if observer.readErr != nil {
		return observer.readErr
	}
	if observer.skipCallback {
		return nil
	}
	if !model.retired {
		return errors.New("native observation preceded independently retired processes")
	}
	observer.reading = true
	err := observer.callback(ctx, observer.matched)
	observer.reading = false
	model.events = append(model.events, "snapshot-end")
	if err != nil {
		return err
	}
	observer.acked = true
	if observer.endFailures > 0 {
		observer.endFailures--
		return errors.New("injected snapshot cleanup failure")
	}
	return nil
}

func (observer *journalRecoveryModelObservation) Close(ctx context.Context) error {
	observer.model.events = append(observer.model.events, "observation-close")
	if err := ctx.Err(); err != nil {
		return err
	}
	if observer.reading {
		return errors.New("observation close escaped the synchronous callback join")
	}
	if observer.closeFailures > 0 {
		observer.closeFailures--
		return errors.New("injected observation close failure")
	}
	observer.closed = true
	return nil
}

func newJournalRecoveryModel(t *testing.T) (*JournalRecovery, *journalRecoveryModel) {
	t.Helper()
	previous := journalTestOff(t)
	model := &journalRecoveryModel{t: t, head: journalRecoverySelection(t, previous), previous: cloneJournalRecord(previous)}
	model.observer = &journalRecoveryModelObservation{model: model, matched: 1}
	owner, err := newJournalRecovery(model.head, journalRecoveryController(), strings.Repeat("e", 32), model,
		func(targets []*mobiletor.DesktopWindowsProtectionTarget, callback func(context.Context, int) error) (journalRecoveryObservation, error) {
			if len(targets) != 2 || targets[0] == nil || targets[1] != nil || *targets[0] != *previous.Committed.Target {
				t.Fatal("native observation lost its two exact recorded alternatives")
			}
			model.observer.callback = callback
			return model.observer, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	model.owner = owner
	return owner, model
}

func TestWindowsProtectionJournalRecoveryOwnedOrdering(t *testing.T) {
	owner, model := newJournalRecoveryModel(t)
	result, err := owner.Run(context.Background())
	if err != nil || result.Selection.Record.Intent == nil || result.Observed.Target != nil || model.finished != 1 {
		t.Fatal("checked restart did not retain the pending Off and observed absence", err)
	}
	want := []string{"verify", "retire", "observe", "verify", "append", "snapshot-end", "observation-close", "process-close", "finish"}
	if !reflect.DeepEqual(model.events, want) {
		t.Fatal("recovery moved persistence outside process retirement and the native snapshot", model.events)
	}
	result.Selection.Record.Intent.ResultProfileRevision = strings.Repeat("1", 64)
	result.Selection.Record.Adoption.PreviousController.PID++
	again, err := owner.Run(context.Background())
	if err != nil || again.Selection.Record.Intent.ResultProfileRevision == strings.Repeat("1", 64) ||
		again.Selection.Record.Adoption.PreviousController != model.previous.Controller || len(model.bodies) != 1 || model.finished != 1 {
		t.Fatal("repeat recovery mutated or replayed the durable owned receipt", err)
	}
}

func TestWindowsProtectionJournalRecoveryRejectsMissingProof(t *testing.T) {
	for _, fault := range []string{"authority", "process", "BFE", "no-callback", "false-receipt"} {
		t.Run(fault, func(t *testing.T) {
			owner, model := newJournalRecoveryModel(t)
			switch fault {
			case "authority":
				model.verifyErr = errors.New("changed desktop or Data")
			case "process":
				model.retireErr = errors.New("old source remains live")
			case "BFE":
				model.observer.readErr = errors.New("unrecorded native target")
			case "no-callback":
				model.observer.skipCallback = true
			case "false-receipt":
				model.falseReceipt = true
			}
			if result, err := owner.Run(context.Background()); err == nil || result.Selection.Record.Sequence != 0 || model.finished != 0 {
				t.Fatal("missing proof admitted journal recovery")
			}
			if fault != "false-receipt" && len(model.bodies) != 0 {
				t.Fatal("unproved process or BFE reached the durable writer")
			}
			if err := owner.Close(context.Background()); err != nil || !model.closed || !model.observer.closed {
				t.Fatal("failed proof lost its actual partial owners", err)
			}
		})
	}
}

func TestWindowsProtectionJournalRecoveryExactWriteRetry(t *testing.T) {
	owner, model := newJournalRecoveryModel(t)
	model.appendErr = errors.New("injected flush denial")
	if result, err := owner.Run(context.Background()); err == nil || result.Selection.Record.Sequence != 0 || owner.adoption == nil {
		t.Fatal("failed adoption write was acknowledged or lost its exact pending record")
	}
	first := append([]byte(nil), model.bodies[0]...)
	model.appendErr = nil
	model.observer.matched = 0
	if _, err := owner.Run(context.Background()); err == nil || len(model.bodies) != 1 {
		t.Fatal("retry replaced the first observed native outcome after uncertain persistence")
	}
	model.observer.matched = 1
	result, err := owner.Run(context.Background())
	if err != nil || result.Selection.Record.Sequence == 0 || len(model.bodies) != 2 || !bytes.Equal(model.bodies[1], first) || model.finished != 1 {
		t.Fatal("exact original adoption could not resume its retained pending write", err)
	}
}

func TestWindowsProtectionJournalRecoveryDurableErrorRetries(t *testing.T) {
	for _, fault := range []string{"append-after-write", "snapshot-cleanup", "observation-close", "process-close", "final-readback"} {
		t.Run(fault, func(t *testing.T) {
			owner, model := newJournalRecoveryModel(t)
			switch fault {
			case "append-after-write":
				model.appendErr, model.writeThenError = errors.New("post-write cancellation"), true
			case "snapshot-cleanup":
				model.observer.endFailures = 1
			case "observation-close":
				model.observer.closeFailures = 1
			case "process-close":
				model.closeFailures = 1
			case "final-readback":
				model.finishFailures = 1
			}
			partial, err := owner.Run(context.Background())
			if err == nil || partial.Selection.Record.Sequence == 0 || model.finished != 0 {
				t.Fatal("durable checkpoint incorrectly implied a joined successful recovery")
			}
			model.appendErr = nil
			result, err := owner.Run(context.Background())
			if err != nil || result.Selection.SHA256 != partial.Selection.SHA256 || model.finished != 1 {
				t.Fatal("retry could not join the identical durable handover", err)
			}
			wantWrites := 1
			if fault == "append-after-write" {
				wantWrites = 2 // same idempotent callback after an uncertain reply
			}
			if len(model.bodies) != wantWrites {
				t.Fatal("cleanup retry replayed an already acknowledged writer", len(model.bodies))
			}
		})
	}
}

func TestWindowsProtectionJournalRecoveryLostSnapshotStaysUnresolved(t *testing.T) {
	owner, model := newJournalRecoveryModel(t)
	model.observer.endFailures = 1
	partial, err := owner.Run(context.Background())
	if err == nil || partial.Selection.Record.Sequence == 0 {
		t.Fatal("native snapshot failure lost the actual durable comparison record")
	}
	// The native observer distinguishes transient cleanup from an aborted or
	// otherwise lost transaction. The latter remains sticky even after the
	// callback wrote successfully; its receipt is never activation authority.
	model.observer.proofLost = true
	for range 2 {
		result, err := owner.Run(context.Background())
		if err == nil || result.Selection.SHA256 != partial.Selection.SHA256 || model.finished != 0 || len(model.bodies) != 1 || model.closed {
			t.Fatal("lost snapshot was converted into successful recovery by a durable-write retry")
		}
	}
	if err := owner.Close(context.Background()); err != nil || !model.closed || !model.observer.closed || model.finished != 0 {
		t.Fatal("abandoned ambiguous recovery did not join without granting admission", err)
	}
}

func TestWindowsProtectionJournalRecoveryCancellationJoinsWriter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		owner, model := newJournalRecoveryModel(t)
		model.appendEntered, model.appendRelease = make(chan struct{}), make(chan struct{})
		type outcome struct {
			result JournalRecoveryResult
			err    error
		}
		run := make(chan outcome, 1)
		go func() { result, err := owner.Run(context.Background()); run <- outcome{result, err} }()
		<-model.appendEntered
		closed := make(chan error, 1)
		go func() { closed <- owner.Close(context.Background()) }()
		synctest.Wait()
		select {
		case <-closed:
			t.Fatal("recovery Close returned while its durable callback was still entered")
		default:
		}
		close(model.appendRelease)
		result := <-run
		if result.err == nil || result.result.Selection.Record.Sequence == 0 || model.finished != 0 {
			t.Fatal("cancelled callback erased its actual write or admitted the retired operation")
		}
		if err := <-closed; err != nil || !model.closed || !model.observer.closed {
			t.Fatal("recovery cancellation did not join its exact callback and resources", err)
		}
		if _, err := owner.Run(context.Background()); err == nil {
			t.Fatal("abandoned recovery reacquired ordinary admission authority")
		}
	})
	owner, model := newJournalRecoveryModel(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := owner.Run(ctx); err == nil || len(model.events) != 0 {
		t.Fatal("cancelled recovery began native work")
	}
}

func TestWindowsProtectionJournalRecoveryCapturesImmutableInputs(t *testing.T) {
	for _, fault := range []string{"incomplete", "digest", "slot", "same-controller", "unbound"} {
		t.Run(fault, func(t *testing.T) {
			owner, model := newJournalRecoveryModel(t)
			head, controller := cloneJournalSelection(owner.head), owner.controller
			switch fault {
			case "incomplete":
				head.Incomplete = true
			case "digest":
				head.SHA256 = strings.Repeat("1", 64)
			case "slot":
				head.Slot = 1 - head.Slot
			case "same-controller":
				controller = head.Record.Controller
			case "unbound":
				head.Record.Committed.ProfileRevision = ""
				head = journalRecoverySelection(t, head.Record)
			}
			called := false
			captured, err := newJournalRecovery(head, controller, strings.Repeat("e", 32), model,
				func([]*mobiletor.DesktopWindowsProtectionTarget, func(context.Context, int) error) (journalRecoveryObservation, error) {
					called = true
					return model.observer, nil
				})
			if err == nil || captured != nil || called {
				t.Fatal("invalid copied head acquired a native observation owner")
			}
		})
	}
	owner, model := newJournalRecoveryModel(t)
	model.previous.Committed.Target.BaselineSHA256 = strings.Repeat("d", 64)
	if owner.head.Record.Committed.Target.BaselineSHA256 == strings.Repeat("d", 64) {
		t.Fatal("caller changed the captured immutable recovery head")
	}
}
