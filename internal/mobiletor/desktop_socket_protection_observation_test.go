package mobiletor

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// This backend is an explicit lifecycle/failure model. Actual kernel snapshot,
// namespace and lock evidence is exercised separately by the Windows tests.
type desktopProtectionObservationModel struct {
	events       *[]string
	read         func(context.Context, []*desktopWindowsProtectionExpected) (int, error)
	closeFailure int
	finishErr    error
	transaction  bool
}

func (m *desktopProtectionObservationModel) observe(ctx context.Context, expected []*desktopWindowsProtectionExpected) (int, error) {
	*m.events = append(*m.events, "read")
	m.transaction = true
	if m.read != nil {
		return m.read(ctx, expected)
	}
	return 0, nil
}
func (m *desktopProtectionObservationModel) finishSnapshot() error {
	*m.events = append(*m.events, "finish")
	if m.finishErr != nil {
		return m.finishErr
	}
	m.transaction = false
	return nil
}
func (m *desktopProtectionObservationModel) close() error {
	*m.events = append(*m.events, "close")
	if m.closeFailure > 0 {
		m.closeFailure--
		return errors.New("injected exact native close failure")
	}
	m.transaction = false
	return nil
}
func desktopProtectionObservationTarget() DesktopWindowsProtectionTarget {
	return desktopWindowsProtectionTarget(DesktopSocketCapture{strings.Repeat("1", 32), strings.Repeat("2", 64), strings.Repeat("3", 32)}, "always", []byte("exact observation baseline"))
}

func TestDesktopWindowsProtectionObservationCapturedOutcomes(t *testing.T) {
	target := desktopProtectionObservationTarget()
	original := target
	candidates := []*DesktopWindowsProtectionTarget{nil, &target}
	events := []string{}
	model := &desktopProtectionObservationModel{events: &events}
	model.read = func(ctx context.Context, expected []*desktopWindowsProtectionExpected) (int, error) {
		if len(expected) != 2 || expected[0].target != nil || expected[1].target == nil || *expected[1].target != original {
			t.Fatal("observation replaced its immutable recorded outcomes")
		}
		return 1, nil
	}
	owner, err := newDesktopWindowsProtectionObservation(candidates, func(ctx context.Context, index int) error {
		if index != 1 || !model.transaction || ctx.Err() != nil {
			t.Fatal("acknowledgement escaped the exact live observation")
		}
		events = append(events, "ack")
		return nil
	}, func() (desktopWindowsProtectionObservationNative, error) {
		events = append(events, "open")
		return model, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	target.Policy = "on-connect"
	candidates[0], candidates[1] = &target, nil
	if err := owner.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := owner.Run(context.Background()); err != nil || !reflect.DeepEqual(events, []string{"open", "read", "ack", "finish", "close"}) {
		t.Fatal("successful acknowledgement was replayed or cleanup ran before it", events, err)
	}
	if err := owner.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := owner.Run(context.Background()); err == nil {
		t.Fatal("retired observation reopened native authority")
	}
}

func TestDesktopWindowsProtectionObservationRejectsInvalidRequest(t *testing.T) {
	target := desktopProtectionObservationTarget()
	invalid := target
	invalid.Policy = "off"
	callback := func(context.Context, int) error { return nil }
	open := func() (desktopWindowsProtectionObservationNative, error) {
		t.Fatal("invalid request opened a native owner")
		return nil, nil
	}
	for name, candidates := range map[string][]*DesktopWindowsProtectionTarget{
		"missing": nil, "many": {nil, &target, &invalid}, "duplicate-absence": {nil, nil},
		"duplicate-target": {&target, &target}, "malformed": {&invalid},
	} {
		t.Run(name, func(t *testing.T) {
			if owner, err := newDesktopWindowsProtectionObservation(candidates, callback, open); owner != nil || err == nil {
				t.Fatal("unbounded or malformed observation acquired an owner")
			}
		})
	}
	if owner, err := newDesktopWindowsProtectionObservation([]*DesktopWindowsProtectionTarget{nil}, nil, open); owner != nil || err == nil {
		t.Fatal("observation accepted an uncaptured callback")
	}
	if owner, err := newDesktopWindowsProtectionObservation([]*DesktopWindowsProtectionTarget{nil}, callback, nil); owner != nil || err == nil {
		t.Fatal("observation accepted no native constructor")
	}
	for _, owner := range []*DesktopWindowsProtectionObservation{nil, {}} {
		if owner.Run(context.Background()) == nil || owner.Close(context.Background()) == nil {
			t.Fatal("unconstructed observation acquired native authority")
		}
	}
	owner, err := newDesktopWindowsProtectionObservation([]*DesktopWindowsProtectionTarget{nil}, callback, open)
	if err != nil {
		t.Fatal(err)
	}
	if owner.Run(nil) == nil || owner.Close(nil) == nil {
		t.Fatal("context-free observation acquired native authority")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := owner.Run(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled request acquired a native snapshot", err)
	}
	if err := owner.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopWindowsProtectionObservationRetainsFailures(t *testing.T) {
	for _, failure := range []string{"partial-open", "read", "uncaptured-index", "callback", "cleanup"} {
		t.Run(failure, func(t *testing.T) {
			events := []string{}
			model := &desktopProtectionObservationModel{events: &events, closeFailure: 2}
			opens, callbacks := 0, 0
			fault := errors.New("injected " + failure)
			model.read = func(context.Context, []*desktopWindowsProtectionExpected) (int, error) {
				if opens == 1 && failure == "read" {
					return -1, fault
				}
				if opens == 1 && failure == "uncaptured-index" {
					return 1, nil
				}
				return 0, nil
			}
			owner, err := newDesktopWindowsProtectionObservation([]*DesktopWindowsProtectionTarget{nil}, func(context.Context, int) error {
				callbacks++
				events = append(events, "ack")
				if callbacks == 1 && failure == "callback" {
					return fault
				}
				return nil
			}, func() (desktopWindowsProtectionObservationNative, error) {
				opens++
				events = append(events, "open")
				if opens == 1 && failure == "partial-open" {
					return model, fault
				}
				return model, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := owner.Run(context.Background()); err == nil || owner.native != model {
				t.Fatal("failed observation lost its partial native owner", err)
			}
			before := callbacks
			if err := owner.Run(context.Background()); err == nil || opens != 1 || callbacks != before || owner.native != model {
				t.Fatal("retry bypassed unjoined native cleanup", events, err)
			}
			if err := owner.Run(context.Background()); err != nil || owner.native != nil || model.transaction {
				t.Fatal("same observation failed to join and retry its captured operation", events, err)
			}
			wantOpen, wantCallback := 2, 1
			if failure == "cleanup" {
				wantOpen = 1
			}
			if failure == "callback" {
				wantCallback = 2
			}
			if opens != wantOpen || callbacks != wantCallback {
				t.Fatal("retry repeated acknowledged durable write or skipped required proof", events)
			}
			if err := owner.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDesktopWindowsProtectionObservationCancelsBeforeAcknowledgement(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := []string{}
	model := &desktopProtectionObservationModel{events: &events}
	model.read = func(context.Context, []*desktopWindowsProtectionExpected) (int, error) { cancel(); return 0, nil }
	owner, err := newDesktopWindowsProtectionObservation([]*DesktopWindowsProtectionTarget{nil}, func(context.Context, int) error {
		t.Fatal("cancelled observation performed a late durable write")
		return nil
	}, func() (desktopWindowsProtectionObservationNative, error) { return model, nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.Run(ctx); !errors.Is(err, context.Canceled) || owner.native != nil || model.transaction {
		t.Fatal("cancelled read failed to join its native snapshot", err)
	}
	if err := owner.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopWindowsProtectionObservationCloseJoinsCallback(t *testing.T) {
	events := []string{}
	model := &desktopProtectionObservationModel{events: &events, closeFailure: 1}
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	owner, err := newDesktopWindowsProtectionObservation([]*DesktopWindowsProtectionTarget{nil}, func(ctx context.Context, _ int) error {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		<-release // model an in-flight durable write that must be joined
		if !model.transaction {
			t.Error("callback outlived its native snapshot")
		}
		return nil
	}, func() (desktopWindowsProtectionObservationNative, error) { return model, nil })
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- owner.Run(context.Background()) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("observation did not enter captured callback")
	}
	closeCtx, stop := context.WithCancel(context.Background())
	closed := make(chan error, 1)
	go func() { closed <- owner.Close(closeCtx) }()
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("cleanup failed to revoke callback context before joining")
	}
	select {
	case err := <-done:
		t.Fatal("Run returned with an unjoined durable writer", err)
	case err := <-closed:
		t.Fatal("Close acknowledged an unjoined durable writer", err)
	default:
	}
	stop()
	if err := <-closed; !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled join returned a false cleanup receipt", err)
	}
	close(release)
	if err := <-done; !errors.Is(err, context.Canceled) || owner.native != model {
		t.Fatal("cancelled writer lost its failed native cleanup owner", err)
	}
	if err := owner.Close(context.Background()); err != nil || owner.native != nil || model.transaction {
		t.Fatal("retry did not join the exact pending native owner", err)
	}
	if err := owner.Run(context.Background()); err == nil {
		t.Fatal("closed observation replayed its durable write")
	}
}

func TestDesktopWindowsProtectionObservationSerializesRequests(t *testing.T) {
	events := []string{}
	model := &desktopProtectionObservationModel{events: &events}
	entered, release := make(chan struct{}), make(chan struct{})
	owner, err := newDesktopWindowsProtectionObservation([]*DesktopWindowsProtectionTarget{nil}, func(context.Context, int) error {
		close(entered)
		<-release
		return nil
	}, func() (desktopWindowsProtectionObservationNative, error) {
		events = append(events, "open")
		return model, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- owner.Run(context.Background()) }()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	waiting := make(chan error, 1)
	go func() { waiting <- owner.Run(ctx) }()
	cancel()
	if err := <-waiting; !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled waiter acquired a second observation", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(events, []string{"open", "read", "finish", "close"}) {
		t.Fatal("concurrent requests acquired overlapping native snapshots", events)
	}
	if err := owner.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopWindowsProtectionObservationRetainsLostSnapshot(t *testing.T) {
	for _, callbackFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "acknowledged", true: "uncertain-write"}[callbackFailure], func(t *testing.T) {
			events := []string{}
			proofErr := errors.New("injected native snapshot loss")
			model := &desktopProtectionObservationModel{events: &events, finishErr: proofErr, closeFailure: 1}
			callbacks, opens := 0, 0
			owner, err := newDesktopWindowsProtectionObservation([]*DesktopWindowsProtectionTarget{nil}, func(context.Context, int) error {
				callbacks++
				if callbackFailure {
					return errors.New("injected ambiguous durable write")
				}
				return nil
			}, func() (desktopWindowsProtectionObservationNative, error) { opens++; return model, nil })
			if err != nil {
				t.Fatal(err)
			}
			if err := owner.Run(context.Background()); !errors.Is(err, proofErr) || owner.native != model {
				t.Fatal("lost snapshot acquired durable adoption or lost its cleanup owner", err)
			}
			model.finishErr = nil // later cleanup/recovery cannot repair the old proof
			if err := owner.Run(context.Background()); !errors.Is(err, proofErr) || owner.native != nil || opens != 1 || callbacks != 1 {
				t.Fatal("joined cleanup converted lost snapshot into adoption or replayed its write", err)
			}
			if err := owner.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}
