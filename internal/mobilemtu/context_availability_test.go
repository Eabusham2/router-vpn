package mobilemtu

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type constructedContextObservation struct {
	caller  context.Context
	bounded bool
}

type constructedContextTestOwner struct {
	*contextTestOwner
	available    bool
	legacyReads  int
	contextReads int
	entered      chan constructedContextObservation
}

func (o *constructedContextTestOwner) ContextCaptureAvailable() bool { return o.available }
func (o *constructedContextTestOwner) Capture() (State, error) {
	o.legacyReads++
	return o.testOwner.Capture()
}
func (o *constructedContextTestOwner) CaptureContext(ctx context.Context) (State, error) {
	o.contextReads++
	return o.contextTestOwner.CaptureContext(ctx)
}
func (o *constructedContextTestOwner) VerifyExternal(ctx context.Context, _ State) error {
	o.entered <- constructedContextObservation{caller: ctx}
	<-ctx.Done()
	return ctx.Err()
}
func newConstructedContextTestOwner(available bool) *constructedContextTestOwner {
	return &constructedContextTestOwner{
		contextTestOwner: &contextTestOwner{externalTestOwner: &externalTestOwner{testOwner: &testOwner{
			state: State{Session: "original", Path: "physical", Interface: "tun-1", MTU: 1380},
		}}},
		available: available,
		entered:   make(chan constructedContextObservation, 1),
	}
}

func TestContextLegacyControllerUsesConstructedAvailability(t *testing.T) {
	for _, available := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy-owner", true: "context-owner"}[available], func(t *testing.T) {
			owner := newConstructedContextTestOwner(available)
			cache := NewCache(&testPreferences{})
			controller, err := NewExternal(owner, externalFixtureGraph(), encoded(externalFixtureAuthority()), cache)
			if err != nil {
				t.Fatal(err)
			}
			defer controller.Close()
			if controller.bounded || controller.cache != cache {
				t.Fatal("observation capability changed the legacy cache contract")
			}
			owner.capture = func(ctx context.Context) (State, error) {
				owner.entered <- constructedContextObservation{caller: ctx, bounded: true}
				<-ctx.Done()
				return owner.state, nil
			}
			request := strings.Repeat("8", 32)
			done := make(chan error, 1)
			go func() { done <- controller.Run(request, true) }()
			var observation constructedContextObservation
			select {
			case observation = <-owner.entered:
			case err := <-done:
				t.Fatal("constructed owner rejected before its owned observation", err)
			case <-time.After(time.Second):
				controller.Cancel(request)
				<-done
				t.Fatal("constructed owner never reached its owned observation")
			}
			if observation.bounded != available || !SameOperationContext(observation.caller, observation.caller) {
				controller.Cancel(request)
				<-done
				t.Fatal("capture selected the wrong capability or lost original cancellation")
			}
			controller.Cancel(request)
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) || observation.caller.Err() != context.Canceled {
					t.Fatal("constructed owner lost the original cancellation", err)
				}
			case <-time.After(time.Second):
				_ = controller.Close()
				<-done
				t.Fatal("constructed owner did not join after cancellation")
			}
			status := readStatus(t, controller)
			if !status.Complete || status.Measured || len(owner.applied) != 0 {
				t.Fatal("canceled observation admitted a measurement or mutation", status)
			}
			if available && (owner.legacyReads != 1 || owner.contextReads != 1) {
				t.Fatal("available context owner fell back to legacy observation", owner.legacyReads, owner.contextReads)
			}
			if !available && (owner.legacyReads < 2 || owner.contextReads != 0) {
				t.Fatal("legacy owner entered an unavailable context observation", owner.legacyReads, owner.contextReads)
			}
		})
	}
}

func TestContextUnavailableCaptureRejectsStrictConstructorAndAdmission(t *testing.T) {
	t.Run("constructor", func(t *testing.T) {
		owner := newConstructedContextTestOwner(false)
		owner.capture = func(context.Context) (State, error) { return State{}, errors.New("unavailable callback invoked") }
		controller, err := NewExternalContext(context.Background(), owner, externalFixtureGraph(), encoded(externalFixtureAuthority()), nil)
		if controller != nil {
			_ = controller.Close()
		}
		if err == nil || owner.legacyReads != 0 || owner.contextReads != 0 {
			t.Fatal("strict construction observed an unavailable owner", err, owner.legacyReads, owner.contextReads)
		}
	})
	for _, action := range []string{"run", "start", "admission", "separate-admission"} {
		t.Run(action, func(t *testing.T) {
			owner := newConstructedContextTestOwner(false)
			owner.capture = func(context.Context) (State, error) { return State{}, errors.New("unavailable callback invoked") }
			controller, err := NewExternal(owner, externalFixtureGraph(), encoded(externalFixtureAuthority()), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer controller.Close()
			request := strings.Repeat("9", 32)
			admitted := false
			admit := func(context.Context) error {
				admitted = true
				return nil
			}
			switch action {
			case "run":
				err = controller.RunContext(context.Background(), request, true)
			case "start":
				err = controller.StartContext(context.Background(), request, true)
			case "admission":
				err = controller.StartContextWithAdmission(context.Background(), request, true, admit)
			case "separate-admission":
				err = controller.StartContextWithAdmissionOn(context.Background(), context.Background(), request, true, admit)
			}
			if err == nil {
				controller.Cancel(request)
				_ = controller.Close()
				t.Fatal("strict operation admitted an unavailable context owner")
			}
			status := readStatus(t, controller)
			if admitted || status.Request != "" || status.Running || status.Complete || owner.legacyReads != 1 || owner.contextReads != 0 || len(owner.applied) != 0 {
				t.Fatal("strict refusal changed the owner or admitted a generation", status, owner.legacyReads, owner.contextReads)
			}
		})
	}
}

func TestContextAvailableCaptureFailureNeverFallsBack(t *testing.T) {
	for _, boundary := range []string{"native-error", "late-cancel"} {
		t.Run(boundary, func(t *testing.T) {
			owner := newConstructedContextTestOwner(true)
			controller, err := NewExternal(owner, externalFixtureGraph(), encoded(externalFixtureAuthority()), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer controller.Close()
			request := strings.Repeat("a", 32)
			refused := errors.New("captured native reader refused observation")
			owner.capture = func(context.Context) (State, error) {
				if boundary == "late-cancel" {
					controller.Cancel(request)
					return owner.state, nil
				}
				return State{}, refused
			}
			err = controller.Run(request, true)
			if boundary == "native-error" && !errors.Is(err, refused) || boundary == "late-cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("original context failure was lost", err)
			}
			status := readStatus(t, controller)
			if owner.legacyReads != 1 || owner.contextReads != 1 || len(owner.applied) != 0 || !status.Complete || status.Measured {
				t.Fatal("context refusal fell back to a legacy read or admitted a result", status, owner.legacyReads, owner.contextReads)
			}
		})
	}
}
