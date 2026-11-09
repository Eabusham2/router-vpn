package mobilemtu

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type finalizedRollbackTestOwner struct {
	*contextTestOwner
	observed func(context.Context, State) (State, error)
}

func (o *finalizedRollbackTestOwner) FinalizedRollbackContext(ctx context.Context, original State) (State, error) {
	return o.observed(ctx, original)
}

// The platform fixture changes controlled TUN readers. The real shared
// controller still runs measurement, winner selection, finalization and the
// second Retest; these tests grant no physical-interface acceptance.
func TestFinalizedRollbackRequiresOriginalObservedOwnerAndRestoresRetestConfig(t *testing.T) {
	for _, fault := range []string{"restored", "wrong-session", "wrong-path", "wrong-interface", "wrong-mtu", "unconfirmed", "cancelled-observation", "replacement-after-observation"} {
		t.Run(fault, func(t *testing.T) {
			controller, native, _ := externalFixtureController(t)
			original, err := native.Capture()
			if err != nil {
				t.Fatal(err)
			}
			before := controller.Config()
			owner := &finalizedRollbackTestOwner{contextTestOwner: &contextTestOwner{externalTestOwner: native}}
			controller.owner, controller.cache = owner, nil
			var accepted context.Context
			observations := 0
			owner.observed = func(ctx context.Context, expected State) (State, error) {
				observations++
				cleanup, err := OperationCleanupOnly(ctx)
				if err != nil || !cleanup || expected != original || !SameOperationContext(ctx, accepted) {
					t.Error("finalized rollback borrowed another capture or renewed cleanup", expected, err)
					return State{}, errors.New("wrong final rollback authority")
				}
				state, err := owner.CaptureContext(ctx)
				if err != nil {
					return state, err
				}
				switch fault {
				case "wrong-session":
					state.Session = "replacement-session"
				case "wrong-path":
					state.Path = "replacement-network"
				case "wrong-interface":
					state.Interface = "replacement-reader"
				case "wrong-mtu":
					state.MTU = 1420
				case "unconfirmed":
					return State{}, errors.New("original rollback never joined")
				case "cancelled-observation":
					return State{}, context.Canceled
				case "replacement-after-observation":
					native.mu.Lock()
					native.state.Session = "replacement-session"
					native.mu.Unlock()
				}
				return state, nil
			}
			parent, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			failure := errors.New("final native commit was rejected")
			err = controller.RunContextWithCleanupProvider(parent, parent, strings.Repeat("a", 32), true,
				func(ctx context.Context) (time.Time, error) { d, _ := ctx.Deadline(); return d, ctx.Err() },
				func(ctx context.Context) error { accepted = ctx; return nil },
				func(ctx context.Context) error {
					status := readStatus(t, controller)
					if !status.Measured || status.EffectiveMTU != 1500 || controller.Config() == before {
						t.Error("fixture did not reach the actual measured winner before native finalization", status)
						return errors.New("fixture did not measure a distinct winner")
					}
					cleanup, err := OperationCleanupContext(ctx)
					if err != nil {
						return err
					}
					current, err := owner.CaptureContext(cleanup)
					if err != nil {
						return err
					}
					if _, err := owner.ChangeMTU(cleanup, current, original.MTU); err != nil {
						return err
					}
					return failure
				})
			if !errors.Is(err, failure) || observations != 1 {
				t.Fatal("failed finalization lost its original failure or observation", observations, err)
			}
			status := readStatus(t, controller)
			if status.Measured || status.Running || !status.Complete {
				t.Fatal("failed finalization reported a measured active winner", status)
			}
			if fault != "restored" {
				if status.Restored || status.EffectiveMTU != 0 || controller.Config() == before {
					t.Fatal("unproved or replacement rollback restored the controller configuration", status)
				}
				return
			}
			if !status.Restored || status.EffectiveMTU != original.MTU || status.Source != "restored-unmeasured" || controller.Config() != before {
				t.Fatal("proved original rollback did not retain the complete previous config", status)
			}
			if err := controller.RunContext(parent, strings.Repeat("b", 32), true); err != nil {
				t.Fatal("second Retest could not use the restored original interface/config", err)
			}
			if status := readStatus(t, controller); !status.Measured || status.EffectiveMTU != 1500 {
				t.Fatal("second Retest did not freshly measure its captured path", status)
			}
		})
	}
}

func TestFinalizedRollbackCannotOutliveOriginalCleanupAtAdmission(t *testing.T) {
	controller, native, _ := externalFixtureController(t)
	controller.owner = &contextTestOwner{externalTestOwner: native}
	original, err := native.Capture()
	if err != nil {
		t.Fatal(err)
	}
	work, finish, err := WithOperationContext(context.Background(), 30*time.Second, 8*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	cleanup, err := OperationCleanupContext(work)
	if err != nil || !controller.live(cleanup, original) {
		t.Fatal("fixture omitted its original live rollback proof", err)
	}
	before := controller.Config()
	if _, err := NewPlan(before, original.MTU); err != nil {
		t.Fatal(err)
	}
	controller.mu.Lock()
	controller.currentConfig = "unconfirmed candidate configuration"
	controller.status.Restored, controller.status.EffectiveMTU = false, 0
	entered, done := make(chan struct{}), make(chan struct{})
	go func() {
		close(entered)
		controller.mu.Lock()
		defer controller.mu.Unlock()
		controller.restoreFinalizedRollbackLocked(cleanup, original, before)
		close(done)
	}()
	<-entered
	finish() // Original cleanup closes while the real admission mutex is held.
	<-cleanup.Done()
	controller.mu.Unlock()
	<-done
	if status := readStatus(t, controller); status.Restored || status.EffectiveMTU != 0 || controller.Config() != "unconfirmed candidate configuration" {
		t.Fatal("final admission renewed an expired original rollback proof", status)
	}
}
