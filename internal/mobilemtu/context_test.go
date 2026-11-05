package mobilemtu

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type contextTestOwner struct {
	*externalTestOwner
	capture func(context.Context) (State, error)
	mutate  func(context.Context, State, int) (State, error)
	recover func(context.Context, State) (State, error)
}

func (o *contextTestOwner) CaptureContext(ctx context.Context) (State, error) {
	if o.capture != nil {
		return o.capture(ctx)
	}
	if err := LockContext(ctx, &o.mu); err != nil {
		return State{}, err
	}
	defer o.mu.Unlock()
	return o.state, ctx.Err()
}
func (o *contextTestOwner) ChangeMTU(ctx context.Context, state State, mtu int) (State, error) {
	if o.mutate != nil {
		return o.mutate(ctx, state, mtu)
	}
	return o.testOwner.ChangeMTU(ctx, state, mtu)
}
func (o *contextTestOwner) RollbackStateContext(ctx context.Context, state State) (State, error) {
	if o.recover != nil {
		return o.recover(ctx, state)
	}
	actual, err := o.CaptureContext(ctx)
	if err == nil && actual != state {
		return State{}, errors.New("unowned rollback reader")
	}
	return actual, err
}
func contextController(t *testing.T) (*Controller, *contextTestOwner) {
	t.Helper()
	owner := &contextTestOwner{externalTestOwner: &externalTestOwner{testOwner: &testOwner{state: State{Session: "original", Path: "physical", Interface: "tun-1", MTU: 1380}}}}
	c, err := NewExternalContext(context.Background(), owner, externalFixtureGraph(), encoded(externalFixtureAuthority()), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, owner
}
func TestContextOperationAdmissionAndStatusDoNotLeaveWaiters(t *testing.T) {
	c, owner := contextController(t)
	for _, action := range []string{"start", "status", "cancel", "close"} {
		t.Run(action, func(t *testing.T) {
			c.mu.Lock()
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				var err error
				switch action {
				case "start":
					err = c.StartContext(ctx, strings.Repeat("a", 32), true)
				case "status":
					_, err = c.StatusJSONContext(ctx)
				case "cancel":
					err = c.CancelContext(ctx, strings.Repeat("a", 32))
				case "close":
					err = c.CloseContext(ctx)
				}
				done <- err
			}()
			select {
			case err := <-done:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Errorf("lost caller deadline: %v", err)
				}
			case <-time.After(time.Second):
				t.Error("bounded call waited on retained lock")
			}
			if c.status.Request != "" || c.closed {
				t.Error("expired admission changed controller")
			}
			c.mu.Unlock()
		})
	}
	if len(owner.applied) != 0 {
		t.Fatal("expired admission mutated reader")
	}
	if _, err := c.StatusJSONContext(context.Background()); err != nil {
		t.Fatal("observation expiry poisoned healthy controller", err)
	}
}
func TestContextOwnerRequiredWithoutLegacyFallback(t *testing.T) {
	owner := &externalTestOwner{testOwner: &testOwner{state: State{Session: "s", Path: "p", Interface: "i", MTU: 1380}}}
	if _, err := NewExternalContext(context.Background(), owner, externalFixtureGraph(), encoded(externalFixtureAuthority()), nil); err == nil {
		t.Fatal("legacy owner accepted")
	}
	if owner.reads != 0 {
		t.Fatal("bounded constructor called legacy capture")
	}
}
func TestContextCaptureLateResultCannotAdmitMutation(t *testing.T) {
	c, owner := contextController(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	deadline, _ := ctx.Deadline()
	owner.capture = func(call context.Context) (State, error) {
		got, ok := call.Deadline()
		if !ok || !got.Equal(deadline) {
			t.Error("capture replaced original deadline")
		}
		<-call.Done()
		return owner.state, nil
	}
	if err := c.RunContext(ctx, strings.Repeat("b", 32), true); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if len(owner.applied) != 0 || readStatus(t, c).Measured {
		t.Fatal("late observation became native mutation or winner")
	}
	owner.capture = nil
	if _, err := owner.CaptureContext(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func TestContextOriginalCleanupDeadlineCannotBeRenewed(t *testing.T) {
	work, finish, err := WithOperationContext(context.Background(), time.Minute, 30*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	cancelled, stop := context.WithCancel(work)
	stop()
	first, err := OperationCleanupContext(cancelled)
	if err != nil {
		t.Fatal(err)
	}
	second, err := OperationCleanupContext(work)
	if err != nil || first != second {
		t.Fatal("cleanup context was replaced", err)
	}
	if !SameOperationContext(first, work) {
		t.Fatal("cleanup lost original capability")
	}
	fresh, end, _ := WithOperationContext(context.Background(), time.Minute, time.Second)
	defer end()
	if SameOperationContext(first, fresh) {
		t.Fatal("new request inherited old cleanup authority")
	}
	<-first.Done()
	if _, err := OperationCleanupContext(work); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("expired cleanup allowance was renewed", err)
	}
	finish()
	if SameOperationContext(first, work) {
		t.Fatal("finished operation retained admission")
	}
}
func TestContextRollbackUsesReturnedTransactionAfterUnpublishedCandidate(t *testing.T) {
	for _, mode := range []string{"cancel-after-mutation", "failed-candidate", "replaced-owner"} {
		t.Run(mode, func(t *testing.T) {
			c, owner := contextController(t)
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			original := owner.state
			var accepted context.Context
			var applied int
			owner.mutate = func(ctx context.Context, expected State, mtu int) (State, error) {
				applied++
				if applied == 1 {
					accepted = ctx
					if expected != original {
						t.Fatal("mutation changed original capture")
					}
					owner.state.Interface = "returned-candidate"
					owner.state.MTU = mtu
					if mode == "replaced-owner" {
						owner.state.Session = "replacement"
					}
					if mode == "cancel-after-mutation" {
						cancel()
						return original, ctx.Err()
					}
					return original, errors.New("candidate failed before publication")
				}
				if !SameOperationContext(ctx, accepted) || expected != owner.state || mtu != original.MTU {
					t.Fatal("cleanup lost exact transaction", expected, owner.state)
				}
				owner.state.Interface = "original-rollback"
				owner.state.MTU = mtu
				return owner.state, nil
			}
			owner.recover = func(ctx context.Context, expected State) (State, error) {
				if !SameOperationContext(ctx, accepted) || expected != original || owner.state.Session != original.Session || owner.state.Path != original.Path {
					return State{}, errors.New("original transaction no longer owns reader")
				}
				return owner.state, nil
			}
			err := c.RunContext(parent, strings.Repeat("c", 32), true)
			if err == nil {
				t.Fatal("failed candidate became successful operation")
			}
			status := readStatus(t, c)
			if status.Measured {
				t.Fatal("expired/failed candidate became winner")
			}
			if mode == "replaced-owner" {
				if applied != 1 || status.Restored {
					t.Fatal("newer owner was rolled back")
				}
			} else if applied != 2 || owner.state.MTU != original.MTU || !status.Restored {
				t.Fatal("original accepted mutation was abandoned", applied, status)
			}
			if mode == "cancel-after-mutation" && !errors.Is(err, context.Canceled) {
				t.Fatal("cleanup overwrote original cancellation", err)
			}
		})
	}
}

func TestContextAdmissionCallbackAndWorkerPublishOneGeneration(t *testing.T) {
	c, _ := contextController(t)
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := strings.Repeat("d", 32)
	called := 0
	if err := c.StartContextWithAdmission(parent, request, true, func(ctx context.Context) error { called++; cancel(); return nil }); err != nil {
		t.Fatal("accepted generation was lost after callback", err)
	}
	c.mu.Lock()
	done := c.done
	observed := c.status.Request
	c.mu.Unlock()
	if observed != request || called != 1 {
		t.Fatal("native admission lost its published controller", observed, called)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled accepted generation did not drain")
	}
	status := readStatus(t, c)
	if status.Running || !status.Complete || status.Measured {
		t.Fatal(status)
	}
}

func TestContextMailboxAdmissionDoesNotOwnAcceptedWorkerLifetime(t *testing.T) {
	c, owner := contextController(t)
	operation, stopOperation := context.WithTimeout(context.Background(), time.Second)
	defer stopOperation()
	admission, stopAdmission := context.WithCancel(operation)
	entered := make(chan context.Context, 1)
	owner.capture = func(ctx context.Context) (State, error) { entered <- ctx; <-ctx.Done(); return State{}, ctx.Err() }
	if err := c.StartContextWithAdmissionOn(admission, operation, strings.Repeat("e", 32), true, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	stopAdmission()
	var work context.Context
	select {
	case work = <-entered:
	case <-time.After(time.Second):
		t.Fatal("accepted worker never entered original owner")
	}
	if work.Err() != nil {
		t.Fatal("finishing admission canceled accepted operation")
	}
	expected, _ := operation.Deadline()
	actual, ok := work.Deadline()
	if !ok || !actual.Equal(expected) {
		t.Fatal("worker lost transported absolute deadline")
	}
	stopOperation()
	c.mu.Lock()
	done := c.done
	c.mu.Unlock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("original operation cancellation did not drain")
	}
}

// Successful registration still owns a generation when only its polling caller
// expires. Drain that generation, without starting work under the live parent.
func TestContextLateAdmissionAcknowledgementDrainsWithoutMutation(t *testing.T) {
	c, owner := contextController(t)
	parent, stopParent := context.WithTimeout(context.Background(), time.Minute)
	defer stopParent()
	admission, stopAdmission := context.WithCancel(parent)
	defer stopAdmission()
	request := strings.Repeat("f", 32)
	called := 0
	op, err := c.beginContextAdmissionOn(admission, parent, request, true, func(context.Context) error {
		called++
		stopAdmission()
		return nil
	})
	if err != nil {
		t.Fatal("accepted native generation was lost", err)
	}
	defer op.cancel()
	defer op.finish()
	if parent.Err() != nil || called != 1 || c.status.Request != request || c.done != op.done {
		t.Fatal("split caller did not retain its admitted generation")
	}
	if !errors.Is(op.ctx.Err(), context.Canceled) {
		t.Fatal("late admission acknowledgement left accepted work live")
	}
	if err := c.execute(op, true); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	select {
	case <-op.done:
	default:
		t.Fatal("accepted generation did not drain")
	}
	status := readStatus(t, c)
	if status.Running || !status.Complete || status.Measured || len(owner.applied) != 0 {
		t.Fatal("expired admission mutated or adopted a native reader", status, owner.applied)
	}
}
