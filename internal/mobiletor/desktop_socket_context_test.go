package mobiletor

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/desktopnetwork"
)

func TestDesktopBrokerContextExpiryDoesNotRetireOriginal(t *testing.T) {
	policy := desktopSocketFixturePolicy()
	ownerCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var held sync.Mutex
	broker := &DesktopSocketBroker{ctx: ownerCtx, cancel: cancel, capture: desktopSocketFixtureCapture(), owner: policy.owner, policy: policy,
		current: func() bool { panic("bounded observation used contextless callback") },
		currentContext: func(ctx context.Context) error {
			if err := desktopnetwork.LockContext(ctx, &held); err != nil {
				return err
			}
			held.Unlock()
			return nil
		}}
	held.Lock()
	ctx, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := broker.CurrentContext(ctx)
	stop()
	held.Unlock()
	if !errors.Is(err, context.DeadlineExceeded) || ownerCtx.Err() != nil {
		t.Fatal("observation expiry retired original", err, ownerCtx.Err())
	}
	if err := broker.MatchesContext(context.Background(), broker.capture); err != nil {
		t.Fatal("original capture did not recover after observation expiry", err)
	}
	foreign := broker.capture
	foreign.NetworkID = "different"
	if err := broker.MatchesContext(context.Background(), foreign); !errors.Is(err, net.ErrClosed) || ownerCtx.Err() != nil {
		t.Fatal("foreign observation changed original", err)
	}
	policy.live.Store(false)
	if err := broker.CurrentContext(context.Background()); !errors.Is(err, net.ErrClosed) || ownerCtx.Err() == nil {
		t.Fatal("real native policy loss did not revoke original", err)
	}
}

func TestDesktopBrokerContextRequiresExplicitObserver(t *testing.T) {
	policy := desktopSocketFixturePolicy()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	broker := &DesktopSocketBroker{ctx: ctx, cancel: cancel, policy: policy, current: func() bool { panic("unbounded fallback") }}
	if err := broker.CurrentContext(context.Background()); err == nil || ctx.Err() != nil {
		t.Fatal("missing bounded observer accepted or retired original", err)
	}
	broker.currentContext = func(context.Context) error { return errors.New("captured network generation replaced") }
	if err := broker.CurrentContext(context.Background()); err == nil || ctx.Err() == nil {
		t.Fatal("actual captured generation loss did not revoke original", err)
	}
}

func TestDesktopBrokerConfirmedLossSurvivesRacedCallerCancellation(t *testing.T) {
	policy := desktopSocketFixturePolicy()
	ownerCtx, stopOwner := context.WithCancel(context.Background())
	defer stopOwner()
	caller, stopCaller := context.WithCancel(context.Background())
	defer stopCaller()
	cause := errors.New("captured policy changed")
	broker := &DesktopSocketBroker{ctx: ownerCtx, cancel: stopOwner, policy: policy, currentContext: func(context.Context) error { stopCaller(); return errors.Join(cause, caller.Err()) }}
	err := broker.CurrentContext(caller)
	if !errors.Is(err, cause) || !errors.Is(err, context.Canceled) || ownerCtx.Err() == nil {
		t.Fatal("caller expiry hid confirmed owner loss", err, ownerCtx.Err())
	}
}
