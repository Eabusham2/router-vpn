package mobiletor

import (
	"context"
	"errors"
	"testing"
	"time"

	"router-vpn/internal/multihoprelay"
)

func serverCurrentFixture(t *testing.T) *ServerTorClient {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &ServerTorClient{ctx: ctx, cancel: cancel, policy: &ServerTorPolicy{}, attempt: true,
		lease:   multihoprelay.TorLease{OwnerID: "original", ExpiresAt: time.Now().Add(time.Minute)},
		current: func() bool { panic("bounded server read used contextless callback") }, currentContext: func(ctx context.Context) error { return ctx.Err() }}
}
func TestServerTorCurrentContextExpiresWithoutRetiringLease(t *testing.T) {
	c := serverCurrentFixture(t)
	c.mu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := c.CurrentContext(ctx)
	cancel()
	c.mu.Unlock()
	if !errors.Is(err, context.DeadlineExceeded) || c.ctx.Err() != nil {
		t.Fatal("lease mutex expiry retired original", err, c.ctx.Err())
	}
	if err := c.CurrentContext(context.Background()); err != nil {
		t.Fatal("original lease lost after pure read expiry", err)
	}
	c.lease.ExpiresAt = time.Now().Add(-time.Second)
	if err := c.CurrentContext(context.Background()); err == nil || c.ctx.Err() == nil {
		t.Fatal("actual lease expiry was not revoked", err)
	}
}
func TestServerTorCurrentContextKeepsCancellationSeparateFromIdentityLoss(t *testing.T) {
	c := serverCurrentFixture(t)
	c.currentContext = func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := c.CurrentContext(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || c.ctx.Err() != nil {
		t.Fatal("physical observation expiry cancelled lease", err)
	}
	c.currentContext = func(context.Context) error { return errors.New("original Router entry replaced") }
	if err := c.CurrentContext(context.Background()); err == nil || c.ctx.Err() == nil {
		t.Fatal("actual entry replacement preserved lease", err)
	}
	c = serverCurrentFixture(t)
	c.currentContext = nil
	if err := c.CurrentContext(context.Background()); err == nil || c.ctx.Err() != nil {
		t.Fatal("unbounded legacy callback accepted or lease cancelled", err)
	}
}

func TestServerTorConfirmedLossSurvivesRacedCallerCancellation(t *testing.T) {
	c := serverCurrentFixture(t)
	caller, cancel := context.WithCancel(context.Background())
	defer cancel()
	cause := errors.New("original lease owner replaced")
	c.currentContext = func(context.Context) error { cancel(); return errors.Join(cause, caller.Err()) }
	err := c.CurrentContext(caller)
	if !errors.Is(err, cause) || !errors.Is(err, context.Canceled) || c.ctx.Err() == nil {
		t.Fatal("caller expiry hid confirmed lease-owner loss", err, c.ctx.Err())
	}
}
