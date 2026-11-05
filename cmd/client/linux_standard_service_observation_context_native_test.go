//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/desktopnetwork"
)

// Only event delivery is modeled. The existing fixtures retain actual source
// files, sealed configuration, namespace descriptors, child and authenticated IPC.
type serviceObservationReader struct {
	linuxStandardStartupObserver
	read     func(context.Context) error
	afterEnd bool
}

func (n *serviceObservationReader) CurrentContext(ctx context.Context) error {
	if n.read != nil {
		return n.read(ctx)
	}
	return n.linuxStandardStartupObserver.CurrentContext(ctx)
}
func (n *serviceObservationReader) Close() error {
	if n.linuxStandardStartupObserver == nil {
		return nil
	}
	return n.linuxStandardStartupObserver.Close()
}
func (n *serviceObservationReader) End(ctx context.Context, r *desktopnetwork.DesktopNetworkReceipt) error {
	err := n.linuxStandardStartupObserver.End(ctx, r)
	if err == nil {
		n.afterEnd = true
	}
	return err
}

type serviceObservationEnteredContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (c *serviceObservationEnteredContext) Err() error {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Err()
}

func TestLinuxStandardServiceNetworkObservationCancellationPreservesOriginal(t *testing.T) {
	for _, kind := range []string{"expired-before", "cancelled-read", "deadline-read", "late-success", "mixed-loss", "replaced-owner", "namespace-loss", "lifetime-loss"} {
		t.Run(kind, func(t *testing.T) {
			s, _, _, _, original := standardNetworkSession(t, "on-connect")
			model := &standardNetworkModel{}
			opens := 0
			if err := s.proveDNSWithNetworkObservers(original, func(context.Context, context.Context) (linuxStandardNetworkObserver, error) {
				opens++
				return model, nil
			}, func(context.Context, *linuxLegacyStandardExitOwner) error { return nil }); err != nil {
				t.Fatal(err)
			}
			retained := s.session.network
			session := s.session
			owner := session.owner
			namespace := owner.namespaceInfo
			ctx, cancel := context.WithCancel(original)
			defer cancel()
			failure := errors.New("original network reader failed")
			if kind == "deadline-read" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(original, 25*time.Millisecond)
				defer stop()
			}
			reader := &serviceObservationReader{}
			reader.read = func(ctx context.Context) error {
				if kind == "deadline-read" {
					<-ctx.Done()
				} else {
					cancel()
				}
				switch kind {
				case "mixed-loss":
					return errors.Join(failure, ctx.Err())
				case "replaced-owner":
					session.owner = &linuxLegacyStandardExitOwner{}
				case "namespace-loss":
					owner.namespaceInfo = nil
				case "lifetime-loss":
					retained.cancel()
				case "late-success":
					return nil
				}
				return ctx.Err()
			}
			// The reader remains the same object for the failed observation and retry.
			retained.observer = reader
			if kind == "expired-before" {
				cancel()
			}
			err := s.networkCurrent(ctx, session, true)
			session.owner = owner
			owner.namespaceInfo = namespace
			genuine := kind == "mixed-loss" || kind == "replaced-owner" || kind == "namespace-loss" || kind == "lifetime-loss"
			if err == nil || (!genuine && !errors.Is(err, ctx.Err())) {
				t.Fatal("observation lost original cancellation or confirmed loss", err)
			}
			if genuine {
				if retained.failure == nil {
					t.Fatal("confirmed loss was not permanently latched")
				}
				if kind == "mixed-loss" && !errors.Is(retained.failure, failure) {
					t.Fatal("cancellation hid genuine reader failure", retained.failure)
				}
			} else if retained.failure != nil {
				t.Fatal("pure observer expiry retired healthy original", retained.failure)
			}
			reader.read = func(context.Context) error { return nil }
			next := s.networkCurrent(original, session, true)
			if (next != nil) != genuine || s.session.network != retained || opens != 1 {
				t.Fatal("later observation changed original ownership", next, opens)
			}
			// Fixture teardown owns the original model's Close; this wrapper has no
			// startup methods because only network observation is exercised here.
			retained.observer = model
		})
	}
}

func TestLinuxStandardServiceControllerEpochObservationCancellationPreservesOriginal(t *testing.T) {
	for _, kind := range []string{"expired-before", "cancelled-read", "deadline-read", "late-success", "mixed-loss", "replaced-source", "held-app-lock", "lifetime-loss"} {
		t.Run(kind, func(t *testing.T) {
			_, _, o, base, original := linuxStandardControllerEpochFixture(t)
			reader := &serviceObservationReader{linuxStandardStartupObserver: base}
			n := o.prepared.requestEpoch
			n.observer = reader
			if err := o.Start(original); err != nil {
				t.Fatal(err)
			}
			source := o.prepared.sourceConfig
			failure := errors.New("original controller reader failed")
			ctx, cancel := context.WithCancel(original)
			defer cancel()
			if kind == "deadline-read" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(original, 25*time.Millisecond)
				defer stop()
			}
			if kind == "held-app-lock" {
				entered := &serviceObservationEnteredContext{Context: ctx, entered: make(chan struct{})}
				o.app.mu.Lock()
				done := make(chan error, 1)
				go func() { done <- n.current(entered, true) }()
				select {
				case <-entered.entered:
				case <-time.After(time.Second):
					o.app.mu.Unlock()
					cancel()
					<-done
					t.Fatal("actual epoch observation did not enter")
				}
				cancel()
				select {
				case err := <-done:
					if !errors.Is(err, context.Canceled) {
						t.Errorf("mutex observation lost cancellation: %v", err)
					}
				case <-time.After(time.Second):
					o.app.mu.Unlock()
					<-done
					t.Fatal("observer waited for captured app mutex")
				}
				o.app.mu.Unlock()
			} else {
				reader.read = func(ctx context.Context) error {
					if kind == "deadline-read" {
						<-ctx.Done()
					} else {
						cancel()
					}
					if kind == "mixed-loss" {
						return errors.Join(failure, ctx.Err())
					}
					if kind == "replaced-source" {
						o.prepared.sourceConfig = nil
					}
					if kind == "lifetime-loss" {
						n.cancel()
					}
					if kind == "late-success" {
						return nil
					}
					return ctx.Err()
				}
				if kind == "expired-before" {
					cancel()
				}
				err := n.current(ctx, true)
				o.prepared.sourceConfig = source
				genuine := kind == "mixed-loss" || kind == "replaced-source" || kind == "lifetime-loss"
				if err == nil || !genuine && !errors.Is(err, ctx.Err()) {
					t.Fatal("original observation outcome lost", err)
				}
			}
			genuine := kind == "mixed-loss" || kind == "replaced-source" || kind == "lifetime-loss"
			if (n.failure != nil) != genuine {
				t.Fatal("observation cancellation changed failure latch", n.failure)
			}
			if kind == "mixed-loss" && !errors.Is(n.failure, failure) {
				t.Fatal("mixed source loss was hidden", n.failure)
			}
			reader.read = nil
			err := n.current(original, true)
			if (err != nil) != genuine || n.observer != reader || o.prepared.requestEpoch != n {
				t.Fatal("retry changed the original epoch", err)
			}
		})
	}
}

func TestLinuxStandardServiceControllerEpochStartupCancellationStillLatches(t *testing.T) {
	for _, phase := range []string{"bind", "begin", "final-admit"} {
		t.Run(phase, func(t *testing.T) {
			_, _, o, base, original := linuxStandardControllerEpochFixture(t)
			n := o.prepared.requestEpoch
			reader := &serviceObservationReader{linuxStandardStartupObserver: base}
			n.observer = reader
			ctx, cancel := context.WithCancel(original)
			defer cancel()
			var err error
			switch phase {
			case "bind":
				n.bound = false
				cancel()
				err = n.bind(ctx, n.profileDigest)
			case "begin":
				cancel()
				err = n.begin(ctx)
			case "final-admit":
				o.app.connectionContext = ctx // Preserve the original startup identity contract.
				reader.read = func(ctx context.Context) error {
					if reader.afterEnd {
						cancel()
					}
					return errors.Join(base.CurrentContext(ctx), ctx.Err())
				}
				err = o.Start(ctx)
			}
			if err == nil || n.failure == nil {
				t.Fatal("failed startup acquired live-observation exemption", phase, err, n.failure)
			}
			reader.read = nil
			if n.current(original, false) == nil {
				t.Fatal("failed startup was rebased by a fresh observer")
			}
			if err := o.prepared.openRequestEpoch(original, func(context.Context, context.Context) (linuxStandardStartupObserver, error) {
				t.Fatal("failed startup opened a replacement stream")
				return nil, nil
			}); err == nil {
				t.Fatal("original partial startup discarded")
			}
		})
	}
}
