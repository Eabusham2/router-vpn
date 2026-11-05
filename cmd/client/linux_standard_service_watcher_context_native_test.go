//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

// The engine, original peer/process descriptors, configuration and selected-DNS
// exchanges are real. Only delivery of the retained network event read is modeled.
type serviceWatcherContextReader struct {
	read func(context.Context) error
}

func (r *serviceWatcherContextReader) CurrentContext(ctx context.Context) error { return r.read(ctx) }
func (r *serviceWatcherContextReader) Close() error                             { return nil }

func TestLinuxStandardServiceWatcherPreservesOnlyPureObservationExpiry(t *testing.T) {
	for _, kind := range []string{"pure-expiry", "mixed-reader-failure"} {
		t.Run(kind, func(t *testing.T) {
			s, _, peer, request, startup := standardNetworkSessionWithDNS(t, "on-connect", true)
			reader := &serviceWatcherContextReader{read: func(ctx context.Context) error { return ctx.Err() }}
			s.openNetwork = func(context.Context, context.Context) (linuxStandardNetworkObserver, error) { return reader, nil }
			if err := s.handle(startup, peer, linuxStandardServiceTestAction(request, "prove-dns", false), nil); err != nil {
				t.Fatal("original selected DNS was not proved", err)
			}
			retained, owner, epoch := s.session, s.session.owner, s.session.network
			entered, expired, retried := make(chan struct{}), make(chan struct{}), make(chan struct{})
			reads := 0
			failure := errors.New("actual original event stream failed")
			reader.read = func(ctx context.Context) error {
				reads++
				if reads == 1 {
					close(entered)
					<-ctx.Done()
					close(expired)
					if kind == "mixed-reader-failure" {
						return errors.Join(failure, ctx.Err())
					}
					return ctx.Err()
				}
				if reads == 2 {
					close(retried)
				}
				return ctx.Err()
			}
			lifetime, stop := context.WithTimeout(context.Background(), 10*time.Second)
			joined := make(chan struct{})
			go func() { defer close(joined); s.watch(lifetime) }()
			defer func() { stop(); <-joined }()
			for _, event := range []<-chan struct{}{entered, expired} {
				select {
				case <-event:
				case <-lifetime.Done():
					t.Fatal("shipping watcher did not execute its original bounded observation")
				}
			}
			for {
				select {
				case <-s.gate:
				case <-lifetime.Done():
					t.Fatal("shipping watcher did not release its original gate")
				}
				if s.session != retained || retained.owner != owner || retained.network != epoch {
					s.gate <- struct{}{}
					t.Fatal("watcher replaced the original session or observer")
				}
				retired, pending := retained.joined, retained.cleanupPending
				latched := epoch.failure
				removed, detached := owner.protection.removed, owner.protection.detached
				s.gate <- struct{}{}
				if kind == "pure-expiry" {
					if retired || pending || latched != nil || removed || detached {
						t.Fatal("pure watcher observation expiry retired the healthy original", retired, pending, latched, removed, detached)
					}
					select {
					case <-retried:
						return
					case <-lifetime.Done():
						t.Fatal("watcher did not retry the same healthy original observer")
					case <-time.After(5 * time.Millisecond):
					}
				} else {
					if !errors.Is(latched, failure) {
						t.Fatal("watcher cancellation erased genuine reader failure", latched)
					}
					if retired {
						if removed || !detached {
							t.Fatal("genuine failure discarded original On-connect protection")
						}
						return
					}
					select {
					case <-lifetime.Done():
						t.Fatal("genuine watcher failure did not retire its original engine")
					case <-time.After(5 * time.Millisecond):
					}
				}
			}
		})
	}
}
