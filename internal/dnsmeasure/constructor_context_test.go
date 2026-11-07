package dnsmeasure

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type constructorEngine struct {
	*fakeEngine
	observe func(context.Context) (string, error)
	reads   atomic.Int32
	legacy  atomic.Int32
}

func (e *constructorEngine) Identity() string {
	e.legacy.Add(1)
	return e.fakeEngine.Identity()
}
func (e *constructorEngine) IdentityContext(ctx context.Context) (string, error) {
	e.reads.Add(1)
	return e.observe(ctx)
}

func TestDNSConstructorRetainsOriginalCallerAndSelectedEndpoint(t *testing.T) {
	for _, phase := range []string{"current", "nil", "cancel-before", "capture-held", "recheck-held", "owner-replaced", "late-cancel", "missing-observer", "invalid-selected"} {
		t.Run(phase, func(t *testing.T) {
			original := newFake()
			defer original.cancel()
			engine := &constructorEngine{fakeEngine: original}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			entered := make(chan struct{})
			engine.observe = func(caller context.Context) (string, error) {
				if caller != ctx {
					return "", errors.New("DNS constructor replaced original caller")
				}
				count := engine.reads.Load()
				if phase == "capture-held" && count == 1 || phase == "recheck-held" && count == 2 {
					close(entered)
					<-caller.Done()
				}
				if count == 2 {
					if phase == "owner-replaced" {
						return "replacement-DNS-owner", nil
					}
					if phase == "late-cancel" {
						cancel()
					}
				}
				return original.Identity(), nil // Late success cannot revive this caller.
			}
			description := Description{NodeID: "saved-exit", SessionID: "proved-session", RouteLabel: "Current external exit", IPv6Enabled: true, Selected: Endpoint{ID: "selected", Kind: "selected", Name: "Selected DNS", Address: "10.77.0.53", Port: 8443, Transport: "https", ServerName: "resolver.example", Path: "/selected-query", Route: "entry-wg", RouteLabel: "Selected DNS via entry-wg"}}
			if phase == "invalid-selected" {
				description.Selected.Path = "/selected-query\nforeign"
			}
			if phase == "cancel-before" {
				cancel()
			}
			type result struct {
				service *Service
				err     error
			}
			done := make(chan result, 1)
			go func() {
				caller := context.Context(ctx)
				if phase == "nil" {
					caller = nil
				}
				input := Engine(engine)
				if phase == "missing-observer" {
					input = struct{ Engine }{engine}
				}
				service, err := NewContext(caller, input, description)
				done <- result{service, err}
			}()
			if phase == "capture-held" || phase == "recheck-held" {
				select {
				case <-entered:
					cancel()
				case result := <-done:
					t.Fatal("DNS constructor bypassed retained observation", result.err)
				case <-time.After(time.Second):
					cancel()
					<-done
					t.Fatal("DNS constructor did not enter original observation")
				}
			}
			var actual result
			select {
			case actual = <-done:
			case <-time.After(time.Second):
				cancel()
				<-done
				t.Fatal("DNS constructor did not join original cancellation")
			}
			if engine.legacy.Load() != 0 || original.active || original.selected.Load() != 0 || len(original.dials) != 0 {
				t.Fatal("DNS construction used legacy identity or started DNS work")
			}
			if phase == "current" {
				if actual.err != nil || actual.service == nil || engine.reads.Load() != 2 {
					t.Fatal("DNS constructor omitted exact capture or final recheck", actual.err)
				}
				s := actual.service
				if s.description != description || s.identity != original.Identity() || s.state.Stage != "idle" || s.state.Request != "" || s.done != nil || len(s.state.Results) != 0 {
					t.Fatal("DNS constructor changed selected resolver or invented a measurement")
				}
				cancel()
				engine.observe = func(ctx context.Context) (string, error) { return original.Identity(), ctx.Err() }
				original.selectFn = func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
				original.dial = func(ctx context.Context, _ string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }
				if err := s.Start(firstRequest, "tcp"); err != nil {
					t.Fatal("constructor cancellation retired independently owned DNS request", err)
				}
				s.Cancel(firstRequest)
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
				if original.ctx.Err() != nil || original.active || original.releases != 1 {
					t.Fatal("DNS cleanup escaped original measurement owner")
				}
			} else {
				if actual.service != nil {
					_ = actual.service.Close()
				}
				if actual.err == nil || actual.service != nil {
					t.Fatal("DNS constructor published cancelled, invalid or replaced owner", actual.err)
				}
				if phase == "cancel-before" || phase == "capture-held" || phase == "recheck-held" || phase == "late-cancel" {
					if !errors.Is(actual.err, context.Canceled) {
						t.Fatal("DNS constructor lost original cancellation", actual.err)
					}
				}
				if (phase == "nil" || phase == "cancel-before" || phase == "missing-observer") && engine.reads.Load() != 0 {
					t.Fatal("retired or unobservable DNS caller started observation")
				}
			}
		})
	}
}
