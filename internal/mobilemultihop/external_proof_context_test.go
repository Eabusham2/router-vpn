package mobilemultihop

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type externalConstructorEngine struct {
	observe func(context.Context) (string, error)
	reads   atomic.Int32
	legacy  atomic.Int32
	dns     atomic.Int32
	dials   atomic.Int32
}

func (e *externalConstructorEngine) Identity() string {
	e.legacy.Add(1)
	return "original-proof-constructor"
}
func (e *externalConstructorEngine) IdentityContext(ctx context.Context) (string, error) {
	e.reads.Add(1)
	return e.observe(ctx)
}
func (e *externalConstructorEngine) DNSProof(ctx context.Context, _ string) error {
	e.dns.Add(1)
	return ctx.Err()
}
func (e *externalConstructorEngine) Dial(context.Context, string, string) (net.Conn, error) {
	e.dials.Add(1)
	return nil, errors.New("constructor fixture forbids ambient networking")
}

func externalConstructorPolicy(t *testing.T) *ExternalPolicy {
	t.Helper()
	source, capture := externalTestFixture(t, "shadowsocks", "")
	policy, err := NewExternalPolicy(externalTestJSON(t, source), externalTestJSON(t, capture))
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func TestExternalProofLegacyConstructorKeepsOriginalBudget(t *testing.T) {
	var original context.Context
	engine := &externalConstructorEngine{observe: func(ctx context.Context) (string, error) {
		if original == nil {
			original = ctx
		}
		if ctx != original {
			return "", errors.New("external proof constructor replaced original caller")
		}
		return "original-proof-constructor", ctx.Err()
	}}
	request, err := NewExternalProofRequest(context.Background(), externalConstructorPolicy(t), "original-session", engine)
	if err != nil || request == nil {
		t.Fatal("external proof constructor lost its original observation budget", err)
	}
	defer request.Close()
	if engine.reads.Load() != 2 || engine.legacy.Load() != 0 || engine.dns.Load() != 0 || engine.dials.Load() != 0 {
		t.Fatal("constructor skipped exact identity capture/recheck or started proof traffic")
	}
	if original.Err() == nil || request.ctx.Err() != nil || request.started.Load() || request.succeeded.Load() {
		t.Fatal("constructor cancellation changed returned lifetime or manufactured proof")
	}
}

func TestExternalProofConstructorRetainsCallerAndIndependentLifetime(t *testing.T) {
	for _, phase := range []string{"current", "nil-caller", "nil-parent", "cancel-before", "parent-cancel-before", "capture-held", "recheck-held", "owner-replaced", "parent-retired-late", "caller-retired-late", "missing-bounded-reader"} {
		t.Run(phase, func(t *testing.T) {
			policy := externalConstructorPolicy(t)
			parent, retire := context.WithCancel(context.Background())
			defer retire()
			caller, cancel := context.WithCancel(context.Background())
			defer cancel()
			entered := make(chan struct{})
			engine := &externalConstructorEngine{}
			engine.observe = func(ctx context.Context) (string, error) {
				if ctx != caller {
					return "", errors.New("external proof replaced original constructor caller")
				}
				count := engine.reads.Load()
				if phase == "capture-held" && count == 1 || phase == "recheck-held" && count == 2 {
					close(entered)
					<-ctx.Done()
				}
				if count == 2 {
					switch phase {
					case "owner-replaced":
						return "replacement-proof-owner", nil
					case "parent-retired-late":
						retire()
					case "caller-retired-late":
						cancel()
					}
				}
				return "original-proof-constructor", nil // Late success does not override cancellation.
			}
			if phase == "cancel-before" {
				cancel()
			}
			if phase == "parent-cancel-before" {
				retire()
			}
			type outcome struct {
				request *ExternalProofRequest
				err     error
			}
			done := make(chan outcome, 1)
			go func() {
				observation, lifetime := context.Context(caller), context.Context(parent)
				if phase == "nil-caller" {
					observation = nil
				}
				if phase == "nil-parent" {
					lifetime = nil
				}
				input := ExternalProofEngine(engine)
				if phase == "missing-bounded-reader" {
					input = struct{ ExternalProofEngine }{engine}
				}
				request, err := NewExternalProofRequestContext(observation, lifetime, policy, "original-session", input)
				done <- outcome{request, err}
			}()
			if phase == "capture-held" || phase == "recheck-held" {
				select {
				case <-entered:
					cancel()
				case result := <-done:
					t.Fatal("proof constructor bypassed held original identity", result.err)
				case <-time.After(time.Second):
					cancel()
					<-done
					t.Fatal("proof constructor did not enter retained caller")
				}
			}
			var result outcome
			select {
			case result = <-done:
			case <-time.After(time.Second):
				cancel()
				<-done
				t.Fatal("proof constructor did not join original cancellation")
			}
			if engine.legacy.Load() != 0 || engine.dns.Load() != 0 || engine.dials.Load() != 0 {
				t.Fatal("proof constructor used a detached identity or executed proof traffic")
			}
			if phase == "current" {
				if result.err != nil || result.request == nil || engine.reads.Load() != 2 {
					t.Fatal("current original graph did not create its proof request", result.err)
				}
				request := result.request
				defer request.Close()
				if request.started.Load() || request.succeeded.Load() || request.Healthy() {
					t.Fatal("constructor manufactured successful native proof")
				}
				cancel()
				if request.ctx.Err() != nil {
					t.Fatal("constructor cancellation retired independent proof lifetime")
				}
				var public atomic.Int32
				// Network proof is an explicit model; actual Run sequencing and its
				// required DNS/exit checks execute after the constructor has ended.
				request.public = func(ctx context.Context, tag, ip string) error {
					if ctx.Err() != nil || tag != ExternalFinalTag || ip != request.meta.ExpectedPublicIP {
						return errors.New("wrong captured public proof")
					}
					public.Add(1)
					return nil
				}
				if _, err := request.Run(); err != nil || !request.Healthy() || engine.dns.Load() != 1 || public.Load() != 1 {
					t.Fatal("returned proof lost its independent selected-DNS/exit operation", err)
				}
				retire()
				if request.Healthy() || request.ctx.Err() == nil {
					t.Fatal("returned proof escaped original VPN lifetime")
				}
			} else {
				if result.request != nil {
					_ = result.request.Close()
				}
				if result.err == nil || result.request != nil {
					t.Fatal("proof constructor published cancelled or replaced owner", result.err)
				}
				if phase == "cancel-before" || phase == "parent-cancel-before" || phase == "capture-held" || phase == "recheck-held" || phase == "parent-retired-late" || phase == "caller-retired-late" {
					if !errors.Is(result.err, context.Canceled) {
						t.Fatal("proof constructor lost original cancellation", result.err)
					}
				}
				if phase == "nil-caller" || phase == "nil-parent" || phase == "cancel-before" || phase == "parent-cancel-before" || phase == "missing-bounded-reader" {
					if engine.reads.Load() != 0 {
						t.Fatal("retired or unobservable caller started an identity read")
					}
				}
			}
		})
	}
}
