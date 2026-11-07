package mobilemultihop

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestExternalDNSAuthorityLegacyKeepsOriginalBudget(t *testing.T) {
	proof, native, observed, source, capture := externalMeasurementContextFixture(t)
	var original context.Context
	var reads atomic.Int32
	observed.observe = func(ctx context.Context) (string, error) {
		reads.Add(1)
		if original == nil {
			original = ctx
		}
		if ctx != original {
			return "", errors.New("DNS authority replaced original constructor caller")
		}
		return native.Identity(), ctx.Err()
	}
	config, metadata, err := proof.DNSMeasurementAuthority(source, capture, proof.session)
	if err != nil || config != proof.policy.Config() || metadata != proof.policy.Metadata() || reads.Load() != 3 {
		t.Fatal("DNS authority skipped original captured path or final proof check", err)
	}
	if original.Err() == nil || proof.ctx.Err() != nil || !proof.succeeded.Load() {
		t.Fatal("DNS authority borrowed the successful proof lifetime")
	}
}

func TestExternalDNSAuthorityContextKeepsOriginalProof(t *testing.T) {
	for _, phase := range []string{"current", "nil", "cancel-before", "health-held", "path-held", "final-held", "path-replaced", "final-replaced", "unproved", "source", "session"} {
		t.Run(phase, func(t *testing.T) {
			proof, native, observed, source, capture := externalMeasurementContextFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			entered := make(chan struct{})
			var reads atomic.Int32
			observed.observe = func(caller context.Context) (string, error) {
				if caller != ctx {
					return "", errors.New("DNS authority detached original caller")
				}
				count := reads.Add(1)
				if phase == "health-held" && count == 1 || phase == "path-held" && count == 2 || phase == "final-held" && count == 3 {
					close(entered)
					<-caller.Done()
				}
				if phase == "path-replaced" && count == 2 || phase == "final-replaced" && count == 3 {
					return "replacement-DNS-proof", nil
				}
				return native.Identity(), nil
			}
			if phase == "cancel-before" {
				cancel()
			}
			if phase == "unproved" {
				proof.succeeded.Store(false)
			}
			type result struct {
				config, metadata string
				err              error
			}
			done := make(chan result, 1)
			go func() {
				caller := context.Context(ctx)
				if phase == "nil" {
					caller = nil
				}
				session := proof.session
				if phase == "session" {
					session = "replacement-session"
				}
				if phase == "source" {
					source += " "
				}
				config, metadata, err := proof.DNSMeasurementAuthorityContext(caller, source, capture, session)
				done <- result{config, metadata, err}
			}()
			if phase == "health-held" || phase == "path-held" || phase == "final-held" {
				select {
				case <-entered:
					cancel()
				case actual := <-done:
					t.Fatal("DNS authority bypassed original held proof", actual.err)
				case <-time.After(time.Second):
					cancel()
					<-done
					t.Fatal("DNS authority did not enter retained proof observation")
				}
			}
			var actual result
			select {
			case actual = <-done:
			case <-time.After(time.Second):
				cancel()
				<-done
				t.Fatal("DNS authority did not join original cancellation")
			}
			if phase == "current" {
				if actual.err != nil || actual.config != proof.policy.Config() || actual.metadata != proof.policy.Metadata() || reads.Load() != 3 {
					t.Fatal("DNS authority changed exact source/metadata or omitted a current path check", actual.err)
				}
				cancel()
				observed.observe = native.IdentityContext
				if err := proof.HealthyContext(context.Background()); err != nil {
					t.Fatal("constructor cancellation damaged original proof", err)
				}
			} else if actual.err == nil || actual.config != "" || actual.metadata != "" {
				t.Fatal("DNS authority published an unproved or replaced capture", actual.err)
			}
			if phase == "cancel-before" || phase == "health-held" || phase == "path-held" || phase == "final-held" {
				if !errors.Is(actual.err, context.Canceled) || proof.ctx.Err() != nil || !proof.succeeded.Load() {
					t.Fatal("DNS cancellation revoked retained original proof", actual.err)
				}
			}
			if (phase == "nil" || phase == "cancel-before" || phase == "unproved" || phase == "session") && reads.Load() != 0 {
				t.Fatal("retired DNS authority started an identity read")
			}
		})
	}
}
