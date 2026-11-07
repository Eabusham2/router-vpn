package mobilemultihop

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
)

type externalContextMeter struct {
	observe func(context.Context) (string, error)
	dial    func(context.Context) (net.Conn, error)
	begin   func(context.Context) (func(), error)
	reads   atomic.Int32
	legacy  atomic.Int32
}

func (e *externalContextMeter) Identity() string {
	e.legacy.Add(1)
	return "detached-measurement-owner"
}
func (e *externalContextMeter) IdentityContext(ctx context.Context) (string, error) {
	e.reads.Add(1)
	return e.observe(ctx)
}
func (e *externalContextMeter) Dial(ctx context.Context, _, _ string) (net.Conn, error) {
	if e.dial != nil {
		return e.dial(ctx)
	}
	return nil, errors.New("shared context fixture supplies no network traffic")
}
func (e *externalContextMeter) BeginMeasurement() (func(), error) {
	e.legacy.Add(1)
	return nil, errors.New("detached measurement activity")
}
func (e *externalContextMeter) BeginMeasurementContext(ctx context.Context) (func(), error) {
	if e.begin != nil {
		return e.begin(ctx)
	}
	return func() {}, ctx.Err()
}

// Prior DNS/public proof is explicitly modeled by externalRequestFixture. The
// actual source compiler, captured proof and measurement lifecycle execute.
func externalMeasurementContextFixture(t *testing.T) (*ExternalProofRequest, *externalProofFixture, *observedExternalProof, string, string) {
	t.Helper()
	proof, native, _ := externalRequestFixture(t, "router-wg")
	if _, err := proof.Run(); err != nil {
		t.Fatal(err)
	}
	observed := &observedExternalProof{externalProofFixture: native, observe: native.IdentityContext}
	proof.engine = observed
	graph, capture := externalTestFixture(t, "shadowsocks", "router-wg")
	return proof, native, observed, externalTestJSON(t, graph), externalTestJSON(t, capture)
}

func TestExternalMeasurementLegacyConstructorKeepsOriginalBudget(t *testing.T) {
	proof, native, observed, source, capture := externalMeasurementContextFixture(t)
	var original context.Context
	check := func(ctx context.Context) (string, error) {
		if original == nil {
			original = ctx
		}
		if original != ctx {
			return "", errors.New("external constructor replaced its original observation context")
		}
		return native.Identity(), ctx.Err()
	}
	observed.observe = check
	input := &externalContextMeter{observe: check}
	service, err := proof.NewHopMeasurement(source, capture, proof.session, input)
	if err != nil || service == nil {
		t.Fatal("external constructor restarted its original observation budget", err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	if input.reads.Load() != 2 || input.legacy.Load() != 0 {
		t.Fatal("constructor omitted its original capture or final service observation")
	}
}

func TestExternalMeasurementConstructorRetainsCallerAndProof(t *testing.T) {
	for _, phase := range []string{"current", "nil", "cancel-before", "proof-health", "capture", "service", "measurement-replaced", "proof-replaced"} {
		t.Run(phase, func(t *testing.T) {
			proof, native, observed, source, capture := externalMeasurementContextFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			entered := make(chan struct{})
			var proofReads atomic.Int32
			observed.observe = func(caller context.Context) (string, error) {
				count := proofReads.Add(1)
				if caller != ctx {
					return "", errors.New("proof replaced the constructor caller")
				}
				if phase == "proof-health" && count == 1 {
					close(entered)
					<-caller.Done()
				}
				return native.Identity(), nil
			}
			originalID := native.Identity()
			input := &externalContextMeter{}
			input.observe = func(caller context.Context) (string, error) {
				if caller != ctx {
					return "", errors.New("measurement replaced the constructor caller")
				}
				count := input.reads.Load()
				if phase == "capture" && count == 1 || phase == "service" && count == 2 {
					close(entered)
					<-caller.Done()
				}
				if count == 2 {
					if phase == "measurement-replaced" {
						return "replacement-measurement-owner", nil
					}
					if phase == "proof-replaced" {
						native.current.Store(false)
					}
				}
				return originalID, nil // A late success cannot defeat cancellation.
			}
			if phase == "cancel-before" {
				cancel()
			}
			type outcome struct {
				service *hopmeasure.Service
				err     error
			}
			done := make(chan outcome, 1)
			go func() {
				caller := context.Context(ctx)
				if phase == "nil" {
					caller = nil
				}
				service, err := proof.NewHopMeasurementContext(caller, source, capture, proof.session, input)
				done <- outcome{service, err}
			}()
			if phase == "proof-health" || phase == "capture" || phase == "service" {
				select {
				case <-entered:
					cancel()
				case result := <-done:
					t.Fatal("constructor bypassed its original observation", result.err)
				case <-time.After(time.Second):
					cancel()
					<-done
					t.Fatal("constructor did not enter its retained caller")
				}
			}
			var result outcome
			select {
			case result = <-done:
			case <-time.After(time.Second):
				cancel()
				<-done
				t.Fatal("constructor did not join its cancelled observation")
			}
			if phase == "current" {
				if result.err != nil || result.service == nil || input.reads.Load() != 2 {
					t.Fatal("original proof did not create its measurement", result.err)
				}
				cancel()
				observed.observe = native.IdentityContext
				input.observe = native.IdentityContext
				id := strings.Repeat("c", 32)
				if err := result.service.Start(id, 65536); err != nil {
					t.Fatal("completed constructor cancellation retired subsequent measurement lifetime", err)
				}
				result.service.Cancel(id)
				if err := result.service.Close(); err != nil {
					t.Fatal(err)
				}
			} else if result.err == nil || result.service != nil {
				if result.service != nil {
					_ = result.service.Close()
				}
				t.Fatal("constructor published a cancelled or replaced proof owner", result.err)
			}
			if phase == "cancel-before" || phase == "proof-health" || phase == "capture" || phase == "service" {
				if !errors.Is(result.err, context.Canceled) {
					t.Fatal("original constructor cancellation lost", result.err)
				}
			}
			if (phase == "nil" || phase == "cancel-before") && (input.reads.Load() != 0 || proofReads.Load() != 0) {
				t.Fatal("retired caller started a native observation")
			}
			if input.legacy.Load() != 0 || proof.ctx.Err() != nil || !proof.succeeded.Load() {
				t.Fatal("constructor used detached reader or revoked retained proof")
			}
		})
	}
}

func TestExternalMeasurementContextOwnsActivityAndLateConnection(t *testing.T) {
	for _, phase := range []string{"activity", "activity-cancel", "activity-replaced", "activity-error", "activity-empty", "dial-cancel", "dial-replaced", "dial-proof-replaced", "dial-error", "dial-empty", "verify-cancel"} {
		t.Run(phase, func(t *testing.T) {
			proof, native, observed, _, _ := externalMeasurementContextFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			input := &externalContextMeter{observe: native.IdentityContext}
			owned := &externalMeasurementEngine{proof: proof, engine: input, identity: native.Identity()}
			if strings.HasPrefix(phase, "activity") {
				var released atomic.Int32
				input.begin = func(caller context.Context) (func(), error) {
					if caller != ctx {
						t.Fatal("activity replaced its original caller")
					}
					release := func() { released.Add(1) }
					switch phase {
					case "activity-cancel":
						cancel()
					case "activity-replaced":
						native.current.Store(false)
					case "activity-error":
						return release, errors.New("captured activity refused")
					case "activity-empty":
						return nil, nil
					}
					return release, nil
				}
				release, err := owned.BeginMeasurementContext(ctx)
				if phase == "activity" {
					if err != nil || release == nil {
						t.Fatal("valid activity not admitted", err)
					}
					release()
				} else if err == nil || release != nil {
					t.Fatal("retired activity gained measurement ownership", err)
				}
				want := int32(1)
				if phase == "activity-empty" {
					want = 0
				}
				if released.Load() != want {
					t.Fatal("captured activity not joined exactly once", released.Load())
				}
			} else if phase == "verify-cancel" {
				observed.observe = func(caller context.Context) (string, error) { cancel(); return native.Identity(), nil }
				if err := owned.VerifyMeasurement(ctx); !errors.Is(err, context.Canceled) {
					t.Fatal("path proof lost original read cancellation", err)
				}
				if !proof.succeeded.Load() || proof.ctx.Err() != nil {
					t.Fatal("cancelled measurement revoked the healthy original connection")
				}
			} else {
				original, peer := net.Pipe()
				defer original.Close()
				defer peer.Close()
				input.dial = func(caller context.Context) (net.Conn, error) {
					if caller != ctx {
						t.Fatal("dial replaced original caller")
					}
					switch phase {
					case "dial-cancel":
						cancel()
					case "dial-replaced":
						input.observe = func(context.Context) (string, error) { return "replacement", nil }
					case "dial-proof-replaced":
						native.current.Store(false)
					case "dial-error":
						return original, errors.New("late original dial failure")
					case "dial-empty":
						return nil, nil
					}
					return original, nil
				}
				connection, err := owned.Dial(ctx, ExternalFinalTag, "1.1.1.1:443")
				if err == nil || connection != nil {
					t.Fatal("late or empty original connection was published", err)
				}
				if phase != "dial-empty" {
					_ = peer.SetReadDeadline(time.Now().Add(time.Second))
					_, err := peer.Read(make([]byte, 1))
					if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
						t.Fatal("retired original connection remained open", err)
					}
				}
			}
			if input.legacy.Load() != 0 {
				t.Fatal("measurement operation used a detached legacy callback")
			}
		})
	}
}
