package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"sync/atomic"
	"testing"
)

// Exercise the real captured HTTP mutation, durable profile write, Commit and
// Close. The kernel handle is an explicit in-memory peer, not a physical TUN.
func TestRouterNodeProvedRetestSatisfiesAutoAfterOwnedCleanup(t *testing.T) {
	for _, outcome := range []string{"committed", "committed-late-hold", "without-persistence", "cancelled", "failed-save", "failed-close", "restored-after-commit", "new-process", "new-session", "new-policy", "new-measurement", "new-network"} {
		t.Run(outcome, func(t *testing.T) {
			owner, kernel := newMTUCapabilityFixture(t)
			a := owner.a
			wantCompleted := outcome == "committed" || outcome == "committed-late-hold"
			pending := &routerNodeAutomaticMTU{command: owner.command, resume: true}
			routerNodeAutomaticMTUs.Store(a, pending)
			t.Cleanup(func() { routerNodeAutomaticMTUs.Delete(a); mtuViewSlots.Delete(a) })
			ctx, operation, err := beginMTUViewOperation(a, context.WithValue(context.Background(), mtuAutomaticContextKey{}, &mtuAutomaticAttempt{}), mtuViewRequest{}, mtuViewIdentity{Session: owner.snapshot.SessionID, Profile: owner.snapshot.Profile.ID})
			if err != nil {
				t.Fatal(err)
			}
			writer := &mtuViewResponse{ResponseWriter: httptest.NewRecorder(), operation: operation}
			defer writer.finish()
			code, _, err := mtuCapabilityCall(ctx, owner, http.MethodPost, "", "Bearer "+owner.token, `{"action":"set","mtu":1380}`)
			if err != nil || code != http.StatusOK {
				t.Fatal("captured kernel operation did not confirm its reader", code, err)
			}
			measurement := testMTUMeasurement()
			measurement.Interface, measurement.OwnerToken = owner.current.Interface, owner.token
			if outcome == "failed-save" {
				a.cfg.ProfilesFile = t.TempDir()
			}
			if outcome != "without-persistence" && outcome != "cancelled" {
				_, err = persistMTUMeasurement(a, owner.snapshot, measurement)
				if (err != nil) != (outcome == "failed-save") {
					t.Fatal("unexpected persistence outcome", err)
				}
			}
			if outcome != "cancelled" && outcome != "failed-save" {
				if err := owner.Commit(); err != nil {
					t.Fatal("proved retained kernel did not commit", err)
				}
			}
			switch outcome {
			case "restored-after-commit":
				if err := owner.Restore(); err != nil {
					t.Fatal("explicit captured rollback failed", err)
				}
			case "failed-close":
				kernel.closeFailures = 1
			case "new-process":
				a.cmd = &exec.Cmd{Path: "replacement"}
			case "new-session":
				tracker := sessionTrackerFor(a)
				tracker.mu.Lock()
				tracker.session.ID = "replacement-session"
				tracker.mu.Unlock()
			case "new-policy":
				a.profiles.Profiles[0].DNSMode = "system"
			case "new-measurement":
				a.profiles.Profiles[0].EffectiveMTU = 1392
			case "new-network":
				owner.network = "replaced-physical-network"
			}
			if err := owner.Close(); (err != nil) != (outcome == "failed-close") {
				t.Fatal("unexpected captured cleanup outcome", err)
			}
			if outcome == "committed-late-hold" {
				// The exact owner has committed and closed, but its HTTP view is
				// still running until the outer response defer. A transition in
				// this real lifecycle window must not erase the proved result.
				cancelCapturedMTU(a)
				if ctx.Err() != context.Canceled {
					t.Fatal("late hold did not cancel its still-draining view")
				}
			}
			pending.mu.Lock()
			satisfied, resume, command := pending.attempted, pending.resume, pending.command
			pending.mu.Unlock()
			if satisfied != wantCompleted || command != owner.command || wantCompleted && resume {
				t.Fatalf("Auto satisfaction escaped committed current-path cleanup: outcome=%s satisfied=%t resume=%t", outcome, satisfied, resume)
			}
			if wantCompleted {
				var calls atomic.Int32
				a.startRouterNodeAutomaticMTUWithRun(func(mtuRetestSnapshot) mtuAutomaticResult {
					calls.Add(1)
					return mtuAutomaticResult{accepted: true}
				})
				pending.mu.Lock()
				waiting := pending.waiting
				pending.mu.Unlock()
				if waiting || calls.Load() != 0 {
					t.Fatal("scheduler launched Auto after the same Router-node Retest committed")
				}
			}
		})
	}
}
