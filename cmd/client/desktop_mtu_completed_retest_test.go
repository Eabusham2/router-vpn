package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// A forced Retest performs the same path comparison as Auto and proves its
// retained winner before returning. Releasing DNS/Speed Lab's MTU hold must
// not schedule another Auto operation for that already satisfied connection.
// These are actual child IPC peers; their transfer values are synthetic.
func TestDesktopMTUCompletedRetestSatisfiesAutoOnlyAfterProvedAdoption(t *testing.T) {
	for _, protocol := range []string{"external", "tor"} {
		for _, outcome := range []string{"committed", "cancelled", "failed-save"} {
			t.Run(protocol+"/"+outcome, func(t *testing.T) {
				kind := "mtu-winner"
				if outcome == "cancelled" {
					kind = "mtu-hold"
				}
				var a *app
				var launch *desktopNodeLaunch
				if protocol == "tor" {
					a, launch = desktopTorMTUControllerFixture(t, "tor-"+kind)
				} else {
					a, launch = desktopMTUControllerFixture(t, kind)
				}
				if outcome == "failed-save" {
					a.cfg.ProfilesFile = t.TempDir()
				}
				owner := desktopMeasurementMTUSession(launch)
				owner.mu.Lock()
				pending := !owner.automatic && owner.active == ""
				owner.mu.Unlock()
				if !pending {
					t.Fatal("fixture has already consumed its initial Auto operation")
				}
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				type result struct {
					record desktopMTURecord
					err    error
				}
				done := make(chan result, 1)
				go func() {
					record, err := a.runDesktopExternalMTU(ctx, launch, true)
					done <- result{record, err}
				}()
				if outcome == "cancelled" {
					desktopMTUWaitRecord(t, launch, func(record desktopMTURecord) bool { return record.Status.Running })
					cancel()
				}
				var completed result
				select {
				case completed = <-done:
				case <-time.After(10 * time.Second):
					t.Fatal("captured Retest did not complete or drain")
				}
				if outcome == "committed" {
					if completed.err != nil || !completed.record.Status.Measured || !completed.record.Status.Complete {
						t.Fatal("forced Retest did not prove and adopt its winner", completed.err)
					}
				} else if completed.err == nil || outcome == "cancelled" && !errors.Is(completed.err, context.Canceled) {
					t.Fatal("cancelled or failed Retest reported adoption", completed.err)
				}
				owner.mu.Lock()
				satisfied, active := owner.automatic, owner.active
				owner.mu.Unlock()
				if satisfied != (outcome == "committed") || active != "" {
					t.Fatalf("Auto completion escaped proved Retest adoption: outcome=%s satisfied=%t active=%q", outcome, satisfied, active)
				}
			})
		}
	}
}

// Exercise the same adoption boundary used after the child proof, then let
// the real transition cancellation find its still-active retained operation.
// No scheduler timing or pause between two goroutine instructions is assumed.
func TestDesktopMTUCompletedAutoSurvivesFinalDrainCancellation(t *testing.T) {
	for _, protocol := range []string{"external", "tor"} {
		for _, outcome := range []string{"committed", "cancelled-before", "replaced-request", "replaced-generation"} {
			t.Run(protocol+"/"+outcome, func(t *testing.T) {
				var a *app
				var launch *desktopNodeLaunch
				if protocol == "tor" {
					a, launch = desktopTorMTUControllerFixture(t, "tor-mtu-winner")
				} else {
					a, launch = desktopMTUControllerFixture(t, "mtu-winner")
				}
				owner := desktopMeasurementMTUSession(launch)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				identifier, generation := strings.Repeat("a", 32), uint64(7)
				owner.mu.Lock()
				owner.active, owner.generation, owner.cancel = identifier, generation, cancel
				owner.automatic, owner.activeAutomatic = true, true
				owner.mu.Unlock()
				t.Cleanup(func() {
					owner.mu.Lock()
					owner.active, owner.cancel, owner.activeAutomatic = "", nil, false
					owner.mu.Unlock()
				})
				switch outcome {
				case "cancelled-before":
					cancel()
				case "replaced-request":
					identifier = strings.Repeat("b", 32)
				case "replaced-generation":
					generation--
				}
				err := owner.retainCompletedMTU(ctx, identifier, generation)
				if (err == nil) != (outcome == "committed") {
					t.Fatal("completion accepted the wrong captured operation", err)
				}
				cancelCapturedMTU(a)
				owner.mu.Lock()
				satisfied, active := owner.automatic, owner.active
				owner.mu.Unlock()
				if ctx.Err() != context.Canceled || active == "" || satisfied != (outcome == "committed") {
					t.Fatalf("final drain cancellation lost its completion boundary: outcome=%s satisfied=%t active=%q", outcome, satisfied, active)
				}
			})
		}
	}
}
