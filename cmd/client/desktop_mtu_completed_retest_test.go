package main

import (
	"context"
	"errors"
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
