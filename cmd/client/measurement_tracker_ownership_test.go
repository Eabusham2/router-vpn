package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestAsyncMeasurementDoesNotRecreateOrReplaceItsSessionTracker(t *testing.T) {
	for _, change := range []string{"removed", "replaced", "wrong-owner", "unchanged"} {
		t.Run(change, func(t *testing.T) {
			a, profile, session := asyncPathFixture(t, "http://10.77.0.1:8787")
			original := sessionTrackerFor(a)
			ctx, stop, validate, err := asyncMeasurementPathContext(context.Background(), a, profile, a.state, session, asyncMeasurementProfileToken(profile))
			if err != nil {
				t.Fatal(err)
			}
			defer stop()
			copySession := original.snapshot(0)
			replacement := &sessionTracker{a: a, session: &copySession}
			switch change {
			case "removed":
				sessionTrackers.Delete(a)
			case "replaced":
				sessionTrackers.Store(a, replacement)
			case "wrong-owner":
				replacement.a = &app{}
				sessionTrackers.Store(a, replacement)
			}
			if err := validate(); (err == nil) != (change == "unchanged") {
				t.Errorf("change=%s path validation error=%v", change, err)
			}
			release, err := a.beginAsyncMeasurementAdoption(ctx)
			if release != nil {
				release()
			}
			if (err == nil) != (change == "unchanged") {
				t.Errorf("change=%s adoption error=%v", change, err)
			}
			current, registered := sessionTrackers.Load(a)
			switch change {
			case "removed":
				if registered {
					t.Error("measurement resurrected an unregistered process observer")
				}
			case "replaced", "wrong-owner":
				if !registered || current != replacement {
					t.Error("measurement replaced the new process owner")
				}
			}
			if !original.mu.TryLock() {
				t.Fatal("old tracker lock was leaked")
			}
			original.mu.Unlock()
			if !replacement.mu.TryLock() {
				t.Fatal("new tracker lock was leaked")
			}
			replacement.mu.Unlock()
			if !a.mu.TryLock() {
				t.Fatal("app lock was leaked")
			}
			a.mu.Unlock()
			if !a.operationMu.TryLock() {
				t.Fatal("operation lock was leaked")
			}
			a.operationMu.Unlock()
		})
	}
}

func TestDNSProofCannotPublishAfterProcessTrackerReplacement(t *testing.T) {
	a, original, snapshot, id := dnsPathFixture(t)
	var replacement *sessionTracker
	original.proveDNSAsyncWithProbe(id, snapshot, "shadowsocks", func(ctx context.Context, owner *app, s observedConnection, runtimeID string) dnsProofState {
		copySession := original.snapshot(0)
		copySession.DNSProof = dnsProofState{Status: "checking", Reason: "replacement owner"}
		replacement = &sessionTracker{a: a, session: &copySession, dnsProofRunning: true}
		sessionTrackers.Store(a, replacement)
		return successfulDNSProof(ctx, owner, s, runtimeID)
	})
	if original.snapshot(0).DNSProof.Status == "passed" {
		t.Error("old DNS worker published while holding another tracker's locks")
	}
	current := replacement.snapshot(0)
	if current.DNSProof.Status != "checking" || current.DNSProof.Reason != "replacement owner" || !replacement.dnsProofRunning {
		t.Errorf("old DNS worker modified replacement proof state: %+v", current.DNSProof)
	}
	if !a.state.Connected {
		t.Fatal("rejecting stale proof stopped the VPN")
	}
}

func TestAsyncMeasurementPreflightRequiresRegisteredTracker(t *testing.T) {
	for _, invalid := range []string{"missing", "wrong-owner", "nil"} {
		t.Run(invalid, func(t *testing.T) {
			a, profile, session := asyncPathFixture(t, "http://10.77.0.1:8787")
			var registered any
			switch invalid {
			case "missing":
				sessionTrackers.Delete(a)
			case "wrong-owner":
				registered = &sessionTracker{a: &app{}, session: &session}
				sessionTrackers.Store(a, registered)
			case "nil":
				registered = (*sessionTracker)(nil)
				sessionTrackers.Store(a, registered)
			}
			_, stop, _, err := asyncMeasurementPathContext(context.Background(), a, profile, a.state, session, asyncMeasurementProfileToken(profile))
			if stop != nil {
				stop()
			}
			if err == nil {
				t.Fatal("unregistered or foreign tracker started a path observer")
			}
			current, ok := sessionTrackers.Load(a)
			if invalid == "missing" && ok || invalid != "missing" && current != registered {
				t.Fatal("failed preflight constructed or replaced a session tracker")
			}
		})
	}
}

func TestAsyncMeasurementObserverStopsOnProcessOwnerChange(t *testing.T) {
	for _, remove := range []bool{true, false} {
		t.Run(fmt.Sprintf("remove=%t", remove), func(t *testing.T) {
			a, profile, session := asyncPathFixture(t, "http://10.77.0.1:8787")
			ctx, stop, _, err := asyncMeasurementPathContext(context.Background(), a, profile, a.state, session, asyncMeasurementProfileToken(profile))
			if err != nil {
				t.Fatal(err)
			}
			defer stop()
			if remove {
				sessionTrackers.Delete(a)
			} else {
				sessionTrackers.Store(a, &sessionTracker{a: a, session: &session})
			}
			select {
			case <-ctx.Done():
				if cause := context.Cause(ctx); cause == nil || !strings.Contains(cause.Error(), "owner") {
					t.Fatalf("missing process ownership cancellation cause: %v", cause)
				}
			case <-time.After(time.Second):
				t.Fatal("network observer survived replacement of its process owner")
			}
			stop()
			if !a.state.Connected {
				t.Fatal("measurement observer stopped the VPN")
			}
		})
	}
}
