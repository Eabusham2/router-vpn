package main

import (
	"strings"
	"testing"

	"router-vpn/internal/common"
)

// Install a controlled tracker rather than starting the background observation
// loop: these tests model partial/contradictory state at the API boundary.
func telemetryProofFixture(t *testing.T) (*app, *sessionTracker, common.RouterProfile) {
	t.Helper()
	p := common.RouterProfile{ID: "active", NodeKind: "router-vpn", RouterAPI: "http://10.77.0.1:8787", APIToken: "fixture-token", NodeProofID: strings.Repeat("a", 64), DNSMode: "home", BaseTunnel: "wg"}
	a := &app{
		state:    state{Connected: true, Phase: "connected", Mode: "wg", RuntimeMode: "wg", Base: "wg", RouterID: p.ID},
		profiles: common.RouterProfileStore{SelectedID: "other", Profiles: []common.RouterProfile{p, {ID: "other", RouterAPI: "http://10.78.0.1:8787"}}},
	}
	tracker := &sessionTracker{a: a, session: &connectionSession{ID: "session-fixture", Connected: true, Phase: "connected", PathProof: "passed", RouterID: p.ID}}
	sessionTrackers.Store(a, tracker)
	t.Cleanup(func() { sessionTrackers.Delete(a) })
	return a, tracker, p
}

func TestTelemetryTargetRequiresCompleteStableIdentity(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*app, *sessionTracker)
	}{
		{"missing-tracker-node", func(a *app, s *sessionTracker) { s.session.RouterID = "" }},
		{"wrong-tracker-node", func(a *app, s *sessionTracker) { s.session.RouterID = "other" }},
		{"missing-runtime-node", func(a *app, s *sessionTracker) { a.state.RouterID = "" }},
		{"transition-with-stale-connected-bit", func(a *app, s *sessionTracker) { a.state.Phase = "reconnecting" }},
		{"unknown-runtime-phase", func(a *app, s *sessionTracker) { a.state.Phase = "" }},
		{"unproved-path", func(a *app, s *sessionTracker) { s.session.PathProof = "not-run" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, tracker, _ := telemetryProofFixture(t)
			tc.change(a, tracker)
			if _, _, err := activeLatencyTarget(a); err == nil {
				t.Fatal("incomplete or transitioning session was accepted as a live telemetry target")
			}
		})
	}
}

func TestTelemetryProofKeepsRuntimeIdentityInsteadOfUISelection(t *testing.T) {
	a, tracker, p := telemetryProofFixture(t)
	got, st, err := activeLatencyTarget(a)
	if err != nil || got.ID != p.ID || got.ID == a.profiles.SelectedID {
		t.Fatalf("target substituted mutable UI selection: %+v, %v", got, err)
	}
	if err := validateActiveTelemetryPath(a, p, st, tracker.session.ID); err != nil {
		t.Fatalf("unchanged proved runtime path was rejected: %v", err)
	}
}

func TestTelemetryResultRejectsClearedSessionIdentity(t *testing.T) {
	a, tracker, p := telemetryProofFixture(t)
	st, sessionID := a.state, tracker.session.ID
	tracker.session.RouterID = ""
	if err := validateActiveTelemetryPath(a, p, st, sessionID); err == nil {
		t.Fatal("measurement accepted after tracker lost its actual node identity")
	}
}

func TestTelemetryResultRejectsChangedNodePolicy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*common.RouterProfile)
	}{
		{"api-origin", func(p *common.RouterProfile) { p.RouterAPI = "http://10.78.0.1:8787" }},
		{"node-proof", func(p *common.RouterProfile) { p.NodeProofID = strings.Repeat("b", 64) }},
		{"credential", func(p *common.RouterProfile) { p.APIToken = "replacement-fixture" }},
		{"dns-policy", func(p *common.RouterProfile) { p.DNSMode = "custom" }},
		{"base-policy", func(p *common.RouterProfile) { p.BaseTunnel = "awg" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, tracker, p := telemetryProofFixture(t)
			st, sessionID := a.state, tracker.session.ID
			tc.change(&a.profiles.Profiles[0])
			if err := validateActiveTelemetryPath(a, p, st, sessionID); err == nil {
				t.Fatal("measurement accepted after saved node identity/policy changed")
			}
		})
	}
}

func TestTelemetryResultAllowsUnrelatedMeasurementMetadata(t *testing.T) {
	a, tracker, p := telemetryProofFixture(t)
	st, sessionID := a.state, tracker.session.ID
	a.profiles.Profiles[0].PublicIP = "198.51.100.2"
	if err := validateActiveTelemetryPath(a, p, st, sessionID); err != nil {
		t.Fatalf("unrelated cached exit measurement invalidated unchanged node policy: %v", err)
	}
}
