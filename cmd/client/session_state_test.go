package main

import (
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func TestTypedSessionObservesConnectionAndFailure(t *testing.T) {
	a := &app{modes: []common.Mode{{ID: "wg", Engine: "wireguard"}}}
	tracker := &sessionTracker{a: a}
	tracker.declareRequest("base-raw", "wg")
	p := common.RouterProfile{ID: "home", BaseTunnel: "wg", DNSMode: "home", DNSHost: "10.77.0.1"}
	tracker.observe(observedConnection{Phase: "starting", Mode: "wg", RuntimeMode: "wg", RouterID: "home", Profile: p})
	tracker.observe(observedConnection{Phase: "checking", Mode: "wg", RuntimeMode: "wg", RouterID: "home", Profile: p})
	tracker.observe(observedConnection{Phase: "connected", Connected: true, Mode: "wg", RuntimeMode: "wg", Base: "wg", LogicalMode: "base-raw", RouterID: "home", Profile: p})
	s := tracker.snapshot(0)
	if s.ID == "" || s.RequestedMode != "base-raw" || s.ActualMode != "wg" || s.Engine != "wireguard" {
		t.Fatalf("bad typed session: %+v", s)
	}
	if !s.Connected || s.PathProof != "passed" || s.Phase != "connected" {
		t.Fatalf("connection proof state not recorded: %+v", s)
	}
	// The async DNS verifier may already be checking, but it must never inherit
	// "passed" merely because the tunnel/path proof connected successfully.
	if s.DNSProof.Status == "passed" {
		t.Fatalf("DNS must not be fabricated as proven: %+v", s.DNSProof)
	}
	if s.DNSProof.Status != "not-proven" && s.DNSProof.Status != "checking" {
		t.Fatalf("unexpected pre-proof DNS state: %+v", s.DNSProof)
	}
	if len(s.Events) < 3 {
		t.Fatalf("expected progress events, got %d", len(s.Events))
	}
}

func TestTypedSessionPathFailureMarksRollback(t *testing.T) {
	a := &app{}
	tracker := &sessionTracker{a: a}
	tracker.declareRequest("wg", "wg")
	p := common.RouterProfile{ID: "home", BaseTunnel: "wg"}
	tracker.observe(observedConnection{Phase: "checking", Mode: "wg", RuntimeMode: "wg", RouterID: "home", Profile: p})
	msg := "WireGuard started but selected-router path proof failed: connection refused"
	tracker.observe(observedConnection{Phase: "failed", Mode: "off", RouterID: "home", LastError: msg, Profile: p})
	s := tracker.snapshot(0)
	if s.Error == nil || s.Error.Code != "path_proof_failed" || !strings.Contains(s.Error.Message, "path proof") {
		t.Fatalf("typed path error missing: %+v", s.Error)
	}
	if s.PathProof != "failed" || s.RollbackState != "completed" || s.EndedAt == nil {
		t.Fatalf("rollback/failure state missing: %+v", s)
	}
}
