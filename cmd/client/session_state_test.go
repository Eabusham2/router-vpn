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

func TestSessionCaptureUsesLiveProfileWhileActiveAndSelectedProfileWhenIdle(t *testing.T) {
	a := &app{
		profiles: common.RouterProfileStore{
			SelectedID: "control",
			Profiles: []common.RouterProfile{
				{ID: "control", Name: "Control", BaseTunnel: "awg", DNSMode: "doh", DNSHost: "1.1.1.1", PublicIP: "198.51.100.10"},
				{ID: "exit", Name: "Exit", BaseTunnel: "wg", DNSMode: "dot", DNSHost: "9.9.9.9", PublicIP: "203.0.113.20"},
			},
		},
		state: state{Connected: true, Phase: "connected", RouterID: "exit", Mode: "multihop", LogicalMode: "multihop", RuntimeMode: "shadowsocks", Base: "wg"},
	}
	tracker := &sessionTracker{a: a}

	active := tracker.capture()
	if active.RouterID != "exit" || active.Profile.ID != "exit" {
		t.Fatalf("active capture did not bind profile to live RouterID: %+v", active)
	}
	if active.Profile.DNSMode != "dot" || active.Profile.DNSHost != "9.9.9.9" || active.Profile.PublicIP != "203.0.113.20" {
		t.Fatalf("active capture inherited selected/control-node policy instead of exit policy: %+v", active.Profile)
	}

	a.mu.Lock()
	a.state = state{Connected: false, Phase: "off", RouterID: "exit"}
	a.mu.Unlock()
	idle := tracker.capture()
	if idle.Profile.ID != "control" {
		t.Fatalf("idle capture did not fall back to selected profile: %+v", idle)
	}
	if idle.Profile.DNSMode != "doh" || idle.Profile.DNSHost != "1.1.1.1" || idle.Profile.PublicIP != "198.51.100.10" {
		t.Fatalf("idle capture lost selected profile policy: %+v", idle.Profile)
	}
}

func TestDNSProofObservationFreshnessRejectsSameSessionPathChanges(t *testing.T) {
	profile := common.RouterProfile{ID: "exit", Endpoint: "exit.example.test", BaseTunnel: "wg", DNSMode: "dot", DNSHost: "9.9.9.9", DNSPort: 853}
	a := &app{
		profiles: common.RouterProfileStore{SelectedID: "control", Profiles: []common.RouterProfile{{ID: "control", Endpoint: "control.example.test"}, profile}},
		state: state{Connected: true, Phase: "connected", RouterID: "exit", Mode: "multihop", LogicalMode: "multihop", RuntimeMode: "shadowsocks", Base: "wg"},
	}
	tracker := &sessionTracker{a: a}
	snapshot := observedConnection{Connected: true, Phase: "connected", RouterID: "exit", Mode: "multihop", LogicalMode: "multihop", RuntimeMode: "shadowsocks", Base: "wg", Profile: profile}

	tracker.mu.Lock()
	if !tracker.dnsProofObservationStillCurrentLocked(snapshot, "shadowsocks") {
		tracker.mu.Unlock()
		t.Fatal("unchanged live DNS proof snapshot was rejected")
	}
	tracker.mu.Unlock()

	a.mu.Lock()
	a.state.RuntimeMode = "hysteria2"
	a.mu.Unlock()
	tracker.mu.Lock()
	if tracker.dnsProofObservationStillCurrentLocked(snapshot, "shadowsocks") {
		tracker.mu.Unlock()
		t.Fatal("runtime change did not stale DNS proof snapshot")
	}
	tracker.mu.Unlock()

	a.mu.Lock()
	a.state.RuntimeMode = "shadowsocks"
	a.state.Base = "awg"
	a.mu.Unlock()
	tracker.mu.Lock()
	if tracker.dnsProofObservationStillCurrentLocked(snapshot, "shadowsocks") {
		tracker.mu.Unlock()
		t.Fatal("base change did not stale DNS proof snapshot")
	}
	tracker.mu.Unlock()

	a.mu.Lock()
	a.state.Base = "wg"
	for i := range a.profiles.Profiles {
		if a.profiles.Profiles[i].ID == "exit" {
			a.profiles.Profiles[i].DNSHost = "1.1.1.1"
			break
		}
	}
	a.mu.Unlock()
	tracker.mu.Lock()
	if tracker.dnsProofObservationStillCurrentLocked(snapshot, "shadowsocks") {
		tracker.mu.Unlock()
		t.Fatal("live profile/DNS policy change did not stale DNS proof snapshot")
	}
	tracker.mu.Unlock()
}
