package main

import (
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func TestHomeSummaryDoesNotTreatCachedProfilePublicIPAsLiveProof(t *testing.T) {
	a := &app{}
	profile := common.RouterProfile{
		ID: "home", Name: "Home Router", Location: "Austin", Endpoint: "vpn.example.test",
		PublicIP: "203.0.113.50", HomeLANAccess: true, KillSwitchPolicy: "strict",
		DNSMode: "home", DNSHost: "10.77.0.1", EffectiveMTU: 1380, EffectiveMTUSource: "auto",
		LatencyMedianMs: 12.5, LatencySamples: 50,
	}
	session := connectionSession{
		ID: "session-1", RouterID: "home", Connected: true, Phase: "connected", PathProof: "passed",
		RequestedMode: "raw", RequestedBase: "wg", ActualMode: "wg", ActualBase: "wg",
		DNSProof: dnsProofState{Mode: "home", Host: "10.77.0.1", LatencyMs: 4.25, Status: "passed"},
	}
	value := buildHomeSummary(a, profile, session, "")
	if value.ActualExitIP != "" || value.ActualExitStatus != "unproven" {
		t.Fatalf("cached profile public_ip was mislabeled as live proof: %+v", value)
	}
	if value.PublicEndpoint != "vpn.example.test" {
		t.Fatalf("public endpoint lost: %+v", value)
	}
	joined := strings.Join(value.Warnings, " | ")
	if !strings.Contains(joined, "actual public exit is not proven") {
		t.Fatalf("missing unproven-exit warning: %+v", value.Warnings)
	}
}

func TestHomeSummaryUsesOnlyProofForCurrentSession(t *testing.T) {
	a := &app{}
	profile := common.RouterProfile{ID: "home", Name: "Home Router", Endpoint: "vpn.example.test"}
	homeExitProofs.Store(a, homeExitProof{SessionID: "old-session", IP: "198.51.100.20", At: time.Now().UTC()})
	defer homeExitProofs.Delete(a)

	current := connectionSession{ID: "new-session", Connected: true, Phase: "connected", PathProof: "passed"}
	value := buildHomeSummary(a, profile, current, "")
	if value.ActualExitIP != "" || value.ActualExitStatus != "unproven" {
		t.Fatalf("old-session exit proof leaked into new session: %+v", value)
	}

	proofTime := time.Now().UTC().Truncate(time.Second)
	homeExitProofs.Store(a, homeExitProof{SessionID: "new-session", IP: "198.51.100.21", At: proofTime})
	value = buildHomeSummary(a, profile, current, "")
	if value.ActualExitIP != "198.51.100.21" || value.ActualExitStatus != "proved" {
		t.Fatalf("current-session exit proof was not surfaced: %+v", value)
	}
	if value.ActualExitTestedAt == "" {
		t.Fatal("current-session exit proof timestamp missing")
	}
}

func TestHomeSummaryReportsFallbackDNSAndSharedState(t *testing.T) {
	a := &app{}
	profile := common.RouterProfile{
		ID: "home", Name: "Home Router", Location: "Austin", Endpoint: "home.example.test",
		HomeLANAccess: false, KillSwitchPolicy: "strict", IPv6Mode: "dual", AutoConnect: true,
		EffectiveMTU: 1360, EffectiveMTUSource: "auto", LatencyMedianMs: 18.75, LatencySamples: 50,
	}
	session := connectionSession{
		ID: "session-2", Connected: true, Phase: "connected", PathProof: "passed",
		RequestedMode: "max-tls", RequestedBase: "awg", ActualMode: "max-tls-wg", ActualBase: "wg",
		DNSProof: dnsProofState{Mode: "doh", Host: "1.1.1.1", LatencyMs: 8.5, Status: "checking"},
	}
	value := buildHomeSummary(a, profile, session, "")
	if value.Fallback != "awg -> wg" {
		t.Fatalf("fallback missing: %+v", value)
	}
	if value.DNSMode != "doh" || value.DNSHost != "1.1.1.1" || value.DNSLatencyMs != 8.5 || value.DNSStatus != "checking" {
		t.Fatalf("DNS proof summary wrong: %+v", value)
	}
	if value.LANAccess || value.KillSwitch != "strict" || value.EffectiveMTU != 1360 || value.NodeLatencySamples != 50 {
		t.Fatalf("shared state summary wrong: %+v", value)
	}
}

func TestHomeSummaryUsesLiveRouterIDInsteadOfMutableSelection(t *testing.T) {
	a := &app{}
	a.profiles = common.RouterProfileStore{
		SelectedID: "selected",
		Profiles: []common.RouterProfile{
			{ID: "selected", Name: "Selected Node", Endpoint: "selected.example.test", Location: "Selected", LatencyMedianMs: 80, LatencySamples: 50, KillSwitchPolicy: "off", EffectiveMTU: 1280},
			{ID: "live", Name: "Live Exit", Endpoint: "live.example.test", Location: "Live", LatencyMedianMs: 9, LatencySamples: 50, KillSwitchPolicy: "strict", EffectiveMTU: 1420},
		},
	}
	a.state = state{Connected: true, Phase: "connected", RouterID: "live", Mode: "multihop", LogicalMode: "multihop", RuntimeMode: "shadowsocks", Base: "wg"}
	tracker := sessionTrackerFor(a)
	tracker.mu.Lock()
	tracker.session = &connectionSession{
		ID: "session-live", RouterID: "live", Connected: true, Phase: "connected", PathProof: "passed",
		RequestedMode: "multihop", RequestedBase: "wg", ActualMode: "shadowsocks", ActualBase: "wg",
		DNSProof: dnsProofState{Status: "passed"},
	}
	tracker.mu.Unlock()
	defer sessionTrackers.Delete(a)

	value, err := a.homeSummaryValue()
	if err != nil {
		t.Fatal(err)
	}
	if value.NodeID != "live" || value.NodeName != "Live Exit" || value.PublicEndpoint != "live.example.test" || value.Location != "Live" {
		t.Fatalf("Home summary used mutable selected node instead of live RouterID: %+v", value)
	}
	if value.NodeLatencyMs != 9 || value.KillSwitch != "strict" || value.EffectiveMTU != 1420 {
		t.Fatalf("Home summary mixed selected-node metadata into live session: %+v", value)
	}
}
