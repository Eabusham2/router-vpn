package main

import (
	"strings"
	"testing"
)

func TestServerControlServicePortsExcludeOnlyInfrastructure(t *testing.T) {
	ports := serverControlServicePorts([]int{22, 53, 80, 443, 585, 1080, 2053, 3000, 8388, 8443, 8786, 8787, 8789, 8790, 8791, 8792, 8793, 9443, 10443, 11443, 12443, 13443, 14443, 14444, 15443, 18080, 45999, 51820, 51822})
	got := map[int]bool{}
	for _, port := range ports {
		got[port] = true
	}
	for _, required := range []int{443, 585, 1080, 2053, 8388, 8443, 10443, 11443, 12443, 13443, 14443, 14444, 15443, 45999, 51820, 51822} {
		if !got[required] {
			t.Fatalf("transport/service port %d missing from Stop policy: %v", required, ports)
		}
	}
	for _, forbidden := range []int{22, 53, 80, 3000, 8786, 8787, 8789, 8790, 8791, 8792, 8793, 9443, 18080} {
		if got[forbidden] {
			t.Fatalf("infrastructure/control port %d must stay outside Stop policy: %v", forbidden, ports)
		}
	}
}

func TestRenderServerControlRulesIsScopedAndFailClosed(t *testing.T) {
	body := renderServerControlRules("router_vpn_server_control", "eth0", true, []int{1080, 443, 14444, 45999, 51820})
	for _, marker := range []string{
		"hook input priority -20; policy accept",
		`iifname "eth0" tcp dport 1080 drop`,
		`iifname "eth0" tcp dport 443 drop`,
		`iifname "eth0" udp dport 443 drop`,
		`iifname "eth0" tcp dport 14444 drop`,
		`iifname "eth0" udp dport 45999 drop`,
		`iifname "eth0" tcp dport 51820 drop`,
		`iifname "eth0" udp dport 51820 drop`,
		"router-vpn server paused",
	} {
		if !strings.Contains(body, marker) {
			t.Fatalf("paused control policy missing %q:\n%s", marker, body)
		}
	}
	for _, forbidden := range []string{"dport 8786", "dport 8792", "dport 8793", "policy drop", "flush ruleset"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("paused control policy contains unsafe/control-plane marker %q:\n%s", forbidden, body)
		}
	}

	running := renderServerControlRules("router_vpn_server_control", "eth0", false, []int{443, 51820})
	if strings.Contains(running, " dport ") || strings.Contains(running, " drop ") {
		t.Fatalf("resume policy must contain no transport drops:\n%s", running)
	}
}

func TestValidateEmergencyPeerTeardownRequiresBothFamiliesAndZeroPeers(t *testing.T) {
	if err := validateEmergencyPeerTeardown([]string{"wg", "awg"}, nil, 0); err != nil {
		t.Fatalf("complete teardown rejected: %v", err)
	}
	cases := []struct {
		name string
		sources []string
		errs []string
		remaining int
	}{
		{name: "missing awg coverage", sources: []string{"wg"}},
		{name: "enumeration error", sources: []string{"wg", "awg"}, errs: []string{"awg: failed"}},
		{name: "peer remains", sources: []string{"wg", "awg"}, remaining: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateEmergencyPeerTeardown(tc.sources, tc.errs, tc.remaining); err == nil {
				t.Fatal("incomplete Emergency Stop verification was accepted")
			}
		})
	}
}
