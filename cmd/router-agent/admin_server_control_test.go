package main

import (
	"strings"
	"testing"
)

func TestServerControlServicePortsExcludeInfrastructure(t *testing.T) {
	ports := serverControlServicePorts([]int{22, 53, 80, 443, 585, 1080, 8388, 8443, 8786, 8787, 8789, 8790, 8791, 8792, 9443, 10443, 11443, 12443, 13443, 14443, 14444, 15443, 18080, 45999, 51820, 51822})
	got := map[int]bool{}
	for _, port := range ports {
		got[port] = true
	}
	for _, required := range []int{443, 585, 8388, 8443, 10443, 11443, 12443, 13443, 14443, 15443, 51820, 51822} {
		if !got[required] {
			t.Fatalf("transport port %d missing from Stop policy: %v", required, ports)
		}
	}
	for _, forbidden := range []int{22, 53, 80, 1080, 8786, 8787, 8789, 8790, 8791, 8792, 9443, 14444, 18080, 45999} {
		if got[forbidden] {
			t.Fatalf("infrastructure/private port %d must stay outside Stop policy: %v", forbidden, ports)
		}
	}
}

func TestRenderServerControlRulesIsScopedAndFailClosed(t *testing.T) {
	body := renderServerControlRules("router_vpn_server_control", "eth0", true, []int{443, 51820})
	for _, marker := range []string{
		"hook input priority -20; policy accept",
		`iifname "eth0" tcp dport 443 drop`,
		`iifname "eth0" udp dport 443 drop`,
		`iifname "eth0" tcp dport 51820 drop`,
		`iifname "eth0" udp dport 51820 drop`,
		"router-vpn server paused",
	} {
		if !strings.Contains(body, marker) {
			t.Fatalf("paused control policy missing %q:\n%s", marker, body)
		}
	}
	for _, forbidden := range []string{"dport 8786", "dport 8792", "policy drop", "flush ruleset"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("paused control policy contains unsafe/control-plane marker %q:\n%s", forbidden, body)
		}
	}

	running := renderServerControlRules("router_vpn_server_control", "eth0", false, []int{443, 51820})
	if strings.Contains(running, " dport ") || strings.Contains(running, " drop ") {
		t.Fatalf("resume policy must contain no transport drops:\n%s", running)
	}
}
