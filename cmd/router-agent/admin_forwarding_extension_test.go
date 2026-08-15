package main

import (
	"net"
	"strings"
	"testing"
)

func TestForwardingExtensionOwnerValidation(t *testing.T) {
	if !validForwardingOwner("wg0 peer abc123") {
		t.Fatal("printable owner/client association should be accepted")
	}
	if validForwardingOwner("") || validForwardingOwner("bad\nowner") {
		t.Fatal("empty/control-character owner must be rejected")
	}
	if !validForwardingRuleID("rule_123-ABC") || validForwardingRuleID("../rule") {
		t.Fatal("forwarding rule id validation is unsafe")
	}
}

func TestProtectedDMZUsesOnlyUnreservedRanges(t *testing.T) {
	s := &adminForwardingExtensionServer{cfg: cfg{
		NftTable:      "router_vpn",
		WANInterface:  "eth0",
		ReservedPorts: []int{22, 53, 8786},
	}}
	script := s.protectedDMZScript(adminProtectedDMZ{TargetIP: "10.77.0.25", Protocol: "both", Enabled: true})
	if script == "" || !strings.Contains(script, adminProtectedDMZComment) {
		t.Fatal("Protected DMZ must emit tagged nft rules")
	}
	if strings.Contains(script, "dport 22 ") || strings.Contains(script, "dport 53 ") || strings.Contains(script, "dport 8786 ") {
		t.Fatal("Protected DMZ must never forward a reserved port")
	}
	wantRules := len(allowedRanges(s.cfg.ReservedPorts)) * 2
	if got := strings.Count(script, "add rule inet router_vpn prerouting"); got != wantRules {
		t.Fatalf("Protected DMZ rule count = %d, want %d", got, wantRules)
	}
}

func TestProtectedDMZIPv6Formatting(t *testing.T) {
	s := &adminForwardingExtensionServer{cfg: cfg{NftTable: "router_vpn", WANInterface: "eth0", ReservedPorts: []int{22}}}
	script := s.protectedDMZScript(adminProtectedDMZ{TargetIP: "fd77:77::25", Protocol: "tcp", Enabled: true})
	if !strings.Contains(script, "dnat to fd77:77::25") {
		t.Fatalf("unexpected IPv6 DNAT syntax: %s", script)
	}
}

func TestProtectedDMZTargetMustBeTunnelPeer(t *testing.T) {
	_, n4, _ := net.ParseCIDR("10.77.0.0/24")
	_, n6, _ := net.ParseCIDR("fd77:77::/64")
	s := &adminForwardingExtensionServer{tunnelNets: []*net.IPNet{n4, n6}}
	for _, good := range []string{"10.77.0.9", "fd77:77::9"} {
		if err := s.validateTunnelTarget(good); err != nil {
			t.Fatalf("valid tunnel target %s rejected: %v", good, err)
		}
	}
	for _, bad := range []string{"192.168.50.25", "8.8.8.8", "not-an-ip"} {
		if err := s.validateTunnelTarget(bad); err == nil {
			t.Fatalf("non-tunnel target %s accepted", bad)
		}
	}
}

func TestForwardingExtensionStateBackCompat(t *testing.T) {
	state := normalizeAdminForwardingExtensionState(adminForwardingExtensionState{})
	if state.Version != 1 || state.Owners == nil {
		t.Fatal("zero/legacy extension state should normalize without losing compatibility")
	}
}
