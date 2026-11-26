package main

import (
	"fmt"
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

func TestProtectedDMZUsesOnlyOtherwiseUnusedUnreservedRanges(t *testing.T) {
	s := &adminForwardingExtensionServer{cfg: cfg{
		NftTable:      "router_vpn",
		WANInterface:  "eth0",
		ReservedPorts: []int{22, 53, 8786},
	}}
	admin := defaultAdminState()
	admin.ForwardRules = []adminForwardRule{
		{ID: "minecraft", Protocol: "tcp", From: 25565, To: 25567, TargetIP: "10.77.0.9", Enabled: true},
		{ID: "disabled", Protocol: "udp", From: 30000, To: 30002, TargetIP: "10.77.0.10", Enabled: false},
	}
	ranges := protectedDMZAllowedRanges(s.cfg.ReservedPorts, admin.ForwardRules)
	for _, blocked := range []int{22, 53, 8786, 25565, 25566, 25567} {
		if rangesContainPort(ranges, blocked) {
			t.Fatalf("Protected DMZ ranges unexpectedly include blocked/explicit port %d: %v", blocked, ranges)
		}
	}
	for _, allowed := range []int{21, 23, 25564, 25568, 30000, 65535} {
		if !rangesContainPort(ranges, allowed) {
			t.Fatalf("Protected DMZ ranges unexpectedly exclude unused port %d: %v", allowed, ranges)
		}
	}

	script := s.protectedDMZScript(adminProtectedDMZ{TargetIP: "10.77.0.25", Protocol: "both", Enabled: true}, admin)
	if script == "" || !strings.Contains(script, adminProtectedDMZComment) {
		t.Fatal("Protected DMZ must emit tagged nft rules")
	}
	wantRules := len(ranges) * 2
	if got := strings.Count(script, "add rule inet router_vpn prerouting"); got != wantRules {
		t.Fatalf("Protected DMZ rule count = %d, want %d", got, wantRules)
	}
}

func rangesContainPort(ranges []string, wanted int) bool {
	for _, raw := range ranges {
		var from, to int
		if strings.Contains(raw, "-") {
			if _, err := fmt.Sscanf(raw, "%d-%d", &from, &to); err != nil {
				continue
			}
		} else {
			if _, err := fmt.Sscanf(raw, "%d", &from); err != nil {
				continue
			}
			to = from
		}
		if wanted >= from && wanted <= to {
			return true
		}
	}
	return false
}

func TestProtectedDMZIPv6Formatting(t *testing.T) {
	s := &adminForwardingExtensionServer{cfg: cfg{NftTable: "router_vpn", WANInterface: "eth0", ReservedPorts: []int{22}}}
	script := s.protectedDMZScript(adminProtectedDMZ{TargetIP: "fd77:77::25", Protocol: "tcp", Enabled: true}, defaultAdminState())
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
