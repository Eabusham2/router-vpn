package main

import (
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestProtectedForwardingRetainsPrivateTargetsAndReservedPorts(t *testing.T) {
	_, network, _ := net.ParseCIDR("10.77.0.0/24")
	s := &adminForwardingExtensionServer{
		cfg:        cfg{NftTable: "router_vpn", WANInterface: "eth0", ReservedPorts: []int{22, 53, 8786}},
		tunnelNets: []*net.IPNet{network},
	}
	if err := s.validateTunnelTarget("10.77.0.25"); err != nil {
		t.Fatal(err)
	}
	if err := s.validateTunnelTarget("192.168.50.25"); err == nil {
		t.Fatal("forwarding admitted a non-tunnel target")
	}
	admin := defaultAdminState()
	admin.ForwardRules = []adminForwardRule{
		{ID: "game", Protocol: "tcp", From: 25565, To: 25567, TargetIP: "10.77.0.9", Enabled: true},
	}
	ranges := protectedDMZAllowedRanges(s.cfg.ReservedPorts, admin.ForwardRules)
	for _, blocked := range []int{22, 53, 8786, 25565, 25566, 25567} {
		if rangesContainPort(ranges, blocked) {
			t.Fatalf("protected forwarding includes reserved/explicit port %d", blocked)
		}
	}
	if !rangesContainPort(ranges, 25564) || !rangesContainPort(ranges, 25568) {
		t.Fatal("unused neighboring ports were lost")
	}
	script := s.protectedDMZScript(adminProtectedDMZ{TargetIP: "10.77.0.25", Protocol: "both", Enabled: true}, admin)
	if !strings.Contains(script, adminProtectedDMZComment) ||
		strings.Count(script, "add rule inet router_vpn prerouting") != 2*len(ranges) {
		t.Fatal("forwarding did not preserve its owned dual-protocol rules")
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
