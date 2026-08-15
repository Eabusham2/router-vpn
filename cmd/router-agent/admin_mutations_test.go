package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testMutationServer(t *testing.T) *adminMutationServer {
	t.Helper()
	_, n4, _ := net.ParseCIDR("10.77.0.0/24")
	_, n6, _ := net.ParseCIDR("fd77:77::/64")
	return &adminMutationServer{
		token:      "t0123456789012345678901234567890123456789",
		cfg:        cfg{WANInterface: "eth0", ReservedPorts: []int{22, 53, 1080, 8786, 8787, 8789, 8790, 9443}, NftTable: "router_vpn", TunnelCIDRs: []string{"10.77.0.0/24", "fd77:77::/64"}},
		statePath:  filepath.Join(t.TempDir(), "admin-state.json"),
		lanCIDR4:   "192.168.50.0/24",
		lanCIDR6:   "fd00::/8",
		tunnelNets: []*net.IPNet{n4, n6},
	}
}

func TestAdminStateDefaultsPersistPrivately(t *testing.T) {
	a := testMutationServer(t)
	if err := a.loadState(); err != nil {
		t.Fatal(err)
	}
	if !a.state.ForwardingMaster || !a.state.LANAccess || a.state.Version != 1 {
		t.Fatalf("unexpected defaults: %+v", a.state)
	}
	info, err := os.Stat(a.statePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("state mode = %o", info.Mode().Perm())
	}
	var disk adminPersistentState
	if err := json.Unmarshal(mustReadFile(t, a.statePath), &disk); err != nil {
		t.Fatal(err)
	}
	if disk.Version != 1 || !disk.ForwardingMaster || !disk.LANAccess {
		t.Fatalf("unexpected disk state: %+v", disk)
	}
}

func TestValidateAdminForward(t *testing.T) {
	a := testMutationServer(t)
	good := adminForwardRule{Protocol: "both", From: 25565, To: 25565, TargetIP: "10.77.0.2", TargetPort: 0, Enabled: true}
	if err := a.validateAdminForward(&good); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []adminForwardRule{
		{Protocol: "icmp", From: 25565, To: 25565, TargetIP: "10.77.0.2"},
		{Protocol: "tcp", From: 1080, To: 1080, TargetIP: "10.77.0.2"},
		{Protocol: "tcp", From: 2000, To: 2001, TargetIP: "10.77.0.2", TargetPort: 3000},
		{Protocol: "tcp", From: 25565, To: 25565, TargetIP: "192.168.50.20"},
	} {
		if err := a.validateAdminForward(&bad); err == nil {
			t.Fatalf("expected validation error for %+v", bad)
		}
	}
}

func TestLANAccessOffBlocksHostAndForwardedLANButPreservesTunnelControlDestination(t *testing.T) {
	rules := renderLANAccessOffRules(
		"router_vpn_admin",
		[]string{"10.77.0.0/24", "fd77:77::/64"},
		"192.168.50.0/24",
		"fd00::/8",
	)
	required := []string{
		"input ip saddr 10.77.0.0/24 ip daddr 192.168.50.0/24 drop",
		"forward ip saddr 10.77.0.0/24 ip daddr 192.168.50.0/24 drop",
		"input ip6 saddr fd77:77::/64 ip6 daddr fd00::/8 drop",
		"forward ip6 saddr fd77:77::/64 ip6 daddr fd00::/8 drop",
	}
	for _, want := range required {
		if !strings.Contains(rules, want) {
			t.Fatalf("LAN-off rules missing %q:\n%s", want, rules)
		}
	}
	for _, tunnelControl := range []string{"10.77.0.1", "10.78.0.1", "fd77:77::1", "fd78:78::1"} {
		if strings.Contains(rules, "daddr "+tunnelControl) {
			t.Fatalf("LAN-off rules unexpectedly block private tunnel control destination %s:\n%s", tunnelControl, rules)
		}
	}
}

func TestValidatePeerPolicyRequiresTunnelHostRoute(t *testing.T) {
	a := testMutationServer(t)
	good := adminPeerPolicy{Interface: "wg0", PublicKey: "abc", AllowedIPs: []string{"10.77.0.2/32", "fd77:77::2/128"}}
	if err := a.validatePeerPolicy(&good); err != nil {
		t.Fatal(err)
	}
	if len(good.AllowedIPs) != 2 || good.AllowedIPs[0] != "10.77.0.2" {
		t.Fatalf("unexpected normalized peer: %+v", good)
	}
	bad := adminPeerPolicy{Interface: "wg0", PublicKey: "abc", AllowedIPs: []string{"10.77.0.0/24"}}
	if err := a.validatePeerPolicy(&bad); err == nil {
		t.Fatal("expected broad-prefix ban to be rejected")
	}
	outside := adminPeerPolicy{Interface: "wg0", PublicKey: "abc", AllowedIPs: []string{"192.168.50.20/32"}}
	if err := a.validatePeerPolicy(&outside); err == nil {
		t.Fatal("expected non-tunnel address to be rejected")
	}
}

func TestPeerPolicyIndex(t *testing.T) {
	items := []adminPeerPolicy{{PublicKey: "a"}, {PublicKey: "b"}}
	if got := peerPolicyIndex(items, "b"); got != 1 {
		t.Fatalf("got %d", got)
	}
	if got := peerPolicyIndex(items, "c"); got != -1 {
		t.Fatalf("got %d", got)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
