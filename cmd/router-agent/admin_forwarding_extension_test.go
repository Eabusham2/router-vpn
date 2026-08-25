package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
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


func writeForwardingAdminState(t *testing.T, path string, state adminPersistentState) {
	t.Helper()
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func forwardingExtensionRequest(method, target, token, body string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:54321"
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

func TestForwardingOwnerPersistenceFailureRestoresRAM(t *testing.T) {
	dir := t.TempDir()
	adminPath := filepath.Join(dir, "admin-state.json")
	admin := defaultAdminState()
	admin.ForwardRules = []adminForwardRule{{ID: "rule1", Protocol: "tcp", From: 443, To: 443, TargetIP: "10.77.0.9", Enabled: true}}
	writeForwardingAdminState(t, adminPath, admin)

	realState := filepath.Join(dir, "real-extension.json")
	statePath := filepath.Join(dir, "forwarding-extension.json")
	if err := os.WriteFile(realState, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realState, statePath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	s := &adminForwardingExtensionServer{
		token: "test-token", adminStatePath: adminPath, statePath: statePath,
		state: adminForwardingExtensionState{Version: 1, Owners: map[string]string{"rule1": "old-owner"}},
	}
	w := httptest.NewRecorder()
	s.owner(w, forwardingExtensionRequest(http.MethodPut, "/api/admin/forwarding-extension/owners/rule1", s.token, `{"owner":"new-owner"}`))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if got := s.state.Owners["rule1"]; got != "old-owner" {
		t.Fatalf("failed owner persistence changed RAM: %q", got)
	}
}

func TestStaleOwnerCleanupPersistenceFailureRestoresRAMAndReportsWarning(t *testing.T) {
	dir := t.TempDir()
	adminPath := filepath.Join(dir, "admin-state.json")
	writeForwardingAdminState(t, adminPath, defaultAdminState())
	realState := filepath.Join(dir, "real-extension.json")
	statePath := filepath.Join(dir, "forwarding-extension.json")
	if err := os.WriteFile(realState, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realState, statePath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	s := &adminForwardingExtensionServer{
		token: "test-token", adminStatePath: adminPath, statePath: statePath,
		state: adminForwardingExtensionState{Version: 1, Owners: map[string]string{"stale": "peer"}},
	}
	w := httptest.NewRecorder()
	s.status(w, forwardingExtensionRequest(http.MethodGet, "/api/admin/forwarding-extension", s.token, ""))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if got := s.state.Owners["stale"]; got != "peer" {
		t.Fatalf("failed cleanup persistence changed RAM: %q", got)
	}
	if !strings.Contains(w.Body.String(), "stale-owner cleanup was not committed") {
		t.Fatalf("missing persistence warning: %s", w.Body.String())
	}
}

func TestProtectedDMZPersistenceFailureRestoresRAM(t *testing.T) {
	dir := t.TempDir()
	realState := filepath.Join(dir, "real-extension.json")
	statePath := filepath.Join(dir, "forwarding-extension.json")
	if err := os.WriteFile(realState, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realState, statePath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	_, tunnel, _ := net.ParseCIDR("10.77.0.0/24")
	old := &adminProtectedDMZ{Owner: "old", TargetIP: "10.77.0.8", Protocol: "tcp", Enabled: true, CreatedAt: 1, UpdatedAt: 1}
	s := &adminForwardingExtensionServer{
		token: "test-token", statePath: statePath, tunnelNets: []*net.IPNet{tunnel},
		state: adminForwardingExtensionState{Version: 1, Owners: map[string]string{}, DMZ: old},
	}
	w := httptest.NewRecorder()
	s.dmz(w, forwardingExtensionRequest(http.MethodPost, "/api/admin/forwarding-extension/dmz", s.token, `{"owner":"new","target_ip":"10.77.0.9","protocol":"tcp","enabled":true}`))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if s.state.DMZ == nil || s.state.DMZ.Owner != "old" || s.state.DMZ.TargetIP != "10.77.0.8" {
		t.Fatalf("failed DMZ persistence changed RAM: %+v", s.state.DMZ)
	}
}

func TestProtectedDMZLiveApplyFailureRestoresDurableAndRAMState(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake nft command uses a POSIX shell")
	}
	dir := t.TempDir()
	fakeBin := filepath.Join(dir, "bin")
	if err := os.Mkdir(fakeBin, 0o700); err != nil {
		t.Fatal(err)
	}
	counter := filepath.Join(dir, "nft-f-count")
	fakeNFT := filepath.Join(fakeBin, "nft")
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = \"-a\" ]; then exit 0; fi\n" +
		"if [ \"$1\" = \"-f\" ]; then n=0; [ -f '" + counter + "' ] && n=$(cat '" + counter + "'); n=$((n+1)); echo $n > '" + counter + "'; [ $n -eq 1 ] && exit 1; fi\n" +
		"exit 0\n"
	if err := os.WriteFile(fakeNFT, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	adminPath := filepath.Join(dir, "admin-state.json")
	admin := defaultAdminState()
	admin.ForwardingMaster = true
	writeForwardingAdminState(t, adminPath, admin)
	statePath := filepath.Join(dir, "forwarding-extension.json")
	initial := adminForwardingExtensionState{Version: 1, Owners: map[string]string{}}
	initialBody, _ := json.MarshalIndent(initial, "", "  ")
	if err := atomicWritePrivilegedState(statePath, append(initialBody, '\n')); err != nil {
		t.Fatal(err)
	}
	_, tunnel, _ := net.ParseCIDR("10.77.0.0/24")
	s := &adminForwardingExtensionServer{
		token: "test-token", statePath: statePath, adminStatePath: adminPath,
		cfg: cfg{NftTable: "router_vpn", WANInterface: "eth0"}, tunnelNets: []*net.IPNet{tunnel}, state: initial,
	}
	w := httptest.NewRecorder()
	s.dmz(w, forwardingExtensionRequest(http.MethodPost, "/api/admin/forwarding-extension/dmz", s.token, `{"owner":"peer","target_ip":"10.77.0.9","protocol":"tcp","enabled":true}`))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "prior durable/live state was restored") {
		t.Fatalf("rollback truth missing: %s", w.Body.String())
	}
	if s.state.DMZ != nil {
		t.Fatalf("RAM kept failed DMZ: %+v", s.state.DMZ)
	}
	body, err := readPrivilegedState(statePath, 256<<10)
	if err != nil {
		t.Fatal(err)
	}
	var disk adminForwardingExtensionState
	if err := json.Unmarshal(body, &disk); err != nil {
		t.Fatal(err)
	}
	if disk.DMZ != nil {
		t.Fatalf("disk kept failed DMZ: %+v", disk.DMZ)
	}
}
