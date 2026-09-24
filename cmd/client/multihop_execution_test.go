package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"router-vpn/internal/multihoprelay"
	"router-vpn/internal/routechoice"
	"strings"
	"testing"
)

func executionFixture() (map[string]any, desktopExecutionDescriptor) {
	cfg := map[string]any{"endpoints": []any{map[string]any{"type": "wireguard", "tag": "entry-wg"}}, "inbounds": []any{map[string]any{"type": "tun", "auto_route": true, "strict_route": true}}, "outbounds": []any{map[string]any{"type": "shadowsocks", "tag": "proxy", "password": "private-exit"}, map[string]any{"type": "socks", "tag": "entry-private"}}, "dns": map[string]any{"servers": []any{map[string]any{"type": "https", "server": "1.1.1.1", "detour": "proxy"}}}, "route": map[string]any{"final": "proxy", "rules": []any{map[string]any{"inbound": []any{"multihop-entry-proof"}, "outbound": "entry-private"}, map[string]any{"inbound": []any{"multihop-proof"}, "outbound": "proxy"}}}}
	d := desktopExecutionDescriptor{Execution: "server", Lease: multihoprelay.Lease{Host: "10.77.0.1", Port: 26241, Username: strings.Repeat("a", 48), Password: strings.Repeat("b", 48)}}
	return cfg, d
}
func TestNativeServerGraphOwnsEntryControlAndPreservesDNS(t *testing.T) {
	cfg, d := executionFixture()
	before, _ := json.Marshal(cfg["dns"])
	path := filepath.Join(t.TempDir(), "sing-box.json")
	raw, _ := json.Marshal(cfg)
	os.WriteFile(path, raw, 0600)
	if err := patchDesktopExecutionConfig(path, d); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(path)
	json.Unmarshal(raw, &cfg)
	after, _ := json.Marshal(cfg["dns"])
	if string(before) != string(after) {
		t.Fatal("DNS settings changed")
	}
	proxy := cfg["outbounds"].([]any)[0].(map[string]any)
	if proxy["type"] != "socks" || proxy["detour"] != "entry-wg" || proxy["server"] != d.Lease.Host || proxy["password"] != d.Lease.Password {
		t.Fatal("server transport not owned")
	}
	route := cfg["route"].(map[string]any)
	rules := route["rules"].([]any)
	if rules[0].(map[string]any)["outbound"] != "entry-wg" || rules[1].(map[string]any)["outbound"] != "proxy" {
		t.Fatal("control/exit identity mixed")
	}
}
func TestNativeServerGraphRejectsUnsafeDescriptorWithoutWrite(t *testing.T) {
	for _, host := range []string{"0.0.0.0", "127.0.0.1", "8.8.8.8", "fe80::1%eth0", "router.invalid"} {
		cfg, d := executionFixture()
		d.Lease.Host = host
		path := filepath.Join(t.TempDir(), "sing-box.json")
		raw, _ := json.Marshal(cfg)
		os.WriteFile(path, raw, 0600)
		if err := patchDesktopExecutionConfig(path, d); err == nil {
			t.Fatal("unsafe listener", host)
		}
		got, _ := os.ReadFile(path)
		if string(got) != string(raw) {
			t.Fatal("failed validation modified source")
		}
	}
}
func TestRelayControlExactJSON(t *testing.T) {
	for _, bad := range []string{`{"node_id":"a","node_id":"b"}`, `{"node_id":"a"}{}`, `{"node_id":"a","unknown":true}`, `[]`, `null`, strings.Repeat("x", 8193)} {
		var value struct {
			NodeID string `json:"node_id"`
		}
		if decodeRelayControlJSON([]byte(bad), &value) == nil {
			t.Fatal("ambiguous control data accepted")
		}
	}
}
func TestComparisonProgressReturnsDetachedNonSecretState(t *testing.T) {
	a := &app{}
	defer desktopComparisons.Delete(a)
	owner := &comparisonOwner{value: routeComparisonProgress{ID: "round", Stage: "probing", Measurements: []routechoice.Measurement{}}}
	desktopComparisons.Store(a, owner)
	result := comparisonProgress(a)
	result.Stage = "changed"
	if comparisonProgress(a).Stage != "probing" {
		t.Fatal("mutable progress shared")
	}
}
