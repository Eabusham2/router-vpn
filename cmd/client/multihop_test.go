package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func mhProfile(id, endpoint string) common.RouterProfile {
	return common.RouterProfile{ID: id, Name: strings.ToUpper(id), Endpoint: endpoint, SocksHost: "192.168.50.133", SocksPort: 1080}
}

func TestResolveMultihopSelectionDefaultsAndRejectsUnsafeSelections(t *testing.T) {
	control := mhProfile("control", "198.51.100.10")
	control.MultihopEnabled = true
	control.MultihopEntryID = "entry"
	control.MultihopExitID = "exit"
	control.BaseTunnel = "auto"
	entry := mhProfile("entry", "203.0.113.11")
	entry.BaseTunnel = "awg"
	exit := mhProfile("exit", "203.0.113.12")
	profiles := []common.RouterProfile{control, entry, exit}

	sel, err := resolveMultihopSelection(control, profiles, multihopConnectRequest{})
	if err != nil { t.Fatal(err) }
	if sel.Entry.ID != "entry" || sel.Exit.ID != "exit" || sel.Base != "awg" || sel.ExitMode != "shadowsocks" {
		t.Fatalf("unexpected defaults: %+v", sel)
	}
	if _, err := resolveMultihopSelection(control, profiles, multihopConnectRequest{EntryID:"entry", ExitID:"entry"}); err == nil {
		t.Fatal("same-node multihop was accepted")
	}
	if _, err := resolveMultihopSelection(control, profiles, multihopConnectRequest{ExitMode:"reality-vision"}); err == nil {
		t.Fatal("unsupported exit transport was accepted")
	}
	badEntry := entry; badEntry.SocksHost = ""
	if _, err := resolveMultihopSelection(control, []common.RouterProfile{control,badEntry,exit}, multihopConnectRequest{}); err == nil {
		t.Fatal("entry without private SOCKS was accepted")
	}
}

func TestMultihopStartLayerNeverSilentlyDropsRequestedLayer(t *testing.T) {
	control := mhProfile("control", "198.51.100.10")
	control.MultihopEntryID = "entry"
	control.MultihopExitID = "exit"
	entry := mhProfile("entry", "203.0.113.11")
	entry.BaseTunnel = "wg"
	exit := mhProfile("exit", "203.0.113.12")
	profiles := []common.RouterProfile{control, entry, exit}

	for _, mode := range []string{common.StartLayerAES256GCM, common.StartLayerAES256GCMXOR} {
		blocked := control
		blocked.StartLayer = mode
		if _, err := resolveMultihopSelection(blocked, profiles, multihopConnectRequest{}); err == nil || !strings.Contains(err.Error(), "no proved entry-side Start Layer composition path") {
			t.Fatalf("Linux/shared multihop silently accepted Start Layer %q: %v", mode, err)
		}
		if _, err := resolveNativeMultihopSelection(blocked, profiles, multihopConnectRequest{}); err == nil || !strings.Contains(err.Error(), "no proved entry-side Start Layer composition path") {
			t.Fatalf("native multihop silently accepted Start Layer %q: %v", mode, err)
		}
	}

	invalid := control
	invalid.StartLayer = "xor-only"
	if _, err := resolveMultihopSelection(invalid, profiles, multihopConnectRequest{}); err == nil || !strings.Contains(err.Error(), "invalid Start Layer preference") {
		t.Fatalf("invalid multihop Start Layer did not fail closed: %v", err)
	}
}

func TestMultihopCommandUsesConfiguredRuntimeRootNotScriptsDirectory(t *testing.T) {
	t.Setenv("HOMEVPN_ROOT", "/tmp/router-vpn-data")
	a := &app{cfg: common.ClientConfig{ScriptsDir: "/tmp/router-vpn-data/modes"}}
	sel := multihopSelection{Control: mhProfile("control","198.51.100.10"), Entry: mhProfile("entry","203.0.113.11"), Exit: mhProfile("exit","203.0.113.12"), Base:"wg", ExitMode:"shadowsocks"}
	cmd := multihopCommand(a, sel)
	if cmd.Dir != "/tmp/router-vpn-data/modes" { t.Fatalf("unexpected working directory: %s", cmd.Dir) }
	joined := strings.Join(cmd.Env, "\n")
	if !strings.Contains(joined, "HOMEVPN_ROOT=/tmp/router-vpn-data") { t.Fatalf("runtime root missing from env: %s", joined) }
	if strings.Contains(joined, "HOMEVPN_ROOT=.") { t.Fatal("multihop controller regressed to scripts-dir HOMEVPN_ROOT") }
}

func TestMultihopNodeSummariesNeverExposeSecrets(t *testing.T) {
	p := mhProfile("node","203.0.113.20")
	p.APIToken = "top-secret-token"
	p.SocksUsername = "secret-user"
	p.SocksPassword = "secret-pass"
	p.Location = "Austin"
	p.LatencyMedianMs = 12.3
	nodes := multihopNodeSummaries([]common.RouterProfile{p})
	if len(nodes) != 1 || nodes[0].ID != "node" || nodes[0].Location != "Austin" || nodes[0].LatencyMedianMs != 12.3 { t.Fatalf("bad summary: %+v", nodes) }
	formatted := strings.ToLower(strings.Join([]string{nodes[0].ID,nodes[0].Name,nodes[0].Location,nodes[0].Endpoint,nodes[0].BaseTunnel},"|"))
	for _, secret := range []string{"top-secret-token","secret-user","secret-pass"} {
		if strings.Contains(formatted, secret) { t.Fatalf("multihop status leaked %s", secret) }
	}
}

func TestNativeMultihopConfigBuildsDistinctEntryAndExitProofLanes(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "sing-box.json")
	cfg := map[string]any{
		"inbounds": []any{map[string]any{"type":"tun", "tag":"tun-in", "interface_name":"router-vpn", "auto_route":true}},
		"outbounds": []any{map[string]any{"type":"shadowsocks", "tag":"proxy", "server":"203.0.113.12", "server_port":8388}},
		"route": map[string]any{"final":"proxy", "rules":[]any{map[string]any{"protocol":"dns", "action":"hijack-dns"}}},
	}
	body, err := json.Marshal(cfg)
	if err != nil { t.Fatal(err) }
	if err := os.WriteFile(path, body, 0o600); err != nil { t.Fatal(err) }
	wg := nativeWG{PrivateKey:"private", PublicKey:"public", Host:"203.0.113.11", Addresses:[]string{"10.77.0.2/32"}, AllowedIPs:[]string{"0.0.0.0/0"}, Port:51820}
	if _, err := patchNativeMultihopConfig(path, "shadowsocks", wg, "10.77.0.1", 1080, "entry-user", "entry-pass"); err != nil {
		t.Fatal(err)
	}
	patchedBody, err := os.ReadFile(path)
	if err != nil { t.Fatal(err) }
	var patched map[string]any
	if err := json.Unmarshal(patchedBody, &patched); err != nil { t.Fatal(err) }

	inbounds, _ := patched["inbounds"].([]any)
	ports := map[string]int{}
	for _, raw := range inbounds {
		item, _ := raw.(map[string]any)
		if item == nil { continue }
		if tag, _ := item["tag"].(string); tag == "multihop-entry-proof" || tag == "multihop-proof" {
			ports[tag] = int(item["listen_port"].(float64))
		}
	}
	if ports["multihop-entry-proof"] != nativeMultihopEntryProofPort || ports["multihop-proof"] != nativeMultihopExitProofPort {
		t.Fatalf("native proof ports are not distinct/exact: %#v", ports)
	}

	outbounds, _ := patched["outbounds"].([]any)
	var entryPrivate map[string]any
	for _, raw := range outbounds {
		item, _ := raw.(map[string]any)
		if item != nil && item["tag"] == "entry-private" { entryPrivate = item }
	}
	if entryPrivate == nil || entryPrivate["type"] != "socks" || entryPrivate["server"] != "10.77.0.1" || int(entryPrivate["server_port"].(float64)) != 1080 || entryPrivate["detour"] != "entry-wg" {
		t.Fatalf("entry-private hop lane is not bound through entry-wg: %#v", entryPrivate)
	}

	route, _ := patched["route"].(map[string]any)
	rules, _ := route["rules"].([]any)
	if len(rules) < 3 { t.Fatalf("native multihop rules missing: %#v", rules) }
	entryRule, _ := rules[0].(map[string]any); exitRule, _ := rules[1].(map[string]any)
	if entryRule["outbound"] != "entry-private" || exitRule["outbound"] != "proxy" {
		t.Fatalf("proof lanes route to wrong outbounds: entry=%#v exit=%#v", entryRule, exitRule)
	}
	if inbound, _ := entryRule["inbound"].([]any); len(inbound) != 1 || inbound[0] != "multihop-entry-proof" {
		t.Fatalf("entry proof rule identity wrong: %#v", entryRule)
	}
	if inbound, _ := exitRule["inbound"].([]any); len(inbound) != 1 || inbound[0] != "multihop-proof" {
		t.Fatalf("exit proof rule identity wrong: %#v", exitRule)
	}
	last, _ := rules[2].(map[string]any)
	if last["protocol"] != "dns" || last["action"] != "hijack-dns" {
		t.Fatalf("existing route rule was not preserved after proof lanes: %#v", rules)
	}
}

func TestNativeEntryPrivateProofLaneFailsClosedOnUnsafeSettings(t *testing.T) {
	for _, tc := range []struct{host string; port int; user,password string}{
		{"router.example",1080,"",""},
		{"10.77.0.1",70000,"",""},
		{"10.77.0.1",1080,"user",""},
	} {
		if _, err := nativeEntryPrivateOutbound(tc.host, tc.port, tc.user, tc.password); err == nil {
			t.Fatalf("unsafe entry-private settings were accepted: %+v", tc)
		}
	}
}
