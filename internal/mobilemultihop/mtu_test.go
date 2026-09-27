package mobilemultihop

import (
	"encoding/json"
	"strings"
	"testing"
)

func mtuGraph(t *testing.T) string {
	t.Helper()
	text, id := wireGuardFixture()
	encoded, err := WireGuardExitConfig(text, id)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	_ = json.Unmarshal([]byte(encoded), &root)
	endpoints := root["endpoints"].([]any)
	exit := endpoints[0].(map[string]any)
	exit["detour"] = "entry-wg"
	raw, _ := json.Marshal(exit)
	var entry map[string]any
	_ = json.Unmarshal(raw, &entry)
	entry["tag"] = "entry-wg"
	delete(entry, "detour")
	root["endpoints"] = append([]any{entry}, endpoints...)
	raw, _ = json.Marshal(root)
	return string(raw)
}
func TestMobileMTUUsesBothFrozenPoliciesAndNestedPaddingBound(t *testing.T) {
	config := mtuGraph(t)
	for _, tc := range []struct {
		profiles         string
		entry, exit, tun int
	}{
		{`{"entry":{},"exit":{}}`, 1420, 1360, 1280},
		{`{"entry":{"mtu_policy":"fixed","manual_mtu":1500},"exit":{}}`, 1500, 1420, 1280},
		{`{"entry":{},"exit":{"mtu_policy":"manual","manual_mtu":1340}}`, 1420, 1340, 1340},
		{`{"entry":{"mtu_policy":"auto","effective_mtu":9000},"exit":{"mtu_policy":"auto","effective_mtu":9000}}`, 1420, 1360, 1280},
	} {
		encoded, err := ApplyMTUPolicy(config, tc.profiles)
		if err != nil {
			t.Fatal(err)
		}
		var root map[string]any
		_ = json.Unmarshal([]byte(encoded), &root)
		ends := root["endpoints"].([]any)
		if int(ends[0].(map[string]any)["mtu"].(float64)) != tc.entry || int(ends[1].(map[string]any)["mtu"].(float64)) != tc.exit || int(root["inbounds"].([]any)[0].(map[string]any)["mtu"].(float64)) != tc.tun {
			t.Fatal("MTU policy applied to the wrong interface", encoded)
		}
	}
	ipv6 := strings.ReplaceAll(config, `"192.0.2.1"`, `"2001:db8::1"`)
	encoded, err := ApplyMTUPolicy(ipv6, `{"entry":{},"exit":{}}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(encoded, `"mtu":1328`) {
		t.Fatal("IPv6 nested overhead was ignored")
	}
}
func TestMobileMTURejectsFixedOverflowAndAmbiguousPolicy(t *testing.T) {
	for _, profiles := range []string{
		`{"entry":{"mtu_policy":"fixed","manual_mtu":1280},"exit":{}}`,
		`{"entry":{},"exit":{"mtu_policy":"manual","manual_mtu":1400}}`,
		`{"entry":{},"exit":{"mtu_policy":"manual","manual_mtu":1279}}`,
		`{"entry":{},"exit":{"mtu_policy":"manual","manual_mtu":true}}`,
		`{"entry":{},"exit":{"mtu_policy":"manual","manual_mtu":1280.5}}`,
		`{"entry":{},"exit":{"mtu_policy":"manual"}}`,
		`{"entry":{},"exit":{"mtu_policy":"unexpected"}}`,
		`{"entry":{},"exit":{"ipv6_mode":"ignored"}}`,
		`{"entry":{},"exit":{"ipv6_mode":true}}`,
		`{"entry":{},"exit":{},"exit":{}}`,
	} {
		if _, err := ApplyMTUPolicy(mtuGraph(t), profiles); err == nil {
			t.Fatal("invalid policy accepted", profiles)
		}
	}
}
func TestMobileIPv6OffKeepsDefaultCaptureAndRejectsOnlyOwnedTun(t *testing.T) {
	encoded, err := ApplyMTUPolicy(mtuGraph(t), `{"entry":{"ipv6_mode":"off"},"exit":{"ipv6_mode":"on"}}`)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	_ = json.Unmarshal([]byte(encoded), &root)
	tun := root["inbounds"].([]any)[0].(map[string]any)
	if len(tun["address"].([]any)) != 2 || tun["auto_route"] != true {
		t.Fatal("IPv6 capture removed")
	}
	rule := root["route"].(map[string]any)["rules"].([]any)[0].(map[string]any)
	if rule["action"] != "reject" || rule["ip_version"] != float64(6) || rule["inbound"].([]any)[0] != tun["tag"] {
		t.Fatal("IPv6 rejection is not owned by the TUN")
	}
	if root["dns"].(map[string]any)["strategy"] != "ipv4_only" {
		t.Fatal("DNS strategy lost")
	}
}
