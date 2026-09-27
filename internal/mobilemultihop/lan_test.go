package mobilemultihop

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"
)

func lanFixture(t *testing.T) (string, map[string]any) {
	t.Helper()
	raw, _ := fixture(t, "local")
	var graph map[string]any
	json.Unmarshal([]byte(raw), &graph)
	graph["inbounds"].([]any)[0].(map[string]any)["tag"] = "tun-in"
	b, _ := json.Marshal(graph)
	return string(b), map[string]any{"entry": map[string]any{"home_lan_access": true}, "exit": map[string]any{"home_lan_access": true, "router_api": "http://10.88.0.1:8787"}}
}
func compileLAN(t *testing.T, graph string, pair map[string]any) map[string]any {
	t.Helper()
	profiles, _ := json.Marshal(pair)
	result, err := ApplyLANPolicy(graph, string(profiles))
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	json.Unmarshal([]byte(result), &value)
	return value
}
func TestLANOnLeavesExactOriginalGraph(t *testing.T) {
	graph, pair := lanFixture(t)
	b, _ := json.Marshal(pair)
	result, err := ApplyLANPolicy(graph, string(b))
	if err != nil || result != graph {
		t.Fatal("default policy changed", err)
	}
}
func TestBothNodeLANPoliciesPreserveDNSAndProofDialers(t *testing.T) {
	for _, node := range []string{"entry", "exit"} {
		t.Run(node, func(t *testing.T) {
			graph, pair := lanFixture(t)
			pair[node].(map[string]any)["home_lan_access"] = false
			value := compileLAN(t, graph, pair)
			var original map[string]any
			json.Unmarshal([]byte(graph), &original)
			for _, key := range []string{"outbounds", "endpoints", "dns"} {
				if !reflect.DeepEqual(original[key], value[key]) {
					t.Fatal("policy changed protected dialer", key)
				}
			}
			rules := value["route"].(map[string]any)["rules"].([]any)
			if len(rules) != 3+len(original["route"].(map[string]any)["rules"].([]any)) {
				t.Fatal("missing LAN policy")
			}
			control := rules[1].(map[string]any)
			if control["network"] != "tcp" || control["port"] != float64(8787) || control["outbound"] != "proxy" || !reflect.DeepEqual(control["ip_cidr"], []any{"10.88.0.1/32"}) {
				t.Fatal("broad control bypass")
			}
			reject := rules[2].(map[string]any)
			if reject["action"] != "reject" || !reflect.DeepEqual(reject["inbound"], []any{"tun-in"}) {
				t.Fatal("proof inlet was blocked or traffic wasn't filtered")
			}
			prefixes := reject["ip_cidr"].([]any)
			for _, host := range []string{"10.3.2.1", "192.168.50.133", "172.16.0.2", "fd99::1"} {
				found := false
				for _, p := range prefixes {
					if netip.MustParsePrefix(p.(string)).Contains(netip.MustParseAddr(host)) {
						found = true
					}
				}
				if !found {
					t.Fatal("unfiltered private address", host)
				}
			}
			capture := value["inbounds"].([]any)[0].(map[string]any)["route_address"].([]any)
			if capture[0] != "0.0.0.0/0" || capture[1] != "::/0" || len(capture) != 7 {
				t.Fatal("more specific physical LAN route can bypass TUN")
			}
		})
	}
}
func TestConfiguredLANNetworksAreUnionedNotInvented(t *testing.T) {
	graph, pair := lanFixture(t)
	a := pair["entry"].(map[string]any)
	b := pair["exit"].(map[string]any)
	a["home_lan_access"] = false
	b["home_lan_access"] = false
	a["home_lan_cidrs"] = []string{"192.168.50.0/24"}
	b["home_lan_cidrs"] = []string{"10.2.0.0/16", "fd99::/64", "192.168.50.0/24"}
	value := compileLAN(t, graph, pair)
	rules := value["route"].(map[string]any)["rules"].([]any)
	if !reflect.DeepEqual(rules[2].(map[string]any)["ip_cidr"], []any{"10.2.0.0/16", "192.168.50.0/24", "fd99::/64"}) {
		t.Fatal("lost configured LAN policy")
	}
}
func TestLANInvalidPolicyDoesNotSilentlyBroadenOrDrop(t *testing.T) {
	for _, invalid := range []any{[]string{"0.0.0.0/0"}, []string{"::/0"}, []string{"8.8.8.0/24"}, []string{"169.254.0.0/16"}, []string{"192.168.50.1/24"}, []string{"::ffff:192.168.50.0/120"}, []string{"fe80::%en0/64"}, []any{false}, "192.168.50.0/24"} {
		graph, pair := lanFixture(t)
		a := pair["entry"].(map[string]any)
		a["home_lan_access"] = false
		a["home_lan_cidrs"] = invalid
		b, _ := json.Marshal(pair)
		if _, err := ApplyLANPolicy(graph, string(b)); err == nil {
			t.Fatal("bad LAN network accepted", invalid)
		}
	}
	for _, invalid := range []any{nil, "off", 0, []any{}} {
		graph, pair := lanFixture(t)
		pair["entry"].(map[string]any)["home_lan_access"] = invalid
		b, _ := json.Marshal(pair)
		if _, err := ApplyLANPolicy(graph, string(b)); err == nil {
			t.Fatal("bad boolean accepted")
		}
	}
	graph, pair := lanFixture(t)
	pair["exit"].(map[string]any)["home_lan_access"] = false
	profiles, _ := json.Marshal(pair)
	for _, bad := range []string{graph + "{}", `{"route":{"final":"proxy"},"inbounds":[]}`, `{"inbounds":[],"inbounds":[]}`} {
		if _, err := ApplyLANPolicy(bad, string(profiles)); err == nil {
			t.Fatal("bad graph accepted")
		}
	}
}
func TestLANRejectsPhysicalBypassAndPreservesPriorRules(t *testing.T) {
	graph, pair := lanFixture(t)
	pair["entry"].(map[string]any)["home_lan_access"] = false
	profiles, _ := json.Marshal(pair)
	for _, key := range []string{"route_exclude_address", "route_exclude_address_set", "route_address_set", "route_address"} {
		var value map[string]any
		json.Unmarshal([]byte(graph), &value)
		value["inbounds"].([]any)[0].(map[string]any)[key] = []string{"192.168.50.0/24"}
		b, _ := json.Marshal(value)
		if _, err := ApplyLANPolicy(string(b), string(profiles)); err == nil {
			t.Fatal("bypass accepted", key)
		}
	}
	var value map[string]any
	json.Unmarshal([]byte(graph), &value)
	prior := map[string]any{"ip_version": 6, "action": "reject"}
	value["route"].(map[string]any)["rules"] = []any{prior}
	b, _ := json.Marshal(value)
	result := compileLAN(t, string(b), pair)
	rules := result["route"].(map[string]any)["rules"].([]any)
	if len(rules) != 4 || rules[3].(map[string]any)["ip_version"] != float64(6) {
		t.Fatal("previous IPv6 policy dropped")
	}
}

func TestLANControlExceptionCannotBypassIPv6Off(t *testing.T) {
	graph, pair := lanFixture(t)
	pair["exit"].(map[string]any)["home_lan_access"] = false
	pair["entry"].(map[string]any)["ipv6_mode"] = "off"
	pair["exit"].(map[string]any)["router_api"] = "https://[fd88::1]:8787"
	value := compileLAN(t, graph, pair)
	first := value["route"].(map[string]any)["rules"].([]any)[0].(map[string]any)
	if first["action"] != "reject" || first["ip_version"] != float64(6) {
		t.Fatal("IPv6 control bypassed IPv6-Off")
	}
}
