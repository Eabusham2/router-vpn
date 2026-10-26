package mobiletor

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestTorMTUProfileCapturedBeforeConnection(t *testing.T) {
	for _, base := range []string{"", torHostBase(t)} {
		profile := torHostProfile()
		profile["mtu_policy"] = "auto"
		config := torHostCompile(t, profile, base)
		source, frozen := torHostEncode(t, config), torHostEncode(t, profile)
		authority, err := MTUAuthority(source, frozen, "frozen-session-1")
		if err != nil {
			t.Fatal(err)
		}
		var actual map[string]any
		if json.Unmarshal([]byte(authority), &actual) != nil || actual["source_kind"] != "tor" || actual["mtu_policy"] != "auto" || actual["id"] != profile["id"] || actual["expected_public_ip"] != nil || len(actual["source_sha256"].(string)) != 64 {
			t.Fatal("Tor authority lost dynamic identity or policy", authority)
		}
		// Reordering/indentation is not a policy change; the full semantic profile
		// is bound. DNS, bridge, LAN, history and automatic policy changes are.
		indented, _ := json.MarshalIndent(profile, "", "  ")
		if _, err := MTUAuthority(source, string(indented), "frozen-session-1"); err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"mtu_policy", "dns_host", "home_lan_access", "effective_mtu", "jumbo_tun"} {
			changed, _ := profileObject(frozen, 256<<10)
			changed[field] = map[string]any{"mtu_policy": "default", "dns_host": "1.1.1.1", "home_lan_access": false, "effective_mtu": 1492, "jumbo_tun": true}[field]
			if _, err := MTUAuthority(source, torHostEncode(t, changed), "frozen-session-1"); err == nil {
				t.Fatal("changed profile adopted", field)
			}
		}
		other := torHostProfile()
		other["mtu_policy"] = "default"
		defaultConfig := torHostCompile(t, other, base)
		delete(torHostTagged(t, defaultConfig["outbounds"], ProfileOutboundTag), "profile_sha256")
		delete(torHostTagged(t, config["outbounds"], ProfileOutboundTag), "profile_sha256")
		if !reflect.DeepEqual(defaultConfig, config) {
			t.Fatal("test must reproduce identical auto/default native graphs")
		}
		if _, err := MTUAuthority(torHostEncode(t, config), frozen, "frozen-session-1"); err == nil {
			t.Fatal("unbound legacy graph minted automatic authority")
		}
	}
}

func TestTorMTURejectsChangedSessionAndRoutingOwner(t *testing.T) {
	profile := torHostProfile()
	profile["mtu_policy"] = "auto"
	frozen := torHostEncode(t, profile)
	for _, mutate := range []func(map[string]any){
		func(g map[string]any) { g["route"].(map[string]any)["final"] = "direct" },
		func(g map[string]any) { g["dns"].(map[string]any)["final"] = "system" },
		func(g map[string]any) {
			torHostTagged(t, g["outbounds"], ProfileOutboundTag)["session_id"] = "replacement"
		},
		func(g map[string]any) {
			torHostTagged(t, g["outbounds"], ProfileOutboundTag)["profile_sha256"] = strings.Repeat("0", 64)
		},
		func(g map[string]any) {
			g["outbounds"] = append(g["outbounds"].([]any), torHostTagged(t, g["outbounds"], ProfileOutboundTag))
		},
	} {
		graph := torHostCompile(t, profile, "")
		mutate(graph)
		if _, err := MTUAuthority(torHostEncode(t, graph), frozen, "frozen-session-1"); err == nil {
			t.Fatal("unowned native graph accepted")
		}
	}
	profile["jumbo_tun"] = "false"
	if _, err := CompileProfile(torHostEncode(t, profile), "frozen-session-1", ""); err == nil {
		t.Fatal("untyped Jumbo policy accepted")
	}
}

func TestTorJumboAuthorityRequiresConfiguredCapacityAndExactTUN(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"downsized":        func(g map[string]any) { g["inbounds"].([]any)[0].(map[string]any)["mtu"] = 1280 },
		"oversized":        func(g map[string]any) { g["inbounds"].([]any)[0].(map[string]any)["mtu"] = 9001 },
		"untyped":          func(g map[string]any) { g["inbounds"].([]any)[0].(map[string]any)["mtu"] = "9000" },
		"no-auto-route":    func(g map[string]any) { g["inbounds"].([]any)[0].(map[string]any)["auto_route"] = false },
		"no-strict-route":  func(g map[string]any) { g["inbounds"].([]any)[0].(map[string]any)["strict_route"] = false },
		"no-tag":           func(g map[string]any) { delete(g["inbounds"].([]any)[0].(map[string]any), "tag") },
		"second-interface": func(g map[string]any) { g["inbounds"] = append(g["inbounds"].([]any), g["inbounds"].([]any)[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			profile := torHostProfile()
			profile["mtu_policy"], profile["jumbo_tun"] = "auto", true
			graph := torHostCompile(t, profile, "")
			mutate(graph)
			if _, err := MTUAuthorityWithPredecessor(torHostEncode(t, graph), torHostEncode(t, profile), "frozen-session-1", nil); err == nil {
				t.Fatal("CONTROL: Jumbo authority ignored its exact configured interface")
			}
		})
	}
	profile := torHostProfile()
	profile["mtu_policy"] = "auto"
	graph := torHostCompile(t, profile, "")
	graph["inbounds"].([]any)[0].(map[string]any)["mtu"] = 9000
	if _, err := MTUAuthorityWithPredecessor(torHostEncode(t, graph), torHostEncode(t, profile), "frozen-session-1", nil); err == nil {
		t.Fatal("CONTROL: an arbitrary 9000 literal minted Jumbo authority")
	}
}
