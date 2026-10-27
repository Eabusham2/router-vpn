package mobiletor

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const mobileServerSession = "ab56a1c2-d3e4-4af9-b0a1-03123456789a"

func mobileServerFixture(t *testing.T, mode string, home bool) MobileServerTorOptions {
	t.Helper()
	profile, entry := torHostProfile(), torHomeEntry()
	if mode == "tor" {
		profile["external"] = map[string]any{"protocol": "tor"}
	} else if mode == "snowflake" {
		profile["external"].(map[string]any)["tor_bridge"] = map[string]any{"transport": "custom", "bridges": []string{"snowflake 192.0.2.3:80 1111111111111111111111111111111111111111 fingerprint=1111111111111111111111111111111111111111 url=https://broker.example/ front=front.example ice=stun:stun.example:3478"}}
	}
	if home {
		profile["dns_mode"], profile["dns_host"], profile["dns_protocol"] = "home", "10.77.0.53", "tcp"
	}
	torHomePair(profile, entry)
	profile["multihop_execution"] = "server"
	profile["ipv6_mode"], profile["home_lan_access"] = "off", false
	profile["mtu_policy"], profile["manual_mtu"] = "fixed", 1400
	return MobileServerTorOptions{Profile: torHostEncode(t, profile), SessionID: mobileServerSession, EntryConfig: torHostBase(t), EntryProfile: torHostEncode(t, entry)}
}

func TestMobileServerTorPolicyRecompilesExactSingleVPNAndCanonicalServerSource(t *testing.T) {
	for _, mode := range []string{"tor", "tor-bridge", "snowflake"} {
		for _, home := range []bool{false, true} {
			t.Run(mode+map[bool]string{true: "/home", false: "/custom"}[home], func(t *testing.T) {
				options := mobileServerFixture(t, mode, home)
				policy, err := NewMobileServerTorPolicy(options)
				if err != nil {
					t.Fatal(err)
				}
				graph, _ := profileObject(policy.Config(), 4<<20)
				final := torHostTagged(t, graph["outbounds"], ProfileOutboundTag)
				if final["type"] != ServerTorClientType || final["session_id"] != mobileServerSession || final["profile"] != options.Profile || final["entry_config"] != options.EntryConfig || final["entry_profile"] != options.EntryProfile || len(final) != 6 {
					t.Fatal("native Server owner lost its exact inputs")
				}
				encoded, _ := json.Marshal(final)
				var replay MobileServerTorOptions
				if json.Unmarshal(encoded, &replay) != nil || replay != options {
					t.Fatal("native options do not retain the full captured source")
				}
				reconstructed, err := NewMobileServerTorPolicy(replay)
				if err != nil || reconstructed.Config() != policy.Config() || reconstructed.LeaseSessionID() != policy.LeaseSessionID() || !capturedHex(policy.LeaseSessionID(), 16) {
					t.Fatal("native constructor did not reproduce its exact policy", err)
				}
				if policy.Options() != options || policy.EntryTag() != "proxy" || policy.SessionID() != mobileServerSession {
					t.Fatal("immutable policy changed its captured selection")
				}
				canonical, err := NewServerTorPolicy(policy.ServerPolicy().Source(), policy.EntryProof().NodeID())
				if err != nil || canonical.SourceSHA256() != policy.ServerPolicy().SourceSHA256() || canonical.DNSPolicySHA256() != policy.ServerPolicy().DNSPolicySHA256() || canonical.ID() != "saved-tor" {
					t.Fatal("mobile selection differs from the operator's canonical policy", err)
				}
				wantMode := "tor-bridge"
				if mode == "tor" {
					wantMode = mode
				}
				if canonical.Mode() != wantMode || canonical.DNS().Transport != "tcp" || canonical.DNS().Port != 5353 {
					t.Fatal("protocol or resolver parameters changed")
				}
				if graph["route"].(map[string]any)["final"] != ProfileOutboundTag || graph["dns"].(map[string]any)["final"] != profileDNS || len(graph["inbounds"].([]any)) != 1 {
					t.Fatal("Server did not retain its single selected VPN path")
				}
				tun := graph["inbounds"].([]any)[0].(map[string]any)
				if tun["mtu"] != json.Number("1400") || tun["auto_route"] != true || tun["strict_route"] != true || graph["dns"].(map[string]any)["strategy"] != "ipv4_only" {
					t.Fatal("saved MTU/IPv6/protection policy changed")
				}
				for _, row := range graph["dns"].(map[string]any)["servers"].([]any) {
					resolver := row.(map[string]any)
					if resolver["tag"] == bootstrapDNS {
						t.Fatal("Server retained unused local PT bootstrap authority")
					}
					if resolver["tag"] == profileDNS {
						want := ProfileOutboundTag
						if home {
							want = "proxy"
							if resolver["server"] != "10.77.0.53" {
								t.Fatal("Home DNS belongs to a different entry")
							}
						}
						if resolver["detour"] != want {
							t.Fatal("selected DNS lost its captured route")
						}
					}
				}
				original, _ := profileObject(options.EntryConfig, 4<<20)
				if !reflect.DeepEqual(torHostTagged(t, graph["outbounds"], "proxy"), torHostTagged(t, original["outbounds"], "proxy")) {
					t.Fatal("Server changed private entry credentials or transport")
				}
				if _, err := CompileProfileWithPredecessor(options.Profile, options.SessionID, options.EntryConfig, options.EntryProfile); err == nil {
					t.Fatal("Server source acquired Local runtime authority")
				}
			})
		}
	}
}

func TestMobileServerTorPolicyRejectsUncapturedWrongAndStaleSelections(t *testing.T) {
	base := mobileServerFixture(t, "tor", true)
	for name, mutate := range map[string]func(*MobileServerTorOptions){
		"no-entry":    func(o *MobileServerTorOptions) { o.EntryConfig = "" },
		"no-proof":    func(o *MobileServerTorOptions) { o.EntryProfile = "" },
		"bad-session": func(o *MobileServerTorOptions) { o.SessionID = "bad\nsession" },
		"ordinary-entry": func(o *MobileServerTorOptions) {
			o.EntryProfile = strings.Replace(o.EntryProfile, "router-vpn", "external", 1)
		},
		"different-entry": func(o *MobileServerTorOptions) {
			o.EntryProfile = strings.Replace(o.EntryProfile, `"id":"captured-entry"`, `"id":"other-entry"`, 1)
		},
		"local": func(o *MobileServerTorOptions) {
			o.Profile = strings.Replace(o.Profile, `"multihop_execution":"server"`, `"multihop_execution":"local"`, 1)
		},
		"compare": func(o *MobileServerTorOptions) {
			o.Profile = strings.Replace(o.Profile, `"multihop_execution":"server"`, `"multihop_execution":"auto"`, 1)
		},
		"direct": func(o *MobileServerTorOptions) {
			o.Profile = strings.Replace(o.Profile, `"multihop_enabled":true`, `"multihop_enabled":false`, 1)
		},
		"wrong-home": func(o *MobileServerTorOptions) { o.Profile = strings.Replace(o.Profile, "10.77.0.53", "10.88.0.53", 1) },
		"second-vpn": func(o *MobileServerTorOptions) {
			graph, _ := profileObject(o.EntryConfig, 4<<20)
			graph["inbounds"] = append(graph["inbounds"].([]any), graph["inbounds"].([]any)[0])
			o.EntryConfig = torHostEncode(t, graph)
		},
		"nested-server": func(o *MobileServerTorOptions) {
			graph, _ := profileObject(o.EntryConfig, 4<<20)
			graph["outbounds"] = append(graph["outbounds"].([]any), map[string]any{"tag": "other-tor", "type": ServerTorClientType})
			o.EntryConfig = torHostEncode(t, graph)
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			if changed == base {
				t.Fatal("negative fixture did not change its source")
			}
			if policy, err := NewMobileServerTorPolicy(changed); err == nil || policy != nil {
				t.Fatal("unowned Server source was accepted")
			}
		})
	}
	first, err := NewMobileServerTorPolicy(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"session", "profile", "entry"} {
		changed := base
		switch field {
		case "session":
			changed.SessionID += "-next"
		case "profile":
			changed.Profile = strings.Replace(changed.Profile, `"ipv6_mode":"off"`, `"ipv6_mode":"on"`, 1)
		case "entry":
			changed.EntryProfile = strings.Replace(changed.EntryProfile, "private-entry-secret", "next-secret", 1)
		}
		if changed == base {
			t.Fatal("identity fixture did not change", field)
		}
		next, err := NewMobileServerTorPolicy(changed)
		if err != nil || next.LeaseSessionID() == first.LeaseSessionID() {
			t.Fatal("replacement selection reused a previous lease session", field, err)
		}
	}
}
