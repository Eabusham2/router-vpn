package mobiletor

import (
	"encoding/json"
	"reflect"
	"testing"
)

func torHomeProfile() map[string]any {
	profile := torHostProfile()
	for _, key := range []string{"dns_mode", "dns_host", "dns_port", "dns_protocol"} {
		delete(profile, key)
	}
	return profile
}

func torHomeEntry() map[string]any {
	entry := predecessorProfile()
	entry["adguard_ipv4"], entry["adguard_ipv6"] = "10.77.0.53", "fd77::53"
	return entry
}

func torHomePair(profile, entry map[string]any) {
	profile["multihop_enabled"], profile["multihop_entry_id"], profile["multihop_exit_id"] = true, entry["id"], profile["id"]
	profile["multihop_entry_mode"], profile["multihop_exit_mode"], profile["multihop_execution"] = "ss", profile["external"].(map[string]any)["protocol"], "local"
}

func TestTorHomeDefaultDraftDoesNotInventRunnablePublicDNS(t *testing.T) {
	for _, mode := range []string{"missing", "", "home"} {
		t.Run(mode, func(t *testing.T) {
			profile := torHomeProfile()
			if mode != "missing" {
				profile["dns_mode"] = mode
			}
			source := torHostEncode(t, profile)
			if err := ValidateProfile(source); err != nil {
				t.Fatal("valid unresolved Home draft cannot save", err)
			}
			for _, base := range []string{"", torHostBase(t)} {
				if graph, err := CompileProfile(source, "captured-session", base); err == nil || graph != "" {
					t.Fatal("Home default silently gained public DNS or an unproved private entry")
				}
			}
			if graph, err := CompileProfileWithPredecessor(source, "captured-session", "", ""); err == nil || graph != "" {
				t.Fatal("direct Home draft became runnable")
			}
			if torHostEncode(t, profile) != source {
				t.Fatal("draft default rewrote the saved node")
			}
		})
	}
}

func TestTorHomeDNSUsesExactCapturedEntryAndKeepsTorFinal(t *testing.T) {
	for _, mode := range []string{"missing", "", "home"} {
		for _, protocol := range []string{"", "udp", "tcp", "dot", "doh", "doh3"} {
			for _, host := range []string{"", "10.77.0.53", "fd77::53"} {
				for _, lan := range []bool{false, true} {
					t.Run(mode+"/"+protocol+"/"+host+"/"+map[bool]string{false: "LAN-off", true: "LAN-on"}[lan], func(t *testing.T) {
						profile, entry := torHomeProfile(), torHomeEntry()
						if mode != "missing" {
							profile["dns_mode"] = mode
						}
						profile["dns_protocol"], profile["dns_host"], profile["home_lan_access"] = protocol, host, lan
						profile["dns_server_name"], profile["dns_path"], profile["dns_port"] = "adguard.home.example", "/selected-dns?policy=home", 5453
						torHomePair(profile, entry)
						source, capturedEntry, base := torHostEncode(t, profile), torHostEncode(t, entry), torHostBase(t)
						encoded, err := CompileProfileWithPredecessor(source, "captured-session", base, capturedEntry)
						if err != nil {
							t.Fatal(err)
						}
						root, err := profileObject(encoded, 4<<20)
						if err != nil {
							t.Fatal(err)
						}
						selected := torHostTagged(t, root["dns"].(map[string]any)["servers"], profileDNS)
						bootstrap := torHostTagged(t, root["dns"].(map[string]any)["servers"], bootstrapDNS)
						wantProtocol := map[string]string{"": "udp", "dot": "tls", "doh": "https", "doh3": "h3"}[protocol]
						if wantProtocol == "" {
							wantProtocol = protocol
						}
						if host == "" {
							host = "10.77.0.53"
						}
						if selected["server"] != host || selected["server_port"] != json.Number("5453") || selected["type"] != wantProtocol || selected["detour"] != "proxy" {
							t.Fatal("selected Home endpoint or exact entry detour changed", selected)
						}
						for key, value := range selected {
							if key != "tag" && !reflect.DeepEqual(value, bootstrap[key]) {
								t.Fatal("bootstrap changed the selected Home policy", key)
							}
						}
						if wantProtocol == "tls" || wantProtocol == "https" || wantProtocol == "h3" {
							if selected["tls"].(map[string]any)["server_name"] != "adguard.home.example" {
								t.Fatal("Home certificate identity changed")
							}
						}
						if wantProtocol == "https" || wantProtocol == "h3" {
							if selected["path"] != "/selected-dns?policy=home" {
								t.Fatal("Home HTTP path changed")
							}
						}
						out := torHostTagged(t, root["outbounds"], ProfileOutboundTag)
						proof, err := NewPredecessorProof(capturedEntry)
						if err != nil {
							t.Fatal(err)
						}
						if out["entry_sha256"] != proof.Fingerprint() || out["detour"] != "proxy" || root["route"].(map[string]any)["final"] != ProfileOutboundTag || root["dns"].(map[string]any)["final"] != profileDNS {
							t.Fatal("Tor traffic, exact entry binding or selected DNS final was lost")
						}
						if source != torHostEncode(t, profile) || capturedEntry != torHostEncode(t, entry) {
							t.Fatal("compile changed captured node preferences or credentials")
						}
						if _, err := MTUAuthority(encoded, source, "captured-session"); err != nil {
							t.Fatal("Home Tor graph no longer reaches its owned MTU path", err)
						}
						if !lan {
							found := false
							for _, raw := range root["route"].(map[string]any)["rules"].([]any) {
								rule := raw.(map[string]any)
								if rule["ip_cidr"] != nil && rule["action"] == "reject" {
									found = true
								}
								if rule["action"] == "route" && rule["outbound"] != ProfileOutboundTag {
									t.Fatal("Home DNS created an application LAN bypass")
								}
							}
							if !found {
								t.Fatal("Home DNS removed LAN-Off")
							}
						}
					})
				}
			}
		}
	}
}

func TestTorHomeRejectsWrongOrUncapturedEntryWithoutFallback(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any, map[string]any){
		"wrong-entry":       func(p, e map[string]any) { e["id"] = "replacement" },
		"wrong-exit":        func(p, e map[string]any) { p["multihop_exit_id"] = "replacement" },
		"wrong-protocol":    func(p, e map[string]any) { p["multihop_exit_mode"] = "socks5" },
		"disabled":          func(p, e map[string]any) { p["multihop_enabled"] = false },
		"untyped-enabled":   func(p, e map[string]any) { p["multihop_enabled"] = "true" },
		"untyped-execution": func(p, e map[string]any) { p["multihop_execution"] = false },
		"server":            func(p, e map[string]any) { p["multihop_execution"] = "server" },
		"compare":           func(p, e map[string]any) { p["multihop_execution"] = "auto" },
		"missing-mode":      func(p, e map[string]any) { delete(p, "multihop_entry_mode") },
		"unpaired":          func(p, e map[string]any) { delete(e, "node_proof_id") },
		"unauthed":          func(p, e map[string]any) { delete(e, "api_token") },
		"public-proof":      func(p, e map[string]any) { e["router_api"] = "http://1.1.1.1:8787" },
		"ordinary-entry":    func(p, e map[string]any) { e["node_kind"] = "external" },
		"no-home":           func(p, e map[string]any) { delete(e, "adguard_ipv4"); delete(e, "adguard_ipv6") },
		"untyped-home":      func(p, e map[string]any) { e["adguard_ipv4"] = false },
		"public-home":       func(p, e map[string]any) { e["adguard_ipv4"] = "1.1.1.1" },
		"mapped-home":       func(p, e map[string]any) { e["adguard_ipv6"] = "::ffff:10.77.0.53" },
		"wrong-family":      func(p, e map[string]any) { e["adguard_ipv6"] = "10.77.0.53" },
		"wrong-resolver":    func(p, e map[string]any) { p["dns_host"] = "10.77.0.54" },
		"system-resolver":   func(p, e map[string]any) { p["dns_host"] = "adguard.local" },
		"other-bootstrap":   func(p, e map[string]any) { p["dns_bootstrap"] = map[string]any{"server": "other"} },
	} {
		t.Run(name, func(t *testing.T) {
			profile, entry := torHomeProfile(), torHomeEntry()
			torHomePair(profile, entry)
			mutate(profile, entry)
			if value, err := CompileProfileWithPredecessor(torHostEncode(t, profile), "captured-session", torHostBase(t), torHostEncode(t, entry)); err == nil || value != "" {
				t.Fatal("invalid Home owner gained a runnable graph")
			}
		})
	}
	profile, entry := torHomeProfile(), torHomeEntry()
	torHomePair(profile, entry)
	for _, inputs := range [][2]string{{"", torHostEncode(t, entry)}, {torHostBase(t), ""}, {"", ""}} {
		if value, err := CompileProfileWithPredecessor(torHostEncode(t, profile), "captured-session", inputs[0], inputs[1]); err == nil || value != "" {
			t.Fatal("incomplete captured predecessor compiled")
		}
	}
}

func TestTorIdleValidationKeepsMalformedDraftRejections(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"wrong-node":    func(p map[string]any) { p["node_kind"] = "router-vpn" },
		"router-secret": func(p map[string]any) { p["api_token"] = "other-node-secret" },
		"bridge": func(p map[string]any) {
			p["external"].(map[string]any)["tor_bridge"].(map[string]any)["bridges"] = []any{obfs4Bridge + "\nSocksPort 9999"}
		},
		"public-home":    func(p map[string]any) { p["dns_host"] = "1.1.1.1" },
		"port":           func(p map[string]any) { p["dns_port"] = "53" },
		"protocol":       func(p map[string]any) { p["dns_protocol"] = "system" },
		"unverified-tls": func(p map[string]any) { p["dns_protocol"] = "dot" },
		"lan":            func(p map[string]any) { p["home_lan_access"] = "false" },
		"mtu":            func(p map[string]any) { p["mtu_policy"], p["manual_mtu"] = "fixed", 0 },
		"ipv6":           func(p map[string]any) { p["ipv6_mode"] = "maybe" },
		"jumbo":          func(p map[string]any) { p["jumbo_tun"] = "true" },
	} {
		t.Run(name, func(t *testing.T) {
			p := torHomeProfile()
			mutate(p)
			if err := ValidateProfile(torHostEncode(t, p)); err == nil {
				t.Fatal("malformed idle node saved")
			}
		})
	}
}

func TestTorExplicitRescueAndCustomKeepSelectedExitDNS(t *testing.T) {
	for _, mode := range []string{"rescue", "custom"} {
		p, e := torHostProfile(), torHomeEntry()
		p["dns_mode"] = mode
		torHomePair(p, e)
		source := torHostEncode(t, p)
		if err := ValidateProfile(source); err != nil {
			t.Fatal(err)
		}
		compiled, err := CompileProfileWithPredecessor(source, "captured-session", torHostBase(t), torHostEncode(t, e))
		if err != nil {
			t.Fatal(err)
		}
		graph, _ := profileObject(compiled, 4<<20)
		dns := torHostTagged(t, graph["dns"].(map[string]any)["servers"], profileDNS)
		wanted := map[string]string{"rescue": "1.1.1.1", "custom": "9.9.9.9"}[mode]
		if dns["server"] != wanted || dns["detour"] != ProfileOutboundTag {
			t.Fatal("explicit saved resolver moved to Home or another route")
		}
		if source != torHostEncode(t, p) {
			t.Fatal("explicit DNS choice was rewritten")
		}
	}
}
