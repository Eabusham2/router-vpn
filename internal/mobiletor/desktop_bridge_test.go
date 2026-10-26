package mobiletor

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const desktopSession = "0123456789abcdef0123456789abcdef"
const desktopIsolation = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func desktopProfile() map[string]any {
	profile := torHostProfile()
	profile["external"].(map[string]any)["tor_bridge"].(map[string]any)["socks_port"] = 19950
	profile["kill_switch_policy"] = "on-connect"
	profile["mtu_policy"] = "auto"
	profile["effective_mtu"] = 9000
	return profile
}

func desktopPolicy(t *testing.T, profile map[string]any, target string) *DesktopBridgePolicy {
	t.Helper()
	policy, err := NewDesktopBridgePolicy(torHostEncode(t, profile), desktopSession, desktopIsolation, target)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func TestDesktopBridgePolicyPreservesResolverDeviceAndStandaloneOwner(t *testing.T) {
	for _, target := range []string{"linux", "darwin", "windows"} {
		for _, protocol := range []string{"tcp", "dot", "doh"} {
			for _, lan := range []bool{false, true} {
				p := desktopProfile()
				p["dns_protocol"], p["dns_server_name"], p["dns_path"] = protocol, "selected.example", "/chosen-query?network=one"
				p["home_lan_access"], p["ipv6_mode"], p["mtu_policy"], p["manual_mtu"] = lan, "off", "manual", 1488
				source := torHostEncode(t, p)
				policy := desktopPolicy(t, p, target)
				meta := policy.Metadata()
				if source != torHostEncode(t, p) || policy.Profile() != source {
					t.Fatal("compiler changed captured private source")
				}
				if meta.NodeID != "saved-tor" || meta.SessionID != desktopSession || meta.SocksPort != 19950 ||
					meta.ConfiguredMTU != 1488 || meta.MTUPolicy != "manual" || meta.IPv6Mode != "off" || meta.HomeLANAccess != lan || meta.KillSwitchPolicy != "on-connect" ||
					meta.SourceSHA256 != policy.SourceSHA256() || meta.ConfigSHA256 != desktopDigest([]byte(policy.Config())) {
					t.Fatal("captured desktop policy metadata changed", meta)
				}
				graph, err := profileObject(policy.Config(), 4<<20)
				if err != nil {
					t.Fatal(err)
				}
				services, ok := graph["services"].([]any)
				if !ok || len(services) != 1 {
					t.Fatal("desktop Tor did not capture its native network-reset service")
				}
				observer, ok := services[0].(map[string]any)
				if !ok || len(observer) != 4 || observer["type"] != "routervpn-desktop-tor-network" || observer["tag"] != "routervpn-tor-physical" || observer["session_id"] != meta.SessionID || observer["source_sha256"] != meta.SourceSHA256 {
					t.Fatal("desktop Tor physical generation belongs to another session or source")
				}
				tun := graph["inbounds"].([]any)[0].(map[string]any)
				if len(graph["inbounds"].([]any)) != 1 || tun["mtu"] != json.Number("1488") || tun["auto_route"] != true || tun["strict_route"] != true {
					t.Fatal("desktop device policy lost its one real TUN")
				}
				if target == "darwin" && tun["interface_name"] != nil || target == "linux" && tun["interface_name"] != "router-vpn" || target == "windows" && tun["interface_name"] != "router-vpn-tor" {
					t.Fatal("native interface selection changed")
				}
				out := torHostTagged(t, graph["outbounds"], ProfileOutboundTag)
				if len(graph["outbounds"].([]any)) != 1 || out["type"] != "socks" || out["server"] != "127.0.0.1" || out["server_port"] != json.Number("19950") || out["username"] != desktopSession || out["password"] != desktopIsolation {
					t.Fatal("compiler embedded or replaced standalone Tor, or lost isolation")
				}
				dns := graph["dns"].(map[string]any)
				selected := torHostTagged(t, dns["servers"], profileDNS)
				bootstrap := torHostTagged(t, dns["servers"], bootstrapDNS)
				transport := map[string]string{"tcp": "tcp", "dot": "tls", "doh": "https"}[protocol]
				if dns["final"] != profileDNS || dns["strategy"] != "ipv4_only" || selected["detour"] != ProfileOutboundTag || bootstrap["detour"] != nil || len(dns["servers"].([]any)) != 2 {
					t.Fatal("application DNS or physical bootstrap has another owner")
				}
				if meta.DNS.Address != "9.9.9.9" || meta.DNS.Port != 5353 || meta.DNS.Transport != transport || selected["type"] != transport || selected["server"] != "9.9.9.9" || selected["server_port"] != json.Number("5353") {
					t.Fatal("selected DNS address, transport or port changed")
				}
				for key, value := range selected {
					if key != "tag" && key != "detour" && !reflect.DeepEqual(bootstrap[key], value) {
						t.Fatal("PT bootstrap substituted selected resolver parameters", key)
					}
				}
				if protocol != "tcp" && (selected["tls"].(map[string]any)["server_name"] != "selected.example" || meta.DNS.ServerName != "selected.example") {
					t.Fatal("selected DNS certificate identity changed")
				}
				if protocol == "doh" && (selected["path"] != "/chosen-query?network=one" || meta.DNS.Path != "/chosen-query?network=one") {
					t.Fatal("selected DNS HTTP request path changed")
				}
				route := graph["route"].(map[string]any)
				if route["final"] != ProfileOutboundTag || route["default_domain_resolver"].(map[string]any)["server"] != bootstrapDNS {
					t.Fatal("final path or explicit bootstrap changed")
				}
				blocked, dnsPort, udp := false, -1, -1
				for i, raw := range route["rules"].([]any) {
					rule := raw.(map[string]any)
					if rule["ip_cidr"] != nil && rule["action"] == "reject" {
						blocked = true
					}
					if rule["port"] == json.Number("53") && rule["action"] == "hijack-dns" {
						dnsPort = i
					}
					if rule["network"] == "udp" && rule["action"] == "reject" {
						udp = i
					}
				}
				if blocked == lan || dnsPort < 0 || udp <= dnsPort {
					t.Fatal("LAN or DNS-before-UDP device policy is not enforced")
				}
			}
		}
	}
}

func TestDesktopBridgeAutoIgnoresHistoricalMTUAndKeepsOmittedLANOff(t *testing.T) {
	for _, policy := range []string{"", "auto", "default"} {
		p := desktopProfile()
		delete(p, "home_lan_access")
		p["mtu_policy"], p["manual_mtu"], p["effective_mtu"] = policy, 9000, 9000
		got := desktopPolicy(t, p, "linux")
		if got.Metadata().ConfiguredMTU != 1280 || got.Metadata().HomeLANAccess {
			t.Fatal("historical MTU or omitempty LAN false changed the requested device policy")
		}
	}
	for _, mtu := range []int{1280, 9000} {
		p := desktopProfile()
		p["mtu_policy"], p["manual_mtu"] = "fixed", mtu
		if desktopPolicy(t, p, "linux").Metadata().ConfiguredMTU != mtu {
			t.Fatal("valid fixed interface capacity was not retained")
		}
	}
}

func TestDesktopBridgeJumboCapturesOnlyVirtualInterfaceCapacity(t *testing.T) {
	for _, target := range []string{"linux", "darwin", "windows"} {
		for _, mtuPolicy := range []string{"", "auto", "default", "manual", "fixed"} {
			t.Run(target+"/"+mtuPolicy, func(t *testing.T) {
				profile := desktopProfile()
				profile["mtu_policy"], profile["manual_mtu"], profile["effective_mtu"] = mtuPolicy, 9000, 1420
				profile["dns_protocol"], profile["dns_server_name"], profile["dns_path"] = "doh", "selected.example", "/chosen-query?network=one"
				profile["home_lan_access"], profile["ipv6_mode"] = false, "off"
				plain := desktopPolicy(t, profile, target)
				profile["jumbo_tun"] = true
				source := torHostEncode(t, profile)
				if err := ValidateDesktopBridgeProfile(source); err != nil {
					t.Fatal("valid idle Jumbo preference was rejected", err)
				}
				jumbo := desktopPolicy(t, profile, target)
				meta := jumbo.Metadata()
				wantPolicy := mtuPolicy
				if wantPolicy == "" {
					wantPolicy = "auto"
				}
				if !meta.JumboTUN || meta.ConfiguredMTU != 9000 || meta.MTUPolicy != wantPolicy || meta.KillSwitchPolicy != "on-connect" ||
					meta.SourceSHA256 == plain.SourceSHA256() || jumbo.Profile() != source || source != torHostEncode(t, profile) {
					t.Fatal("Jumbo lost its requested interface, source or strict policy", meta)
				}
				graph, err := profileObject(jumbo.Config(), 4<<20)
				if err != nil {
					t.Fatal(err)
				}
				base, err := profileObject(plain.Config(), 4<<20)
				if err != nil {
					t.Fatal(err)
				}
				tun := graph["inbounds"].([]any)[0].(map[string]any)
				if tun["mtu"] != json.Number("9000") || tun["stack"] != "system" || tun["auto_route"] != true || tun["strict_route"] != true {
					t.Fatal("Jumbo was not applied to the captured system TUN")
				}
				// Only the owned virtual capacity and its source-bound observer
				// identity may change. DNS, SOCKS isolation, PT bootstrap, device
				// routes and the physical network policy remain byte-equivalent.
				tun["mtu"] = base["inbounds"].([]any)[0].(map[string]any)["mtu"]
				graph["services"].([]any)[0].(map[string]any)["source_sha256"] = plain.SourceSHA256()
				if !reflect.DeepEqual(graph, base) || meta.DNS != plain.Metadata().DNS || meta.ConfigSHA256 != desktopDigest([]byte(jumbo.Config())) {
					t.Fatal("Jumbo changed a transport, resolver or protected route")
				}
			})
		}
	}
}

func TestDesktopBridgeJumboRejectsConflictingFixedAndUntypedPreferences(t *testing.T) {
	for _, value := range []any{1280, 1492, 0, 9001, "9000"} {
		for _, policy := range []string{"manual", "fixed"} {
			profile := desktopProfile()
			profile["jumbo_tun"], profile["mtu_policy"], profile["manual_mtu"] = true, policy, value
			source := torHostEncode(t, profile)
			if ValidateDesktopBridgeProfile(source) == nil {
				t.Fatal("conflicting idle Jumbo and Fixed preference was accepted", policy, value)
			}
			if compiled, err := NewDesktopBridgePolicy(source, desktopSession, desktopIsolation, "linux"); err == nil || compiled != nil {
				t.Fatal("conflicting Jumbo and Fixed preference reached the native graph", policy, value)
			}
		}
	}
	for _, value := range []any{"true", 1, nil} {
		profile := desktopProfile()
		profile["jumbo_tun"] = value
		source := torHostEncode(t, profile)
		if ValidateDesktopBridgeProfile(source) == nil {
			t.Fatal("untyped Jumbo preference was accepted", value)
		}
		if compiled, err := NewDesktopBridgePolicy(source, desktopSession, desktopIsolation, "linux"); err == nil || compiled != nil {
			t.Fatal("untyped Jumbo preference reached the native graph", value)
		}
	}
}

func TestDesktopBridgeSourceAndPlanRemainCaptured(t *testing.T) {
	p := desktopProfile()
	policy := desktopPolicy(t, p, "linux")
	plan, err := policy.Plan()
	if err != nil {
		t.Fatal(err)
	}
	plan.Bridges[0].Line = meekBridge
	plan.Bridges[0].Arguments["cert"] = "changed"
	again, err := policy.Plan()
	if err != nil || again.Bridges[0].Line != obfs4Bridge || again.Bridges[0].Arguments["cert"] != "Y2VydA" {
		t.Fatal("exported plan mutated the captured policy")
	}
	meta := policy.Metadata()
	meta.DNS.Address = "1.1.1.1"
	if policy.Metadata().DNS.Address != "9.9.9.9" {
		t.Fatal("metadata mutation changed selected DNS")
	}
	for _, changed := range [][4]string{
		{policy.Profile() + " ", desktopSession, desktopIsolation, "linux"},
		{policy.Profile(), strings.Repeat("b", 32), desktopIsolation, "linux"},
		{policy.Profile(), desktopSession, strings.Repeat("b", 64), "linux"},
		{policy.Profile(), desktopSession, desktopIsolation, "windows"},
	} {
		other, err := NewDesktopBridgePolicy(changed[0], changed[1], changed[2], changed[3])
		if err != nil || other.SourceSHA256() == policy.SourceSHA256() {
			t.Fatal("changed private source, session, isolation or OS reused an old identity", err)
		}
	}
	encoded, _ := json.Marshal(policy.Metadata())
	if strings.Contains(string(encoded), desktopIsolation) || strings.Contains(string(encoded), "Y2VydA") {
		t.Fatal("public policy metadata exposed private isolation or bridge material")
	}
}

func TestDesktopBridgeIdleHomeIsNotRunnableAndInvalidPolicyDoesNotFallback(t *testing.T) {
	p := desktopProfile()
	for _, key := range []string{"dns_mode", "dns_host", "dns_protocol", "dns_port"} {
		delete(p, key)
	}
	source := torHostEncode(t, p)
	if err := ValidateDesktopBridgeProfile(source); err != nil {
		t.Fatal(err)
	}
	if policy, err := NewDesktopBridgePolicy(source, desktopSession, desktopIsolation, "linux"); err == nil || policy != nil {
		t.Fatal("unresolved Home acquired a runnable public resolver")
	}
	for name, mutate := range map[string]func(map[string]any){
		"dns-hostname":          func(p map[string]any) { p["dns_host"] = "resolver.example" },
		"dns-public-to-private": func(p map[string]any) { p["dns_host"] = "10.0.0.53" },
		"dns-udp":               func(p map[string]any) { p["dns_protocol"] = "udp" },
		"dns-port-type":         func(p map[string]any) { p["dns_port"] = "5353" },
		"dns-tls-identity":      func(p map[string]any) { p["dns_protocol"] = "dot" },
		"dns-path": func(p map[string]any) {
			p["dns_protocol"], p["dns_server_name"], p["dns_path"] = "doh", "resolver.example", "//other.invalid/dns"
		},
		"dns-unowned-bootstrap": func(p map[string]any) { p["dns_bootstrap"] = map[string]any{"server": "1.1.1.1"} },
		"router-credentials":    func(p map[string]any) { p["api_token"] = "private-router-secret" },
		"fixed-zero":            func(p map[string]any) { p["mtu_policy"], p["manual_mtu"] = "manual", 0 },
		"fixed-too-large":       func(p map[string]any) { p["mtu_policy"], p["manual_mtu"] = "fixed", 9001 },
		"fixed-type":            func(p map[string]any) { p["mtu_policy"], p["manual_mtu"] = "fixed", "1400" },
		"ipv6-type":             func(p map[string]any) { p["ipv6_mode"] = true },
		"lan-type":              func(p map[string]any) { p["home_lan_access"] = "false" },
		"lan-public-range":      func(p map[string]any) { p["home_lan_access"], p["home_lan_cidrs"] = false, []string{"10.0.0.0/7"} },
		"kill-type":             func(p map[string]any) { p["kill_switch_policy"] = false },
		"kill-unknown":          func(p map[string]any) { p["kill_switch_policy"] = "maybe" },
		"multihop-type":         func(p map[string]any) { p["multihop_enabled"] = "false" },
		"socks-type": func(p map[string]any) {
			p["external"].(map[string]any)["tor_bridge"].(map[string]any)["socks_port"] = "19950"
		},
		"socks-reserved": func(p map[string]any) {
			p["external"].(map[string]any)["tor_bridge"].(map[string]any)["socks_port"] = 8788
		},
		"bridge-command": func(p map[string]any) {
			p["external"].(map[string]any)["tor_bridge"].(map[string]any)["bridges"] = []string{obfs4Bridge + "\nDisableNetwork 0"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := desktopProfile()
			mutate(p)
			source := torHostEncode(t, p)
			if ValidateDesktopBridgeProfile(source) == nil {
				t.Fatal("invalid idle selection accepted")
			}
			if policy, err := NewDesktopBridgePolicy(source, desktopSession, desktopIsolation, "linux"); err == nil || policy != nil {
				t.Fatal("invalid selection compiled")
			}
		})
	}
}

func TestDesktopBridgeDoesNotDiscardUnimplementedSelections(t *testing.T) {
	for _, key := range []string{"multihop_enabled", "daita_enabled"} {
		p := desktopProfile()
		p[key] = true
		if policy, err := NewDesktopBridgePolicy(torHostEncode(t, p), desktopSession, desktopIsolation, "linux"); err == nil || policy != nil {
			t.Fatal("required unimplemented selection was silently discarded", key)
		}
	}
	for _, parameters := range [][3]string{{"bad", desktopIsolation, "linux"}, {desktopSession, "bad", "linux"}, {desktopSession, desktopIsolation, "android"}} {
		if policy, err := NewDesktopBridgePolicy(torHostEncode(t, desktopProfile()), parameters[0], parameters[1], parameters[2]); err == nil || policy != nil {
			t.Fatal("unowned source identity compiled")
		}
	}
}

func TestDesktopBridgeDynamicPTCannotPretendStrictFirewallSupport(t *testing.T) {
	for _, bridges := range [][]string{{meekBridge}, {obfs4Bridge, meekBridge}} {
		p := desktopProfile()
		block := p["external"].(map[string]any)["tor_bridge"].(map[string]any)
		block["transport"], block["bridges"] = "custom", bridges
		if ValidateDesktopBridgeProfile(torHostEncode(t, p)) == nil {
			t.Fatal("dynamic or multiple bridge egress bypassed strict protection")
		}
		p["kill_switch_policy"] = "off"
		if err := ValidateDesktopBridgeProfile(torHostEncode(t, p)); err != nil {
			t.Fatal(err)
		}
		got, err := desktopPolicy(t, p, "linux").Plan()
		if err != nil || len(got.Bridges) != len(bridges) {
			t.Fatal("non-strict captured bridge plan changed")
		}
	}
}
