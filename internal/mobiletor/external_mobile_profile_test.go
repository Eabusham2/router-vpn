package mobiletor

import (
	"encoding/json"
	"strings"
	"testing"
)

func mobileExternalTorSelection(t *testing.T, protocol string) (map[string]any, map[string]any, map[string]any) {
	t.Helper()
	entry, graph := externalTorPredecessorFixture(t, protocol)
	exit := torHostProfile()
	torHomePair(exit, entry)
	exit["multihop_entry_mode"] = protocol
	return exit, entry, graph
}

func TestMobileExternalTorCompilesExactOrdinarySourceAndDistinctPolicies(t *testing.T) {
	for _, protocol := range []string{"wireguard", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2"} {
		for _, dns := range []string{"tcp", "dot", "doh"} {
			for _, mtu := range []string{"auto", "fixed", "jumbo"} {
				t.Run(protocol+"/"+dns+"/"+mtu, func(t *testing.T) {
					exit, entry, graph := mobileExternalTorSelection(t, protocol)
					exit["dns_protocol"], exit["dns_server_name"], exit["dns_path"] = dns, "selected.example", "/selected-query"
					if mtu == "fixed" {
						entry["mtu_policy"], entry["manual_mtu"] = "fixed", 1400
					} else if mtu == "jumbo" {
						exit["jumbo_tun"] = true
					}
					profile, provider, original := torHostEncode(t, exit), torHostEncode(t, entry), torHostEncode(t, graph)
					compiled, err := CompileProfileWithExternalPredecessor(profile, "ordinary-tor-session", original, provider)
					if err != nil {
						t.Fatal(err)
					}
					owner, err := NewExternalPredecessorProof(provider, original)
					if err != nil {
						t.Fatal(err)
					}
					root, _ := profileObject(compiled, 4<<20)
					outbound := torHostTagged(t, root["outbounds"], ProfileOutboundTag)
					if outbound["external_predecessor_profile"] != owner.Profile() || outbound["external_predecessor_config"] != original || outbound["external_tor_profile"] != profile ||
						outbound["detour"] != "custom-exit" || outbound["entry_sha256"] != owner.Fingerprint() {
						t.Fatal("native ordinary capture replaced transport source or proof identity")
					}
					selected := torHostTagged(t, root["dns"].(map[string]any)["servers"], profileDNS)
					bootstrap := torHostTagged(t, root["dns"].(map[string]any)["servers"], bootstrapDNS)
					if selected["detour"] != ProfileOutboundTag || bootstrap["detour"] != "custom-exit" || selected["server"] != exit["dns_host"] {
						t.Fatal("selected DNS or Tor bootstrap escaped its captured route")
					}
					if _, err := MTUAuthorityWithExternalPredecessor(compiled, profile, "ordinary-tor-session", owner); err != nil {
						t.Fatal("captured ordinary graph cannot reach native MTU ownership", err)
					}
					if _, err := MTUAuthorityWithPredecessor(compiled, profile, "ordinary-tor-session", nil); err == nil {
						t.Fatal("ordinary MTU acquired private or missing predecessor authority")
					}
					if profile != torHostEncode(t, exit) || provider != torHostEncode(t, entry) || original != torHostEncode(t, graph) {
						t.Fatal("ordinary Tor compilation changed caller-owned source")
					}
					again, err := CompileProfileWithExternalPredecessor(profile, "ordinary-tor-session", original, provider)
					if err != nil || compiled != again {
						t.Fatal("native reconstruction changed the exact captured graph", err)
					}
				})
			}
		}
	}
}

func TestMobileExternalTorRejectsMixedAuthorityAndChangedOwners(t *testing.T) {
	for _, fault := range []string{"home", "server", "compare", "entry-id", "exit-id", "entry-mode", "entry-private", "entry-secret", "fixed-conflict", "local-padding"} {
		t.Run(fault, func(t *testing.T) {
			exit, entry, graph := mobileExternalTorSelection(t, "socks5")
			switch fault {
			case "home":
				exit["dns_mode"], exit["dns_host"] = "home", "10.77.0.53"
			case "server":
				exit["multihop_execution"] = "server"
			case "compare":
				exit["multihop_execution"] = "auto"
			case "entry-id":
				exit["multihop_entry_id"] = "another-provider"
			case "exit-id":
				exit["multihop_exit_id"] = "another-tor"
			case "entry-mode":
				exit["multihop_entry_mode"] = "wireguard"
			case "entry-private":
				entry["api_token"] = "unowned-private-credential"
			case "entry-secret":
				graph["outbounds"].([]any)[0].(map[string]any)["password"] = "another-provider-password"
			case "fixed-conflict":
				entry["mtu_policy"], entry["manual_mtu"] = "fixed", 1400
				exit["mtu_policy"], exit["manual_mtu"] = "fixed", 1450
			case "local-padding":
				exit["daita_enabled"] = true
			}
			compiled, err := CompileProfileWithExternalPredecessor(torHostEncode(t, exit), "ordinary-tor-session", torHostEncode(t, graph), torHostEncode(t, entry))
			if err == nil || compiled != "" || strings.Contains(err.Error(), "unowned-private-credential") || strings.Contains(err.Error(), "another-provider-password") {
				t.Fatal("invalid ordinary authority reached native compilation or leaked credentials", err)
			}
		})
	}
}

func TestMobileExternalTorProfileMatchAndMTURequireExactCapturedSource(t *testing.T) {
	exit, entry, graph := mobileExternalTorSelection(t, "socks5")
	provider, source := torHostEncode(t, entry), torHostEncode(t, graph)
	owner, err := NewExternalPredecessorProof(provider, source)
	if err != nil {
		t.Fatal(err)
	}
	formatted, _ := json.MarshalIndent(entry, "", "  ")
	if !owner.MatchesProfile(string(formatted)) {
		t.Fatal("formatting changed canonical provider identity")
	}
	entry["dns_host"] = "1.1.1.1"
	if owner.MatchesProfile(torHostEncode(t, entry)) || (*ExternalPredecessorProof)(nil).MatchesProfile(provider) {
		t.Fatal("changed or missing provider acquired ordinary source authority")
	}
	compiled, err := CompileProfileWithExternalPredecessor(torHostEncode(t, exit), "ordinary-tor-session", source, provider)
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"missing", "different-source", "different-exit", "different-session"} {
		candidate, profile, session := owner, torHostEncode(t, exit), "ordinary-tor-session"
		switch fault {
		case "missing":
			candidate = nil
		case "different-source":
			candidate, err = NewExternalPredecessorProof(torHostEncode(t, entry), source)
			if err != nil {
				t.Fatal(err)
			}
		case "different-exit":
			changed, _ := profileObject(profile, 256<<10)
			changed["dns_host"] = "1.1.1.1"
			profile = torHostEncode(t, changed)
		case "different-session":
			session = "replacement-session"
		}
		if _, err := MTUAuthorityWithExternalPredecessor(compiled, profile, session, candidate); err == nil {
			t.Fatal("changed source acquired retained native MTU", fault)
		}
	}
}
