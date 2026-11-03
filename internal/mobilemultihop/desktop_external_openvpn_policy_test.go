package mobilemultihop

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/nativeopenvpn"
)

func desktopOpenVPNPhysicalInputs(t *testing.T, network, kill string) (map[string]any, map[string]any, []nativeopenvpn.Remote) {
	t.Helper()
	graph, capture := externalTestFixture(t, "hysteria2", "")
	first, second := network, network
	if network == "mixed" {
		first, second = "tcp", "udp"
	}
	remotes := []nativeopenvpn.Remote{{Host: "203.0.113.20", Port: 1194, Network: first}, {Host: "203.0.113.21", Port: 443, Network: second}, {Host: "2001:db8::24", Port: 8443, Network: first}}
	config := "# original imported source\r\nclient\ndev tun\n"
	for _, remote := range remotes {
		config += fmt.Sprintf("remote %s %d %s\n", remote.Host, remote.Port, remote.Network)
	}
	config += "auth-user-pass\nremote-cert-tls server\nverify-x509-name captured-provider.example name\npeer-fingerprint " + strings.Repeat("ab", 32) + "\ntun-mtu 1500\nmssfix 1400\ndata-ciphers AES-256-GCM:AES-128-GCM\n"
	private := map[string]any{"config": config, "username": " captured user ", "password": " captured password "}
	endpoint, err := nativeopenvpn.CompileEndpoint(config, private["username"].(string), private["password"].(string), ExternalFinalTag, "")
	if err != nil {
		t.Fatal(err)
	}
	graph["outbounds"], graph["endpoints"] = []any{}, []any{externalTestRead(t, endpoint)}
	capture["protocol"] = "openvpn"
	profile := capture["profile"].(map[string]any)
	profile["external"] = map[string]any{"protocol": "openvpn", "expected_public_ip": "203.0.113.88", "openvpn": private}
	profile["kill_switch_policy"], profile["kill_switch"] = kill, kill != "off"
	profile["ipv6_mode"], profile["home_lan_access"] = "on", true
	profile["mtu_policy"], profile["manual_mtu"] = "fixed", float64(1360)
	profile["dns_mode"], profile["dns_protocol"], profile["dns_host"] = "custom", "https", "192.0.2.53"
	profile["dns_port"], profile["dns_server_name"], profile["dns_path"] = float64(5443), "selected.resolver.example", "/captured/query"
	return graph, capture, remotes
}

func TestDesktopExternalOpenVPNPolicyKeepsOrderedRemotesAndCompleteSource(t *testing.T) {
	desktopExternalOpenVPNPolicyKeepsOrderedRemotesAndCompleteSource(t, "linux")
}
func TestDesktopExternalWindowsOpenVPNPolicyKeepsOrderedRemotesAndCompleteSource(t *testing.T) {
	desktopExternalOpenVPNPolicyKeepsOrderedRemotesAndCompleteSource(t, "windows")
}

func desktopExternalOpenVPNPolicyKeepsOrderedRemotesAndCompleteSource(t *testing.T, target string) {
	for _, network := range []string{"tcp", "udp", "mixed"} {
		for _, kill := range []string{"on-connect", "always"} {
			t.Run(network+"/"+kill, func(t *testing.T) {
				graph, selection, want := desktopOpenVPNPhysicalInputs(t, network, kill)
				original := externalDesktopCompile(t, graph, selection)
				before, metadata := original.Config(), original.Metadata()
				originalCapture, err := original.DesktopCapture()
				if err != nil {
					t.Fatal(err)
				}
				policy := desktopExternalPlan(t, original, desktopExternalTestSession, target)
				actual, err := policy.Capture()
				meta := policy.Metadata()
				if err != nil || !reflect.DeepEqual(actual, originalCapture) || policy.OriginalPolicy() != original || policy.Validate() != nil ||
					meta.Protocol != "openvpn" || meta.RootType != "openvpn-client" || meta.TargetOS != target || meta.SOCKSUDPAssociationRequired ||
					meta.OriginalSourceSHA256 != original.SourceSHA256() || meta.OriginalConfigSHA256 != externalDigest([]byte(before)) ||
					meta.OriginalMetadataSHA256 != externalDigest([]byte(metadata)) || meta.OriginalCaptureSHA256 != actual.CaptureSHA256 ||
					meta.KillSwitchPolicy != kill || meta.IPv6Mode != "on" || !meta.HomeLANAccess || actual.ConfiguredMTU != 1360 ||
					actual.SelectedDNS.Host != "192.0.2.53" || actual.SelectedDNS.Port != 5443 || actual.SelectedDNS.Type != "https" || actual.SelectedDNS.Physical ||
					len(actual.PhysicalRoots) != 1 || actual.PhysicalRoots[0].Family != "endpoints" || len(actual.PrivateDestinations) != 0 {
					t.Fatal("OpenVPN adaptation lost complete original policy or invented private/lower authority", meta, err)
				}
				derived := externalTestRead(t, policy.Config())
				endpoints, outbounds, services := derived["endpoints"].([]any), derived["outbounds"].([]any), derived["services"].([]any)
				if len(endpoints) != 1 || len(outbounds) != 1 || len(services) != 1 {
					t.Fatal("OpenVPN acquired a replacement endpoint or bypass path")
				}
				endpoint := endpoints[0].(map[string]any)
				remotes, err := nativeopenvpn.Remotes(endpoint)
				if err != nil || !reflect.DeepEqual(remotes, want) || endpoint["detour"] != DesktopExternalPhysicalTag ||
					meta.OriginalRootSHA256 != actual.PhysicalRoots[0].ConfigSHA256 || meta.DerivedRootSHA256 != desktopExternalObjectDigest(endpoint) {
					t.Fatal("OpenVPN lost ordered TCP/UDP remotes or original/derived endpoint identity", remotes, err)
				}
				expected := make(map[PhysicalEgress]bool)
				for _, remote := range want {
					expected[PhysicalEgress{Host: remote.Host, Port: remote.Port, Network: remote.Network}] = true
				}
				if len(actual.PhysicalRoots[0].Destinations) != len(expected) {
					t.Fatal("captured OpenVPN tuples broadened")
				}
				for _, destination := range actual.PhysicalRoots[0].Destinations {
					if !expected[destination] {
						t.Fatal("remote networks crossed provider addresses", destination)
					}
				}
				delete(endpoint, "detour")
				delete(derived, "services")
				derived["outbounds"] = []any{}
				if !reflect.DeepEqual(derived, externalTestRead(t, before)) || before != original.Config() || metadata != original.Metadata() {
					t.Fatal("OpenVPN adaptation changed credentials, TLS, DNS, MTU, source text or device policy")
				}
				actual.PhysicalRoots[0].Destinations[0].Port++
				again, err := policy.Capture()
				if err != nil || !reflect.DeepEqual(again, originalCapture) {
					t.Fatal("caller-owned tuple mutation changed sealed policy", err)
				}
			})
		}
	}
}

func TestDesktopExternalOpenVPNPolicyKeepsUnsupportedHostAndGraphGuards(t *testing.T) {
	reject := func(t *testing.T, original *ExternalPolicy, target string) {
		t.Helper()
		before := original.Config()
		if _, err := original.DesktopCapture(); err != nil {
			t.Fatal("negative requires an independently valid complete policy", err)
		}
		if next, err := NewDesktopExternalPolicy(original, desktopExternalTestSession, target); err == nil || next != nil || original.Config() != before {
			t.Fatal("unsupported OpenVPN capture acquired a retained owner", target)
		}
	}
	for _, target := range []string{"darwin", "android"} {
		t.Run(target, func(t *testing.T) {
			graph, capture, _ := desktopOpenVPNPhysicalInputs(t, "mixed", "always")
			reject(t, externalDesktopCompile(t, graph, capture), target)
		})
	}
	t.Run("off", func(t *testing.T) {
		graph, capture, _ := desktopOpenVPNPhysicalInputs(t, "mixed", "off")
		reject(t, externalDesktopCompile(t, graph, capture), "linux")
		reject(t, externalDesktopCompile(t, graph, capture), "windows")
	})
	for _, entry := range []string{"router-wg", "socks5", "shadowsocks", "hysteria2"} {
		t.Run("predecessor/"+entry, func(t *testing.T) {
			graph, capture := externalTestFixture(t, "hysteria2", entry)
			externalOpenVPNReplace(t, graph, capture, false, "tcp")
			capture["profile"].(map[string]any)["kill_switch_policy"] = "always"
			reject(t, externalDesktopCompile(t, graph, capture), "linux")
			reject(t, externalDesktopCompile(t, graph, capture), "windows")
		})
	}
	for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		t.Run("start-layer/"+layer, func(t *testing.T) {
			source, raw := externalOpenVPNExecutionFixture(t, "local", layer)
			graph, capture := externalTestRead(t, source), externalTestRead(t, raw)
			final := externalTestFind(t, graph, ExternalFinalTag)
			delete(final, "detour")
			graph["endpoints"] = []any{final}
			delete(capture, "entry")
			delete(capture, "entry_tag")
			delete(capture, "predecessor_config")
			profile := capture["profile"].(map[string]any)
			profile["kill_switch_policy"], profile["multihop_enabled"] = "always", false
			external := profile["external"].(map[string]any)
			delete(external, "response_probe")
			delete(external, "openvpn_pairing")
			original, err := NewExternalPolicy(externalTestJSON(t, graph), externalTestJSON(t, capture))
			if err != nil {
				t.Fatal(err)
			}
			captured, err := original.DesktopCapture()
			if err != nil || captured.StartLayer != layer || captured.EntryID != "" || captured.PredecessorSHA256 != "" {
				t.Fatal("layer guard fixture acquired an unrelated predecessor", err)
			}
			reject(t, original, "linux")
			reject(t, original, "windows")
		})
	}
	for _, choice := range []string{"server", "auto"} {
		t.Run("execution/"+choice, func(t *testing.T) {
			source, raw := externalOpenVPNExecutionFixture(t, choice, "")
			capture := externalTestRead(t, raw)
			capture["profile"].(map[string]any)["kill_switch_policy"] = "always"
			prepared, err := PrepareExternalExecutionCapture(source, externalTestJSON(t, capture), "")
			if err != nil {
				t.Fatal(err)
			}
			original, err := NewExternalPolicy(source, prepared)
			if err != nil {
				t.Fatal(err)
			}
			reject(t, original, "linux")
			reject(t, original, "windows")
		})
	}
}
