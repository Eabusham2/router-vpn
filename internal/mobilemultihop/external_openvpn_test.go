package mobilemultihop

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/nativeopenvpn"
)

func externalOpenVPNReplace(t *testing.T, graph, capture map[string]any, entry bool, network string) {
	t.Helper()
	tag, field, host, detour := ExternalFinalTag, "profile", "203.0.113.24", predecessorText(capture, "entry_tag")
	if entry {
		tag, field, host, detour = predecessorText(capture, "entry_tag"), "entry", "198.51.100.24", ""
	} else {
		capture["protocol"] = "openvpn"
	}
	config := "client\ndev tun\nproto " + network + "\nremote " + host + " 1194\nremote 2001:db8::24 443\nauth-user-pass\nremote-cert-tls server\npeer-fingerprint " + strings.Repeat("ab", 32) + "\ntun-mtu 1280\ndata-ciphers AES-256-GCM:AES-128-GCM\n"
	credentials := map[string]any{"config": config, "username": " captured user ", "password": " captured secret "}
	compiled, err := nativeopenvpn.CompileEndpoint(config, credentials["username"].(string), credentials["password"].(string), tag, detour)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := startObject(t, compiled)
	for _, family := range []string{"outbounds", "endpoints"} {
		rows, _ := graph[family].([]any)
		kept := []any{}
		for _, raw := range rows {
			if raw.(map[string]any)["tag"] != tag {
				kept = append(kept, raw)
			}
		}
		graph[family] = kept
	}
	graph["endpoints"] = append(graph["endpoints"].([]any), endpoint)
	profile := capture[field].(map[string]any)
	profile["external"] = map[string]any{"protocol": "openvpn", "expected_public_ip": "203.0.113.88", "openvpn": credentials}
}

func TestExternalOpenVPNCompletePredecessors(t *testing.T) {
	count := 0
	for _, mode := range predecessorFamilies {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, network := range []string{"tcp", "udp"} {
				t.Run(mode+"/"+layer+"/"+network, func(t *testing.T) {
					graph, capture := externalTestFixture(t, "hysteria2", "")
					externalOpenVPNReplace(t, graph, capture, false, network)
					source, entry := externalPredecessorFixture(t, mode, layer, true)
					predecessor := startObject(t, source)
					for _, family := range []string{"endpoints", "outbounds"} {
						if predecessor[family] == nil {
							predecessor[family] = []any{}
						}
					}
					final := externalTestFind(t, predecessor, predecessor["route"].(map[string]any)["final"].(string))
					if final["type"] == "wireguard" || final["type"] == AmneziaType || final["type"] == PQType {
						final["mtu"] = float64(1500)
						entry["mtu_policy"], entry["manual_mtu"] = "fixed", float64(1500)
						predecessor["inbounds"].([]any)[0].(map[string]any)["mtu"] = float64(1500)
					}
					source = startJSON(t, predecessor)
					capture["entry"], capture["entry_tag"], capture["predecessor_config"] = entry, externalEntryTag, source
					capture["profile"].(map[string]any)["multihop_entry_mode"] = mode
					before := predecessorCopy(externalTestFind(t, graph, ExternalFinalTag))
					policy, err := NewExternalPolicy(startJSON(t, graph), startJSON(t, capture))
					if err != nil {
						t.Fatal(err)
					}
					result, meta := startObject(t, policy.Config()), startObject(t, policy.Metadata())
					actual := predecessorCopy(externalTestFind(t, result, ExternalFinalTag))
					delete(actual, "detour")
					if !reflect.DeepEqual(actual, before) || meta["udp_available"] != true || meta["entry_proof"] != "required" || meta["public_exit_proof"] != "required" || meta["dns_proof"] != "required" {
						t.Fatal("OpenVPN source options, encapsulated UDP, or proofs lost")
					}
					if meta["predecessor_sha256"] != externalDigest([]byte(source)) || meta["auto_mtu"] != "unmeasured" {
						t.Fatal("predecessor capture or unmeasured MTU truth lost")
					}
					if directory := os.Getenv("ROUTERVPN_EXTERNAL_OPENVPN_GRAPHS"); directory != "" {
						name := mode + "-" + layer + "-" + network + ".json"
						if err := os.WriteFile(filepath.Join(directory, name), []byte(policy.Config()), 0600); err != nil {
							t.Fatal(err)
						}
					}
					count++
				})
			}
		}
	}
	if count != 114 {
		t.Fatal("incomplete OpenVPN predecessor matrix", count)
	}
}

func TestExternalOpenVPNExactCaptureRejectsChangedOptions(t *testing.T) {
	mutations := map[string]func(map[string]any, map[string]any){
		"server": func(endpoint, _ map[string]any) { endpoint["server"] = "203.0.113.99" },
		"remote order": func(endpoint, _ map[string]any) {
			values := endpoint["servers"].([]any)
			values[0], values[1] = values[1], values[0]
		},
		"later remote": func(endpoint, _ map[string]any) {
			endpoint["servers"].([]any)[1].(map[string]any)["server_port"] = float64(4433)
		},
		"password trimmed": func(endpoint, _ map[string]any) {
			endpoint["password"] = strings.TrimSpace(endpoint["password"].(string))
		},
		"unknown field": func(endpoint, _ map[string]any) { endpoint["bind_interface"] = "wlan0" },
		"second VPN":    func(endpoint, _ map[string]any) { endpoint["system"] = true },
		"lost TLS":      func(endpoint, _ map[string]any) { delete(endpoint, "tls") },
		"changed fingerprint": func(endpoint, _ map[string]any) {
			endpoint["tls"].(map[string]any)["peer_fingerprint"] = []any{strings.Repeat("cd", 32)}
		},
		"insecure TLS":    func(endpoint, _ map[string]any) { endpoint["tls"].(map[string]any)["insecure"] = true },
		"changed mode":    func(endpoint, _ map[string]any) { endpoint["mode"] = "static" },
		"removed capture": func(_, capture map[string]any) { capture["profile"].(map[string]any)["node_kind"] = "router-vpn" },
		"injected script": func(_, capture map[string]any) {
			ovpn := capture["profile"].(map[string]any)["external"].(map[string]any)["openvpn"].(map[string]any)
			ovpn["config"] = ovpn["config"].(string) + "up arbitrary-command\n"
		},
		"changed capture": func(_, capture map[string]any) {
			capture["profile"].(map[string]any)["external"].(map[string]any)["openvpn"].(map[string]any)["password"] = "different"
		},
		"unknown capture": func(_, capture map[string]any) {
			capture["profile"].(map[string]any)["external"].(map[string]any)["openvpn"].(map[string]any)["command"] = "unexpected"
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			graph, capture := externalTestFixture(t, "hysteria2", "")
			externalOpenVPNReplace(t, graph, capture, false, "tcp")
			mutate(externalTestFind(t, graph, ExternalFinalTag), capture)
			if _, err := NewExternalPolicy(startJSON(t, graph), startJSON(t, capture)); err == nil {
				t.Fatal("accepted modified native OpenVPN capture", name)
			}
		})
	}
}

func TestExternalOpenVPNOuterTransportAndVirtualUDP(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		graph, capture := externalTestFixture(t, "hysteria2", "http-connect")
		externalOpenVPNReplace(t, graph, capture, false, network)
		profile := capture["profile"].(map[string]any)
		profile["dns_mode"], profile["dns_host"], profile["dns_protocol"], profile["dns_port"] = "custom", "9.9.9.9", "udp", float64(5353)
		policy, err := NewExternalPolicy(startJSON(t, graph), startJSON(t, capture))
		if network == "udp" {
			if err == nil {
				t.Fatal("UDP OpenVPN crossed a TCP-only predecessor")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		meta := startObject(t, policy.Metadata())
		if meta["udp_available"] != true || meta["dns_protocol"] != "udp" {
			t.Fatal("encapsulated UDP DNS was disabled")
		}
		// A later UDP remote must not bypass eligibility while TCP is first.
		endpoint := externalTestFind(t, graph, ExternalFinalTag)
		endpoint["servers"].([]any)[1].(map[string]any)["network"] = "udp"
		config := profile["external"].(map[string]any)["openvpn"].(map[string]any)
		config["config"] = strings.Replace(config["config"].(string), "remote 2001:db8::24 443", "remote 2001:db8::24 443 udp", 1)
		if _, err := NewExternalPolicy(startJSON(t, graph), startJSON(t, capture)); err == nil {
			t.Fatal("UDP fallback remote bypassed predecessor eligibility")
		}
	}
}

func TestExternalOpenVPNEntryAndFixedMTUOwnership(t *testing.T) {
	for _, protocol := range append(append([]string{}, externalTestProtocols...), "openvpn") {
		graph, capture := externalTestFixture(t, "hysteria2", "wireguard")
		if protocol == "openvpn" {
			externalOpenVPNReplace(t, graph, capture, false, "tcp")
		} else {
			graph, capture = externalTestFixture(t, protocol, "wireguard")
		}
		externalOpenVPNReplace(t, graph, capture, true, "tcp")
		entry := capture["entry"].(map[string]any)
		entry["mtu_policy"], entry["manual_mtu"] = "fixed", float64(1500)
		capture["profile"].(map[string]any)["mtu_policy"], capture["profile"].(map[string]any)["manual_mtu"] = "fixed", float64(1380)
		policy, err := NewExternalPolicy(startJSON(t, graph), startJSON(t, capture))
		if err != nil {
			t.Fatal(protocol, err)
		}
		result, meta := startObject(t, policy.Config()), startObject(t, policy.Metadata())
		if externalTestFind(t, result, externalEntryTag)["mtu"] != float64(1500) || meta["configured_mtu"] != float64(1380) || meta["entry_mtu"] != float64(1500) {
			t.Fatal("OpenVPN entry MTU was confused with the shared TUN")
		}
	}
	graph, capture := externalTestFixture(t, "hysteria2", "wireguard")
	externalOpenVPNReplace(t, graph, capture, false, "udp")
	entry, profile := capture["entry"].(map[string]any), capture["profile"].(map[string]any)
	entry["mtu_policy"], entry["manual_mtu"] = "fixed", float64(1500)
	profile["mtu_policy"], profile["manual_mtu"] = "fixed", float64(1500)
	if _, err := NewExternalPolicy(startJSON(t, graph), startJSON(t, capture)); err == nil {
		t.Fatal("oversized fixed UDP OpenVPN packet accepted")
	}
	// Explicit imported fragmentation may carry the larger inner packet, but
	// only when each framed datagram fits its separately captured packet entry.
	for _, fragment := range []int{1400, 1490} {
		ovpn := profile["external"].(map[string]any)["openvpn"].(map[string]any)
		source := strings.Split(ovpn["config"].(string), "fragment ")[0]
		encoded, _ := json.Marshal(fragment)
		ovpn["config"] = source + "fragment " + string(encoded) + "\n"
		compiled, err := nativeopenvpn.CompileEndpoint(ovpn["config"].(string), ovpn["username"].(string), ovpn["password"].(string), ExternalFinalTag, externalEntryTag)
		if err != nil {
			t.Fatal(err)
		}
		graph["endpoints"].([]any)[len(graph["endpoints"].([]any))-1] = startObject(t, compiled)
		_, err = NewExternalPolicy(startJSON(t, graph), startJSON(t, capture))
		if (err == nil) != (fragment == 1400) {
			t.Fatal("fragment wire bound not enforced", fragment, err)
		}
	}
}
