package mobilemultihop

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func externalAmneziaReplace(t *testing.T, graph, capture map[string]any, entry bool, variant string) {
	t.Helper()
	tag, field, detour, mtu := ExternalFinalTag, "profile", predecessorText(capture, "entry_tag"), 1280
	if entry {
		tag, field, detour, mtu = predecessorText(capture, "entry_tag"), "entry", "", 1500
	} else {
		capture["protocol"] = "amneziawg"
	}
	raw, id := amneziaFixture()
	raw = strings.Replace(raw, "MTU = 1420", fmt.Sprint("MTU = ", mtu), 1)
	if entry {
		raw = strings.Replace(raw, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32))), base64.StdEncoding.EncodeToString([]byte(strings.Repeat("e", 32))), 1)
	}
	if variant == "fast" {
		raw = strings.NewReplacer("Jc=3", "Jc=0", "Jmin=40", "Jmin=20", "Jmax=900", "Jmax=40", "S4=32", "S4=8").Replace(raw)
	}
	compiled, err := CompileAmneziaProfile(raw, id)
	if err != nil {
		t.Fatal(err)
	}
	parsed := startObject(t, compiled)
	endpoint := parsed["endpoint"].(map[string]any)
	endpoint["tag"] = tag
	if detour != "" {
		endpoint["detour"] = detour
	}
	peer := endpoint["peers"].([]any)[0].(map[string]any)
	credentials := map[string]any{"private_key": endpoint["private_key"], "addresses": endpoint["address"], "peer_public_key": peer["public_key"],
		"preshared_key": peer["pre_shared_key"], "endpoint": net.JoinHostPort(peer["address"].(string), fmt.Sprint(peer["port"])),
		"allowed_ips": peer["allowed_ips"], "dns": parsed["dns"], "mtu": endpoint["mtu"],
		"persistent_keepalive_interval": peer["persistent_keepalive_interval"], "parameters": endpoint["amnezia"]}
	for _, family := range []string{"outbounds", "endpoints"} {
		rows, _ := graph[family].([]any)
		kept := []any{}
		for _, value := range rows {
			if value.(map[string]any)["tag"] != tag {
				kept = append(kept, value)
			}
		}
		graph[family] = kept
	}
	graph["endpoints"] = append(graph["endpoints"].([]any), endpoint)
	profile := capture[field].(map[string]any)
	profile["external"] = map[string]any{"protocol": "amneziawg", "expected_public_ip": "203.0.113.88", "amneziawg": credentials}
	// The native endpoint and private saved profile are independent snapshots.
	profile["external"] = startObject(t, startJSON(t, profile["external"]))
}

func TestExternalAmneziaCompletePredecessors(t *testing.T) {
	count := 0
	for _, mode := range predecessorFamilies {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, variant := range []string{"fast", "strong"} {
				t.Run(mode+"/"+layer+"/"+variant, func(t *testing.T) {
					graph, capture := externalTestFixture(t, "wireguard", "")
					externalAmneziaReplace(t, graph, capture, false, variant)
					source, entry := externalPredecessorFixture(t, mode, layer, true)
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
					if !reflect.DeepEqual(before, actual) || actual["type"] != AmneziaType || meta["protocol"] != "amneziawg" || meta["entry_proof"] != "required" || meta["dns_proof"] != "required" || meta["public_exit_proof"] != "required" {
						t.Fatal("imported AWG source, native protocol or owned proofs lost")
					}
					if _, err := AmneziaRuntimeConfig(startJSON(t, actual)); err != nil {
						t.Fatal("preserved AWG cannot reach the pinned native adapter", err)
					}
					if directory := os.Getenv("ROUTERVPN_EXTERNAL_AWG_GRAPHS"); directory != "" {
						if err := os.WriteFile(filepath.Join(directory, mode+"-"+layer+"-"+variant+".json"), []byte(policy.Config()), 0600); err != nil {
							t.Fatal(err)
						}
					}
					count++
				})
			}
		}
	}
	if count != 114 {
		t.Fatal("incomplete imported AWG predecessor matrix", count)
	}
}

func TestExternalAmneziaImportedRolesAndOuterUDP(t *testing.T) {
	for _, protocol := range append(append([]string{}, externalTestProtocols...), "amneziawg", "openvpn") {
		t.Run("entry/"+protocol, func(t *testing.T) {
			base := protocol
			if base == "amneziawg" || base == "openvpn" {
				base = "wireguard"
			}
			graph, capture := externalTestFixture(t, base, "wireguard")
			externalAmneziaReplace(t, graph, capture, true, "strong")
			if protocol == "amneziawg" {
				externalAmneziaReplace(t, graph, capture, false, "fast")
			} else if protocol == "openvpn" {
				externalOpenVPNReplace(t, graph, capture, false, "udp")
			}
			policy, err := NewExternalPolicy(startJSON(t, graph), startJSON(t, capture))
			if err != nil {
				t.Fatal(err)
			}
			actual := externalTestFind(t, startObject(t, policy.Config()), capture["entry_tag"].(string))
			if !reflect.DeepEqual(actual, externalTestFind(t, graph, capture["entry_tag"].(string))) {
				t.Fatal("imported AWG entry changed its captured endpoint or MTU")
			}
		})
	}
	for _, entry := range append(append([]string{""}, externalTestProtocols...), "openvpn") {
		t.Run("exit/"+entry, func(t *testing.T) {
			base := entry
			if base == "openvpn" {
				base = "wireguard"
			}
			graph, capture := externalTestFixture(t, "wireguard", base)
			externalAmneziaReplace(t, graph, capture, false, "strong")
			if entry == "openvpn" {
				externalOpenVPNReplace(t, graph, capture, true, "tcp")
				capture["entry"].(map[string]any)["mtu_policy"] = "fixed"
				capture["entry"].(map[string]any)["manual_mtu"] = float64(1500)
			}
			_, err := NewExternalPolicy(startJSON(t, graph), startJSON(t, capture))
			if (err != nil) != (entry == "http-connect" || entry == "https-connect") {
				t.Fatal("incorrect AWG UDP carrier admission", err)
			}
		})
	}
}

func TestExternalAmneziaExactCaptureRejectsChanges(t *testing.T) {
	mutations := map[string]func(map[string]any, map[string]any){
		"WG substitution":   func(e, _ map[string]any) { e["type"] = "wireguard"; delete(e, "amnezia") },
		"lost parameters":   func(e, _ map[string]any) { delete(e, "amnezia") },
		"changed S4":        func(e, _ map[string]any) { e["amnezia"].(map[string]any)["s4"] = "64" },
		"changed range":     func(e, _ map[string]any) { e["amnezia"].(map[string]any)["h1"] = "50000000-59999999" },
		"numeric parameter": func(e, _ map[string]any) { e["amnezia"].(map[string]any)["s4"] = float64(32) },
		"native extra":      func(e, _ map[string]any) { e["fwmark"] = float64(9) },
		"second TUN":        func(e, _ map[string]any) { e["system"] = true },
		"listener":          func(e, _ map[string]any) { e["listen_port"] = float64(9999) },
		"changed keepalive": func(e, _ map[string]any) {
			e["peers"].([]any)[0].(map[string]any)["persistent_keepalive_interval"] = float64(45)
		},
		"capture extra":              func(_, s map[string]any) { s["unowned"] = true },
		"missing capture parameters": func(_, s map[string]any) { delete(s, "parameters") },
		"wrong captured peer":        func(_, s map[string]any) { s["peer_public_key"] = s["private_key"] },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			graph, capture := externalTestFixture(t, "wireguard", "")
			externalAmneziaReplace(t, graph, capture, false, "strong")
			source := capture["profile"].(map[string]any)["external"].(map[string]any)["amneziawg"].(map[string]any)
			mutate(externalTestFind(t, graph, ExternalFinalTag), source)
			if _, err := NewExternalPolicy(startJSON(t, graph), startJSON(t, capture)); err == nil {
				t.Fatal("changed imported AWG policy accepted")
			}
		})
	}
}

func TestExternalAmneziaMTUIncludesExactS4(t *testing.T) {
	for _, row := range []struct {
		host  string
		limit int
	}{{"192.0.2.1", 1328}, {"2001:db8::1", 1296}} {
		graph, capture := externalTestFixture(t, "wireguard", "wireguard")
		externalAmneziaReplace(t, graph, capture, false, "strong")
		endpoint := externalTestFind(t, graph, ExternalFinalTag)
		endpoint["mtu"] = float64(1420)
		endpoint["peers"].([]any)[0].(map[string]any)["address"] = row.host
		source := capture["profile"].(map[string]any)["external"].(map[string]any)["amneziawg"].(map[string]any)
		source["mtu"], source["endpoint"] = float64(1420), net.JoinHostPort(row.host, "51820")
		policy, err := NewExternalPolicy(startJSON(t, graph), startJSON(t, capture))
		if err != nil {
			t.Fatal(err)
		}
		if actual := externalTestFind(t, startObject(t, policy.Config()), ExternalFinalTag); actual["mtu"] != float64(row.limit) || actual["amnezia"].(map[string]any)["s4"] != "32" {
			t.Fatal("nested MTU ignored captured AWG transport padding")
		}
		capture["profile"].(map[string]any)["mtu_policy"] = "fixed"
		capture["profile"].(map[string]any)["manual_mtu"] = float64(1380)
		if _, err := NewExternalPolicy(startJSON(t, graph), startJSON(t, capture)); err == nil {
			t.Fatal("oversized fixed AWG inner MTU silently clamped")
		}
	}
}
