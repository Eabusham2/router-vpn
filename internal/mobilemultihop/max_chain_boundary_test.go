package mobilemultihop

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/multihoprelay"
)

func compiledMAXBoundary(t *testing.T, mode, layer, service string) (map[string]any, []any, string) {
	t.Helper()
	files, policy := maxFixture(t, mode)
	var metadata map[string]any
	if err := json.Unmarshal([]byte(policy), &metadata); err != nil {
		t.Fatal(err)
	}
	metadata["start_layer"] = layer
	metadata["router_api"] = "http://" + service + ":8787"
	if strings.Contains(service, ":") {
		metadata["router_api"] = "https://[" + service + "]:8787"
	}
	encoded, _ := json.Marshal(metadata)
	text, err := CompileMAXProfile(mode, pqEncoded(files), string(encoded))
	if err != nil {
		t.Fatal(err)
	}
	var graph map[string]any
	if err = json.Unmarshal([]byte(text), &graph); err != nil {
		t.Fatal(err)
	}
	return graph["endpoints"].([]any)[0].(map[string]any), graph["outbounds"].([]any), metadata["node_id"].(string)
}

func canonicalMAXTags() multihoprelay.MAXTags {
	return multihoprelay.MAXTags{Root: "proxy", Middle: MAXShadowsocksTag, Outer: MAXOuterTag, Start: MAXStartLayerTag}
}

func TestCompleteMAXChainRelabelsWithoutLosingAnyEncryption(t *testing.T) {
	graphs := 0
	for _, mode := range []string{"max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"} {
		for _, layer := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, service := range []string{"10.77.0.1", "fd77:77::1"} {
				t.Run(mode+"/"+layer+"/"+service, func(t *testing.T) {
					base, outs, node := compiledMAXBoundary(t, mode, layer, service)
					before, _ := json.Marshal([]any{base, outs})
					for _, role := range []string{"entry", "exit"} {
						via := ""
						root := "entry-wg"
						if role == "exit" {
							via = "entry-wg"
							root = "proxy"
						}
						names := multihoprelay.MAXTags{Root: root, Middle: "routervpn-" + role + "-max-ss", Outer: "routervpn-" + role + "-max-outer", Start: "routervpn-" + role + "-max-start"}
						ep, mapped, err := multihoprelay.RelabelMAXChain(base, outs, mode, node, layer, canonicalMAXTags(), names, "", via)
						if err != nil {
							t.Fatal(err)
						}
						if ep["detour"] != names.Middle || ep["tag"] != root {
							t.Fatal("chain base changed ownership")
						}
						if err = multihoprelay.ValidateMAXChain(ep, mapped, mode, node, layer, names, via); err != nil {
							t.Fatal(err)
						}
						restored, restoredOut, err := multihoprelay.RelabelMAXChain(ep, mapped, mode, node, layer, names, canonicalMAXTags(), via, "")
						if err != nil || !reflect.DeepEqual(restored, base) || !reflect.DeepEqual(restoredOut, outs) {
							t.Fatal("round trip rewrote encrypted bytes, addresses or policy", err)
						}
						for _, item := range mapped {
							item.(map[string]any)["test-only-mutation"] = true
						}
						ep["pq"].(map[string]any)["secret"] = "test-only-mutation"
						after, _ := json.Marshal([]any{base, outs})
						if string(before) != string(after) {
							t.Fatal("output aliased the frozen input")
						}
						graphs++
					}
				})
			}
		}
	}
	if graphs != 48 {
		t.Fatal("incomplete chain matrix", graphs)
	}
}

func TestCompleteMAXBoundaryRejectsMissingOrForeignLayerOwners(t *testing.T) {
	for _, mode := range []string{"max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"} {
		for _, layer := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, fault := range []string{"raw-base", "pq-mode", "pq-peer", "node", "physical-base", "listen-base", "base-route", "middle-route", "middle-type", "middle-key", "middle-host", "outer-route", "outer-type", "unknown-out", "duplicate-out", "unknown-base", "omit-outer", "unexpected-layer"} {
				t.Run(mode+"/"+layer+"/"+fault, func(t *testing.T) {
					base, outs, node := compiledMAXBoundary(t, mode, layer, "10.77.0.1")
					middle := outs[0].(map[string]any)
					outer := outs[1].(map[string]any)
					switch fault {
					case "raw-base":
						base["type"] = "wireguard"
					case "pq-mode":
						base["mode"] = "wg"
					case "pq-peer":
						base["pq"].(map[string]any)["endpoint"] = "192.0.2.55:51822"
					case "node":
						node = strings.Repeat("f", 64)
					case "physical-base":
						base["system"] = true
					case "listen-base":
						base["listen_port"] = float64(5000)
					case "base-route":
						delete(base, "detour")
					case "middle-route":
						middle["detour"] = "direct"
					case "middle-type":
						middle["type"] = "socks"
					case "middle-key":
						middle["password"] = "not a 256-bit key"
					case "middle-host":
						middle["server"] = "10.77.0.99"
					case "outer-route":
						outer["detour"] = "foreign-physical"
					case "outer-type":
						outer["type"] = "direct"
					case "unknown-out":
						outer["bind_interface"] = "eth0"
					case "duplicate-out":
						outs[1] = outs[0]
					case "unknown-base":
						base["route_exclude_address"] = []string{"0.0.0.0/0"}
					case "omit-outer":
						outs = outs[:1]
					case "unexpected-layer":
						layer = "unregistered-layer"
					}
					if multihoprelay.ValidateMAXChain(base, outs, mode, node, layer, canonicalMAXTags(), "") == nil {
						t.Fatal("weakened composite graph accepted")
					}
				})
			}
		}
	}
}

func TestCompleteMAXBoundaryDoesNotAcceptAnotherPrefixOrEntry(t *testing.T) {
	base, outs, node := compiledMAXBoundary(t, "max-quic-wg", "aes-256-gcm+xor-whitening", "10.77.0.1")
	tags := multihoprelay.MAXTags{Root: "proxy", Middle: "exit-ss", Outer: "exit-outer", Start: "exit-start"}
	ep, mapped, err := multihoprelay.RelabelMAXChain(base, outs, "max-quic-wg", node, "aes-256-gcm+xor-whitening", canonicalMAXTags(), tags, "", "entry-wg")
	if err != nil {
		t.Fatal(err)
	}
	for _, via := range []string{"", "wrong-entry", tags.Middle} {
		if multihoprelay.ValidateMAXChain(ep, mapped, "max-quic-wg", node, "aes-256-gcm+xor-whitening", tags, via) == nil {
			t.Fatal("substituted outer owner accepted")
		}
	}
	for _, bad := range []multihoprelay.MAXTags{{Root: "proxy", Middle: "same", Outer: "same", Start: "start"}, {Root: "proxy", Middle: "entry-wg", Outer: "outer", Start: "start"}, {Root: "proxy", Middle: "../foreign", Outer: "outer", Start: "start"}} {
		if _, _, err := multihoprelay.RelabelMAXChain(base, outs, "max-quic-wg", node, "aes-256-gcm+xor-whitening", canonicalMAXTags(), bad, "", "entry-wg"); err == nil {
			t.Fatal("colliding or unsafe tags accepted")
		}
	}
}
