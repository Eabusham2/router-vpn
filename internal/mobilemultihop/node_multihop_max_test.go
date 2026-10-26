package mobilemultihop

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/multihoprelay"
)

func nodeMAXFixture(t *testing.T, mode, layer string, fixed int) *NodeProfile {
	t.Helper()
	encoded, profile, start := nodeProfileFixture(t, mode, layer)
	var assets map[string]string
	if err := json.Unmarshal([]byte(encoded), &assets); err != nil {
		t.Fatal(err)
	}
	asset, compat := "wg.conf", "wg-socks.conf"
	if strings.HasSuffix(mode, "-awg") {
		asset, compat = "awg.conf", "awg-socks.conf"
	}
	peer, err := ecdh.X25519().NewPrivateKey([]byte(strings.Repeat("z", 32)))
	if err != nil {
		t.Fatal(err)
	}
	public := base64.StdEncoding.EncodeToString(peer.PublicKey().Bytes())
	for _, name := range []string{asset, compat, "rosenpass.env"} {
		if assets[name] == "" {
			continue
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(assets[name])
		if err != nil {
			t.Fatal(err)
		}
		text := strings.ReplaceAll(string(raw), base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32))), public)
		text = strings.ReplaceAll(text, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32))), base64.StdEncoding.EncodeToString([]byte(strings.Repeat("e", 32))))
		assets[name] = base64.StdEncoding.EncodeToString([]byte(text))
	}
	proof := sha256.Sum256([]byte("router-vpn-node-proof-v1\n" + public))
	profile["id"], profile["node_proof_id"] = "exit", hex.EncodeToString(proof[:])
	profile["router_api"], profile["adguard_ipv4"] = "http://10.88.0.1:8787", "10.88.0.53"
	profile["ipv6_mode"], profile["home_lan_access"] = "off", false
	profile["daita_enabled"], profile["daita_rate_kbps"], profile["daita_host"] = true, float64(64), "10.88.0.1"
	if fixed != 0 {
		profile["mtu_policy"], profile["manual_mtu"] = "fixed", float64(fixed)
	}
	node, err := NewNodeProfile(mode, startJSON(t, assets), startJSON(t, profile), start, "")
	if err != nil {
		t.Fatal(err)
	}
	return node
}

func nodeMAXOwners(t *testing.T, graph map[string]any) (map[string]any, []any) {
	t.Helper()
	var base map[string]any
	var children []any
	for _, raw := range graph["endpoints"].([]any) {
		value := raw.(map[string]any)
		if value["tag"] == "proxy" {
			if base != nil {
				t.Fatal("duplicate MAX base")
			}
			base = value
		}
	}
	for _, raw := range graph["outbounds"].([]any) {
		value := raw.(map[string]any)
		if strings.HasPrefix(predecessorText(value, "tag"), MAXExitPrefix) {
			children = append(children, value)
		}
	}
	return base, children
}

func TestNodeCompleteMAXPreservesWholeExitAndCapturedPredecessor(t *testing.T) {
	count := 0
	for _, entryMode := range NodeMultihopEntryModes() {
		for _, exitMode := range []string{"max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"} {
			for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				t.Run(entryMode+"/"+exitMode+"/"+layer, func(t *testing.T) {
					entry := multihopNodeFixture(t, entryMode, layer, "entry")
					exit := nodeMAXFixture(t, exitMode, layer, 0)
					beforeEntry, beforeExit := entry.Config(), exit.Config()
					encoded, err := NodeMultihopConfig(entry, exit)
					if err != nil {
						t.Fatal(err)
					}
					if entry.Config() != beforeEntry || exit.Config() != beforeExit {
						t.Fatal("MAX composition changed either captured source")
					}
					graph := startObject(t, encoded)
					base, children := nodeMAXOwners(t, graph)
					node := predecessorText(exit.profile, "node_proof_id")
					if err := multihoprelay.ValidateMAXChain(base, children, exitMode, node, layer, maxTags("proxy", false), "entry-wg"); err != nil {
						t.Fatal("complete exit lost an encrypted owner", err)
					}
					restored, restoredChildren, err := multihoprelay.RelabelMAXChain(base, children, exitMode, node, layer, maxTags("proxy", false), generatedMAXTags(), "entry-wg", "")
					original := startObject(t, beforeExit)
					if err != nil || !reflect.DeepEqual(restored, original["endpoints"].([]any)[0]) || !reflect.DeepEqual(restoredChildren, original["outbounds"]) {
						t.Fatal("MAX keys, private services, packet parameters or outer authentication changed", err)
					}
					owners, err := entry.MultihopEntryOwners()
					if err != nil {
						t.Fatal(err)
					}
					seen := map[string]bool{}
					for _, family := range []string{"endpoints", "outbounds"} {
						for _, raw := range graph[family].([]any) {
							value := raw.(map[string]any)
							name := predecessorText(value, "tag")
							if seen[name] || name == MAXShadowsocksTag || name == MAXOuterTag || name == MAXStartLayerTag {
								t.Fatal("MAX composition duplicated or retained a standalone owner")
							}
							seen[name] = true
						}
					}
					for _, name := range owners.Nodes {
						if !seen[name] {
							t.Fatal("complete predecessor lost one of its captured owners", name)
						}
					}
					if graph["route"].(map[string]any)["final"] != "proxy" || len(graph["inbounds"].([]any)) != 1 || graph["inbounds"].([]any)[0].(map[string]any)["mtu"] != float64(1280) {
						t.Fatal("MAX changed the one TUN, final path or conservative unmeasured MTU")
					}
					dns := graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
					if dns["server"] != "10.88.0.53" || dns["detour"] != "proxy" || dns["type"] != "udp" {
						t.Fatal("MAX substituted or bypassed selected exit DNS")
					}
					services := graph["services"].([]any)
					if len(services) != 2 || services[0].(map[string]any)["proof_tag"] != "entry-wg" || services[1].(map[string]any)["proof_tag"] != "proxy" {
						t.Fatal("MAX lost the independent entry/exit proof service owners")
					}
					count++
				})
			}
		}
	}
	if count != 228 {
		t.Fatal("missing complete native entry/MAX exit/layer combination", count)
	}
}

func TestNodeCompleteMAXPublicIdentitiesRequireWholeChain(t *testing.T) {
	for _, mode := range []string{"max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"} {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				node := nodeMAXFixture(t, mode, layer, 0)
				key, _ := ecdh.X25519().NewPrivateKey([]byte(strings.Repeat("e", 32)))
				public, err := node.PacketClientPublicKey()
				if err != nil || public != base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()) {
					t.Fatal("MAX returned a different classical public identity", err)
				}
				kem, err := node.PQClientIdentity()
				want := sha256.Sum256([]byte(strings.Repeat(string([]byte{2}), 128)))
				if err != nil || kem != hex.EncodeToString(want[:]) {
					t.Fatal("MAX returned a different captured KEM identity", err)
				}
				for _, fault := range []string{"base-mode", "base-owner", "private-service", "middle-key", "middle-edge", "missing-outer", "node", "dns", "layer"} {
					broken := *node
					graph := startObject(t, node.Config())
					base := graph["endpoints"].([]any)[0].(map[string]any)
					middle := graph["outbounds"].([]any)[0].(map[string]any)
					switch fault {
					case "base-mode":
						base["mode"] = "wg"
					case "base-owner":
						base["detour"] = "direct"
					case "private-service":
						base["peers"].([]any)[0].(map[string]any)["address"] = "10.99.0.1"
					case "middle-key":
						middle["password"] = "invalid"
					case "middle-edge":
						middle["detour"] = "proxy"
					case "missing-outer":
						graph["outbounds"] = graph["outbounds"].([]any)[:1]
					case "node":
						base["node_id"] = strings.Repeat("c", 64)
					case "dns":
						graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)["detour"] = "direct"
					case "layer":
						broken.profile = predecessorCopy(node.profile)
						broken.profile["start_layer"] = "xor"
					}
					broken.config = startJSON(t, graph)
					if _, err := broken.PacketClientPublicKey(); err == nil {
						t.Fatal("incomplete MAX exposed a classical identity", fault)
					}
					if _, err := broken.PQClientIdentity(); err == nil {
						t.Fatal("incomplete MAX exposed a KEM identity", fault)
					}
					if _, err := NodeMultihopConfig(multihopNodeFixture(t, "wg", "", "entry"), &broken); err == nil {
						t.Fatal("incomplete MAX graph was composed", fault)
					}
				}
			})
		}
	}
}

func TestNodeCompleteMAXMTUSeparatesLogicalAndOuterPacketBounds(t *testing.T) {
	for _, mode := range []string{"max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"} {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, capacity := range []int{1280, 1285, 1286, 1420} {
				for _, fixed := range []int{0, 1280, 1400} {
					entry := multihopNodeCapacityFixture(t, "awg2-strong", "", "entry", capacity)
					exit := nodeMAXFixture(t, mode, layer, fixed)
					text, err := NodeMultihopConfig(entry, exit)
					if strings.HasPrefix(mode, "max-quic-") && layer != "" && capacity < 1286 {
						if err == nil {
							t.Fatal("QUIC minimum datagram and selected AES overhead did not fit entry", mode, layer, capacity)
						}
						continue
					}
					if err != nil {
						t.Fatal(mode, layer, capacity, fixed, err)
					}
					graph := startObject(t, text)
					base, _ := nodeMAXOwners(t, graph)
					wantPacket, wantTUN := float64(1420), float64(1280)
					if fixed != 0 {
						wantPacket, wantTUN = float64(fixed), float64(fixed)
					}
					if base["mtu"] != wantPacket || graph["inbounds"].([]any)[0].(map[string]any)["mtu"] != wantTUN {
						t.Fatal("MAX silently clamped fixed MTU or fabricated PMTU from logical framing")
					}
				}
			}
		}
	}
}

func TestNodeCompleteMAXCanonicalPacketIdentityAndIndependentKEM(t *testing.T) {
	original := []byte(strings.Repeat("e", 32))
	alias := append([]byte(nil), original...)
	alias[0] ^= 7
	alias[31] ^= 128
	first, _ := ecdh.X25519().NewPrivateKey(original)
	second, _ := ecdh.X25519().NewPrivateKey(alias)
	if first.Equal(second) || !first.PublicKey().Equal(second.PublicKey()) {
		t.Fatal("fixture requires distinct private encodings of the same public peer")
	}
	for _, mode := range []string{"max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"} {
		node := nodeMAXFixture(t, mode, "aes-256-gcm+xor-whitening", 0)
		public, err := node.PacketClientPublicKey()
		if err != nil {
			t.Fatal(err)
		}
		kem, err := node.PQClientIdentity()
		if err != nil {
			t.Fatal(err)
		}
		changed := *node
		graph := startObject(t, node.Config())
		graph["endpoints"].([]any)[0].(map[string]any)["private_key"] = base64.StdEncoding.EncodeToString(alias)
		changed.config = startJSON(t, graph)
		got, err := changed.PacketClientPublicKey()
		if err != nil || got != public {
			t.Fatal("a clamped MAX private-key alias changed its Server peer identity", mode, err)
		}
		got, err = changed.PQClientIdentity()
		if err != nil || got != kem {
			t.Fatal("classical key spelling changed the independent captured KEM identity", mode, err)
		}
	}
}

func TestNodeCompleteMAXRejectsInvalidFixedAndConflictingInterfacePolicy(t *testing.T) {
	for _, mode := range []string{"max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"} {
		for _, invalid := range []any{nil, "1280", float64(1279), float64(9001), 1280.5} {
			for _, role := range []string{"entry", "exit"} {
				entry := multihopNodeFixture(t, "wg", "", "entry")
				exit := nodeMAXFixture(t, mode, "", 0)
				selected := exit
				if role == "entry" {
					selected = entry
				}
				selected.profile = predecessorCopy(selected.profile)
				selected.profile["mtu_policy"], selected.profile["manual_mtu"] = "fixed", invalid
				if _, err := NodeMultihopConfig(entry, exit); err == nil {
					t.Fatal("invalid captured fixed MTU was replaced or accepted", mode, role, invalid)
				}
			}
		}
		entry := multihopNodeFixture(t, "shadowsocks", "", "entry")
		entry.profile = predecessorCopy(entry.profile)
		entry.profile["mtu_policy"], entry.profile["manual_mtu"] = "fixed", float64(1280)
		if _, err := NodeMultihopConfig(entry, nodeMAXFixture(t, mode, "", 1400)); err == nil {
			t.Fatal("two different fixed policies were installed on one shared OS interface", mode)
		}
	}
}

func TestNodeCompleteMAXQUICMinimumCapturesBothFamiliesAndEveryIdentityHeader(t *testing.T) {
	names := maxTags("proxy", false)
	for _, kind := range []string{"shadowsocks", "routervpn-aes-xor"} {
		for _, outer := range []string{"198.51.100.9", "2001:db8::9"} {
			for _, inner := range []string{"10.88.0.1", "fd88::1"} {
				for _, count := range []int{1, 2, 3, 64} {
					keys := make([]string, count)
					for i := range keys {
						keys[i] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))
					}
					captured := &externalPredecessor{nodes: map[string]map[string]any{
						names.Outer: {"type": "hysteria2", "server": inner},
						names.Start: {"type": kind, "method": NativeStartLayerMethod, "server": outer, "password": strings.Join(keys, ":")},
					}}
					got, err := nodeMAXQUICMinimum(captured, names, "aes-256-gcm")
					ip, address, cipher := 28, 7, 51
					if strings.Contains(outer, ":") {
						ip = 48
					}
					if strings.Contains(inner, ":") {
						address = 19
					}
					if count > 1 {
						cipher = 43 + 16*(count-1)
					}
					if err != nil || got != 1200+ip+address+cipher {
						t.Fatal("MAX QUIC lost its captured public/private family or EIH envelope", got, err)
					}
					captured.nodes[names.Start]["password"] = "invalid"
					if _, err := nodeMAXQUICMinimum(captured, names, "aes-256-gcm"); err == nil {
						t.Fatal("invalid authenticated envelope received a QUIC capacity")
					}
				}
			}
		}
	}
}
