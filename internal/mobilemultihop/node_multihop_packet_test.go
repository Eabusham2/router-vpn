package mobilemultihop

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

func TestNodeMultihopPacketIdentityUsesCanonicalPublicPeer(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong", "wg-pq", "awg2-pq"} {
		t.Run(mode, func(t *testing.T) { nodeMultihopPacketIdentityUsesCanonicalPublicPeer(t, mode) })
	}
}

func nodeMultihopPacketIdentityUsesCanonicalPublicPeer(t *testing.T, mode string) {
	t.Helper()
	asset := "wg.conf"
	if mode != "wg" && mode != "wg-pq" {
		asset = "awg.conf"
	}
	files, profile, start := multihopNodeSources(t, mode, "aes-256-gcm", "exit")
	var assets map[string]string
	if err := json.Unmarshal([]byte(files), &assets); err != nil {
		t.Fatal(err)
	}
	original := []byte(strings.Repeat("e", 32))
	alias := append([]byte(nil), original...)
	alias[0] ^= 7
	alias[31] ^= 128
	first, _ := ecdh.X25519().NewPrivateKey(original)
	second, _ := ecdh.X25519().NewPrivateKey(alias)
	if first.Equal(second) || !first.PublicKey().Equal(second.PublicKey()) {
		t.Fatal("fixture needs distinct encodings of the same clamped public identity")
	}
	var captured string
	for _, private := range [][]byte{original, alias} {
		raw, _ := base64.StdEncoding.DecodeString(assets[asset])
		text := strings.ReplaceAll(string(raw), base64.StdEncoding.EncodeToString(original), base64.StdEncoding.EncodeToString(private))
		copy := map[string]string{}
		for name, value := range assets {
			copy[name] = value
		}
		copy[asset] = base64.StdEncoding.EncodeToString([]byte(text))
		node, err := NewNodeProfile(mode, startJSON(t, copy), startJSON(t, profile), start, "")
		if err != nil {
			t.Fatal(err)
		}
		public, err := node.PacketClientPublicKey()
		if err != nil || public != base64.StdEncoding.EncodeToString(first.PublicKey().Bytes()) || captured != "" && public != captured {
			t.Fatal("private-key spelling changed the public peer identity", err)
		}
		captured = public
	}
	for _, node := range []*NodeProfile{nil, multihopNodeFixture(t, "hysteria2", "", "exit"), {mode: "wg", config: `{}`}} {
		if _, err := node.PacketClientPublicKey(); err == nil {
			t.Fatal("unowned or non-packet source exposed a packet identity")
		}
	}
}

func TestNodeMultihopWireGuardPacketMTUPreservesFixedBounds(t *testing.T) {
	for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		for _, fixed := range []int{0, 1280, 1392} {
			t.Run(layer+"/"+strconv.Itoa(fixed), func(t *testing.T) {
				entry := multihopNodeFixture(t, "awg2-strong", "aes-256-gcm", "entry")
				files, profile, start := multihopNodeSources(t, "wg", layer, "exit")
				if fixed != 0 {
					profile["mtu_policy"], profile["manual_mtu"] = "fixed", float64(fixed)
				}
				exit, err := NewNodeProfile("wg", files, startJSON(t, profile), start, "")
				if err != nil {
					t.Fatal(err)
				}
				config, err := NodeMultihopConfig(entry, exit)
				if fixed == 1392 {
					if err == nil {
						t.Fatal("oversized fixed packet MTU was silently clamped or accepted")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				graph := startObject(t, config)
				want := float64(1360)
				if layer != "" {
					want = 1296
				}
				if fixed != 0 {
					want = float64(fixed)
				}
				for _, raw := range graph["endpoints"].([]any) {
					endpoint := raw.(map[string]any)
					if endpoint["tag"] == "proxy" && endpoint["mtu"] != want {
						t.Fatal("captured packet envelope was not accounted", endpoint["mtu"], want)
					}
					if endpoint["tag"] == "entry-wg" && endpoint["mtu"] != float64(1420) {
						t.Fatal("exit changed the entry transport capacity")
					}
				}
				if graph["inbounds"].([]any)[0].(map[string]any)["mtu"] != float64(1280) {
					t.Fatal("configured baseline was replaced by stale effective MTU")
				}
			})
		}
	}
}

func TestNodeMultihopPacketEnvelopeCapturesPublicFamilyAndPrivateAddress(t *testing.T) {
	for _, kind := range []string{"shadowsocks", "routervpn-aes-xor"} {
		for _, outer := range []string{"198.51.100.9", "2001:db8::9"} {
			for _, inner := range []string{"10.88.0.1", "fd88::1"} {
				for _, count := range []int{1, 2, 3} {
					keys := make([]string, count)
					for i := range keys {
						keys[i] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))
					}
					node := &externalPredecessor{final: map[string]any{"type": "wireguard", "detour": NativeStartLayerTag, "peers": []any{map[string]any{"address": inner}}}, nodes: map[string]map[string]any{NativeStartLayerTag: {"type": kind, "method": NativeStartLayerMethod, "server": outer, "password": strings.Join(keys, ":")}}}
					got, err := nodePacketEnvelope(node, "wg")
					ipBytes, addressBytes := 20, 7
					if strings.Contains(outer, ":") {
						ipBytes = 40
					}
					if strings.Contains(inner, ":") {
						addressBytes = 19
					}
					cipher := 51
					if count > 1 {
						cipher = 43 + 16*(count-1)
					}
					if err != nil || got != ipBytes+8+32+addressBytes+cipher {
						t.Fatal("captured public/private packet envelope changed", got, err)
					}
					node.nodes[NativeStartLayerTag]["password"] = "invalid"
					if _, err := nodePacketEnvelope(node, "wg"); err == nil {
						t.Fatal("unvalidated Start Layer key received a packet budget")
					}
				}
			}
		}
	}
}

// The packet capacity is a captured configuration bound, never an inferred
// PMTU. Preserve S4 as well as the public/private Start Layer datagram headers
// before the one final 16-byte alignment; reject an incompatible fixed choice.
func TestNodeMultihopAmneziaPacketMTUPreservesPaddingAndLayerBounds(t *testing.T) {
	for _, mode := range []string{"awg2-fast", "awg2-strong"} {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, capacity := range []int{1420, 1500} {
				for _, fixed := range []int{0, 1280, 1408} {
					t.Run(mode+"/"+layer+"/"+strconv.Itoa(capacity)+"/"+strconv.Itoa(fixed), func(t *testing.T) {
						entry := multihopNodeCapacityFixture(t, "awg2-strong", "aes-256-gcm", "entry", capacity)
						files, profile, start := multihopNodeSources(t, mode, layer, "exit")
						if fixed != 0 {
							profile["mtu_policy"], profile["manual_mtu"] = "fixed", float64(fixed)
						}
						exit, err := NewNodeProfile(mode, files, startJSON(t, profile), start, "")
						if err != nil {
							t.Fatal(err)
						}
						config, err := NodeMultihopConfig(entry, exit)
						overhead := 60 + 32
						if layer != "" {
							overhead += 58
						}
						limit := (capacity - overhead) &^ 15
						if limit < 1280 || fixed > limit {
							if err == nil {
								t.Fatal("incompatible S4/layer/fixed packet capacity silently accepted", limit, fixed)
							}
							return
						}
						if err != nil {
							t.Fatal(err)
						}
						want := limit
						if want > 1420 {
							want = 1420
						}
						if fixed != 0 {
							want = fixed
						}
						graph := startObject(t, config)
						for _, raw := range graph["endpoints"].([]any) {
							endpoint := raw.(map[string]any)
							if endpoint["tag"] == "proxy" {
								if endpoint["type"] != AmneziaType || endpoint["mtu"] != float64(want) {
									t.Fatal("AWG packet type or complete envelope lost", endpoint["mtu"], want)
								}
								encoded, _ := json.Marshal(endpoint)
								runtime, err := AmneziaRuntimeConfig(string(encoded))
								if err != nil || runtime.TransportPadding != 32 || len(endpoint["amnezia"].(map[string]any)) != 11 {
									t.Fatal("captured AWG parameters changed", err)
								}
							}
							if endpoint["tag"] == "entry-wg" && endpoint["mtu"] != float64(capacity) {
								t.Fatal("exit changed captured entry capacity")
							}
						}
						interfaceMTU := 1280
						if fixed != 0 {
							interfaceMTU = fixed
						}
						if graph["inbounds"].([]any)[0].(map[string]any)["mtu"] != float64(interfaceMTU) {
							t.Fatal("saved effective MTU replaced the selected fixed or conservative initial interface value")
						}
					})
				}
			}
		}
	}
}

func TestNodeMultihopAmneziaEnvelopeRetainsFamilyAddressAndPadding(t *testing.T) {
	for _, mode := range []string{"awg2-fast", "awg2-strong"} {
		for _, outer := range []string{"198.51.100.9", "2001:db8::9"} {
			for _, inner := range []string{"10.88.0.1", "fd88::1"} {
				for _, padding := range []int{0, 32, 63} {
					node := multihopNodeFixture(t, mode, "aes-256-gcm+xor-whitening", "exit")
					graph := startObject(t, node.Config())
					endpoint := graph["endpoints"].([]any)[0].(map[string]any)
					endpoint["peers"].([]any)[0].(map[string]any)["address"] = inner
					endpoint["amnezia"].(map[string]any)["s4"] = strconv.Itoa(padding)
					var layer map[string]any
					for _, raw := range graph["outbounds"].([]any) {
						candidate := raw.(map[string]any)
						if candidate["tag"] == NativeStartLayerTag {
							layer = candidate
						}
					}
					layer["server"] = outer
					captured := &externalPredecessor{final: endpoint, nodes: map[string]map[string]any{NativeStartLayerTag: layer}}
					got, err := nodePacketEnvelope(captured, mode)
					want := 60 + 58 + padding
					if strings.Contains(outer, ":") {
						want += 20
					}
					if strings.Contains(inner, ":") {
						want += 12
					}
					if err != nil || got != want {
						t.Fatal("captured AWG public/private family or S4 lost", got, want, err)
					}
					endpoint["amnezia"].(map[string]any)["s4"] = "unknown"
					if _, err := nodePacketEnvelope(captured, mode); err == nil {
						t.Fatal("invalid AWG padding received a packet capacity")
					}
					if _, err := node.PacketClientPublicKey(); err != nil {
						t.Fatal("valid immutable capture changed when fixture graph mutated", err)
					}
				}
			}
		}
	}
}
