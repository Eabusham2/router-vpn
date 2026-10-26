package mobilemultihop

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

func TestNodeMultihopWireGuardIdentityUsesCanonicalPublicPeer(t *testing.T) {
	files, profile, start := multihopNodeSources(t, "wg", "aes-256-gcm", "exit")
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
		raw, _ := base64.StdEncoding.DecodeString(assets["wg.conf"])
		text := strings.ReplaceAll(string(raw), base64.StdEncoding.EncodeToString(original), base64.StdEncoding.EncodeToString(private))
		copy := map[string]string{"wg.conf": base64.StdEncoding.EncodeToString([]byte(text))}
		node, err := NewNodeProfile("wg", startJSON(t, copy), startJSON(t, profile), start, "")
		if err != nil {
			t.Fatal(err)
		}
		public, err := node.WireGuardClientPublicKey()
		if err != nil || public != base64.StdEncoding.EncodeToString(first.PublicKey().Bytes()) || captured != "" && public != captured {
			t.Fatal("private-key spelling changed the public peer identity", err)
		}
		captured = public
	}
	for _, node := range []*NodeProfile{nil, multihopNodeFixture(t, "hysteria2", "", "exit"), {mode: "wg", config: `{}`}} {
		if _, err := node.WireGuardClientPublicKey(); err == nil {
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
					got, err := nodeWireGuardPacketEnvelope(node, "wg")
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
					if _, err := nodeWireGuardPacketEnvelope(node, "wg"); err == nil {
						t.Fatal("unvalidated Start Layer key received a packet budget")
					}
				}
			}
		}
	}
}
