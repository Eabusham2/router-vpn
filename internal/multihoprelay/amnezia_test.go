package multihoprelay

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func awgExit(t *testing.T, mode string) Exit {
	t.Helper()
	key, err := ecdh.X25519().NewPrivateKey([]byte(strings.Repeat("a", 32)))
	if err != nil {
		t.Fatal(err)
	}
	peer, err := ecdh.X25519().NewPrivateKey([]byte(strings.Repeat("b", 32)))
	if err != nil {
		t.Fatal(err)
	}
	return Exit{ID: "exit", Mode: mode, DNS: "10.88.0.1", NodeID: strings.Repeat("b", 64), Transport: map[string]any{
		"type": "routervpn-amneziawg", "private_key": base64.StdEncoding.EncodeToString(key.Bytes()), "address": []string{"10.88.0.2/32", "fd88::2/128"}, "mtu": 1280,
		"amnezia": map[string]string{"jc": "3", "jmin": "40", "jmax": "900", "s1": "56", "s2": "48", "s3": "24", "s4": "32", "h1": "10-19", "h2": "20-29", "h3": "30-39", "h4": "40-49"},
		"peers":   []any{map[string]any{"address": "192.0.2.2", "port": 51820, "public_key": base64.StdEncoding.EncodeToString(peer.PublicKey().Bytes()), "allowed_ips": []string{"0.0.0.0/0", "::/0"}, "persistent_keepalive_interval": 25}},
	}}
}
func TestAmneziaRelayKeepsNativeParametersAndOwnership(t *testing.T) {
	for _, mode := range []string{"awg2-fast", "awg2-strong"} {
		t.Run(mode, func(t *testing.T) {
			c := config()
			c.Exits = []Exit{awgExit(t, mode)}
			r := &runner{}
			m, err := New(c, req().EntryNodeID, r)
			if err != nil {
				t.Fatal(err)
			}
			q := req()
			q.ExitMode = mode
			peer := netip.MustParseAddr("10.77.0.2")
			available := m.Available()
			raw, _ := json.Marshal(available)
			if !strings.Contains(string(raw), "client_public_key") || strings.Contains(string(raw), "private_key") || strings.Contains(string(raw), "amnezia") {
				t.Fatal("invalid capabilities", string(raw))
			}
			if _, err = m.Create(context.Background(), peer, q); err != nil {
				t.Fatal(err)
			}
			var cfg map[string]any
			if json.Unmarshal(r.configs[0], &cfg) != nil {
				t.Fatal("invalid generated graph")
			}
			endpoints := cfg["endpoints"].([]any)
			if len(endpoints) != 1 || len(cfg["outbounds"].([]any)) != 0 {
				t.Fatal("AWG did not use exact native endpoint")
			}
			actual := endpoints[0].(map[string]any)
			if actual["type"] != "routervpn-amneziawg" || actual["amnezia"].(map[string]any)["s4"] != "32" || actual["tag"] != "exit" {
				t.Fatal("AWG parameters lost")
			}
			dns := cfg["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
			if dns["detour"] != "exit" {
				t.Fatal("DNS escaped exit")
			}
			if _, err = m.Create(context.Background(), netip.MustParseAddr("10.77.0.3"), q); err == nil {
				t.Fatal("AWG client identity roamed between simultaneous relay processes")
			}
			if err = m.Delete(context.Background(), peer, q); err != nil {
				t.Fatal(err)
			}
			if _, err = m.Create(context.Background(), netip.MustParseAddr("10.77.0.3"), q); err != nil {
				t.Fatal("released AWG identity not reusable", err)
			}
			if err = m.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestAmneziaRelayRejectsUnownedAndMalformedParameters(t *testing.T) {
	for _, fn := range []func(map[string]any){
		func(p map[string]any) { delete(p, "amnezia") }, func(p map[string]any) { p["type"] = "wireguard" }, func(p map[string]any) { p["bind_interface"] = "wan" },
		func(p map[string]any) { p["mtu"] = 1279 }, func(p map[string]any) { p["address"] = []string{"10.88.0.2/32", "10.88.0.3/32"} },
		func(p map[string]any) { p["amnezia"].(map[string]string)["h2"] = "10-19" }, func(p map[string]any) { p["amnezia"].(map[string]string)["s4"] = "32\nlisten_port=42" },
		func(p map[string]any) { p["peers"].([]any)[0].(map[string]any)["persistent_keepalive_interval"] = 25.5 },
		func(p map[string]any) { p["peers"].([]any)[0].(map[string]any)["allowed_ips"] = []string{"10.0.0.0/8"} },
		func(p map[string]any) { p["peers"].([]any)[0].(map[string]any)["reserved"] = []int{1, 2, 3} },
	} {
		c := config()
		c.Exits = []Exit{awgExit(t, "awg2-strong")}
		fn(c.Exits[0].Transport)
		if _, err := New(c, req().EntryNodeID, &runner{}); err == nil {
			t.Fatal("unsafe AWG endpoint reached core")
		}
	}
}
