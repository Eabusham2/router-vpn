package multihoprelay

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The image build sends these exact production-built plans to its bundled
// sing-box checker. No network connection or real-node proof is claimed.
func TestExportPinnedCoreRelayConfigurations(t *testing.T) {
	root := os.Getenv("ROUTER_VPN_RELAY_FIXTURES_DIR")
	if root == "" {
		t.Skip("fixture export is requested by the router-agent image build")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.X25519().NewPrivateKey([]byte(strings.Repeat("a", 32)))
	if err != nil {
		t.Fatal(err)
	}
	peer, err := ecdh.X25519().NewPrivateKey([]byte(strings.Repeat("b", 32)))
	if err != nil {
		t.Fatal(err)
	}
	configurations := []Exit{
		{ID: "fixture", Mode: "shadowsocks", DNS: "10.88.0.1", NodeID: strings.Repeat("b", 64), Transport: map[string]any{"type": "shadowsocks", "server": "192.0.2.2", "server_port": 8388, "method": "2022-blake3-aes-128-gcm", "password": "AAAAAAAAAAAAAAAAAAAAAA=="}},
		{ID: "fixture", Mode: "hysteria2", DNS: "10.88.0.1", NodeID: strings.Repeat("b", 64), Transport: map[string]any{"type": "hysteria2", "server": "192.0.2.2", "server_port": 443, "password": "offline-fixture-only", "tls": map[string]any{"enabled": true, "server_name": "vpn.invalid"}}},
		{ID: "fixture", Mode: "wg", DNS: "10.88.0.1", NodeID: strings.Repeat("b", 64), Transport: map[string]any{"type": "wireguard", "private_key": base64.StdEncoding.EncodeToString(key.Bytes()), "address": []string{"10.88.0.2/32"}, "mtu": 1280, "peers": []any{map[string]any{"address": "192.0.2.2", "port": 51820, "public_key": base64.StdEncoding.EncodeToString(peer.PublicKey().Bytes()), "allowed_ips": []string{"0.0.0.0/0", "::/0"}}}}},
	}
	for _, exit := range configurations {
		cfg := config()
		cfg.Exits = []Exit{exit}
		r := &runner{}
		m, e := New(cfg, req().EntryNodeID, r)
		if e != nil {
			t.Fatal(e)
		}
		q := req()
		q.ExitID = exit.ID
		q.ExitMode = exit.Mode
		if _, e = m.Create(context.Background(), netip.MustParseAddr("10.77.0.2"), q); e != nil {
			t.Fatal(e)
		}
		var plan map[string]any
		if e = json.Unmarshal(r.configs[0], &plan); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(root, exit.Mode+".json"), r.configs[0], 0600); e != nil {
			t.Fatal(e)
		}
	}
}
