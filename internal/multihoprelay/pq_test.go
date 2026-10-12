package multihoprelay

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func pqExit(t *testing.T, mode string) Exit {
	t.Helper()
	e := awgExit(t, "awg2-fast")
	e.Mode = mode
	raw, _ := json.Marshal(e.Transport)
	var value map[string]any
	if json.Unmarshal(raw, &value) != nil {
		t.Fatal("fixture")
	}
	e.Transport = value
	p := e.Transport
	p["type"], p["mode"] = "routervpn-pq", mode
	if mode == "wg-pq" {
		delete(p, "amnezia")
		peer := p["peers"].([]any)[0].(map[string]any)
		hash := sha256.Sum256([]byte("router-vpn-node-proof-v1\n" + peer["public_key"].(string)))
		e.NodeID = hex.EncodeToString(hash[:])
	}
	p["node_id"] = e.NodeID
	p["pq"] = map[string]any{"endpoint": "192.0.2.2:51822", "version": 2, "secret": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 64))), "public": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("p", 128))), "peer": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("r", 128)))}
	return e
}
func TestPQRelayCapturesNativeEndpointAndPrivateIdentity(t *testing.T) {
	for _, mode := range []string{"wg-pq", "awg2-pq"} {
		c := config()
		c.Exits = []Exit{pqExit(t, mode)}
		r := &runner{}
		m, err := New(c, req().EntryNodeID, r)
		if err != nil {
			t.Fatal(err)
		}
		defer m.Close(context.Background())
		caps := m.Available()
		if len(caps) != 1 || caps[0]["client_public_key"] == "" || len(caps[0]["pq_client_identity"]) != 64 {
			t.Fatal("independent public identities missing")
		}
		data, _ := json.Marshal(caps)
		for _, secret := range []string{"private_key", "secret", "amnezia", "endpoint"} {
			if strings.Contains(string(data), secret) {
				t.Fatal("capability leaked config")
			}
		}
		q := req()
		q.ExitMode = mode
		owner := netip.MustParseAddr("10.77.0.2")
		if _, err = m.Create(context.Background(), owner, q); err != nil {
			t.Fatal(err)
		}
		var graph map[string]any
		if json.Unmarshal(r.configs[0], &graph) != nil {
			t.Fatal("graph")
		}
		native := graph["endpoints"].([]any)[0].(map[string]any)
		if native["type"] != "routervpn-pq" || native["mode"] != mode || native["node_id"] != c.Exits[0].NodeID || len(graph["outbounds"].([]any)) != 0 {
			t.Fatal("PQ downgraded or moved")
		}
		if graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)["detour"] != "exit" {
			t.Fatal("DNS bypasses PQ")
		}
		if _, err = m.Create(context.Background(), owner.Next(), q); err == nil {
			t.Fatal("same client key entered two processes")
		}
	}
}
func TestPQRegistryRejectsIndependentKeyReuseAcrossModes(t *testing.T) {
	for _, secondMode := range []string{"wg-pq", "awg2-pq"} {
		for _, kind := range []string{"wg-alias", "pq-reuse", "independent"} {
			c := config()
			first, second := pqExit(t, "awg2-pq"), pqExit(t, secondMode)
			first.ID = "first"
			second.ID = "second"
			if kind == "wg-alias" {
				first.Transport["private_key"] = scalarAlias(t, 0)
				second.Transport["private_key"] = scalarAlias(t, 31)
				second.Transport["pq"].(map[string]any)["public"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 128)))
			} else {
				second.Transport["private_key"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
				if kind == "independent" {
					second.Transport["pq"].(map[string]any)["public"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 128)))
				}
			}
			c.Exits = []Exit{first, second}
			r := &runner{}
			m, err := New(c, req().EntryNodeID, r)
			if err != nil {
				t.Fatal(err)
			}
			a, b := identityRequest("first", first.Mode), identityRequest("second", second.Mode)
			owner := netip.MustParseAddr("10.77.0.2")
			if _, err = m.Create(context.Background(), owner, a); err != nil {
				t.Fatal(err)
			}
			_, err = m.Create(context.Background(), owner.Next(), b)
			if (err == nil) != (kind == "independent") {
				t.Fatal(secondMode, kind, err)
			}
			if kind != "independent" {
				if err = m.Delete(context.Background(), owner, a); err != nil {
					t.Fatal(err)
				}
				if _, err = m.Create(context.Background(), owner.Next(), b); err != nil {
					t.Fatal("verified release did not free identity", err)
				}
			}
			if err = m.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
	}
}
func TestPQRelayRejectsWrongPeerAndArbitraryOptions(t *testing.T) {
	for _, mode := range []string{"wg-pq", "awg2-pq"} {
		for _, mutate := range []func(map[string]any){
			func(p map[string]any) { p["type"] = "wireguard" }, func(p map[string]any) { p["mode"] = "wg" }, func(p map[string]any) { p["node_id"] = strings.Repeat("e", 64) },
			func(p map[string]any) { p["system"] = true }, func(p map[string]any) { p["detour"] = "direct" }, func(p map[string]any) { p["pq"].(map[string]any)["endpoint"] = "192.0.2.9:51822" },
			func(p map[string]any) { p["pq"].(map[string]any)["secret_path"] = "/private" }, func(p map[string]any) { p["pq"].(map[string]any)["version"] = 1 },
			func(p map[string]any) { p["peers"].([]any)[0].(map[string]any)["allowed_ips"] = []string{"10.0.0.0/8"} }, func(p map[string]any) { p["mtu"] = 1279 },
		} {
			e := pqExit(t, mode)
			mutate(e.Transport)
			if _, err := Build(e, netip.MustParseAddr("10.77.0.2"), Lease{Host: "10.77.0.1", Port: 26240, Username: "user", Password: "private"}); err == nil {
				t.Fatal("invalid PQ registry transport accepted")
			}
		}
	}
}
func TestPQExitStartLayerKeepsBothHandshakesTogether(t *testing.T) {
	for _, mode := range []string{"wg-pq", "awg2-pq"} {
		for _, layerMode := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			e := pqExit(t, mode)
			e.Transport["tag"] = "exit"
			layer := &StartLayer{Mode: layerMode, API: "http://[fd88::1]:8787", Transport: map[string]any{"type": "shadowsocks", "tag": "proxy", "server": "192.0.2.2", "server_port": 8388, "method": "2022-blake3-aes-256-gcm", "password": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))}}
			before, _ := json.Marshal(e.Transport)
			inner, outer, err := WrapStartLayer(e.Transport, e.Mode, layer, ExitStartLayerTag, "")
			if err != nil {
				t.Fatal(err)
			}
			after, _ := json.Marshal(e.Transport)
			if string(before) != string(after) {
				t.Fatal("saved source mutated")
			}
			if inner["peers"].([]any)[0].(map[string]any)["address"] != "fd88::1" || inner["pq"].(map[string]any)["endpoint"] != "[fd88::1]:51822" || inner["detour"] != ExitStartLayerTag || outer["detour"] != nil {
				t.Fatal("PQ handshake bypassed AES")
			}
			e.StartLayer = layer
			lease := Lease{Request: Request{ExitStartLayer: layerMode}, Host: "10.77.0.1", Port: 26240, Username: "user", Password: "private"}
			if _, err = Build(e, netip.MustParseAddr("10.77.0.2"), lease); err != nil {
				t.Fatal(err)
			}
		}
	}
}
