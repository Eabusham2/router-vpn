package multihoprelay

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/awgpolicy"
)

func packetPinConfig(seed byte) Config { return packetModePinConfig("wg", seed) }

func packetModePinConfig(mode string, seed byte) Config {
	c := config()
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string(seed), 32)))
	peer, _ := ecdh.X25519().NewPrivateKey([]byte(strings.Repeat("b", 32)))
	c.Exits[0].Mode = mode
	c.Exits[0].Transport = map[string]any{"type": "wireguard", "mtu": 1280, "private_key": key, "address": []string{"10.78.0.2/32"}, "peers": []any{map[string]any{"address": "192.0.2.2", "port": 51820, "public_key": base64.StdEncoding.EncodeToString(peer.PublicKey().Bytes()), "allowed_ips": []string{"0.0.0.0/0", "::/0"}}}}
	if awgpolicy.IsMode(mode) {
		c.Exits[0].Transport["type"] = "routervpn-amneziawg"
		c.Exits[0].Transport["amnezia"] = map[string]string{"jc": "3", "jmin": "40", "jmax": "900", "s1": "56", "s2": "48", "s3": "24", "s4": "32", "h1": "10000000-19999999", "h2": "20000000-29999999", "h3": "30000000-39999999", "h4": "40000000-49999999"}
	}
	return c
}

func TestExpectedPacketIdentityBindsDiscoveryToCreateAndRenewal(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		t.Run(mode, func(t *testing.T) { expectedPacketIdentityBindsDiscoveryToCreateAndRenewal(t, mode) })
	}
}

func expectedPacketIdentityBindsDiscoveryToCreateAndRenewal(t *testing.T, mode string) {
	t.Helper()
	peer := netip.MustParseAddr("10.77.0.2")
	c := packetModePinConfig(mode, 'a')
	public, err := clientIdentity(c.Exits[0].Transport)
	if err != nil {
		t.Fatal(err)
	}
	q := req()
	q.ExitMode, q.ExpectedPacketPublicKey = mode, public
	for _, scenario := range []string{"same-identity", "clamped-alias", "changed-after-discovery", "missing-exit", "wrong-layer", "malformed-pin", "proxy-pin"} {
		t.Run(scenario, func(t *testing.T) {
			config := packetModePinConfig(mode, 'a')
			request := q
			switch scenario {
			case "clamped-alias":
				raw, _ := base64.StdEncoding.DecodeString(config.Exits[0].Transport["private_key"].(string))
				raw[0] ^= 7
				raw[31] ^= 128
				config.Exits[0].Transport["private_key"] = base64.StdEncoding.EncodeToString(raw)
			case "changed-after-discovery":
				config = packetModePinConfig(mode, 'z')
			case "missing-exit":
				config.Exits[0].ID = "replacement"
			case "wrong-layer":
				request.ExitStartLayer = "aes-256-gcm"
			case "malformed-pin":
				request.ExpectedPacketPublicKey = "bad"
			case "proxy-pin":
				request.ExitMode = "shadowsocks"
			}
			r := &runner{}
			m, err := New(config, request.EntryNodeID, r)
			if err != nil {
				t.Fatal(err)
			}
			lease, err := m.Create(context.Background(), peer, request)
			if scenario != "same-identity" && scenario != "clamped-alias" {
				if !errors.Is(err, ErrOwnership) || r.starts != 0 || len(m.leases) != 0 {
					t.Fatal("unmatched captured identity reached server startup", err)
				}
				return
			}
			if err != nil || lease.Request != request || r.starts != 1 {
				t.Fatal("canonical packet pin changed on acquisition", err)
			}
			m.now = func() time.Time { return lease.ExpiresAt.Add(-5 * time.Second) }
			renewed, err := m.Create(context.Background(), peer, request)
			if err != nil || !renewed.ExpiresAt.After(lease.ExpiresAt) || renewed.Request != request || r.starts != 1 {
				t.Fatal("exact renewal restarted or changed pinned peer", err)
			}
			// Exercise the lock-protected check before the existing-lease return.
			// Production registries are frozen; a restarted/repaired manager is
			// covered above by changed-after-discovery with the original request.
			m.mu.Lock()
			m.cfg.Exits = packetModePinConfig(mode, 'z').Exits
			m.mu.Unlock()
			if _, err = m.Create(context.Background(), peer, request); !errors.Is(err, ErrOwnership) || r.starts != 1 || m.leases[PeerKey(peer)].ExpiresAt != renewed.ExpiresAt {
				t.Fatal("changed registry renewed the old packet identity", err)
			}
			if err = m.Delete(context.Background(), peer, request); err != nil || len(m.leases) != 0 || r.processes[0].alive {
				t.Fatal("identity failure prevented cleanup of its exact owned lease", err)
			}
		})
	}
}

func TestLegacyPacketAndProxyLeasesKeepOptionalPinCompatibility(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong", "shadowsocks"} {
		c := config()
		if awgpolicy.WireGuardFamily(mode) {
			c = packetModePinConfig(mode, 'a')
		}
		r := &runner{}
		m, err := New(c, req().EntryNodeID, r)
		if err != nil {
			t.Fatal(err)
		}
		q := req()
		q.ExitMode = mode
		peer := netip.MustParseAddr("10.77.0.2")
		for range 2 {
			l, err := m.Create(context.Background(), peer, q)
			if err != nil || l.Request != q || r.starts != 1 {
				t.Fatal("legacy lease changed without an optional identity pin", mode, err)
			}
		}
		if err := m.Delete(context.Background(), peer, q); err != nil {
			t.Fatal(err)
		}
	}
}
