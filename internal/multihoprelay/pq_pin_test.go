package multihoprelay

import (
	"context"
	"encoding/base64"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func pinnedPQRequest(t *testing.T, exit Exit) Request {
	t.Helper()
	q := identityRequest(exit.ID, exit.Mode)
	q.ExitStartLayer = ExitLayerMode(exit)
	var err error
	q.ExpectedPacketPublicKey, err = clientIdentity(relayPacketTransport(exit))
	if err != nil {
		t.Fatal(err)
	}
	q.ExpectedPQClientIdentity, err = pqIdentity(relayPacketTransport(exit))
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func TestPQIdentityPinsBindDiscoveryCreateRenewalAndCleanup(t *testing.T) {
	for _, mode := range []string{"wg-pq", "awg2-pq"} {
		for _, change := range []string{"clamped-packet-alias", "different-packet", "different-pq"} {
			t.Run(mode+"/"+change, func(t *testing.T) {
				exit := pqExit(t, mode)
				q := pinnedPQRequest(t, exit)
				config := config()
				config.Exits = []Exit{exit}
				r := &runner{}
				m, err := New(config, q.EntryNodeID, r)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = m.Close(context.Background()) })
				caps := m.Available()
				if len(caps) != 1 || caps[0]["client_public_key"] != q.ExpectedPacketPublicKey || caps[0]["pq_client_identity"] != q.ExpectedPQClientIdentity {
					t.Fatal("discovery did not identify the exact packet and KEM owners")
				}
				peer := netip.MustParseAddr("10.77.0.2")
				lease, err := m.Create(context.Background(), peer, q)
				if err != nil || lease.Request != q || r.starts != 1 {
					t.Fatal("exact PQ identity pins did not acquire one native owner", err)
				}
				m.now = func() time.Time { return lease.ExpiresAt.Add(-5 * time.Second) }
				renewed, err := m.Create(context.Background(), peer, q)
				if err != nil || renewed.Request != q || !renewed.ExpiresAt.After(lease.ExpiresAt) || r.starts != 1 {
					t.Fatal("unchanged pinned renewal replaced its process or request", err)
				}
				// Exercise the actual lock-protected registry boundary. A manager
				// restart with this replacement registry is tested below too.
				m.mu.Lock()
				transport := m.cfg.Exits[0].Transport
				switch change {
				case "clamped-packet-alias":
					key, _ := base64.StdEncoding.DecodeString(transport["private_key"].(string))
					key[0] ^= 7
					key[31] ^= 128
					transport["private_key"] = base64.StdEncoding.EncodeToString(key)
				case "different-packet":
					transport["private_key"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32)))
				case "different-pq":
					transport["pq"].(map[string]any)["public"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 128)))
				}
				replacement := m.cfg
				m.mu.Unlock()
				_, err = m.Create(context.Background(), peer, q)
				if change == "clamped-packet-alias" {
					if err != nil || r.starts != 1 {
						t.Fatal("equivalent private-key encoding changed canonical pin ownership", err)
					}
				} else if !errors.Is(err, ErrOwnership) || r.starts != 1 || m.leases[PeerKey(peer)].ExpiresAt != renewed.ExpiresAt {
					t.Fatal("registry replacement renewed a different packet or KEM identity", err)
				}
				if err := m.Delete(context.Background(), peer, q); err != nil || len(m.leases) != 0 || r.processes[0].alive {
					t.Fatal("identity rejection prevented exact owned cleanup", err)
				}
				freshRunner := &runner{}
				fresh, err := New(replacement, q.EntryNodeID, freshRunner)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = fresh.Close(context.Background()) })
				_, err = fresh.Create(context.Background(), peer, q)
				if change != "clamped-packet-alias" && (!errors.Is(err, ErrOwnership) || freshRunner.starts != 0) {
					t.Fatal("new manager substituted an identity captured before restart", err)
				}
			})
		}
	}
}

func TestPQIdentityPinsRejectPartialMalformedAndUnownedRequests(t *testing.T) {
	for _, mode := range []string{"wg-pq", "awg2-pq"} {
		for _, fault := range []string{"no-packet", "no-pq", "bad-packet", "noncanonical-packet", "bad-pq", "uppercase-pq", "foreign-packet", "foreign-pq", "wrong-layer", "missing-exit", "plain-wg", "proxy", "external-wg", "external-awg", "external-fingerprint"} {
			t.Run(mode+"/"+fault, func(t *testing.T) {
				exit := pqExit(t, mode)
				q := pinnedPQRequest(t, exit)
				switch fault {
				case "no-packet":
					q.ExpectedPacketPublicKey = ""
				case "no-pq":
					q.ExpectedPQClientIdentity = ""
				case "bad-packet":
					q.ExpectedPacketPublicKey = "bad"
				case "noncanonical-packet":
					q.ExpectedPacketPublicKey += "\n"
				case "bad-pq":
					q.ExpectedPQClientIdentity = "bad"
				case "uppercase-pq":
					q.ExpectedPQClientIdentity = strings.Repeat("A", 64)
				case "foreign-packet":
					q.ExpectedPacketPublicKey = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32)))
				case "foreign-pq":
					q.ExpectedPQClientIdentity = strings.Repeat("f", 64)
				case "wrong-layer":
					q.ExitStartLayer = "aes-256-gcm"
				case "missing-exit":
					q.ExitID = "replacement"
				case "plain-wg":
					q.ExitMode = "wg"
				case "proxy":
					q.ExitMode = "shadowsocks"
				case "external-wg":
					q.ExitMode = "wireguard"
				case "external-awg":
					q.ExitMode = "amneziawg"
				case "external-fingerprint":
					q.ExternalFingerprint = strings.Repeat("a", 64)
				}
				cfg := config()
				cfg.Exits = []Exit{exit}
				r := &runner{}
				m, err := New(cfg, q.EntryNodeID, r)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = m.Create(context.Background(), netip.MustParseAddr("10.77.0.2"), q); !errors.Is(err, ErrOwnership) || r.starts != 0 || len(m.leases) != 0 {
					t.Fatal("unowned or incomplete public pins reached native startup", err)
				}
			})
		}
	}
}

func TestPQIdentityPinsPreserveLegacyRequestsWithoutDowngradingActiveOwners(t *testing.T) {
	for _, mode := range []string{"wg-pq", "awg2-pq"} {
		for _, pinned := range []bool{false, true} {
			t.Run(mode+map[bool]string{false: "/legacy", true: "/pinned"}[pinned], func(t *testing.T) {
				cfg := config()
				cfg.Exits = []Exit{pqExit(t, mode)}
				q := pinnedPQRequest(t, cfg.Exits[0])
				if !pinned {
					q.ExpectedPacketPublicKey, q.ExpectedPQClientIdentity = "", ""
				}
				r := &runner{}
				m, err := New(cfg, q.EntryNodeID, r)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = m.Close(context.Background()) })
				peer := netip.MustParseAddr("10.77.0.2")
				for range 2 {
					lease, err := m.Create(context.Background(), peer, q)
					if err != nil || lease.Request != q || r.starts != 1 {
						t.Fatal("legacy/exact renewal changed its contract", err)
					}
				}
				changed := pinnedPQRequest(t, cfg.Exits[0])
				if pinned {
					changed.ExpectedPacketPublicKey, changed.ExpectedPQClientIdentity = "", ""
				}
				if _, err := m.Create(context.Background(), peer, changed); !errors.Is(err, ErrBusy) || r.starts != 1 || !r.processes[0].alive {
					t.Fatal("an active request silently changed its pin contract", err)
				}
				if err := m.Delete(context.Background(), peer, changed); !errors.Is(err, ErrOwnership) || !r.processes[0].alive {
					t.Fatal("different pin contract deleted the owner", err)
				}
				if err := m.Delete(context.Background(), peer, q); err != nil || r.processes[0].alive {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestPinnedPQIdentitiesCannotBypassCanonicalReuse(t *testing.T) {
	for _, kind := range []string{"packet-alias", "pq-reuse", "independent"} {
		t.Run(kind, func(t *testing.T) {
			first, second := pqExit(t, "wg-pq"), pqExit(t, "awg2-pq")
			first.ID, second.ID = "first", "second"
			first.Transport["private_key"], second.Transport["private_key"] = scalarAlias(t, 0), scalarAlias(t, 31)
			if kind != "packet-alias" {
				second.Transport["private_key"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32)))
			}
			if kind != "pq-reuse" {
				second.Transport["pq"].(map[string]any)["public"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 128)))
			}
			cfg := config()
			cfg.Exits = []Exit{first, second}
			r := &runner{}
			m, err := New(cfg, req().EntryNodeID, r)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = m.Close(context.Background()) })
			peer := netip.MustParseAddr("10.77.0.2")
			if _, err := m.Create(context.Background(), peer, pinnedPQRequest(t, first)); err != nil {
				t.Fatal(err)
			}
			_, err = m.Create(context.Background(), peer.Next(), pinnedPQRequest(t, second))
			if (err == nil) != (kind == "independent") {
				t.Fatal("pins changed independent-key reuse protection", err)
			}
			if kind != "independent" && (r.starts != 1 || !r.processes[0].alive) {
				t.Fatal("rejected reuse changed the first owner")
			}
		})
	}
}

func TestCompleteMAXIdentityPinsRequireBothPublicOwners(t *testing.T) {
	packet := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("p", 32)))
	pq := strings.Repeat("a", 64)
	for _, mode := range []string{"max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"} {
		for _, pair := range [][2]string{{"", ""}, {packet, pq}} {
			if err := ValidateIdentityPins(mode, pair[0], pair[1]); err != nil {
				t.Fatal(mode, err)
			}
		}
		for _, pair := range [][2]string{{packet, ""}, {"", pq}, {packet, strings.Repeat("A", 64)}, {packet + "\n", pq}} {
			if err := ValidateIdentityPins(mode, pair[0], pair[1]); !errors.Is(err, ErrOwnership) {
				t.Fatal("complete MAX accepted an incomplete public owner", mode, err)
			}
		}
	}
}

func TestPQIdentityPinsCannotOverrideAuthenticatedExternalOwners(t *testing.T) {
	for _, mode := range []string{"wireguard", "amneziawg", "shadowsocks"} {
		t.Run(mode, func(t *testing.T) {
			var m *Manager
			var r *runner
			var q Request
			peer := netip.MustParseAddr("10.77.0.2")
			if mode == "shadowsocks" {
				cfg, prepared := externalFixture(t)
				r = &runner{}
				var err error
				m, err = New(cfg, prepared.EntryNodeID, r)
				if err != nil {
					t.Fatal(err)
				}
				q = challengedExternalFixture(t, m, cfg.Exits[0], prepared, peer)
			} else {
				client, server, prepared := packetPair(t, mode, "")
				m, r = packetManager(t, server)
				q = packetChallenge(t, m, client, peer, prepared)
			}
			t.Cleanup(func() { _ = m.Close(context.Background()) })
			pins := [][2]string{
				{base64.StdEncoding.EncodeToString([]byte(strings.Repeat("p", 32))), ""},
				{"", strings.Repeat("a", 64)},
				{base64.StdEncoding.EncodeToString([]byte(strings.Repeat("p", 32))), strings.Repeat("a", 64)},
			}
			for _, pair := range pins {
				changed := q
				changed.ExpectedPacketPublicKey, changed.ExpectedPQClientIdentity = pair[0], pair[1]
				if _, err := m.Create(context.Background(), peer, changed); !errors.Is(err, ErrOwnership) || r.starts != 0 {
					t.Fatal("Router identity pins overrode an authenticated external credential owner", err)
				}
			}
			// This is a fully valid independently authenticated external request;
			// rejection above must not consume or damage its owned challenge.
			if lease, err := m.Create(context.Background(), peer, q); err != nil || lease.Request != q || r.starts != 1 {
				t.Fatal("rejected Router pins damaged the exact external request", err)
			}
			if err := m.Delete(context.Background(), peer, q); err != nil || r.processes[0].alive {
				t.Fatal(err)
			}
		})
	}
}
