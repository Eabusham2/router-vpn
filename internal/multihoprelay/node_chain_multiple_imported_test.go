package multihoprelay

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
)

func multipleImportedCaptureFixture(t *testing.T, count int, positions []int) NodeChainCapture {
	t.Helper()
	c := chainCaptureFixture(t, count)
	c.Source.Schema, c.Request.Schema = 6, 6
	for _, position := range positions {
		if position < 1 || position >= count {
			t.Fatal("public suffix position must precede paired final")
		}
		c.Source.Members[position-1] = NodeChainMember{Position: position, ProfileID: fmt.Sprintf("independent-import-%d", position), Mode: "shadowsocks", StartLayer: "off", NodeKind: "external", ProofKind: "public-path", SourceSHA256: fmt.Sprintf("%064x", 500+position), ExpectedPublicIP: fmt.Sprintf("198.51.100.%d", 40+position)}
	}
	c.Request.LocalPacketPositions, c.Request.LocalPacketPublicKeys = []int{0}, []string{chainCapturePublic(t, 71)}
	for i, member := range c.Source.Members[:count-1] {
		if member.NodeKind == "" {
			c.Request.LocalPacketPositions = append(c.Request.LocalPacketPositions, member.Position)
			c.Request.LocalPacketPublicKeys = append(c.Request.LocalPacketPublicKeys, chainCapturePublic(t, byte(72+i)))
		}
	}
	digest, err := c.Source.Digest()
	if err != nil {
		t.Fatal(err)
	}
	c.RegistrySHA256, c.Request.DescriptorSHA256 = digest, digest
	if err := c.Validate(); err != nil {
		t.Fatal("complete schema6 source/request", err)
	}
	return c
}

// A long remote suffix is made entirely of independent imported SS2022
// members followed by the original paired SS final, and every layer is Off.
func TestExtendedImportedDescriptorPreservesPacketEntry(t *testing.T) {
	for _, count := range []int{9, 16} {
		base := multipleImportedCaptureFixture(t, 2, []int{1}).Source
		last := base.Members[1]
		last.Position, last.StartLayer = count-1, "off"
		base.Members = base.Members[:1]
		for position := 2; position < last.Position; position++ {
			member := base.Members[0]
			member.Position = position
			member.ProfileID = fmt.Sprintf("independent-import-%d", position)
			member.SourceSHA256 = fmt.Sprintf("%064x", 500+position)
			member.ExpectedPublicIP = fmt.Sprintf("198.51.100.%d", 40+position)
			base.Members = append(base.Members, member)
		}
		base.Members = append(base.Members, last)
		for _, entry := range []string{"wg", "awg2-fast", "awg2-strong"} {
			valid := base.Clone()
			valid.EntryMode = entry
			if _, err := valid.Digest(); err != nil {
				t.Fatalf("original %d-node %s remote descriptor refused: %v", count, entry, err)
			}
			for _, fault := range []string{"private-middle", "active-final", "foreign-entry", "borrowed-source"} {
				changed := valid.Clone()
				switch fault {
				case "private-middle":
					changed.Members[0] = chainCaptureFixture(t, 2).Source.Members[0]
				case "active-final":
					changed.Members[len(changed.Members)-1].StartLayer = "aes-256-gcm"
				case "foreign-entry":
					changed.EntryMode = "awg2-pq"
				case "borrowed-source":
					changed.Members[1].SourceSHA256 = changed.Members[0].SourceSHA256
				}
				if _, err := changed.Digest(); err == nil {
					t.Fatalf("accepted changed %d-node %s descriptor: %s", count, entry, fault)
				}
			}
		}
	}
}

func TestNodeChainMultipleImportedCaptureComplement(t *testing.T) {
	for _, layout := range []struct {
		name      string
		count     int
		positions []int
	}{{"one", 2, []int{1}}, {"adjacent", 3, []int{1, 2}}, {"separated", 4, []int{1, 3}}, {"packet-first", 5, []int{2, 4}}, {"maximum-sparse", 7, []int{1, 4, 6}}, {"maximum-public", 7, []int{1, 2, 3, 4, 5, 6}}} {
		t.Run(layout.name, func(t *testing.T) {
			c := multipleImportedCaptureFixture(t, layout.count, layout.positions)
			want := []int{0}
			for _, member := range c.Source.Members[:layout.count-1] {
				if member.NodeKind == "" {
					want = append(want, member.Position)
				}
			}
			if !reflect.DeepEqual(c.Request.LocalPacketPositions, want) || len(c.Request.LocalPacketPublicKeys) != len(want) || len(c.Request.Users) != layout.count {
				t.Fatal("omitted packet complement or per-position credentials")
			}
			before, err := c.Digest()
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(c)
			var replay NodeChainCapture
			if json.Unmarshal(raw, &replay) != nil {
				t.Fatal("roundtrip")
			}
			after, err := replay.Digest()
			if err != nil || before != after || !reflect.DeepEqual(c, replay) {
				t.Fatal("complete positional capture changed", err)
			}
			copy := c.Clone()
			copy.Source.Members[0].ProfileID = "foreign"
			copy.Request.LocalPacketPositions[0] = 1
			if _, err := c.Digest(); err != nil || c.Request.LocalPacketPositions[0] != 0 {
				t.Fatal("copy-out aliased source")
			}
		})
	}
}

func TestNodeChainMultipleImportedCaptureRefusals(t *testing.T) {
	for _, fault := range []string{"missing-public", "public-final", "public-kind", "public-role", "public-mode", "public-layer", "public-proof", "public-router-id", "public-client-key", "public-server-key", "public-openvpn-pair", "duplicate-source", "duplicate-id", "private-public-metadata", "reordered-members", "missing-position", "reordered-positions", "duplicate-position", "public-position", "final-position", "extra-key", "missing-key", "borrowed-server-key", "shared-local-key", "missing-user", "reordered-users", "duplicate-password", "wrong-dns", "wrong-source", "wrong-owner", "cross-schema"} {
		t.Run(fault, func(t *testing.T) {
			c := multipleImportedCaptureFixture(t, 7, []int{1, 4, 6})
			m := &c.Source.Members[0]
			switch fault {
			case "missing-public":
				for _, i := range []int{0, 3, 5} {
					c.Source.Members[i] = chainCaptureFixture(t, 7).Source.Members[i]
				}
			case "public-final":
				c.Source.Members[6] = *m
				c.Source.Members[6].Position = 7
				c.Source.Members[6].ProfileID = "import-final"
			case "public-kind":
				m.NodeKind = "paired"
			case "public-role":
				m.ProofKind = "private-path"
			case "public-mode":
				m.Mode = "socks5"
			case "public-layer":
				m.StartLayer = "aes-256-gcm"
			case "public-proof":
				m.SourceSHA256 = ""
			case "public-router-id":
				m.NodeID = strings.Repeat("a", 64)
			case "public-client-key":
				m.ClientPublicKey = chainCapturePublic(t, 211)
			case "public-server-key":
				m.ServerPublicKey = chainCapturePublic(t, 212)
			case "public-openvpn-pair":
				m.OpenVPNPairSHA256 = strings.Repeat("a", 64)
			case "duplicate-source":
				c.Source.Members[3].SourceSHA256 = m.SourceSHA256
			case "duplicate-id":
				c.Source.Members[3].ProfileID = m.ProfileID
			case "private-public-metadata":
				c.Source.Members[1].SourceSHA256 = m.SourceSHA256
			case "reordered-members":
				c.Source.Members[0], c.Source.Members[1] = c.Source.Members[1], c.Source.Members[0]
			case "missing-position":
				c.Request.LocalPacketPositions = c.Request.LocalPacketPositions[:len(c.Request.LocalPacketPositions)-1]
			case "reordered-positions":
				c.Request.LocalPacketPositions[1], c.Request.LocalPacketPositions[2] = c.Request.LocalPacketPositions[2], c.Request.LocalPacketPositions[1]
			case "duplicate-position":
				c.Request.LocalPacketPositions[1] = 0
			case "public-position":
				c.Request.LocalPacketPositions[1] = 1
			case "final-position":
				c.Request.LocalPacketPositions[len(c.Request.LocalPacketPositions)-1] = 7
			case "extra-key":
				c.Request.LocalPacketPublicKeys = append(c.Request.LocalPacketPublicKeys, chainCapturePublic(t, 213))
			case "missing-key":
				c.Request.LocalPacketPublicKeys = c.Request.LocalPacketPublicKeys[1:]
			case "borrowed-server-key":
				c.Request.LocalPacketPublicKeys[1] = c.Source.Members[1].ClientPublicKey
			case "shared-local-key":
				c.Request.LocalPacketPublicKeys[1] = c.Request.LocalPacketPublicKeys[0]
			case "missing-user":
				c.Request.Users = c.Request.Users[:6]
			case "reordered-users":
				c.Request.Users[0], c.Request.Users[1] = c.Request.Users[1], c.Request.Users[0]
			case "duplicate-password":
				c.Request.Users[1].Password = c.Request.Users[0].Password
			case "wrong-dns":
				c.Request.DNSPolicySHA256 = strings.Repeat("a", 64)
			case "wrong-source":
				c.Request.SourceSHA256 = strings.Repeat("b", 64)
			case "wrong-owner":
				c.OwnerID = ""
			case "cross-schema":
				c.Request.Schema = 2
			}
			// A malformed descriptor must fail on its own rather than only on
			// the stale enclosing digest. Valid descriptors receive a fresh hash.
			if digest, err := c.Source.Digest(); err == nil {
				c.RegistrySHA256, c.Request.DescriptorSHA256 = digest, digest
			}
			if err := c.Validate(); err == nil {
				t.Fatal("changed positional source authority accepted")
			}
		})
	}
}

func TestNodeChainMultipleImportedLeaseOriginalPublicReceipts(t *testing.T) {
	for _, fault := range []string{"none", "public-source", "public-role", "missing-row", "reordered-row", "selected-dns", "owner"} {
		t.Run(fault, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c := multipleImportedCaptureFixture(t, 4, []int{1, 3})
				cfg := nodeChainFixtureConfig(t, 4)
				c.Source.EntryNodeID = req().EntryNodeID
				cfg.NodeChains = []NodeChainDescriptor{c.Source}
				r := &nodeChainFixtureRunner{configure: func(p *nodeChainFixtureProcess) {
					p.transform = func(receipt *NodeChainReceipt) {
						for i := range receipt.Prefixes {
							member := p.capture.Source.Members[i]
							receipt.Prefixes[i].NodeKind = member.NodeKind
							receipt.Prefixes[i].ProofKind = member.ProofKind
							receipt.Prefixes[i].SourceSHA256 = member.SourceSHA256
						}
						if receipt.Phase != NodeChainReady {
							return
						}
						switch fault {
						case "public-source":
							receipt.Prefixes[0].SourceSHA256 = receipt.Prefixes[2].SourceSHA256
						case "public-role":
							receipt.Prefixes[0].ProofKind = ""
						case "missing-row":
							receipt.Prefixes = receipt.Prefixes[:3]
						case "reordered-row":
							receipt.Prefixes[0], receipt.Prefixes[1] = receipt.Prefixes[1], receipt.Prefixes[0]
						case "selected-dns":
							receipt.DNSProven = false
						case "owner":
							receipt.OwnerID = strings.Repeat("a", 64)
						}
					}
				}}
				m, err := New(cfg, req().EntryNodeID, r)
				if err != nil {
					t.Fatal(err)
				}
				defer nodeChainFixtureClose(t, m)
				peer := netip.MustParseAddr("10.77.0.2")
				challenge, err := m.PacketChallenge(peer)
				if err != nil {
					t.Fatal(err)
				}
				q := c.Request
				q.EntryNodeID = c.Source.EntryNodeID
				q.DescriptorSHA256, err = c.Source.Digest()
				if err != nil {
					t.Fatal(err)
				}
				q.Epoch, q.Peer, q.AcquireExpiresAt, q.Port = challenge.Epoch, challenge.Peer, challenge.ExpiresAt, cfg.FirstPort
				lease, err := m.CreateChain(context.Background(), peer, q)
				if err != nil || lease.Phase != NodeChainPending {
					t.Fatal("owned pending acquisition", err)
				}
				p := r.worker(t, 0)
				<-p.bootstrap
				pending, err := m.ChainStatus(context.Background(), peer, q, strings.Repeat("b", 64))
				if err != nil || pending.Receipt.TrafficAllowed || pending.Receipt.DNSProven || len(pending.Receipt.Prefixes) != 0 {
					t.Fatal("pending source fabricated proof", err)
				}
				p.finish()
				synctest.Wait()
				status, err := m.ChainStatus(context.Background(), peer, q, strings.Repeat("c", 64))
				if fault != "none" {
					if err == nil {
						t.Fatal("changed original worker proof admitted")
					}
					return
				}
				if err != nil || status.Receipt.Phase != NodeChainReady || !status.Receipt.DNSProven || !status.Receipt.PublicProven || len(status.Receipt.Prefixes) != 4 || r.count() != 1 || r.ordinaryStarts.Load() != 0 {
					t.Fatal("complete positional owner was not admitted", err)
				}
				if err := m.DeleteChain(context.Background(), peer, q); err != nil || p.Alive() || p.stops.Load() != 1 {
					t.Fatal("original worker retirement did not join", err)
				}
				if _, err := m.ChainStatus(context.Background(), peer, q, strings.Repeat("d", 64)); err == nil {
					t.Fatal("retired owner reused")
				}
			})
		})
	}
}
