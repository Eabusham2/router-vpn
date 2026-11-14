package multihoprelay

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
)

func importedChainCaptureFixture(t *testing.T) NodeChainCapture {
	t.Helper()
	c := chainCaptureFixture(t, 2)
	c.Source.Schema, c.Request.Schema = 2, 2
	c.Source.Members[0] = NodeChainMember{Position: 1, ProfileID: "original-imported-ss", Mode: "shadowsocks", StartLayer: "off",
		NodeKind: "external", ProofKind: "public-path", SourceSHA256: strings.Repeat("a", 64), ExpectedPublicIP: "203.0.113.44"}
	c.Request.LocalPacketPublicKeys = c.Request.LocalPacketPublicKeys[:1]
	c.Request.LocalPacketPositions = []int{0}
	c.RegistrySHA256, _ = c.Source.Digest()
	c.Request.DescriptorSHA256 = c.RegistrySHA256
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNodeChainImportedCaptureOwnsTypedProofAndActualPacketPositions(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		t.Run(mode, func(t *testing.T) {
			c := importedChainCaptureFixture(t)
			c.Source.EntryMode = mode
			c.RegistrySHA256, _ = c.Source.Digest()
			c.Request.DescriptorSHA256 = c.RegistrySHA256
			before, err := c.Digest()
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			var restored NodeChainCapture
			if json.Unmarshal(raw, &restored) != nil || restored.Validate() != nil || !reflect.DeepEqual(restored, c) {
				t.Fatal("typed source or positional packet ownership changed on handoff")
			}
			after, _ := restored.Digest()
			if before != after || len(c.Request.Users) != 2 || len(c.Request.LocalPacketPublicKeys) != 1 ||
				c.Source.Members[0].NodeID != "" || c.Source.Members[0].ClientPublicKey != "" {
				t.Fatal("SS acquired a fake paired identity or packet key")
			}
			copy := c.Clone()
			copy.Request.LocalPacketPositions[0] = 1
			copy.Source.Members[0].SourceSHA256 = strings.Repeat("b", 64)
			if c.Request.LocalPacketPositions[0] != 0 || c.Source.Members[0].SourceSHA256 != strings.Repeat("a", 64) {
				t.Fatal("clone retained caller-owned positional source storage")
			}
		})
	}
}

func TestNodeChainImportedCaptureRejectsForgedKindsSourcesAndPacketPins(t *testing.T) {
	faults := map[string]func(*NodeChainCapture){
		"paired-schema":     func(c *NodeChainCapture) { c.Source.Schema = 1 },
		"request-schema":    func(c *NodeChainCapture) { c.Request.Schema = 1 },
		"extra-member":      func(c *NodeChainCapture) { c.Source.Members = append(c.Source.Members, c.Source.Members[1]) },
		"private-node":      func(c *NodeChainCapture) { c.Source.Members[0].NodeID = strings.Repeat("b", 64) },
		"private-proof":     func(c *NodeChainCapture) { c.Source.Members[0].ProofKind = "private-node" },
		"paired-kind":       func(c *NodeChainCapture) { c.Source.Members[0].NodeKind = "router" },
		"missing-source":    func(c *NodeChainCapture) { c.Source.Members[0].SourceSHA256 = "" },
		"local-egress":      func(c *NodeChainCapture) { c.Source.Members[0].ExpectedPublicIP = "192.168.50.1" },
		"mapped-egress":     func(c *NodeChainCapture) { c.Source.Members[0].ExpectedPublicIP = "::ffff:203.0.113.44" },
		"middle-socks":      func(c *NodeChainCapture) { c.Source.Members[0].Mode = "socks5" },
		"middle-connect":    func(c *NodeChainCapture) { c.Source.Members[0].Mode = "http-connect" },
		"middle-layer":      func(c *NodeChainCapture) { c.Source.Members[0].StartLayer = "aes-256-gcm" },
		"middle-packet-key": func(c *NodeChainCapture) { c.Source.Members[0].ClientPublicKey = chainCapturePublic(t, 111) },
		"middle-server-key": func(c *NodeChainCapture) { c.Source.Members[0].ServerPublicKey = chainCapturePublic(t, 112) },
		"final-external":    func(c *NodeChainCapture) { c.Source.Members[1].NodeKind = "external" },
		"duplicate-profile": func(c *NodeChainCapture) { c.Source.Members[1].ProfileID = c.Source.Members[0].ProfileID },
		"missing-position":  func(c *NodeChainCapture) { c.Request.LocalPacketPositions = nil },
		"ss-position":       func(c *NodeChainCapture) { c.Request.LocalPacketPositions[0] = 1 },
		"extra-position":    func(c *NodeChainCapture) { c.Request.LocalPacketPositions = []int{0, 1} },
		"placeholder-key": func(c *NodeChainCapture) {
			c.Request.LocalPacketPublicKeys = append(c.Request.LocalPacketPublicKeys, "")
		},
		"extra-real-key": func(c *NodeChainCapture) {
			c.Request.LocalPacketPublicKeys = append(c.Request.LocalPacketPublicKeys, chainCapturePublic(t, 113))
		},
		"missing-key": func(c *NodeChainCapture) { c.Request.LocalPacketPublicKeys = nil },
		"low-order-key": func(c *NodeChainCapture) {
			c.Request.LocalPacketPublicKeys[0] = base64.StdEncoding.EncodeToString(make([]byte, 32))
		},
		"key-alias": func(c *NodeChainCapture) {
			raw, _ := base64.StdEncoding.DecodeString(c.Request.LocalPacketPublicKeys[0])
			raw[31] ^= 128
			c.Request.LocalPacketPublicKeys[0] = base64.StdEncoding.EncodeToString(raw)
		},
	}
	for name, mutate := range faults {
		t.Run(name, func(t *testing.T) {
			c := importedChainCaptureFixture(t)
			mutate(&c)
			// Recompute valid descriptor hashes so rejection tests the typed
			// shape/authority rather than relying only on an old digest.
			if digest, err := c.Source.Digest(); err == nil {
				c.RegistrySHA256, c.Request.DescriptorSHA256 = digest, digest
			}
			if c.Validate() == nil {
				t.Fatal("changed imported authority was accepted")
			}
		})
	}
	for _, field := range []string{"source", "egress"} {
		t.Run("capture-bound-"+field, func(t *testing.T) {
			c := importedChainCaptureFixture(t)
			if field == "source" {
				c.Source.Members[0].SourceSHA256 = strings.Repeat("b", 64)
			} else {
				c.Source.Members[0].ExpectedPublicIP = "203.0.113.45"
			}
			if c.Source.Validate() != nil || c.Validate() == nil {
				t.Fatal("valid replacement borrowed original registry authorization")
			}
		})
	}
}

func TestNodeChainImportedReceiptRequiresExactPublicProofIdentity(t *testing.T) {
	c, ready, challenge, started, now := nodeChainReceiptFixture(t, 2)
	imported := importedChainCaptureFixture(t)
	c.Source, c.Request, c.RegistrySHA256 = imported.Source, imported.Request, imported.RegistrySHA256
	ready.RegistrySHA256 = c.RegistrySHA256
	ready.CaptureSHA256, _ = c.Digest()
	member := c.Source.Members[0]
	ready.Prefixes[0] = NodeChainPrefixReceipt{Position: member.Position, ProfileID: member.ProfileID, NodeID: member.NodeID,
		Mode: member.Mode, Proven: true, ResponseMS: 1.25, NodeKind: member.NodeKind, ProofKind: member.ProofKind, SourceSHA256: member.SourceSHA256}
	if err := ValidateNodeChainReceipt(ready, c, challenge, started, now); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*NodeChainPrefixReceipt){
		"private-node":       func(r *NodeChainPrefixReceipt) { r.NodeID = strings.Repeat("b", 64) },
		"missing-kind":       func(r *NodeChainPrefixReceipt) { r.NodeKind = "" },
		"wrong-proof":        func(r *NodeChainPrefixReceipt) { r.ProofKind = "private-node" },
		"missing-source":     func(r *NodeChainPrefixReceipt) { r.SourceSHA256 = "" },
		"replacement-source": func(r *NodeChainPrefixReceipt) { r.SourceSHA256 = strings.Repeat("b", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := ready.Clone()
			mutate(&bad.Prefixes[0])
			if ValidateNodeChainReceipt(bad, c, challenge, started, now) == nil {
				t.Fatal("receipt substituted the imported proof")
			}
		})
	}
}

func TestNodeChainImportedLeasePinsActualEntryAcrossRegistryChange(t *testing.T) {
	for _, sameKey := range []bool{true, false} {
		t.Run(fmt.Sprintf("same-key-%t", sameKey), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				original := importedChainCaptureFixture(t)
				cfg := nodeChainFixtureConfig(t, 2)
				original.Source.EntryNodeID = req().EntryNodeID
				cfg.NodeChains = []NodeChainDescriptor{original.Source}
				r := &nodeChainFixtureRunner{}
				m, err := New(cfg, req().EntryNodeID, r)
				if err != nil {
					t.Fatal(err)
				}
				defer nodeChainFixtureClose(t, m)
				peer := netip.MustParseAddr("10.77.0.2")
				request := func(peer netip.Addr) NodeChainRequest {
					q := nodeChainFixtureRequestFor(t, m, peer)
					q.Schema = 2
					q.LocalPacketPublicKeys = q.LocalPacketPublicKeys[:1]
					q.LocalPacketPositions = []int{0}
					return q
				}
				q := request(peer)
				if _, err := m.CreateChain(context.Background(), peer, q); err != nil {
					t.Fatal(err)
				}
				p := r.worker(t, 0)
				<-p.bootstrap
				next := request(peer.Next())
				next.SessionID = strings.Repeat("d", 32)
				next.Port++
				for i := range next.Users {
					next.Users[i].Username = fmt.Sprintf("%048x", 501+i*2)
					next.Users[i].Password = fmt.Sprintf("%048x", 502+i*2)
				}
				if !sameKey {
					next.LocalPacketPublicKeys[0] = chainCapturePublic(t, 201)
				}
				_, err = m.CreateChain(context.Background(), peer.Next(), next)
				if sameKey && (err == nil || r.count() != 1) || !sameKey && (err != nil || r.count() != 2) {
					t.Fatal("imported suffix changed canonical entry ownership", err)
				}
				if !sameKey {
					if err := m.DeleteChain(context.Background(), peer.Next(), next); err != nil {
						t.Fatal(err)
					}
				}
				// A source replacement cannot erase the active original entry
				// key. Its private worker has not joined, so the pin remains.
				p.stopFail.Store(true)
				if m.DeleteChain(context.Background(), peer, q) == nil {
					t.Fatal("failed native join reported successful retirement")
				}
				m.mu.Lock()
				m.cfg.NodeChains[0].SourceSHA256 = strings.Repeat("e", 64)
				m.mu.Unlock()
				next = request(peer.Next())
				next.SessionID = strings.Repeat("e", 32)
				next.Port++
				if !sameKey {
					next.LocalPacketPublicKeys[0] = chainCapturePublic(t, 201)
				}
				before := r.count()
				_, err = m.CreateChain(context.Background(), peer.Next(), next)
				if err == nil || r.count() != before || !p.Alive() || p.capture.Request.LocalPacketPublicKeys[0] != q.LocalPacketPublicKeys[0] {
					t.Fatal("failed original retirement lost its packet pin or permitted a replacement", err)
				}
				p.stopFail.Store(false)
				if err := m.DeleteChain(context.Background(), peer, q); err != nil {
					t.Fatal("original owner cannot retire after registry replacement", err)
				}
				if r.ordinaryStarts.Load() != 0 {
					t.Fatal("typed imported lease fell back to ordinary relay")
				}
			})
		})
	}
}
