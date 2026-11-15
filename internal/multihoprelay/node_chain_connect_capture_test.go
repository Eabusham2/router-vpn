package multihoprelay

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func connectChainCaptureFixture(t *testing.T, mode string) NodeChainCapture {
	t.Helper()
	c := importedChainCaptureFixture(t)
	c.Source.Schema, c.Request.Schema = 4, 4
	c.Source.Members[0].Mode = mode
	c.Source.Members[0].ProfileID = "original-connect-middle"
	c.RegistrySHA256, _ = c.Source.Digest()
	c.Request.DescriptorSHA256 = c.RegistrySHA256
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNodeChainCONNECTCaptureSeparatesOriginalEntryFromSuffix(t *testing.T) {
	for _, entry := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, mode := range []string{"http-connect", "https-connect"} {
			t.Run(entry+"/"+mode, func(t *testing.T) {
				c := connectChainCaptureFixture(t, mode)
				c.Source.EntryMode = entry
				c.RegistrySHA256, _ = c.Source.Digest()
				c.Request.DescriptorSHA256 = c.RegistrySHA256
				if c.Validate() != nil || len(c.Request.LocalPacketPublicKeys) != 1 || !reflect.DeepEqual(c.Request.LocalPacketPositions, []int{0}) {
					t.Fatal("CONNECT borrowed suffix packet authority")
				}
				middle := c.Source.Members[0]
				if middle.NodeID != "" || middle.ClientPublicKey != "" || middle.ServerPublicKey != "" || middle.ProofKind != "public-path" || middle.Mode != mode {
					t.Fatal("CONNECT acquired synthetic paired transport identity")
				}
				raw, err := json.Marshal(c)
				if err != nil {
					t.Fatal(err)
				}
				var restored NodeChainCapture
				if json.Unmarshal(raw, &restored) != nil || restored.Validate() != nil || !reflect.DeepEqual(c, restored) {
					t.Fatal("CONNECT handoff changed original positional identities")
				}
				digest, _ := c.Source.Digest()
				legacy, _ := nodeChainDigest("routervpn-server-node-chain-descriptor-v2", c.Source)
				if digest == legacy {
					t.Fatal("CONNECT borrowed SS descriptor domain")
				}
				request, _ := c.Request.Digest()
				legacyRequest, _ := nodeChainDigest("routervpn-server-node-chain-request-v2", c.Request)
				if request == legacyRequest {
					t.Fatal("CONNECT borrowed SS request domain")
				}
				clone := c.Clone()
				clone.Request.LocalPacketPositions[0] = 1
				clone.Source.Members[0].Mode = "shadowsocks"
				if c.Request.LocalPacketPositions[0] != 0 || c.Source.Members[0].Mode != mode {
					t.Fatal("CONNECT clone shares mutable authority")
				}
			})
		}
	}
}

func TestNodeChainCONNECTCaptureRejectsCrossFamilyAndSyntheticOwnership(t *testing.T) {
	faults := map[string]func(*NodeChainCapture){
		"ss-schema":              func(c *NodeChainCapture) { c.Source.Schema = 2; c.Request.Schema = 2 },
		"paired-schema":          func(c *NodeChainCapture) { c.Source.Schema = 1; c.Request.Schema = 1 },
		"socks-schema":           func(c *NodeChainCapture) { c.Source.Schema = 3; c.Request.Schema = 3 },
		"ss-mode":                func(c *NodeChainCapture) { c.Source.Members[0].Mode = "shadowsocks" },
		"socks-mode":             func(c *NodeChainCapture) { c.Source.Members[0].Mode = "socks5" },
		"imported-node-id":       func(c *NodeChainCapture) { c.Source.Members[0].NodeID = strings.Repeat("b", 64) },
		"imported-private-proof": func(c *NodeChainCapture) { c.Source.Members[0].ProofKind = "private-node" },
		"missing-middle-source":  func(c *NodeChainCapture) { c.Source.Members[0].SourceSHA256 = "" },
		"missing-public-proof":   func(c *NodeChainCapture) { c.Source.Members[0].ExpectedPublicIP = "" },
		"private-public-proof":   func(c *NodeChainCapture) { c.Source.Members[0].ExpectedPublicIP = "10.0.0.1" },
		"layered-middle":         func(c *NodeChainCapture) { c.Source.Members[0].StartLayer = "aes-256-gcm" },
		"synthetic-client-key":   func(c *NodeChainCapture) { c.Source.Members[0].ClientPublicKey = chainCapturePublic(t, 114) },
		"synthetic-server-key":   func(c *NodeChainCapture) { c.Source.Members[0].ServerPublicKey = chainCapturePublic(t, 115) },
		"synthetic-key-position": func(c *NodeChainCapture) { c.Request.LocalPacketPositions = []int{1} },
		"extra-entry-key": func(c *NodeChainCapture) {
			c.Request.LocalPacketPublicKeys = append(c.Request.LocalPacketPublicKeys, chainCapturePublic(t, 116))
			c.Request.LocalPacketPositions = []int{0, 1}
		},
		"wrong-final":    func(c *NodeChainCapture) { c.Source.Members[1].Mode = "hysteria2" },
		"external-final": func(c *NodeChainCapture) { c.Source.Members[1].NodeKind = "external" },
		"long-suffix":    func(c *NodeChainCapture) { c.Source.Members = append(c.Source.Members, c.Source.Members[1]) },
		"reordered-suffix": func(c *NodeChainCapture) {
			c.Source.Members[0], c.Source.Members[1] = c.Source.Members[1], c.Source.Members[0]
		},
		"duplicate-profile":    func(c *NodeChainCapture) { c.Source.Members[0].ProfileID = c.Source.EntryID },
		"wrong-request-family": func(c *NodeChainCapture) { c.Request.Schema = 2 },
	}
	for name, change := range faults {
		t.Run(name, func(t *testing.T) {
			c := connectChainCaptureFixture(t, "https-connect")
			change(&c)
			if digest, err := c.Source.Digest(); err == nil {
				c.RegistrySHA256 = digest
				c.Request.DescriptorSHA256 = digest
			}
			if c.Validate() == nil {
				t.Fatal("CONNECT capture accepted changed family, identity or packet authority")
			}
		})
	}
	for _, field := range []string{"transport", "source", "public-proof"} {
		t.Run("bound-"+field, func(t *testing.T) {
			c := connectChainCaptureFixture(t, "https-connect")
			if field == "transport" {
				c.Source.Members[0].Mode = "http-connect"
			}
			if field == "source" {
				c.Source.Members[0].SourceSHA256 = strings.Repeat("b", 64)
			}
			if field == "public-proof" {
				c.Source.Members[0].ExpectedPublicIP = "203.0.113.45"
			}
			if c.Source.Validate() != nil || c.Validate() == nil {
				t.Fatal("replacement CONNECT source borrowed original registry receipt")
			}
		})
	}
}
