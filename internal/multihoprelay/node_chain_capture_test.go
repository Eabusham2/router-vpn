package multihoprelay

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func chainCapturePublic(t *testing.T, seed byte) string {
	t.Helper()
	key, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{seed}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
}

func chainCaptureFixture(t *testing.T, count int) NodeChainCapture {
	t.Helper()
	source := NodeChainDescriptor{Schema: 1, EntryID: "original-entry", EntryNodeID: strings.Repeat("1", 64),
		EntryMode: "wg", SourceSHA256: strings.Repeat("2", 64), DNSPolicySHA256: strings.Repeat("3", 64)}
	request := NodeChainRequest{Schema: 1, SessionID: strings.Repeat("4", 32), EntryNodeID: source.EntryNodeID,
		SourceSHA256: source.SourceSHA256, DNSPolicySHA256: source.DNSPolicySHA256,
		Epoch: strings.Repeat("5", 64), Peer: "10.77.0.2", AcquireExpiresAt: 1794484810, Port: 26240}
	for i := 0; i < count; i++ {
		member := NodeChainMember{Position: i + 1, ProfileID: fmt.Sprintf("suffix-%d", i), NodeID: fmt.Sprintf("%064x", 100+i),
			Mode: []string{"wg", "awg2-fast", "awg2-strong"}[i%3], StartLayer: []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"}[i%3],
			ClientPublicKey: chainCapturePublic(t, byte(11+i)), ServerPublicKey: chainCapturePublic(t, byte(41+i))}
		if i == count-1 {
			member.Mode, member.ClientPublicKey, member.ServerPublicKey = "shadowsocks", "", ""
		}
		source.Members = append(source.Members, member)
		request.LocalPacketPublicKeys = append(request.LocalPacketPublicKeys, chainCapturePublic(t, byte(71+i)))
		request.Users = append(request.Users, NodeChainUser{i + 1, fmt.Sprintf("%048x", 200+i*2), fmt.Sprintf("%048x", 201+i*2)})
	}
	digest, err := source.Digest()
	if err != nil {
		t.Fatal(err)
	}
	request.DescriptorSHA256 = digest
	return NodeChainCapture{Schema: 1, Request: request, Source: source, RegistrySHA256: digest,
		OwnerID: strings.Repeat("6", 64), Peer: request.Peer, Host: "10.77.0.1", BootstrapDeadline: time.Unix(1794484890, 0).UTC()}
}

func TestNodeChainCaptureBoundsAndCanonicalRoundTrip(t *testing.T) {
	for _, count := range []int{1, 2, 3, 7} {
		for _, entry := range []string{"wg", "awg2-fast", "awg2-strong"} {
			t.Run(fmt.Sprintf("%d/%s", count, entry), func(t *testing.T) {
				capture := chainCaptureFixture(t, count)
				capture.Source.EntryMode = entry
				capture.RegistrySHA256, _ = capture.Source.Digest()
				capture.Request.DescriptorSHA256 = capture.RegistrySHA256
				if err := capture.Validate(); err != nil {
					t.Fatal(err)
				}
				before, err := capture.Digest()
				if err != nil {
					t.Fatal(err)
				}
				raw, err := json.Marshal(capture)
				if err != nil {
					t.Fatal(err)
				}
				var restored NodeChainCapture
				if err := json.Unmarshal(raw, &restored); err != nil {
					t.Fatal(err)
				}
				after, err := restored.Digest()
				if err != nil || before != after || !reflect.DeepEqual(capture, restored) {
					t.Fatal("complete private worker capture changed after handoff", err)
				}
			})
		}
	}
}

func TestNodeChainCaptureRejectsChangedAuthority(t *testing.T) {
	// These are malformed descriptor shapes independently of any stale request
	// digest. Valid source/DNS replacements below remain capture-binding cases.
	descriptorInvalid := map[string]bool{}
	for _, name := range []string{"source-schema", "source-empty", "source-over-bound", "entry-mode", "entry-proof", "entry-id", "source-reorder",
		"prefix-unsupported", "final-unsupported", "final-packet-key", "start-layer-alias", "duplicate-profile", "duplicate-proof",
		"duplicate-server-client", "low-order-key", "key-high-bit-alias"} {
		descriptorInvalid[name] = true
	}
	tests := map[string]func(*NodeChainCapture){
		"capture-schema":    func(c *NodeChainCapture) { c.Schema++ },
		"source-schema":     func(c *NodeChainCapture) { c.Source.Schema++ },
		"source-empty":      func(c *NodeChainCapture) { c.Source.Members = nil },
		"source-over-bound": func(c *NodeChainCapture) { c.Source.Members = append(c.Source.Members, c.Source.Members...) },
		"entry-mode":        func(c *NodeChainCapture) { c.Source.EntryMode = "max" },
		"entry-proof":       func(c *NodeChainCapture) { c.Source.EntryNodeID = c.Source.Members[0].NodeID },
		"entry-id":          func(c *NodeChainCapture) { c.Source.EntryID = c.Source.Members[0].ProfileID },
		"source-id":         func(c *NodeChainCapture) { c.Source.SourceSHA256 = strings.Repeat("a", 64) },
		"source-dns":        func(c *NodeChainCapture) { c.Source.DNSPolicySHA256 = strings.Repeat("b", 64) },
		"source-reorder": func(c *NodeChainCapture) {
			c.Source.Members[0], c.Source.Members[1] = c.Source.Members[1], c.Source.Members[0]
		},
		"prefix-unsupported":      func(c *NodeChainCapture) { c.Source.Members[0].Mode = "pq" },
		"final-unsupported":       func(c *NodeChainCapture) { c.Source.Members[3].Mode = "wg" },
		"final-packet-key":        func(c *NodeChainCapture) { c.Source.Members[3].ClientPublicKey = c.Source.Members[0].ClientPublicKey },
		"start-layer-alias":       func(c *NodeChainCapture) { c.Source.Members[0].StartLayer = "" },
		"duplicate-profile":       func(c *NodeChainCapture) { c.Source.Members[1].ProfileID = c.Source.Members[0].ProfileID },
		"duplicate-proof":         func(c *NodeChainCapture) { c.Source.Members[1].NodeID = c.Source.Members[0].NodeID },
		"duplicate-server-client": func(c *NodeChainCapture) { c.Source.Members[1].ClientPublicKey = c.Source.Members[0].ServerPublicKey },
		"low-order-key": func(c *NodeChainCapture) {
			c.Source.Members[0].ClientPublicKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
		},
		"key-high-bit-alias": func(c *NodeChainCapture) {
			raw, _ := base64.StdEncoding.DecodeString(c.Source.Members[0].ClientPublicKey)
			raw[31] |= 128
			c.Source.Members[0].ClientPublicKey = base64.StdEncoding.EncodeToString(raw)
		},
		"request-schema":                func(c *NodeChainCapture) { c.Request.Schema++ },
		"session":                       func(c *NodeChainCapture) { c.Request.SessionID = "" },
		"request-source":                func(c *NodeChainCapture) { c.Request.SourceSHA256 = strings.Repeat("a", 64) },
		"request-descriptor":            func(c *NodeChainCapture) { c.Request.DescriptorSHA256 = strings.Repeat("a", 64) },
		"request-dns":                   func(c *NodeChainCapture) { c.Request.DNSPolicySHA256 = strings.Repeat("a", 64) },
		"request-entry":                 func(c *NodeChainCapture) { c.Request.EntryNodeID = strings.Repeat("a", 64) },
		"no-epoch":                      func(c *NodeChainCapture) { c.Request.Epoch = "" },
		"no-acquisition":                func(c *NodeChainCapture) { c.Request.AcquireExpiresAt = 0 },
		"peer-replacement":              func(c *NodeChainCapture) { c.Request.Peer = "10.77.0.3" },
		"public-peer":                   func(c *NodeChainCapture) { c.Peer = "198.51.100.1"; c.Request.Peer = c.Peer },
		"mapped-peer":                   func(c *NodeChainCapture) { c.Peer = "::ffff:10.77.0.2"; c.Request.Peer = c.Peer },
		"public-host":                   func(c *NodeChainCapture) { c.Host = "198.51.100.1" },
		"loopback-host":                 func(c *NodeChainCapture) { c.Host = "127.0.0.1" },
		"no-port-proposal":              func(c *NodeChainCapture) { c.Request.Port = 0 },
		"port-overflow":                 func(c *NodeChainCapture) { c.Request.Port = 65536 },
		"missing-local-pin":             func(c *NodeChainCapture) { c.Request.LocalPacketPublicKeys = c.Request.LocalPacketPublicKeys[1:] },
		"duplicate-local-pin":           func(c *NodeChainCapture) { c.Request.LocalPacketPublicKeys[1] = c.Request.LocalPacketPublicKeys[0] },
		"local-server-client-collision": func(c *NodeChainCapture) { c.Request.LocalPacketPublicKeys[0] = c.Source.Members[1].ClientPublicKey },
		"local-server-peer-collision":   func(c *NodeChainCapture) { c.Request.LocalPacketPublicKeys[2] = c.Source.Members[0].ServerPublicKey },
		"missing-user":                  func(c *NodeChainCapture) { c.Request.Users = c.Request.Users[1:] },
		"reordered-user": func(c *NodeChainCapture) {
			c.Request.Users[0], c.Request.Users[1] = c.Request.Users[1], c.Request.Users[0]
		},
		"empty-user":          func(c *NodeChainCapture) { c.Request.Users[0].Username = "" },
		"duplicate-secret":    func(c *NodeChainCapture) { c.Request.Users[1].Password = c.Request.Users[0].Username },
		"short-secret":        func(c *NodeChainCapture) { c.Request.Users[0].Password = strings.Repeat("a", 47) },
		"foreign-registry":    func(c *NodeChainCapture) { c.RegistrySHA256 = strings.Repeat("a", 64) },
		"missing-owner":       func(c *NodeChainCapture) { c.OwnerID = "" },
		"missing-deadline":    func(c *NodeChainCapture) { c.BootstrapDeadline = time.Time{} },
		"deadline-zone-alias": func(c *NodeChainCapture) { c.BootstrapDeadline = c.BootstrapDeadline.In(time.FixedZone("alias", 3600)) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			capture := chainCaptureFixture(t, 4)
			mutate(&capture)
			if descriptorInvalid[name] {
				if capture.Source.Validate() == nil {
					t.Fatal("malformed descriptor passed direct shape validation")
				}
				if _, err := capture.Source.Digest(); err == nil {
					t.Fatal("malformed descriptor obtained a new valid digest")
				}
			}
			if capture.Validate() == nil {
				t.Fatal("changed source, credential, key or lifetime authority passed")
			}
			if _, err := capture.Digest(); err == nil {
				t.Fatal("invalid capture acquired a digest")
			}
		})
	}
}

func TestNodeChainCaptureClonesAndDigestsOwnEveryField(t *testing.T) {
	original := chainCaptureFixture(t, 4)
	copy := original.Clone()
	copy.Source.Members[0].Mode = "awg2-strong"
	copy.Request.Users[0].Username = strings.Repeat("a", 48)
	copy.Request.LocalPacketPublicKeys[0] = chainCapturePublic(t, 111)
	if original.Source.Members[0].Mode != "wg" || original.Request.Users[0].Username == copy.Request.Users[0].Username || original.Request.LocalPacketPublicKeys[0] == copy.Request.LocalPacketPublicKeys[0] {
		t.Fatal("returned capture aliases an original owner")
	}
	base, _ := original.Digest()
	for name, mutate := range map[string]func(*NodeChainCapture){
		"owner":           func(c *NodeChainCapture) { c.OwnerID = strings.Repeat("a", 64) },
		"deadline":        func(c *NodeChainCapture) { c.BootstrapDeadline = c.BootstrapDeadline.Add(time.Second) },
		"host":            func(c *NodeChainCapture) { c.Host = "10.77.0.3" },
		"epoch":           func(c *NodeChainCapture) { c.Request.Epoch = strings.Repeat("a", 64) },
		"acquisition":     func(c *NodeChainCapture) { c.Request.AcquireExpiresAt++ },
		"port":            func(c *NodeChainCapture) { c.Request.Port++ },
		"user":            func(c *NodeChainCapture) { c.Request.Users[0].Username = strings.Repeat("a", 48) },
		"password":        func(c *NodeChainCapture) { c.Request.Users[0].Password = strings.Repeat("b", 48) },
		"all-client-pins": func(c *NodeChainCapture) { c.Request.LocalPacketPublicKeys[1] = chainCapturePublic(t, 111) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := original.Clone()
			mutate(&changed)
			digest, err := changed.Digest()
			if err != nil || digest == base {
				t.Fatal("valid distinct captured authority was not bound to its digest", err)
			}
		})
	}
	requestDigest, _ := original.Request.Digest()
	descriptorDigest, _ := original.Source.Digest()
	if base == requestDigest || base == descriptorDigest || requestDigest == descriptorDigest {
		t.Fatal("identity domains collided")
	}
}
