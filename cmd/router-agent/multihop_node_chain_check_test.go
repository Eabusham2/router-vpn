package main

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/multihoprelay"
)

func pairingOrderedDescriptor(t *testing.T, schema int) multihoprelay.NodeChainDescriptor {
	t.Helper()
	source := chainPipeCapture(t).Source.Clone()
	if schema == 2 || schema == 3 || schema == 4 {
		source.Schema = schema
		final := source.Members[0]
		final.Position = 2
		source.Members = []multihoprelay.NodeChainMember{{Position: 1, ProfileID: "original-imported-ss", Mode: "shadowsocks", StartLayer: "off",
			NodeKind: "external", ProofKind: "public-path", SourceSHA256: strings.Repeat("a", 64), ExpectedPublicIP: "203.0.113.88"}, final}
		if schema == 3 {
			source.Members[0].ProfileID, source.Members[0].Mode = "original-imported-socks", "socks5"
		}
		if schema == 4 {
			source.Members[0].ProfileID, source.Members[0].Mode = "original-imported-connect", "https-connect"
		}
	} else {
		client, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{71}, 32))
		if err != nil {
			t.Fatal(err)
		}
		server, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{81}, 32))
		if err != nil {
			t.Fatal(err)
		}
		final := source.Members[0]
		final.Position = 2
		source.Members = []multihoprelay.NodeChainMember{{Position: 1, ProfileID: "original-paired-packet", NodeID: strings.Repeat("b", 64), Mode: "awg2-strong", StartLayer: "off",
			ClientPublicKey: base64.StdEncoding.EncodeToString(client.PublicKey().Bytes()), ServerPublicKey: base64.StdEncoding.EncodeToString(server.PublicKey().Bytes())}, final}
	}
	if err := source.Validate(); err != nil {
		t.Fatal(err)
	}
	return source
}

func TestOrderedRegistryParserCaptureKeepsActualPacketPositions(t *testing.T) {
	for _, schema := range []int{1, 2, 3, 4} {
		source := pairingOrderedDescriptor(t, schema)
		now := time.Unix(1794657600, 0).UTC()
		first, err := relayNodeChainValidationCapture(source, "10.77.0.1", "10.77.0.2", 26240, now)
		if err != nil || first.Validate() != nil || !reflect.DeepEqual(first.Source, source) {
			t.Fatal("temporary parser capture changed the actual operator descriptor", err)
		}
		if first.Request.Schema != schema || first.Schema != 1 || first.Request.Peer != "10.77.0.2" || first.Host != "10.77.0.1" ||
			first.Request.Port != 26240 || len(first.Request.Users) != len(source.Members) || first.Request.AcquireExpiresAt != now.Add(time.Minute).Unix() {
			t.Fatal("offline capture changed positional or envelope authority")
		}
		want := len(source.Members)
		if schema == 2 || schema == 3 || schema == 4 {
			want = 1
			if !reflect.DeepEqual(first.Request.LocalPacketPositions, []int{0}) || first.Source.Members[0].NodeID != "" || first.Source.Members[0].ClientPublicKey != "" {
				t.Fatal("imported proxy acquired a fabricated packet or Router identity")
			}
		} else if len(first.Request.LocalPacketPositions) != 0 {
			t.Fatal("paired schema1 changed its original positional contract")
		}
		if len(first.Request.LocalPacketPublicKeys) != want {
			t.Fatal("offline parser key inventory changed", first.Request.LocalPacketPublicKeys)
		}
		for _, key := range first.Request.LocalPacketPublicKeys {
			for _, member := range source.Members {
				if key == member.ClientPublicKey || key == member.ServerPublicKey {
					t.Fatal("parser-only key reused an actual operator packet identity")
				}
			}
		}
		second, err := relayNodeChainValidationCapture(source, "10.77.0.1", "10.77.0.2", 26240, now)
		if err != nil || second.OwnerID == first.OwnerID || second.Request.SessionID == first.Request.SessionID || second.Request.Epoch == first.Request.Epoch ||
			reflect.DeepEqual(second.Request.Users, first.Request.Users) || reflect.DeepEqual(second.Request.LocalPacketPublicKeys, first.Request.LocalPacketPublicKeys) {
			t.Fatal("independent parser checks reused client-shaped credentials", err)
		}
		source.Members[0].ProfileID = "changed-after-capture"
		if first.Source.Members[0].ProfileID == source.Members[0].ProfileID || second.Source.Members[0].ProfileID == source.Members[0].ProfileID {
			t.Fatal("parser capture borrowed mutable caller source")
		}
	}
}

func TestOrderedRegistryParserCaptureRefusesInvalidAuthority(t *testing.T) {
	good := pairingOrderedDescriptor(t, 2)
	for _, fault := range []string{"schema", "source-digest", "fake-imported-key", "fake-imported-node", "same-peer", "public-peer", "public-host", "port", "clock"} {
		t.Run(fault, func(t *testing.T) {
			source := good.Clone()
			host, peer, port, now := "10.77.0.1", "10.77.0.2", 26240, time.Unix(1794657600, 0).UTC()
			switch fault {
			case "schema":
				source.Schema = 1
			case "source-digest":
				source.SourceSHA256 = ""
			case "fake-imported-key":
				source.Members[0].ClientPublicKey = chainPipeCapture(t).Request.LocalPacketPublicKeys[0]
			case "fake-imported-node":
				source.Members[0].NodeID = strings.Repeat("e", 64)
			case "same-peer":
				peer = host
			case "public-peer":
				peer = "203.0.113.10"
			case "public-host":
				host = "203.0.113.11"
			case "port":
				port = 80
			case "clock":
				now = time.Time{}
			}
			if _, err := relayNodeChainValidationCapture(source, host, peer, port, now); err == nil {
				t.Fatal("offline parser accepted invalid captured authority")
			}
		})
	}
}

func pairingImportedPrefixDescriptor(t *testing.T, count int) multihoprelay.NodeChainDescriptor {
	t.Helper()
	source := pairingOrderedDescriptor(t, 2)
	members := make([]multihoprelay.NodeChainMember, 0, count-1)
	for i := 0; i < count-3; i++ {
		key := func(value byte) string {
			private, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{value}, 32))
			if err != nil {
				t.Fatal(err)
			}
			return base64.StdEncoding.EncodeToString(private.PublicKey().Bytes())
		}
		members = append(members, multihoprelay.NodeChainMember{Position: i + 1, ProfileID: fmt.Sprintf("original-prefix-%d", i), NodeID: fmt.Sprintf("%064x", 201+i), Mode: "awg2-strong", StartLayer: "off", ClientPublicKey: key(byte(91 + i)), ServerPublicKey: key(byte(111 + i))})
	}
	members = append(members, source.Members...)
	for i := range members {
		members[i].Position = i + 1
	}
	source.Members = members
	if source.Validate() != nil {
		t.Fatal("invalid original complete descriptor")
	}
	return source
}

func TestOrderedRegistryImportedPrefixParserCapture(t *testing.T) {
	for _, count := range []int{3, 4, 8} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			source := pairingImportedPrefixDescriptor(t, count)
			now := time.Unix(1794657600, 0).UTC()
			capture, err := relayNodeChainValidationCapture(source, "10.77.0.1", "10.77.0.2", 26240, now)
			if err != nil || capture.Validate() != nil {
				t.Fatal("complete original imported parser capture refused", err)
			}
			want := make([]int, count-2)
			for i := range want {
				want[i] = i
			}
			if !reflect.DeepEqual(capture.Source, source) || !reflect.DeepEqual(capture.Request.LocalPacketPositions, want) || len(capture.Request.LocalPacketPublicKeys) != len(want) || len(capture.Request.Users) != count-1 {
				t.Fatal("complete original packet positions lost")
			}
			for _, key := range capture.Request.LocalPacketPublicKeys {
				for _, member := range source.Members {
					if key == member.ClientPublicKey || key == member.ServerPublicKey {
						t.Fatal("parser invented original packet ownership")
					}
				}
			}
			for _, fault := range []string{"missing-key", "import-position", "duplicate-position", "foreign-key", "middle-key", "middle-node", "socks-shape", "connect-shape"} {
				t.Run(fault, func(t *testing.T) {
					changed := capture.Clone()
					switch fault {
					case "missing-key":
						changed.Request.LocalPacketPublicKeys = changed.Request.LocalPacketPublicKeys[:len(want)-1]
					case "import-position":
						changed.Request.LocalPacketPositions[len(want)-1]++
					case "duplicate-position":
						changed.Request.LocalPacketPositions[len(want)-1] = -1
					case "foreign-key":
						if count == 3 {
							changed.Request.LocalPacketPublicKeys[0] = "foreign"
						} else {
							changed.Request.LocalPacketPublicKeys[0] = source.Members[0].ClientPublicKey
						}
					case "middle-key":
						changed.Source.Members[count-3].ClientPublicKey = changed.Request.LocalPacketPublicKeys[0]
					case "middle-node":
						changed.Source.Members[count-3].NodeID = strings.Repeat("e", 64)
					case "socks-shape":
						changed.Source.Schema, changed.Request.Schema = 3, 3
					case "connect-shape":
						changed.Source.Schema, changed.Request.Schema = 4, 4
					}
					if changed.Validate() == nil {
						t.Fatal("invalid complete parser authority accepted")
					}
				})
			}
		})
	}
}

func TestOrderedRegistryCONNECTPrefixParserCapture(t *testing.T) {
	for _, count := range []int{3, 4, 8} {
		for _, protocol := range []string{"http-connect", "https-connect"} {
			t.Run(fmt.Sprintf("%d/%s", count, protocol), func(t *testing.T) {
				source := pairingImportedPrefixDescriptor(t, count)
				source.Schema = 4
				source.Members[count-3].Mode = protocol
				capture, err := relayNodeChainValidationCapture(source, "10.77.0.1", "10.77.0.2", 26240, time.Unix(1794657600, 0).UTC())
				if err != nil || capture.Validate() != nil {
					t.Fatal("complete original CONNECT parser capture refused", err)
				}
				if len(capture.Request.LocalPacketPublicKeys) != count-2 || len(capture.Request.LocalPacketPositions) != count-2 {
					t.Fatal("complete original CONNECT packet inventory lost")
				}
				for i, position := range capture.Request.LocalPacketPositions {
					if position != i {
						t.Fatal("original CONNECT packet position moved")
					}
				}
				changed := capture.Clone()
				changed.Request.LocalPacketPositions[count-3]++
				if changed.Validate() == nil {
					t.Fatal("imported CONNECT acquired packet identity")
				}
			})
		}
	}
}
