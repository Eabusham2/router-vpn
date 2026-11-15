package multihoprelay

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func socksChainCaptureFixture(t *testing.T) NodeChainCapture {
	t.Helper()
	c := importedChainCaptureFixture(t)
	c.Source.Schema, c.Request.Schema = 3, 3
	c.Source.Members[0].Mode = "socks5"
	c.Source.Members[0].ProfileID = "original-socks-association"
	c.RegistrySHA256, _ = c.Source.Digest()
	c.Request.DescriptorSHA256 = c.RegistrySHA256
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	return c
}
func TestNodeChainSOCKSCaptureKeepsOriginalAssociationFamily(t *testing.T) {
	c := socksChainCaptureFixture(t)
	if len(c.Request.LocalPacketPublicKeys) != 1 || !reflect.DeepEqual(c.Request.LocalPacketPositions, []int{0}) || c.Source.Members[0].NodeID != "" {
		t.Fatal("association gained a synthetic packet owner")
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var restored NodeChainCapture
	if json.Unmarshal(raw, &restored) != nil || restored.Validate() != nil || !reflect.DeepEqual(c, restored) {
		t.Fatal("handoff lost exact suffix authority")
	}
	descriptor, _ := c.Source.Digest()
	request, _ := c.Request.Digest()
	for _, family := range []string{"v1", "v2", "v4"} {
		other, _ := nodeChainDigest("routervpn-server-node-chain-descriptor-"+family, c.Source)
		otherRequest, _ := nodeChainDigest("routervpn-server-node-chain-request-"+family, c.Request)
		if descriptor == other || request == otherRequest {
			t.Fatal("SOCKS borrowed another family digest")
		}
	}
	for _, fault := range []string{"connect-schema", "connect-mode", "ss-schema", "packet-position", "synthetic-key", "synthetic-node", "private-proof", "changed-source", "changed-public"} {
		t.Run(fault, func(t *testing.T) {
			other := c.Clone()
			switch fault {
			case "connect-schema":
				other.Source.Schema, other.Request.Schema = 4, 4
			case "connect-mode":
				other.Source.Members[0].Mode = "http-connect"
			case "ss-schema":
				other.Source.Schema, other.Request.Schema = 2, 2
			case "packet-position":
				other.Request.LocalPacketPositions[0] = 1
			case "synthetic-key":
				other.Source.Members[0].ClientPublicKey = chainCapturePublic(t, 114)
			case "synthetic-node":
				other.Source.Members[0].NodeID = strings.Repeat("b", 64)
			case "private-proof":
				other.Source.Members[0].ProofKind = "private-node"
			case "changed-source":
				other.Source.Members[0].SourceSHA256 = strings.Repeat("b", 64)
			case "changed-public":
				other.Source.Members[0].ExpectedPublicIP = "203.0.113.45"
			}
			if other.Validate() == nil {
				t.Fatal("changed association borrowed original capture")
			}
			if c.Validate() != nil {
				t.Fatal("clone mutated original authority")
			}
		})
	}
}
