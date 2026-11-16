package multihoprelay

import (
	"fmt"
	"testing"
)

func chainSOCKSPrefixCapture(t *testing.T, count int, protocol string) NodeChainCapture {
	t.Helper()
	c := chainImportedPrefixCapture(t, count)
	c.Source.Schema, c.Request.Schema = 3, 3
	c.Source.Members[count-1].Mode = protocol
	digest, err := c.Source.Digest()
	if err != nil {
		t.Fatal(err)
	}
	c.RegistrySHA256, c.Request.DescriptorSHA256 = digest, digest
	return c
}
func TestNodeChainSOCKSPrefixCaptureRetainsAllPacketIdentities(t *testing.T) {
	for _, count := range []int{1, 2, 3, 4, 5, 6} {
		for _, protocol := range []string{"socks5"} {
			t.Run(fmt.Sprintf("%d/%s", count, protocol), func(t *testing.T) {
				c := chainSOCKSPrefixCapture(t, count, protocol)
				if c.Validate() != nil {
					t.Fatal("complete original SOCKS capture refused")
				}
				for position := range c.Request.LocalPacketPositions {
					changed := c.Clone()
					changed.Request.LocalPacketPositions[position]++
					if changed.Validate() == nil {
						t.Fatal("original packet position moved")
					}
					if count > 1 {
						changed = c.Clone()
						changed.Request.LocalPacketPublicKeys[position] = c.Source.Members[0].ClientPublicKey
						if changed.Validate() == nil {
							t.Fatal("client identity borrowed remote original key")
						}
					}
				}
				for _, fault := range []string{"connect-family", "ss-family", "middle-node", "middle-key", "middle-mode", "missing-position", "extra-position", "wrong-import-position"} {
					t.Run(fault, func(t *testing.T) {
						changed := c.Clone()
						switch fault {
						case "connect-family":
							changed.Source.Schema, changed.Request.Schema = 4, 4
						case "ss-family":
							changed.Source.Schema, changed.Request.Schema = 2, 2
						case "middle-node":
							changed.Source.Members[count-1].NodeID = changed.Source.EntryNodeID
						case "middle-key":
							changed.Source.Members[count-1].ClientPublicKey = changed.Request.LocalPacketPublicKeys[0]
						case "middle-mode":
							changed.Source.Members[count-1].Mode = "shadowsocks"
						case "missing-position":
							changed.Request.LocalPacketPositions = changed.Request.LocalPacketPositions[:count-1]
						case "extra-position":
							changed.Request.LocalPacketPositions = append(changed.Request.LocalPacketPositions, count)
						case "wrong-import-position":
							changed.Source.Members[count-1], changed.Source.Members[count] = changed.Source.Members[count], changed.Source.Members[count-1]
						}
						if changed.Validate() == nil {
							t.Fatal("foreign SOCKS capture authority accepted")
						}
					})
				}
			})
		}
	}
}
