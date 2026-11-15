package multihoprelay

import (
	"fmt"
	"strings"
	"testing"
)

func chainImportedPrefixCapture(t *testing.T, count int) NodeChainCapture {
	t.Helper()
	c := chainCaptureFixture(t, count+1)
	c.Source.Schema, c.Request.Schema = 2, 2
	c.Source.Members[count-1] = NodeChainMember{Position: count, ProfileID: "original-import", Mode: "shadowsocks", StartLayer: "off", NodeKind: "external", ProofKind: "public-path", SourceSHA256: strings.Repeat("a", 64), ExpectedPublicIP: "203.0.113.88"}
	c.Request.LocalPacketPublicKeys = c.Request.LocalPacketPublicKeys[:count]
	for i := 0; i < count; i++ {
		c.Request.LocalPacketPositions = append(c.Request.LocalPacketPositions, i)
	}
	digest, err := c.Source.Digest()
	if err != nil {
		t.Fatal(err)
	}
	c.RegistrySHA256, c.Request.DescriptorSHA256 = digest, digest
	return c
}
func TestNodeChainImportedPrefixCaptureBindsEveryPacketPosition(t *testing.T) {
	for count := 1; count <= 6; count++ {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			c := chainImportedPrefixCapture(t, count)
			if err := c.Validate(); err != nil {
				t.Fatal(err)
			}
			for position := range c.Request.LocalPacketPositions {
				changed := c.Clone()
				changed.Request.LocalPacketPositions[position]++
				if changed.Validate() == nil {
					t.Fatal("packet position moved", position)
				}
				if count > 1 {
					changed = c.Clone()
					changed.Request.LocalPacketPublicKeys[position] = c.Source.Members[0].ClientPublicKey
					if changed.Validate() == nil {
						t.Fatal("Local key borrowed Server identity", position)
					}
				}
			}
			for _, schema := range []int{3, 4} {
				changed := c.Clone()
				changed.Source.Schema = schema
				changed.Request.Schema = schema
				if changed.Validate() == nil {
					t.Fatal("SS descriptor relabelled as typed transport", schema)
				}
			}
			changed := c.Clone()
			changed.Request.LocalPacketPublicKeys = append(changed.Request.LocalPacketPublicKeys, chainCapturePublic(t, 201))
			changed.Request.LocalPacketPositions = append(changed.Request.LocalPacketPositions, count)
			if changed.Validate() == nil {
				t.Fatal("import acquired packet identity")
			}
			if count > 1 {
				changed = c.Clone()
				changed.Source.Members[0], changed.Source.Members[count-1] = changed.Source.Members[count-1], changed.Source.Members[0]
				changed.Source.Members[0].Position = 1
				changed.Source.Members[count-1].Position = count
				if changed.Source.Validate() == nil {
					t.Fatal("import moved before original paired prefixes")
				}
			}
		})
	}
}
