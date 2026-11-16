package multihoprelay

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Public pairing digest is discovery identity only; these captures confer no
// native endpoint or connected-packet authority.
func TestNodeChainOpenVPNCaptureRetainsOriginalPositionsAndFamily(t *testing.T) {
	for count := 1; count <= 6; count++ {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			c := chainImportedPrefixCapture(t, count)
			c.Source.Schema, c.Request.Schema = 5, 5
			c.Source.Members[count-1].Mode = "openvpn"
			c.Source.Members[count-1].OpenVPNPairSHA256 = strings.Repeat("a", 64)
			digest, err := c.Source.Digest()
			if err != nil {
				t.Fatal(err)
			}
			c.RegistrySHA256, c.Request.DescriptorSHA256 = digest, digest
			if c.Validate() != nil {
				t.Fatal("original schema5 inventory refused")
			}
			for position := range c.Request.LocalPacketPositions {
				changed := c.Clone()
				changed.Request.LocalPacketPositions[position]++
				if changed.Validate() == nil {
					t.Fatal("original packet position changed")
				}
				if count > 1 {
					changed = c.Clone()
					changed.Request.LocalPacketPublicKeys[position] = c.Source.Members[0].ClientPublicKey
					if changed.Validate() == nil {
						t.Fatal("Local borrowed Server packet identity")
					}
				}
			}
			for _, fault := range []string{"schema1", "schema2", "schema3", "schema4", "missing-pair", "foreign-pair", "paired-pair", "public-as-private", "middle-key", "request-family", "swapped-position"} {
				t.Run(fault, func(t *testing.T) {
					changed := c.Clone()
					switch fault {
					case "schema1", "schema2", "schema3", "schema4":
						changed.Source.Schema, changed.Request.Schema = int(fault[6]-'0'), int(fault[6]-'0')
					case "missing-pair":
						changed.Source.Members[count-1].OpenVPNPairSHA256 = ""
					case "foreign-pair":
						changed.Source.Members[count-1].OpenVPNPairSHA256 = strings.Repeat("b", 64)
					case "paired-pair":
						changed.Source.Members[count].OpenVPNPairSHA256 = strings.Repeat("a", 64)
					case "public-as-private":
						changed.Source.Members[count-1].NodeID = changed.Source.EntryNodeID
					case "middle-key":
						changed.Source.Members[count-1].ClientPublicKey = changed.Request.LocalPacketPublicKeys[0]
					case "request-family":
						changed.Request.Schema = 4
					case "swapped-position":
						changed.Source.Members[count-1], changed.Source.Members[count] = changed.Source.Members[count], changed.Source.Members[count-1]
					}
					if changed.Validate() == nil {
						t.Fatal("foreign original identity admitted")
					}
					if !reflect.DeepEqual(c.Request.LocalPacketPositions, func() []int {
						p := []int{}
						for i := 0; i < count; i++ {
							p = append(p, i)
						}
						return p
					}()) {
						t.Fatal("clone mutated original inventory")
					}
				})
			}
			legacy, _ := nodeChainDigest("routervpn-server-node-chain-descriptor-v4", c.Source)
			if legacy == digest {
				t.Fatal("OpenVPN borrowed CONNECT descriptor domain")
			}
			request, err := c.Request.Digest()
			if err != nil {
				t.Fatal(err)
			}
			legacy, _ = nodeChainDigest("routervpn-server-node-chain-request-v4", c.Request)
			if legacy == request {
				t.Fatal("OpenVPN borrowed CONNECT request domain")
			}
		})
	}
}
