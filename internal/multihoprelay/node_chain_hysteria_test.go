package multihoprelay

import (
	"fmt"
	"testing"
)

func TestNodeChainHysteriaFinalDescriptorRetainsCapturedFamily(t *testing.T) {
	for count := 1; count <= 7; count++ {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			capture := chainCaptureFixture(t, count)
			last := &capture.Source.Members[count-1]
			last.Mode, last.StartLayer = "hysteria2", "off"
			original := capture.Request.DescriptorSHA256
			digest, err := capture.Source.Digest()
			if err != nil || digest == original {
				t.Fatal("Hysteria2 descriptor lost original family or reused SS identity", err)
			}
			if capture.Validate() == nil {
				t.Fatal("Hysteria2 final accepted old SS request/registry receipt")
			}
			capture.Request.DescriptorSHA256, capture.RegistrySHA256 = digest, digest
			if err := capture.Validate(); err != nil {
				t.Fatal("original paired Hysteria2 capture refused", err)
			}
			for _, fault := range []string{"layer", "packet-key", "public-proof", "external-kind", "imported-family"} {
				t.Run(fault, func(t *testing.T) {
					changed := capture.Clone()
					final := &changed.Source.Members[count-1]
					switch fault {
					case "layer":
						final.StartLayer = "aes-256-gcm"
					case "packet-key":
						final.ClientPublicKey = chainCapturePublic(t, 91)
					case "public-proof":
						final.ProofKind = "public-path"
					case "external-kind":
						final.NodeKind = "external"
					case "imported-family":
						changed.Source.Schema = 2
					}
					if changed.Source.Validate() == nil {
						t.Fatal("unsupported Hysteria2 family or identity gained descriptor authority")
					}
				})
			}
		})
	}
}
