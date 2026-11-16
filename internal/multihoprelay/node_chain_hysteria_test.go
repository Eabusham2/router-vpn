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
						final.StartLayer = "aes-256-gcm+unowned"
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

func TestNodeChainHysteriaFinalLayersKeepOriginalCapture(t *testing.T) {
	for count := 1; count <= 7; count++ {
		for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(fmt.Sprint(count)+"/"+layer, func(t *testing.T) {
				capture := chainCaptureFixture(t, count)
				last := &capture.Source.Members[count-1]
				last.Mode, last.StartLayer = "hysteria2", layer
				digest, err := capture.Source.Digest()
				if err != nil || digest == capture.Request.DescriptorSHA256 || capture.Validate() == nil {
					t.Fatal("layered final reused an Off/SS descriptor or request", err)
				}
				capture.Request.DescriptorSHA256, capture.RegistrySHA256 = digest, digest
				if capture.Validate() != nil {
					t.Fatal("original layered paired final capture refused")
				}
				for _, fault := range []string{"layer", "node", "position", "source", "registry", "request", "schema"} {
					changed := capture.Clone()
					switch fault {
					case "layer":
						changed.Source.Members[count-1].StartLayer = "off"
					case "node":
						changed.Source.Members[count-1].NodeID = changed.Source.EntryNodeID
					case "position":
						changed.Source.Members[count-1].Position++
					case "source":
						changed.Source.SourceSHA256 = fmt.Sprintf("%064x", 9001)
					case "registry":
						changed.RegistrySHA256 = fmt.Sprintf("%064x", 9002)
					case "request":
						changed.Request.DescriptorSHA256 = fmt.Sprintf("%064x", 9003)
					case "schema":
						changed.Source.Schema = 2
					}
					if changed.Validate() == nil {
						t.Fatal("changed layered descriptor borrowed original request/registry", fault)
					}
				}
				for _, schema := range []int{2, 3, 4, 5} {
					changed := capture.Source.Clone()
					changed.Schema = schema
					if changed.Validate() == nil {
						t.Fatal("layered paired Hysteria2 widened imported final family", schema)
					}
				}
			})
		}
	}
}
