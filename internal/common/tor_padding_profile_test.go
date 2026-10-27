package common

import (
	"encoding/json"
	"fmt"
	"testing"
)

func torPaddingProfile(protocol string, rate int, enabled bool) RouterProfile {
	profile := RouterProfile{ID: "saved-tor", NodeKind: "external", DAITAEnabled: enabled, DAITARateKbps: rate,
		External: &ExternalNodeConfig{Protocol: protocol}, DNSMode: "home"}
	if protocol == "tor-bridge" {
		profile.External.TorBridge = &ExternalTorBridgeConfig{Transport: "obfs4", Bridges: []string{validObfs4Bridge}}
	}
	return profile
}

// The UI stores this same RouterProfile and complete profile-store encoding.
// Preserving intent here grants no runtime capability or native path proof.
func TestTorPaddingProfileRoundTripPreservesBoundedIntent(t *testing.T) {
	for _, protocol := range []string{"tor", "tor-bridge"} {
		for _, rate := range []int{0, 32, 64, 192} {
			for _, enabled := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%d/%t", protocol, rate, enabled), func(t *testing.T) {
					profile := torPaddingProfile(protocol, rate, enabled)
					// Legacy private endpoint defaults must still be stripped.
					profile.RouterAPI, profile.DAITAHost, profile.DAITAPort = "http://10.77.0.1:8787", "10.77.0.1", 45999
					profile.AdGuardIPv4, profile.SocksHost, profile.SocksPort = "10.77.0.1", "10.77.0.1", 1080
					store := RouterProfileStore{Profiles: []RouterProfile{profile}, SelectedID: profile.ID}
					for round := 0; round < 3; round++ {
						raw, err := json.Marshal(store)
						if err != nil {
							t.Fatal(err)
						}
						var restored RouterProfileStore
						if err := json.Unmarshal(raw, &restored); err != nil {
							t.Fatal(err)
						}
						got := restored.Profiles[0]
						if restored.SelectedID != profile.ID || got.External.Protocol != protocol || got.DAITAEnabled != enabled || got.DAITARateKbps != rate || got.DNSMode != "home" {
							t.Fatal("saved Tor policy changed during complete-store normalization")
						}
						if got.RouterAPI != "" || got.DAITAHost != "" || got.DAITAPort != 0 || got.AdGuardIPv4 != "" || got.SocksHost != "" || got.SocksPort != 0 {
							t.Fatal("preserved Tor rate acquired private Router endpoint authority")
						}
						store = restored
					}
					if profile.DAITARateKbps != rate {
						t.Fatal("encoding mutated caller's saved policy")
					}
				})
			}
		}
	}
}

func TestTorPaddingProfileRejectsInvalidRateInsteadOfReplacingIt(t *testing.T) {
	for _, protocol := range []string{"tor", "tor-bridge"} {
		for _, rate := range []int{-1, 1, 31, 193, 10000} {
			t.Run(fmt.Sprintf("%s/%d", protocol, rate), func(t *testing.T) {
				profile := torPaddingProfile(protocol, rate, false)
				if err := NormalizeRouterProfile(&profile); err == nil {
					t.Fatal("invalid saved Tor rate silently became a default")
				}
				if _, err := json.Marshal(torPaddingProfile(protocol, rate, true)); err == nil {
					t.Fatal("invalid enabled Tor rate was persisted")
				}
			})
		}
	}
}

func TestTorPaddingRateDoesNotAdoptAnotherNodesCredentials(t *testing.T) {
	for _, field := range []string{"api", "token", "identity"} {
		t.Run(field, func(t *testing.T) {
			profile := torPaddingProfile("tor", 64, true)
			switch field {
			case "api":
				profile.RouterAPI = "https://other.example:8787"
			case "token":
				profile.APIToken = "another-node-token"
			case "identity":
				profile.NodeProofID = "another-node"
			}
			if _, err := json.Marshal(profile); err == nil {
				t.Fatal("Tor rate preservation bypassed private credential rejection")
			}
		})
	}
}
