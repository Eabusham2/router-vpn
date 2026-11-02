//go:build linux

package main

import (
	"strings"
	"testing"
)

func TestDesktopLinuxOpenVPNSourceKeepsExactSavedImport(t *testing.T) {
	for _, network := range []string{"tcp", "udp", "mixed"} {
		t.Run(network, func(t *testing.T) {
			profile, launch := desktopRetainedOpenVPNFixture(t, network, "always")
			if !desktopLinuxExternalEligible(launch) {
				t.Fatal("direct Local OpenVPN is absent from the retained Linux host")
			}
			if err := prepareDesktopExternalPhysicalCaptured(launch, "linux"); err != nil {
				t.Fatal(err)
			}
			if err := validateDesktopLinuxExternalSource(profile, launch); err != nil {
				t.Fatal("original OpenVPN saved profile rejected", err)
			}
			for _, fault := range []string{"password", "username", "remote-order", "remote-network", "tls-name", "fingerprint", "mtu", "dns", "lan", "ipv6", "source-text"} {
				t.Run(fault, func(t *testing.T) {
					cloned := cloneRouterProfile(profile)
					switch fault {
					case "password":
						cloned.External.OpenVPN.Password += " changed"
					case "username":
						cloned.External.OpenVPN.Username += " changed"
					case "remote-order":
						lines := strings.Split(cloned.External.OpenVPN.Config, "\n")
						positions := []int{}
						for i, line := range lines {
							if strings.HasPrefix(line, "remote ") {
								positions = append(positions, i)
							}
						}
						if len(positions) != 2 {
							t.Fatal("fixture lost original remote order")
						}
						lines[positions[0]], lines[positions[1]] = lines[positions[1]], lines[positions[0]]
						cloned.External.OpenVPN.Config = strings.Join(lines, "\n")
					case "remote-network":
						old, new := "1194 tcp", "1194 udp"
						if network == "udp" {
							old, new = "1194 udp", "1194 tcp"
						}
						cloned.External.OpenVPN.Config = strings.Replace(cloned.External.OpenVPN.Config, old, new, 1)
					case "tls-name":
						cloned.External.OpenVPN.Config = strings.Replace(cloned.External.OpenVPN.Config, "captured-provider.example", "foreign-provider.example", 1)
					case "fingerprint":
						cloned.External.OpenVPN.Config = strings.Replace(cloned.External.OpenVPN.Config, strings.Repeat("ab", 32), strings.Repeat("cd", 32), 1)
					case "mtu":
						cloned.ManualMTU = 1340
					case "dns":
						cloned.DNSPort++
					case "lan":
						cloned.HomeLANAccess = !cloned.HomeLANAccess
					case "ipv6":
						cloned.IPv6Mode = "off"
					case "source-text":
						cloned.External.OpenVPN.Config += "# changed captured source\n"
					}
					if desktopOwnedNodeProfileToken(cloned) == desktopOwnedNodeProfileToken(profile) {
						t.Fatal("negative did not change source")
					}
					if validateDesktopLinuxExternalSource(cloned, launch) == nil {
						t.Fatal("changed saved OpenVPN policy was accepted", fault)
					}
					if validateDesktopLinuxExternalSource(profile, launch) != nil {
						t.Fatal("rejected replacement mutated the retained original")
					}
				})
			}
		})
	}
	for _, fault := range []string{"server", "auto", "off", "predecessor", "not-direct"} {
		t.Run("selection/"+fault, func(t *testing.T) {
			_, launch := desktopRetainedOpenVPNFixture(t, "mixed", "always")
			switch fault {
			case "server", "auto":
				launch.external.selection = fault
			case "off":
				launch.external.profile.KillSwitchPolicy = "off"
				launch.external.profile.KillSwitch = false
			case "predecessor":
				launch.external.predecessor = "original Router path"
			case "not-direct":
				launch.external.direct = false
			}
			if desktopLinuxExternalEligible(launch) {
				t.Fatal("unimplemented execution acquired retained direct OpenVPN admission", fault)
			}
		})
	}
}
