//go:build darwin

package main

import (
	"strconv"
	"strings"
	"testing"
)

func TestDesktopMacOSAmneziaRetainsCapturedSourceAndGraphBoundary(t *testing.T) {
	for _, variant := range []string{"fast", "strong"} {
		for _, kill := range []string{"on-connect", "always"} {
			t.Run(variant+"/"+kill, func(t *testing.T) {
				launch := desktopExternalPhysicalLaunchVariant(t, "amneziawg", kill, "on", true, variant)
				if !desktopMacOSExternalEligible(launch) {
					t.Fatal("captured direct AmneziaWG lacks retained native admission")
				}
				original := cloneRouterProfile(launch.external.profile)
				if err := prepareDesktopExternalPhysicalCaptured(launch, "darwin"); err != nil {
					t.Fatal(err)
				}
				if err := validateDesktopWindowsExternalSource(original, launch); err != nil {
					t.Fatal(err)
				}
				faults := []string{"private-key", "peer-key", "psk", "peer", "address", "allowed", "mtu", "dns", "lan", "ipv6", "protection"}
				for _, key := range []string{"jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4"} {
					faults = append(faults, "parameter/"+key)
				}
				for _, fault := range faults {
					t.Run(fault, func(t *testing.T) {
						changed := cloneRouterProfile(original)
						switch fault {
						case "private-key":
							changed.External.AmneziaWG.PrivateKey = testWGKey('k')
						case "peer-key":
							changed.External.AmneziaWG.PeerPublicKey = testWGKey('q')
						case "psk":
							changed.External.AmneziaWG.PresharedKey = testWGKey('p')
						case "peer":
							changed.External.AmneziaWG.Endpoint = "198.51.100.44:51820"
						case "address":
							changed.External.AmneziaWG.Addresses = []string{"10.90.0.2/32"}
						case "allowed":
							changed.External.AmneziaWG.AllowedIPs = []string{"0.0.0.0/1"}
						case "mtu":
							changed.ManualMTU = 1340
						case "dns":
							changed.DNSPort++
						case "lan":
							changed.HomeLANAccess = !changed.HomeLANAccess
						case "ipv6":
							changed.IPv6Mode = "off"
						case "protection":
							changed.KillSwitchPolicy = "off"
							changed.KillSwitch = false
						default:
							key := strings.TrimPrefix(fault, "parameter/")
							if strings.HasPrefix(key, "h") {
								changed.External.AmneziaWG.Parameters[key] = "50000000-59999999"
							} else {
								value, err := strconv.Atoi(changed.External.AmneziaWG.Parameters[key])
								if err != nil {
									t.Fatal(err)
								}
								changed.External.AmneziaWG.Parameters[key] = strconv.Itoa(value + 1)
							}
						}
						if validateDesktopWindowsExternalSource(changed, launch) == nil || validateDesktopWindowsExternalSource(original, launch) != nil {
							t.Fatal("replacement policy changed or acquired original retained AWG owner", fault)
						}
					})
				}
			})
		}
	}
	for _, fault := range []string{"server", "auto", "off", "entry", "predecessor", "layer"} {
		t.Run(fault, func(t *testing.T) {
			launch := desktopExternalPhysicalLaunchVariant(t, "amneziawg", "always", "on", false, "strong")
			switch fault {
			case "server", "auto":
				launch.external.selection = fault
			case "off":
				launch.external.profile.KillSwitchPolicy = "off"
				launch.external.profile.KillSwitch = false
			case "entry":
				launch.external.direct = false
			case "predecessor":
				launch.external.predecessor = "captured predecessor"
			case "layer":
				launch.external.profile.StartLayer = "aes-256-gcm"
			}
			if desktopMacOSExternalEligible(launch) {
				t.Fatal("AmneziaWG integration widened an unsupported native graph", fault)
			}
		})
	}
}
