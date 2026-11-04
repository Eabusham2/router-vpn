//go:build darwin

package main

import "testing"

func TestDesktopMacOSWireGuardRetainsCapturedSourceAndGraphBoundary(t *testing.T) {
	for _, kill := range []string{"on-connect", "always"} {
		t.Run(kill, func(t *testing.T) {
			launch := desktopExternalPhysicalLaunchFixture(t, "wireguard", kill, "on", true)
			if !desktopMacOSExternalEligible(launch) {
				t.Fatal("captured direct WireGuard lacks retained native admission")
			}
			original := cloneRouterProfile(launch.external.profile)
			if err := prepareDesktopExternalPhysicalCaptured(launch, "darwin"); err != nil {
				t.Fatal(err)
			}
			if err := validateDesktopWindowsExternalSource(original, launch); err != nil {
				t.Fatal(err)
			}
			for _, fault := range []string{"private-key", "peer-key", "psk", "peer", "address", "allowed", "mtu", "dns", "lan", "ipv6", "protection"} {
				t.Run(fault, func(t *testing.T) {
					changed := cloneRouterProfile(original)
					switch fault {
					case "private-key":
						changed.External.WireGuard.PrivateKey = testWGKey('k')
					case "peer-key":
						changed.External.WireGuard.PeerPublicKey = testWGKey('q')
					case "psk":
						changed.External.WireGuard.PresharedKey = testWGKey('p')
					case "peer":
						changed.External.WireGuard.Endpoint = "198.51.100.44:51820"
					case "address":
						changed.External.WireGuard.Addresses = []string{"10.90.0.2/32"}
					case "allowed":
						changed.External.WireGuard.AllowedIPs = []string{"0.0.0.0/1"}
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
					}
					if validateDesktopWindowsExternalSource(changed, launch) == nil || validateDesktopWindowsExternalSource(original, launch) != nil {
						t.Fatal("replaced policy acquired or modified original retained WG host", fault)
					}
				})
			}
		})
	}
	for _, fault := range []string{"server", "auto", "off", "entry", "predecessor", "layer", "openvpn"} {
		t.Run(fault, func(t *testing.T) {
			launch := desktopExternalPhysicalLaunchFixture(t, "wireguard", "always", "on", false)
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
			case "openvpn":
				launch.external.profile.External.Protocol = "openvpn"
			}
			if desktopMacOSExternalEligible(launch) {
				t.Fatal("WireGuard integration widened an unsupported native graph", fault)
			}
		})
	}
}
