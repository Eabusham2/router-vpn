//go:build darwin

package main

import "testing"

func TestDesktopMacOSSOCKSRetainsCapturedSourceAndGraphBoundary(t *testing.T) {
	for _, kill := range []string{"on-connect", "always"} {
		t.Run(kill, func(t *testing.T) {
			_, launch := desktopRetainedSOCKSFixture(t, kill)
			if !desktopMacOSExternalEligible(launch) {
				t.Fatal("captured direct SOCKS5 lacks retained native admission")
			}
			original := cloneRouterProfile(launch.external.profile)
			if err := prepareDesktopExternalPhysicalCaptured(launch, "darwin"); err != nil {
				t.Fatal(err)
			}
			if err := validateDesktopWindowsExternalSource(original, launch); err != nil {
				t.Fatal(err)
			}
			for _, fault := range []string{"username", "password", "host", "port", "mtu", "dns", "lan", "ipv6", "protection"} {
				t.Run(fault, func(t *testing.T) {
					changed := cloneRouterProfile(original)
					switch fault {
					case "username":
						changed.External.SOCKS5.Username += "-another"
					case "password":
						changed.External.SOCKS5.Password += "-another"
					case "host":
						changed.External.SOCKS5.Host = "198.51.100.44"
					case "port":
						changed.External.SOCKS5.Port++
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
						t.Fatal("replaced policy acquired or modified original retained SOCKS host", fault)
					}
				})
			}
		})
	}
	for _, fault := range []string{"server", "auto", "off", "entry", "predecessor", "layer", "awg", "openvpn"} {
		t.Run(fault, func(t *testing.T) {
			_, launch := desktopRetainedSOCKSFixture(t, "always")
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
			case "awg":
				launch.external.profile.External.Protocol = "amneziawg"
			case "openvpn":
				launch.external.profile.External.Protocol = "openvpn"
			}
			if desktopMacOSExternalEligible(launch) {
				t.Fatal("SOCKS5 integration widened an unsupported native graph", fault)
			}
		})
	}
}
