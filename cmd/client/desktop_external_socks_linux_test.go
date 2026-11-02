//go:build linux

package main

import "testing"

func TestDesktopLinuxSOCKSKeepsSavedCredentialsAndCompletePolicy(t *testing.T) {
	profile, launch := desktopRetainedSOCKSFixture(t, "always")
	if !desktopLinuxExternalEligible(launch) {
		t.Fatal("direct Local SOCKS association is absent from retained Linux admission")
	}
	if err := prepareDesktopExternalPhysicalCaptured(launch, "linux"); err != nil || validateDesktopLinuxExternalSource(profile, launch) != nil {
		t.Fatal("exact saved SOCKS source did not validate", err)
	}
	for _, fault := range []string{"username", "password", "host", "port", "mtu", "dns", "lan", "ipv6"} {
		t.Run(fault, func(t *testing.T) {
			cloned := cloneRouterProfile(profile)
			switch fault {
			case "username":
				cloned.External.SOCKS5.Username += " changed"
			case "password":
				cloned.External.SOCKS5.Password += " changed"
			case "host":
				cloned.External.SOCKS5.Host = "203.0.113.21"
			case "port":
				cloned.External.SOCKS5.Port++
			case "mtu":
				cloned.ManualMTU = 1340
			case "dns":
				cloned.DNSPort++
			case "lan":
				cloned.HomeLANAccess = true
			case "ipv6":
				cloned.IPv6Mode = "off"
			}
			if desktopOwnedNodeProfileToken(cloned) == desktopOwnedNodeProfileToken(profile) || validateDesktopLinuxExternalSource(cloned, launch) == nil ||
				validateDesktopLinuxExternalSource(profile, launch) != nil {
				t.Fatal("SOCKS accepted a changed source or mutated its retained original", fault)
			}
		})
	}
	for _, execution := range []string{"server", "auto"} {
		t.Run(execution, func(t *testing.T) {
			_, other := desktopRetainedSOCKSFixture(t, "always")
			other.external.selection = execution
			if desktopLinuxExternalEligible(other) {
				t.Fatal("direct Local SOCKS widened Server or Compare admission")
			}
		})
	}
}
