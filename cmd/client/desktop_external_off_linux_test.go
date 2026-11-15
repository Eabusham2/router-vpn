//go:build linux

package main

import (
	"context"
	"testing"

	"router-vpn/internal/common"
)

func TestDesktopLinuxExternalOffRetainsCapturedSource(t *testing.T) {
	for _, protocol := range []string{"shadowsocks", "http-connect", "https-connect", "socks5", "hysteria2", "wireguard", "amneziawg", "openvpn"} {
		t.Run(protocol, func(t *testing.T) {
			launch := desktopExternalPhysicalLaunchFixture(t, protocol, "off", "off", false)
			if !desktopLinuxExternalEligible(launch) {
				t.Fatal("sealed Local Off graph has no Linux owner")
			}
			if err := prepareDesktopExternalPhysicalCaptured(launch, "linux"); err != nil {
				t.Fatal(err)
			}
			captured, err := launch.external.physical.Capture()
			if err != nil || captured.KillSwitchPolicy != "off" || captured.SelectedDNS.Physical || captured.ConfiguredMTU != 1360 {
				t.Fatal("Off changed captured DNS/MTU/protection", err)
			}
			original := cloneRouterProfile(launch.external.profile)
			if err := validateDesktopLinuxExternalSource(original, launch); err != nil {
				t.Fatal(err)
			}
			for _, fault := range []string{"policy", "id", "dns", "mtu", "endpoint"} {
				t.Run(fault, func(t *testing.T) {
					changed := cloneRouterProfile(original)
					switch fault {
					case "policy":
						changed.KillSwitchPolicy, changed.KillSwitch = "always", true
					case "id":
						changed.ID += "-foreign"
					case "dns":
						changed.DNSPort++
					case "mtu":
						changed.ManualMTU++
					case "endpoint":
						changed.Endpoint = "192.0.2.244"
					}
					if validateDesktopLinuxExternalSource(changed, launch) == nil {
						t.Fatal("Off adopted changed original source")
					}
					if validateDesktopLinuxExternalSource(original, launch) != nil {
						t.Fatal("rejected source mutated original Off owner")
					}
				})
			}
			launch.external.profile.KillSwitchPolicy = "on-connect"
			if desktopLinuxExternalEligible(launch) {
				t.Fatal("stale Off owner changed its captured mode")
			}
		})
	}
}

func TestDesktopLinuxExternalOffPairBindsBothOriginalMembers(t *testing.T) {
	for _, kind := range []string{"wireguard", "ss2022"} {
		t.Run(kind, func(t *testing.T) {
			var profile, entry common.RouterProfile
			var launch *desktopNodeLaunch
			if kind == "wireguard" {
				profile, entry, launch = desktopExternalPacketEntryFixture(t, "off", "wireguard")
			} else {
				profile, entry, launch = desktopSSEntryFixture(t, "off", desktopSSEntryMethods[1], desktopSSEntryMethods[1], "udp")
			}
			if !desktopLinuxExternalEligible(launch) {
				t.Fatal("sealed all-member Off pair lacks Linux owner")
			}
			if err := prepareDesktopExternalPhysicalCaptured(launch, "linux"); err != nil {
				t.Fatal(err)
			}
			if launch.external.physical.Metadata().KillSwitchPolicy != "off" {
				t.Fatal("all-member Off pair changed policy")
			}
			if err := validateDesktopLinuxExternalSource(profile, launch, entry); err != nil {
				t.Fatal(err)
			}
			for _, member := range []string{"entry", "final"} {
				p, e := cloneRouterProfile(profile), cloneRouterProfile(entry)
				if member == "entry" {
					e.KillSwitchPolicy, e.KillSwitch = "always", true
				} else {
					p.KillSwitchPolicy, p.KillSwitch = "always", true
				}
				if validateDesktopLinuxExternalSource(p, launch, e) == nil {
					t.Fatal("stale Off source adopted stronger replacement member", member)
				}
			}
		})
	}
}

func TestDesktopLinuxExternalOffCannotFallBackWithoutOriginalController(t *testing.T) {
	for _, fault := range []string{"missing-controller", "stale-policy", "stale-source", "foreign-target", "missing-seal", "changed-seal"} {
		t.Run(fault, func(t *testing.T) {
			launch := desktopExternalPhysicalLaunchFixture(t, "shadowsocks", "off", "off", false)
			switch fault {
			case "stale-policy":
				launch.external.profile.KillSwitchPolicy = "always"
			case "stale-source":
				launch.external.source = append(launch.external.source, ' ')
			case "foreign-target":
				launch.external.selection = "server"
			case "missing-seal":
				launch.external.protection = desktopExternalProtectionCapture{}
			case "changed-seal":
				launch.external.protection.policy = "always"
			}
			owner, err := prepareDesktopRetainedExternalWith(&app{}, launch, func(context.Context, string) (string, error) {
				t.Fatal("Off entered binary staging without original controller")
				return "", nil
			})
			if owner != nil || err == nil {
				t.Fatal("Off fell through to a legacy unowned runtime", err)
			}
		})
	}
}

func TestDesktopLinuxExternalOffPreservesLegacyRouterServerCompare(t *testing.T) {
	for _, selection := range []string{"server", "auto"} {
		t.Run(selection, func(t *testing.T) {
			profile, originalExit := desktopExternalNativeFixture(t, "shadowsocks")
			profile.External.ResponseProbe = &common.ExternalResponseProbe{URL: "https://" + originalExit.Server + "/node-response", ServerName: "exit.example.test"}
			entry, files := desktopNodeFixture(t, "198.51.100.8")
			profile.KillSwitch, profile.KillSwitchPolicy = false, "off"
			entry.KillSwitch, entry.KillSwitchPolicy = false, "off"
			profile.MultihopExecution, profile.MultihopEntryMode = selection, "wg"
			exit, err := standardExitFromExternalProfile(profile)
			if err != nil {
				t.Fatal(err)
			}
			launch, err := compileDesktopExternalCaptured(context.Background(), profile, entry, exit, false, "", files, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if desktopExternalCapturedProtectionPolicy(launch.external) != "off" || desktopLinuxExternalEligible(launch) || desktopExternalOffRequiresRetainedForOS(launch.external, "linux") {
				t.Fatal("original legacy Router execution acquired native Linux Off obligation")
			}
			owner, err := prepareDesktopRetainedExternalWith(&app{}, launch, func(context.Context, string) (string, error) {
				t.Fatal("legacy Router execution entered native staging")
				return "", nil
			})
			if owner != nil || err != nil {
				t.Fatal("unchanged legacy Router execution lost its existing fallback", err)
			}
		})
	}
}
