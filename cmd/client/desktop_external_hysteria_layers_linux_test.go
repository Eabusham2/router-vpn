//go:build linux

package main

import (
	"context"
	"reflect"
	"testing"

	"router-vpn/internal/common"
)

func desktopLinuxHysteriaLayerFixture(t *testing.T, layer, kill string) (common.RouterProfile, *desktopNodeLaunch) {
	t.Helper()
	profile := desktopLayerProfile(t, "hysteria2", layer)
	profile.KillSwitch, profile.KillSwitchPolicy = kill != "off", kill
	profile.MTUPolicy, profile.ManualMTU, profile.MultihopExecution = "manual", 1360, "local"
	profile.IPv6Mode = "on"
	exit, err := standardExitFromExternalProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	launch, err := compileDesktopExternalCaptured(context.Background(), profile, common.RouterProfile{}, exit, true, "", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return profile, launch
}

func TestDesktopLinuxHysteriaLayersRetainCompleteSavedPolicy(t *testing.T) {
	for _, layer := range []string{common.StartLayerAES256GCM, common.StartLayerAES256GCMXOR} {
		for _, kill := range []string{"on-connect", "always"} {
			t.Run(layer+"/"+kill, func(t *testing.T) {
				profile, launch := desktopLinuxHysteriaLayerFixture(t, layer, kill)
				if !desktopLinuxExternalEligible(launch) {
					t.Fatal("direct Local HY2 layer is absent from retained Linux admission")
				}
				if err := prepareDesktopExternalPhysicalCaptured(launch, "linux"); err != nil || launch.external.physical == nil {
					t.Fatal("Linux layer lost its independently compiled physical owner", err)
				}
				if err := validateDesktopLinuxExternalSource(profile, launch); err != nil {
					t.Fatal("original saved HY2 layer rejected", err)
				}
				capture, err := launch.external.physical.Capture()
				if err != nil || capture.StartLayer != layer || capture.ConfiguredMTU != 1360 || capture.SelectedDNS.Physical ||
					capture.SelectedDNS.Host != profile.DNSHost || capture.SelectedDNS.Port != profile.DNSPort ||
					len(capture.PhysicalRoots) != 1 || len(capture.PhysicalRoots[0].Destinations) != 1 || capture.PhysicalRoots[0].Destinations[0].Network != "udp" {
					t.Fatal("Linux layer changed its selected DNS, MTU or outer UDP ownership", err)
				}
				for _, fault := range []string{"layer-key", "layer-mode", "private-peer", "outer-peer", "outer-port", "inner-key", "inner-trust", "dns", "mtu", "lan", "ipv6"} {
					t.Run(fault, func(t *testing.T) {
						changed := cloneRouterProfile(profile)
						switch fault {
						case "layer-key":
							changed.External.StartLayer.Transport["password"] = testWGKey('p')
						case "layer-mode":
							changed.StartLayer = common.StartLayerOff
						case "private-peer":
							changed.External.StartLayer.API = "http://10.77.0.2:8787"
						case "outer-peer":
							changed.External.StartLayer.Transport["server"] = "198.51.100.21"
						case "outer-port":
							changed.External.StartLayer.Transport["server_port"] = float64(8390)
						case "inner-key":
							changed.External.Hysteria2.Password += " changed"
						case "inner-trust":
							changed.External.Hysteria2.TLSServerName = "another.example"
						case "dns":
							changed.DNSPort++
						case "mtu":
							changed.ManualMTU = 1340
						case "lan":
							changed.HomeLANAccess = !changed.HomeLANAccess
						case "ipv6":
							changed.IPv6Mode = "off"
						}
						if desktopOwnedNodeProfileToken(changed) == desktopOwnedNodeProfileToken(profile) || validateDesktopLinuxExternalSource(changed, launch) == nil {
							t.Fatal("replaced policy or private identity acquired the original Linux host", fault)
						}
						if validateDesktopLinuxExternalSource(profile, launch) != nil || !reflect.DeepEqual(profile.External, launch.external.profile.External) {
							t.Fatal("refused replacement changed the retained original")
						}
					})
				}
			})
		}
	}
}

func TestDesktopLinuxHysteriaLayersPreserveUnsupportedGraphBoundaries(t *testing.T) {
	for _, fault := range []string{"server", "auto", "off", "predecessor", "not-direct", "unknown-layer", "unpaired-layer", "http-layer", "ss-layer"} {
		t.Run(fault, func(t *testing.T) {
			_, launch := desktopLinuxHysteriaLayerFixture(t, common.StartLayerAES256GCMXOR, "always")
			switch fault {
			case "server", "auto":
				launch.external.selection = fault
			case "off":
				launch.external.profile.KillSwitchPolicy, launch.external.profile.KillSwitch = "off", false
			case "predecessor":
				launch.external.predecessor = "captured Router predecessor"
			case "not-direct":
				launch.external.direct = false
			case "unknown-layer":
				launch.external.profile.StartLayer = "xor-only"
			case "unpaired-layer":
				profile := cloneRouterProfile(launch.external.profile)
				profile.External.StartLayer = nil
				exit, err := standardExitFromExternalProfile(profile)
				if err == nil {
					_, err = compileDesktopExternalCaptured(context.Background(), profile, common.RouterProfile{}, exit, true, "", nil, nil, nil)
				}
				if err == nil {
					t.Fatal("unpaired layer reached physical preparation")
				}
				return
			case "http-layer":
				launch.external.profile.External.Protocol = "http-connect"
			case "ss-layer":
				launch.external.profile.External.Protocol = "shadowsocks"
			}
			if desktopLinuxExternalEligible(launch) {
				t.Fatal("unsupported graph acquired Linux direct HY2 layer authority", fault)
			}
		})
	}
}
