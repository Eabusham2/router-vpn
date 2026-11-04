package main

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func desktopRetainedSOCKSFixture(t *testing.T, kill string) (common.RouterProfile, *desktopNodeLaunch) {
	t.Helper()
	profile, err := externalProfileFromCreateRequest(externalProfileCreateRequest{Name: "Captured SOCKS association", Protocol: "socks5",
		Server: "203.0.113.20", Port: 1080, Username: "captured-user", Password: "captured-password",
		ExpectedPublicIP: "203.0.113.88", StartLayer: common.StartLayerOff})
	if err != nil {
		t.Fatal(err)
	}
	profile.KillSwitchPolicy, profile.KillSwitch, profile.IPv6Mode, profile.HomeLANAccess = kill, kill != "off", "on", false
	profile.DNSMode, profile.DNSProtocol, profile.DNSHost, profile.DNSPort = "custom", "udp", "203.0.113.53", 5353
	profile.MTUPolicy, profile.ManualMTU, profile.EffectiveMTU, profile.MultihopExecution = "manual", 1360, 9000, "local"
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

func TestDesktopExternalPhysicalSOCKSKeepsOriginalSourceAndOwnedAssociation(t *testing.T) {
	for _, target := range []string{"linux", "windows", "darwin"} {
		for _, kill := range []string{"on-connect", "always"} {
			t.Run(target+"/"+kill, func(t *testing.T) {
				profile, launch := desktopRetainedSOCKSFixture(t, kill)
				owner := launch.external
				source, capture, expected := bytes.Clone(owner.source), bytes.Clone(owner.capture), owner.expected
				if err := prepareDesktopExternalPhysicalCaptured(launch, target); err != nil || owner.physical == nil {
					t.Fatal("direct native SOCKS did not retain its complete association plan", err)
				}
				meta, err := capturedDesktopExternalPhysical(owner)
				if err != nil || meta == nil || meta.Protocol != "socks5" || meta.TargetOS != target || meta.RootType != "socks" || !meta.SOCKSUDPAssociationRequired ||
					meta.KillSwitchPolicy != kill || meta.HomeLANAccess || meta.IPv6Mode != "on" || owner.expected != expected ||
					!bytes.Equal(source, owner.source) || !bytes.Equal(capture, owner.capture) || !reflect.DeepEqual(profile.External, owner.profile.External) {
					t.Fatal("SOCKS changed its original authentication, device policy or proof identity", err)
				}
				captured, err := owner.physical.Capture()
				if err != nil || captured.ConfiguredMTU != 1360 || captured.SelectedDNS.Physical || captured.SelectedDNS.Host != profile.DNSHost ||
					captured.SelectedDNS.Port != profile.DNSPort || captured.SelectedDNS.Type != "udp" || len(captured.PhysicalRoots) != 1 {
					t.Fatal("SOCKS lost selected DNS, current selected MTU or its single physical root", err)
				}
				root := captured.PhysicalRoots[0]
				if !root.DynamicSOCKSUDP || root.SOCKSControl == nil || root.SOCKSControl.Network != "tcp" || root.SOCKSControl.Host != profile.External.SOCKS5.Host ||
					root.SOCKSControl.Port != profile.External.SOCKS5.Port || len(root.Destinations) != 1 || root.Destinations[0] != *root.SOCKSControl {
					t.Fatal("SOCKS invented a static UDP relay from its control endpoint")
				}
				var graph map[string]any
				if json.Unmarshal(launch.config, &graph) != nil {
					t.Fatal("invalid derived SOCKS graph")
				}
				derived := taggedRuntimeItem(graph["outbounds"].([]any), mobilemultihop.ExternalFinalTag)
				if derived["type"] != mobilemultihop.DesktopExternalSOCKSType || derived["version"] != "5" || derived["username"] != profile.External.SOCKS5.Username ||
					derived["password"] != profile.External.SOCKS5.Password || derived["detour"] != mobilemultihop.DesktopExternalPhysicalTag ||
					derived["session_id"] != meta.SessionID || derived["source_sha256"] != meta.SourceSHA256 || derived["udp_over_tcp"] != nil {
					t.Fatal("SOCKS derived root changed its captured source or substituted UDP over TCP")
				}
				measurement, err := capturedDesktopMeasurementRuntime(launch)
				if err != nil || measurement.source != meta.SourceSHA256 || measurement.config != meta.ConfigSHA256 || measurement.session != owner.session {
					t.Fatal("SOCKS measurements adopted another physical operation", err)
				}
				resolver, err := capturedDesktopDNSRuntime(launch)
				if err != nil || resolver.source != meta.SourceSHA256 || resolver.config != meta.ConfigSHA256 {
					t.Fatal("SOCKS DNS mailbox substituted another native source", err)
				}
				if err := prepareDesktopExternalPhysicalCaptured(launch, target); err == nil {
					t.Fatal("SOCKS repeated preparation replaced the original owner")
				}
			})
		}
	}
}

func TestDesktopExternalPhysicalSOCKSKeepsOtherPlatformAndUnownedGuards(t *testing.T) {
	for _, target := range []string{"freebsd", ""} {
		t.Run(target, func(t *testing.T) {
			_, launch := desktopRetainedSOCKSFixture(t, "always")
			if err := prepareDesktopExternalPhysicalCaptured(launch, target); err != nil || launch.external.physical != nil {
				t.Fatal("native SOCKS relay ownership broadened another platform", err)
			}
		})
	}
	for _, target := range []string{"linux", "windows", "darwin"} {
		for _, fault := range []string{"off", "predecessor", "not-direct", "changed-source"} {
			t.Run(target+"/"+fault, func(t *testing.T) {
				kill := "always"
				if fault == "off" {
					kill = "off"
				}
				_, launch := desktopRetainedSOCKSFixture(t, kill)
				switch fault {
				case "predecessor":
					launch.external.predecessor = "captured-router-source"
				case "not-direct":
					launch.external.direct = false
				case "changed-source":
					launch.config = bytes.Replace(launch.config, []byte("captured-password"), []byte("foreign-password"), 1)
				}
				err := prepareDesktopExternalPhysicalCaptured(launch, target)
				if launch.external.physical != nil || (fault == "changed-source") != (err != nil) {
					t.Fatal("unowned SOCKS graph acquired retained admission", fault, err)
				}
			})
		}
	}

}
