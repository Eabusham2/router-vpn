package mobilemultihop

import (
	"reflect"
	"testing"

	"router-vpn/internal/applexray"
)

func TestDesktopUnixREALITYRetainsOriginalPolicyAndRestoration(t *testing.T) {
	for _, target := range []string{"linux", "darwin"} {
		for _, mode := range []string{"reality-vision", "reality-pq-vision", "reality-xhttp"} {
			for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				for _, protection := range []string{"off", "on-connect", "always"} {
					t.Run(target+"/"+mode+"/"+layer+"/"+protection, func(t *testing.T) {
						files, profile, start := nodeProfileFixture(t, mode, layer)
						profile["kill_switch"], profile["kill_switch_policy"] = protection != "off", protection
						profile["home_lan_access"] = false
						original, err := NewNodeProfile(mode, files, startJSON(t, profile), start, "")
						if err != nil {
							t.Fatal(err)
						}
						policy, err := NewDesktopNodePolicy(original, desktopNodeTestSession, target)
						if err != nil || !DesktopLinuxNodePhysicalGraphSupported(mode, layer) {
							t.Fatal("retained Unix REALITY lost its original native graph", err)
						}
						capture, err := policy.Capture()
						kind := applexray.Type
						if layer == "aes-256-gcm" {
							kind = "shadowsocks"
						}
						if layer == "aes-256-gcm+xor-whitening" {
							kind = "routervpn-aes-xor"
						}
						if err != nil || policy.OriginalProfile() != original || capture.Mode != mode || len(capture.PhysicalRoots) != 1 || capture.PhysicalRoots[0].Type != kind || len(capture.PhysicalRoots[0].Destinations) != 1 || capture.PhysicalRoots[0].Destinations[0].Network != "tcp" || capture.SelectedDNS.Host != "192.168.50.133" || capture.SelectedDNS.Physical || capture.SelectedDNS.Detour != "proxy" || len(capture.BootstrapDNS) != 0 || capture.KillSwitchPolicy != protection || capture.ConfiguredMTU != 1280 {
							t.Fatal("REALITY borrowed a UDP lower, resolver, protection or historical MTU", capture, err)
						}
						assertDesktopNodeExactDerivation(t, policy)
						restored, err := NewDesktopNodePolicyWithMTU(original, desktopNodeTestSession, target, 1376)
						if err != nil || restored.OriginalProfile() != original {
							t.Fatal("REALITY restoration replaced its original complete source", err)
						}
						next, err := restored.Capture()
						if err != nil || next.ConfiguredMTU != capture.ConfiguredMTU || restored.Metadata().RestoredMTU != 1376 || desktopNodeObject(t, startObject(t, restored.Config()), "inbounds", next.TUNTag)["mtu"] != float64(1376) || !reflect.DeepEqual(next.SelectedDNS, capture.SelectedDNS) || !reflect.DeepEqual(next.PhysicalRoots, capture.PhysicalRoots) || next.KillSwitchPolicy != protection || next.NodeID != capture.NodeID || next.Mode != mode || next.StartLayer != capture.StartLayer || policy.Validate() != nil || restored.Validate() != nil {
							t.Fatal("REALITY restored another source, DNS, native lower or profile owner", err)
						}
					})
				}
			}
		}
	}
}

func TestDesktopUnixREALITYAdmissionRetainsExactFamilies(t *testing.T) {
	for _, mode := range []string{"reality", "REALITY-VISION", "reality-pq", "xhttp", "naive-h3", "wg-pq", "max", "split", "tor", "openvpn", "unknown"} {
		if DesktopLinuxNodePhysicalGraphSupported(mode, "off") {
			t.Fatal("REALITY opened a separately unproved Unix composition", mode)
		}
	}
	for _, mode := range []string{"reality-vision", "reality-pq-vision", "reality-xhttp"} {
		for _, layer := range []string{"xor", "aes-128-gcm", "aes-256-gcm+xor", "foreign"} {
			if DesktopLinuxNodePhysicalGraphSupported(mode, layer) {
				t.Fatal("REALITY admitted an unauthenticated or foreign Start Layer", mode, layer)
			}
		}
	}
}
