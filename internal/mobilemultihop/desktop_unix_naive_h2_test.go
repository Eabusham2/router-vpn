package mobilemultihop

import (
	"reflect"
	"testing"
)

func TestDesktopUnixNaiveH2RetainsOriginalPolicyAndRestoration(t *testing.T) {
	for _, target := range []string{"linux", "darwin"} {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, protection := range []string{"off", "on-connect", "always"} {
				t.Run(target+"/"+layer+"/"+protection, func(t *testing.T) {
					files, profile, start := nodeProfileFixture(t, "naive-h2", layer)
					profile["kill_switch"], profile["kill_switch_policy"] = protection != "off", protection
					profile["home_lan_access"] = false
					original, err := NewNodeProfile("naive-h2", files, startJSON(t, profile), start, "")
					if err != nil {
						t.Fatal(err)
					}
					policy, err := NewDesktopNodePolicy(original, desktopNodeTestSession, target)
					if err != nil || !DesktopLinuxNodePhysicalGraphSupported("naive-h2", layer) {
						t.Fatal("retained Unix Naive H2 admission lost its actual original graph", err)
					}
					capture, err := policy.Capture()
					kind, destinations := "naive", 1
					if layer == "aes-256-gcm" {
						kind, destinations = "shadowsocks", 2
					}
					if layer == "aes-256-gcm+xor-whitening" {
						kind, destinations = "routervpn-aes-xor", 2
					}
					if err != nil || policy.OriginalProfile() != original || len(capture.PhysicalRoots) != 1 || capture.PhysicalRoots[0].Type != kind || len(capture.PhysicalRoots[0].Destinations) != destinations || capture.PhysicalRoots[0].Destinations[0].Network != "tcp" || capture.SelectedDNS.Host != "192.168.50.133" || capture.SelectedDNS.Physical || capture.SelectedDNS.Detour != "proxy" || capture.KillSwitchPolicy != protection || capture.ConfiguredMTU != 1280 {
						t.Fatal("retained Naive H2 borrowed a UDP lower, DNS, protection or historical MTU", capture, err)
					}
					if len(capture.BootstrapDNS) != 1 || capture.BootstrapDNS[0].Host != "192.168.50.133" || capture.BootstrapDNS[0].Type != "udp" || capture.BootstrapDNS[0].Port != 53 || capture.BootstrapDNS[0].Physical != (layer == "") || layer != "" && (capture.BootstrapDNS[0].Detour != NativeStartLayerTag || capture.PhysicalRoots[0].Destinations[1].Network != "udp") {
						t.Fatal("Naive H2 replaced its separately captured selected-resolver bootstrap", capture.BootstrapDNS)
					}
					assertDesktopNodeExactDerivation(t, policy)
					restored, err := NewDesktopNodePolicyWithMTU(original, desktopNodeTestSession, target, 1376)
					if err != nil || restored.OriginalProfile() != original {
						t.Fatal("Naive H2 restoration replaced the original source", err)
					}
					next, err := restored.Capture()
					if err != nil || next.ConfiguredMTU != capture.ConfiguredMTU || restored.Metadata().RestoredMTU != 1376 || desktopNodeObject(t, startObject(t, restored.Config()), "inbounds", next.TUNTag)["mtu"] != float64(1376) || !reflect.DeepEqual(next.SelectedDNS, capture.SelectedDNS) || !reflect.DeepEqual(next.PhysicalRoots, capture.PhysicalRoots) || next.KillSwitchPolicy != capture.KillSwitchPolicy || next.NodeID != capture.NodeID || next.StartLayer != capture.StartLayer {
						t.Fatal("Naive H2 restored another physical/DNS/profile owner", err)
					}
					if policy.Validate() != nil || restored.Validate() != nil {
						t.Fatal("captured Naive H2 policy became invalid")
					}
				})
			}
		}
	}
}

func TestDesktopUnixNaiveH2AdmissionKeepsOtherFamiliesClosed(t *testing.T) {
	for _, mode := range []string{"naive-h3", "naive", "NAIVE-H2", "reality-vision", "wg-pq", "max", "tor", "openvpn", "unknown"} {
		if DesktopLinuxNodePhysicalGraphSupported(mode, "off") {
			t.Fatal("Naive H2 opened a separately unproved Unix owner", mode)
		}
	}
	for _, layer := range []string{"xor", "aes-128-gcm", "aes-256-gcm+xor", "foreign"} {
		if DesktopLinuxNodePhysicalGraphSupported("naive-h2", layer) {
			t.Fatal("Naive H2 admitted a foreign Start Layer", layer)
		}
	}
}
