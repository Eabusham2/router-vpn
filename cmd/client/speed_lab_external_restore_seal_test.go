package main

import (
	"router-vpn/internal/common"
	"strings"
	"testing"
)

func TestSpeedLabDirectLayeredHysteriaRestoreRejectsChangedCapturedLayer(t *testing.T) {
	for _, layer := range []string{common.StartLayerAES256GCM, common.StartLayerAES256GCMXOR} {
		for _, field := range []string{"key", "private-api", "port"} {
			if layer == common.StartLayerAES256GCMXOR && field == "port" {
				continue
			} // XOR has a canonical fixed port.
			t.Run(layer+"/"+field, func(t *testing.T) {
				profile := desktopLayerProfile(t, "hysteria2", layer)
				profile.MultihopExecution = "local"
				exit, err := standardExitFromExternalProfile(profile)
				if err != nil {
					t.Fatal(err)
				}
				graph, err := buildDirectStandardExitConfig(profile, exit)
				if err != nil {
					t.Fatal(err)
				}
				original, err := compileDesktopExternalGraph(graph, profile, common.RouterProfile{}, exit, true, "")
				if err != nil {
					t.Fatal(err)
				}
				saved := &speedLabExternalRestore{source: append([]byte(nil), original.external.source...), profile: cloneRouterProfile(original.external.profile), direct: true, execution: "local", network: "original-network"}
				if err := captureSpeedLabExternalRestoreSeal(saved, original.external); err != nil {
					t.Fatal(err)
				}
				if _, err := compileSpeedLabExternalRestore(saved, exit); err != nil {
					t.Fatal("unchanged original restore refused", err)
				}
				switch field {
				case "key":
					saved.profile.External.StartLayer.Transport["password"] = testWGKey('p')
				case "private-api":
					saved.profile.External.StartLayer.API = "http://10.77.0.2:8787"
				case "port":
					saved.profile.External.StartLayer.Transport["server_port"] = 8390
				}
				if next, err := compileSpeedLabExternalRestore(saved, exit); err == nil || next != nil {
					t.Fatal("changed captured layer acquired a replacement restored runtime", field)
				}
			})
		}
	}
}

func TestSpeedLabExternalRestoreSealRetainsOriginalOwner(t *testing.T) {
	for _, fault := range []string{"missing-seal", "source", "profile", "entry", "predecessor", "direct", "execution", "original-config", "original-capture", "original-session", "original-source-proof", "capture-effective-mtu", "capture-daita", "capture-jumbo", "capture-socks"} {
		t.Run(fault, func(t *testing.T) {
			profile := desktopLayerProfile(t, "hysteria2", common.StartLayerAES256GCM)
			exit, err := standardExitFromExternalProfile(profile)
			if err != nil {
				t.Fatal(err)
			}
			graph, err := buildDirectStandardExitConfig(profile, exit)
			if err != nil {
				t.Fatal(err)
			}
			original, err := compileDesktopExternalGraph(graph, profile, common.RouterProfile{}, exit, true, "")
			if err != nil {
				t.Fatal(err)
			}
			saved := &speedLabExternalRestore{source: append([]byte(nil), original.external.source...), profile: cloneRouterProfile(original.external.profile), direct: true, execution: "local", network: "original-network"}
			switch fault {
			case "capture-effective-mtu":
				saved.profile.EffectiveMTU = 1412
			case "capture-daita":
				saved.profile.DAITAEnabled = !saved.profile.DAITAEnabled
			case "capture-jumbo":
				saved.profile.JumboTUN = !saved.profile.JumboTUN
			case "capture-socks":
				saved.profile.SocksEnabled = !saved.profile.SocksEnabled
			case "original-capture":
				original.external.capture = []byte(`{}`)
			case "original-session":
				original.external.session = "replacement-session"
			case "original-source-proof":
				original.external.expected.SourceSHA256 = "replacement-source"
			}
			if strings.HasPrefix(fault, "capture-") || fault == "original-capture" || fault == "original-session" || fault == "original-source-proof" {
				if err := captureSpeedLabExternalRestoreSeal(saved, original.external); err == nil || saved.seal != nil {
					t.Fatal("replaced original owner acquired restoration authority")
				}
				return
			}
			if err := captureSpeedLabExternalRestoreSeal(saved, original.external); err != nil {
				t.Fatal(err)
			}
			if err := captureSpeedLabExternalRestoreSeal(saved, original.external); err == nil {
				t.Fatal("already captured seal was refreshed")
			}
			switch fault {
			case "missing-seal":
				saved.seal = nil
			case "source":
				saved.source = append(saved.source, ' ')
			case "profile":
				saved.profile.DNSHost = "203.0.113.99"
			case "entry":
				saved.entry.ID = "replacement-entry"
			case "predecessor":
				saved.predecessor = `{}`
			case "direct":
				saved.direct = false
			case "execution":
				saved.execution = "server"
			case "original-config":
				copied := *saved.seal
				copied.configSHA256 = strings.Repeat("f", 64)
				saved.seal = &copied
			}
			if next, err := compileSpeedLabExternalRestore(saved, exit); err == nil || next != nil {
				t.Fatal("changed original restore authority acquired replacement runtime", fault)
			}
		})
	}
}
