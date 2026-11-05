//go:build linux

package main

import (
	"reflect"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"testing"
)

func TestDesktopLinuxSSCONNECTRetainsSourcesTCPDNSAndRestore(t *testing.T) {
	for _, method := range desktopSSEntryMethods {
		for _, protocol := range []string{"http-connect", "https-connect"} {
			for _, kill := range []string{"on-connect", "always"} {
				t.Run(method+"/"+protocol+"/"+kill, func(t *testing.T) {
					profile, entry, launch := desktopSSCONNECTFixture(t, kill, method, protocol)
					if !desktopLinuxExternalEligible(launch) {
						t.Fatal("original Linux SS CONNECT pair was not admitted")
					}
					if err := prepareDesktopExternalPhysicalCaptured(launch, "linux"); err != nil {
						t.Fatal(err)
					}
					capture, err := launch.external.physical.Capture()
					if err != nil || capture.UDPAvailable || capture.Protocol != protocol || capture.SelectedDNS.Type != "tcp" || capture.SelectedDNS.Physical || capture.SelectedDNS.Detour != mobilemultihop.ExternalFinalTag || len(capture.PhysicalRoots) != 1 || len(capture.PhysicalRoots[0].Destinations) != 1 {
						t.Fatal("CONNECT lost TCP-only entry/final DNS", err)
					}
					d := capture.PhysicalRoots[0].Destinations[0]
					if d.Network != "tcp" || d.Host != entry.External.Shadowsocks.Server || d.Port != entry.External.Shadowsocks.Port {
						t.Fatal("CONNECT acquired UDP or physical final")
					}
					a := &app{profiles: common.RouterProfileStore{Profiles: []common.RouterProfile{profile, entry}}}
					h := &desktopLinuxNodeHost{launch: launch, revision: desktopOwnedNodeProfileToken(profile), externalEntryRevision: desktopOwnedNodeProfileToken(entry), savedOptions: [3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled}, externalEntryOptions: [3]bool{entry.DAITAEnabled, entry.JumboTUN, entry.SocksEnabled}}
					if err := h.externalSourcesLocked(a); err != nil {
						t.Fatal(err)
					}
					for _, fault := range []string{"password", "method", "server", "port", "public", "id", "option"} {
						e := cloneRouterProfile(entry)
						mutateDesktopSSSource(&e, fault)
						a.profiles.Profiles = []common.RouterProfile{profile, e}
						if h.externalSourcesLocked(a) == nil {
							t.Fatal("CONNECT accepted changed SS entry", fault)
						}
					}
					for _, fault := range []string{"username", "password", "tls", "host", "port", "public", "option"} {
						p := cloneRouterProfile(profile)
						mutateSSCONNECTFinal(&p, fault)
						a.profiles.Profiles = []common.RouterProfile{p, entry}
						if h.externalSourcesLocked(a) == nil {
							t.Fatal("CONNECT accepted changed final", fault)
						}
					}
					a.profiles.Profiles = []common.RouterProfile{profile, entry}
					if err := h.externalSourcesLocked(a); err != nil {
						t.Fatal(err)
					}
					measure, err := capturedDesktopMeasurementRuntime(launch)
					if err != nil || measure.node != profile.ID {
						t.Fatal("measurement borrowed entry", err)
					}
					dns, err := capturedDesktopDNSRuntime(launch)
					if err != nil || dns.node != profile.ID {
						t.Fatal("DNS borrowed entry", err)
					}
					saved := &speedLabExternalRestore{source: append([]byte(nil), launch.external.source...), profile: cloneRouterProfile(launch.external.profile), entry: cloneRouterProfile(launch.external.entry), execution: "local", root: "original-root", network: "original-network", mtu: 1360}
					if err := captureSpeedLabExternalRestoreSeal(saved, launch.external); err != nil {
						t.Fatal(err)
					}
					exit, err := standardExitFromExternalProfile(profile)
					if err != nil {
						t.Fatal(err)
					}
					restored, err := compileSpeedLabExternalRestore(saved, exit)
					if err != nil || !desktopLinuxExternalEligible(restored) || restored.external.session == launch.external.session || !reflect.DeepEqual(restored.external.source, launch.external.source) {
						t.Fatal("CONNECT lost original sealed restoration", err)
					}
					if err := prepareDesktopExternalPhysicalCaptured(restored, "linux"); err != nil {
						t.Fatal(err)
					}
					if validateDesktopLinuxExternalSource(profile, restored, entry) != nil || restored.external.mtu == nil || restored.external.mtu.restoreMTU != 1360 {
						t.Fatal("CONNECT restored another source or MTU")
					}
				})
			}
		}
	}
}
