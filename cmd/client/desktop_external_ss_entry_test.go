package main

import (
	"context"
	"encoding/base64"
	"router-vpn/internal/common"
	"strings"
	"testing"
)

var desktopSSEntryMethods = []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"}

func desktopSSEntryKey(method string, seed byte) string {
	size := 32
	if method == desktopSSEntryMethods[0] {
		size = 16
	}
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string(seed), size)))
}
func desktopSSEntryFixture(t *testing.T, kill, entryMethod, finalMethod, dns string) (common.RouterProfile, common.RouterProfile, *desktopNodeLaunch) {
	t.Helper()
	profile, _ := desktopExternalNativeFixture(t, "shadowsocks")
	entry, _ := desktopExternalNativeFixture(t, "shadowsocks")
	entry.ID = "captured-ss-entry"
	entry.Endpoint = "198.51.100.20"
	entry.External.Shadowsocks.Server = entry.Endpoint
	entry.External.Shadowsocks.Port = 8443
	entry.External.Shadowsocks.Method, entry.External.Shadowsocks.Password = entryMethod, desktopSSEntryKey(entryMethod, 'i')
	entry.External.ExpectedPublicIP = "203.0.113.77"
	entry.IPv6Mode = "on"
	entry.HomeLANAccess = true
	profile.External.Shadowsocks.Method, profile.External.Shadowsocks.Password = finalMethod, desktopSSEntryKey(finalMethod, 'e')
	profile.KillSwitchPolicy, profile.KillSwitch, profile.MultihopExecution = kill, true, "local"
	profile.MTUPolicy, profile.ManualMTU = "manual", 1360
	profile.DNSProtocol = dns
	exit, err := standardExitFromExternalProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	launch, err := compileDesktopExternalCaptured(context.Background(), profile, entry, exit, false, "", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return profile, entry, launch
}
func TestDesktopExternalSSEntryRetainsBothSourcesAndMeasurementOwner(t *testing.T) {
	for _, entryMethod := range desktopSSEntryMethods {
		for _, finalMethod := range desktopSSEntryMethods {
			for _, kill := range []string{"on-connect", "always"} {
				for _, dns := range []string{"tcp", "udp"} {
					profile, entry, launch := desktopSSEntryFixture(t, kill, entryMethod, finalMethod, dns)
					if err := prepareDesktopExternalPhysicalCaptured(launch, "darwin"); err != nil || launch.external.physical == nil {
						t.Fatal("SS entry did not retain native physical owner", err)
					}
					if err := validateDesktopMacOSExternalSources(profile, entry, launch); err != nil {
						t.Fatal(err)
					}
					meta, err := capturedDesktopExternalPhysical(launch.external)
					if err != nil || meta == nil || meta.RootType != "shadowsocks" || meta.RootTag != "external-entry" {
						t.Fatal("SS entry lost first root", err)
					}
					measure, err := capturedDesktopMeasurementRuntime(launch)
					if err != nil || measure.node != profile.ID || measure.source != meta.SourceSHA256 || measure.config != meta.ConfigSHA256 {
						t.Fatal("SS measurement changed original final ownership", err)
					}
					resolver, err := capturedDesktopDNSRuntime(launch)
					if err != nil || resolver.node != profile.ID || resolver.source != meta.SourceSHA256 {
						t.Fatal("SS DNS mailbox changed original final ownership", err)
					}
					for _, field := range []string{"entry", "final"} {
						for _, fault := range []string{"password", "method", "server", "port", "public", "id", "option"} {
							p, e := cloneRouterProfile(profile), cloneRouterProfile(entry)
							selected := &p
							if field == "entry" {
								selected = &e
							}
							mutateDesktopSSSource(selected, fault)
							if err := validateDesktopMacOSExternalSources(p, e, launch); err == nil {
								t.Fatal("replaced SS source accepted", field, fault)
							}
							if err := validateDesktopMacOSExternalSources(profile, entry, launch); err != nil {
								t.Fatal("replacement damaged original", err)
							}
						}
					}
				}
			}
		}
	}
}
func mutateDesktopSSSource(p *common.RouterProfile, fault string) {
	switch fault {
	case "password":
		p.External.Shadowsocks.Password = desktopSSEntryKey(p.External.Shadowsocks.Method, 'z')
	case "method":
		p.External.Shadowsocks.Method = "aes-256-gcm"
	case "server":
		p.External.Shadowsocks.Server = "192.0.2.99"
	case "port":
		p.External.Shadowsocks.Port++
	case "public":
		p.External.ExpectedPublicIP = "203.0.113.99"
	case "id":
		p.ID += "replaced"
	case "option":
		p.DAITAEnabled = !p.DAITAEnabled
	}
}
func TestDesktopExternalSSEntryRestoreRetainsOriginalCompleteGraph(t *testing.T) {
	for _, entryMethod := range desktopSSEntryMethods {
		for _, finalMethod := range desktopSSEntryMethods {
			for _, kill := range []string{"on-connect", "always"} {
				_, _, initial := desktopSSEntryFixture(t, kill, entryMethod, finalMethod, "udp")
				exit, err := standardExitFromExternalProfile(initial.external.profile)
				if err != nil {
					t.Fatal(err)
				}
				saved := &speedLabExternalRestore{source: append([]byte(nil), initial.external.source...), profile: cloneRouterProfile(initial.external.profile), entry: cloneRouterProfile(initial.external.entry), direct: false, execution: "local", root: "captured-root", network: "captured-original-network", mtu: 1360}
				if err := captureSpeedLabExternalRestoreSeal(saved, initial.external); err != nil {
					t.Fatal(err)
				}
				restored, err := compileSpeedLabExternalRestore(saved, exit)
				if err != nil {
					t.Fatal(err)
				}
				if restored.external.session == initial.external.session || restored.profileID != saved.entry.ID || restored.policyProfileID != saved.profile.ID || restored.external.selection != "local" || restored.external.expected.EntryID != saved.entry.ID || !restored.external.expected.EntryProven || restored.external.predecessor != "" || restored.external.network != saved.network || string(restored.external.source) != string(saved.source) || restored.external.mtu == nil || restored.external.mtu.restoreMTU != 1360 {
					t.Fatal("SS restore changed original graph/Local proof/measurement identity")
				}
				if err := prepareDesktopExternalPhysicalCaptured(restored, "darwin"); err != nil || restored.external.physical == nil {
					t.Fatal("SS restore lost original firstroot", err)
				}
				for _, field := range []string{"entry", "final"} {
					for _, fault := range []string{"password", "method", "server", "port", "public", "id", "option"} {
						copy := *saved
						copy.profile = cloneRouterProfile(saved.profile)
						copy.entry = cloneRouterProfile(saved.entry)
						selected := &copy.profile
						if field == "entry" {
							selected = &copy.entry
						}
						mutateDesktopSSSource(selected, fault)
						if next, err := compileSpeedLabExternalRestore(&copy, exit); err == nil || next != nil {
							t.Fatal("SS restore accepted modified saved source", field, fault)
						}
					}
				}
			}
		}
	}
}
func TestDesktopExternalSSEntryPreservesUnsupportedGraphs(t *testing.T) {
	for _, fault := range []string{"server", "auto", "predecessor", "same-id", "off", "entry-layer", "final-layer", "entry-legacy", "final-legacy", "final-family"} {
		t.Run(fault, func(t *testing.T) {
			_, _, launch := desktopSSEntryFixture(t, "always", desktopSSEntryMethods[1], desktopSSEntryMethods[1], "tcp")
			o := launch.external
			switch fault {
			case "server", "auto":
				o.selection = fault
			case "predecessor":
				o.predecessor = "another-runtime"
			case "same-id":
				o.entry.ID = o.profile.ID
			case "off":
				o.profile.KillSwitchPolicy = "off"
				o.profile.KillSwitch = false
			case "entry-layer":
				o.entry.StartLayer = common.StartLayerAES256GCM
			case "final-layer":
				o.profile.StartLayer = common.StartLayerAES256GCM
			case "entry-legacy":
				o.entry.External.Shadowsocks.Method = "aes-256-gcm"
			case "final-legacy":
				o.profile.External.Shadowsocks.Method = "aes-256-gcm"
			case "final-family":
				o.profile.External.Protocol = "hysteria2"
			}
			if desktopExternalRetainedEntryOwner(o) {
				t.Fatal("unsupported SS graph acquired native eligibility", fault)
			}
		})
	}
}
