package main

import (
	"context"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"strconv"
	"strings"
	"testing"
)

func desktopExternalPacketEntryFixture(t *testing.T, kill, variant string) (common.RouterProfile, common.RouterProfile, *desktopNodeLaunch) {
	return desktopExternalPacketEntryExitFixture(t, kill, variant, "shadowsocks")
}
func desktopExternalPacketEntryExitFixture(t *testing.T, kill, variant, protocol string) (common.RouterProfile, common.RouterProfile, *desktopNodeLaunch) {
	t.Helper()
	profile, exit := desktopExternalNativeFixture(t, protocol)
	entry, _ := desktopExternalNativeFixture(t, "wireguard")
	entry.ID = "captured-wg-entry"
	if variant != "wireguard" {
		entry.ID = "captured-awg-entry"
		parameters := map[string]string{"jc": "3", "jmin": "40", "jmax": "900", "s1": "56", "s2": "48", "s3": "24", "s4": "32", "h1": "10000000-19999999", "h2": "20000000-29999999", "h3": "30000000-39999999", "h4": "40000000-49999999"}
		if variant == "fast" {
			parameters["jc"], parameters["jmin"], parameters["jmax"], parameters["s4"] = "0", "20", "40", "8"
		} else if variant != "strong" {
			t.Fatal("unknown entry import")
		}
		entry.External.Protocol, entry.External.AmneziaWG = "amneziawg", &common.ExternalAmneziaWGConfig{ExternalWireGuardConfig: *entry.External.WireGuard, Parameters: parameters}
		entry.External.WireGuard = nil
	}
	profile.KillSwitchPolicy, profile.KillSwitch, profile.MultihopExecution = kill, true, "local"
	profile.MTUPolicy, profile.ManualMTU = "manual", 1360
	if protocol == "hysteria2" || protocol == "socks5" {
		profile.DNSProtocol = "udp"
	}
	launch, err := compileDesktopExternalCaptured(context.Background(), profile, entry, exit, false, "", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return profile, entry, launch
}
func TestDesktopExternalWireGuardEntryRetainsBothSourcesAndMeasurementOwner(t *testing.T) {
	desktopExternalPacketEntryRetainsSources(t, "wireguard")
}
func TestDesktopExternalAmneziaEntryRetainsBothSourcesAndMeasurementOwner(t *testing.T) {
	for _, variant := range []string{"fast", "strong"} {
		t.Run(variant, func(t *testing.T) { desktopExternalPacketEntryRetainsSources(t, variant) })
	}
}
func desktopExternalPacketEntryRetainsSources(t *testing.T, variant string) {
	desktopExternalPacketEntryExitRetainsSources(t, variant, "shadowsocks")
}
func TestDesktopExternalPacketEntryCONNECTRetainsBothSourcesAndMeasurementOwner(t *testing.T) {
	for _, variant := range []string{"wireguard", "fast", "strong"} {
		for _, protocol := range []string{"http-connect", "https-connect"} {
			t.Run(variant+"/"+protocol, func(t *testing.T) { desktopExternalPacketEntryExitRetainsSources(t, variant, protocol) })
		}
	}
}
func TestDesktopExternalPacketEntryHysteriaRetainsBothSourcesAndMeasurementOwner(t *testing.T) {
	for _, variant := range []string{"wireguard", "fast", "strong"} {
		t.Run(variant, func(t *testing.T) { desktopExternalPacketEntryExitRetainsSources(t, variant, "hysteria2") })
	}
}
func TestDesktopExternalPacketEntrySOCKSRetainsBothSourcesAndMeasurementOwner(t *testing.T) {
	for _, variant := range []string{"wireguard", "fast", "strong"} {
		t.Run(variant, func(t *testing.T) { desktopExternalPacketEntryExitRetainsSources(t, variant, "socks5") })
	}
}
func desktopExternalPacketEntryExitRetainsSources(t *testing.T, variant, protocol string) {
	for _, kill := range []string{"on-connect", "always"} {
		profile, entry, launch := desktopExternalPacketEntryExitFixture(t, kill, variant, protocol)
		if err := prepareDesktopExternalPhysicalCaptured(launch, "darwin"); err != nil || launch.external.physical == nil {
			t.Fatal(err)
		}
		if err := validateDesktopMacOSExternalSources(profile, entry, launch); err != nil {
			t.Fatal(err)
		}
		meta, err := capturedDesktopExternalPhysical(launch.external)
		rootType := "wireguard"
		if variant != "wireguard" {
			rootType = mobilemultihop.AmneziaType
		}
		if err != nil || meta == nil || meta.RootType != rootType || meta.Protocol != protocol {
			t.Fatal("lost captured first root", err)
		}
		measure, err := capturedDesktopMeasurementRuntime(launch)
		if err != nil || measure.node != profile.ID || measure.source != meta.SourceSHA256 || measure.config != meta.ConfigSHA256 {
			t.Fatal("measurement borrowed entry identity", err)
		}
		resolver, err := capturedDesktopDNSRuntime(launch)
		if err != nil || resolver.node != profile.ID || resolver.source != meta.SourceSHA256 {
			t.Fatal("DNS mailbox borrowed entry identity", err)
		}
		faults := []string{"entry-key", "entry-peer-key", "entry-psk", "entry-id", "entry-address", "entry-public", "entry-option", "exit-id", "exit-key", "exit-public", "dns", "mtu", "lan", "ipv6"}
		if protocol == "hysteria2" {
			faults = append(faults, "exit-tls")
		}
		if protocol == "http-connect" || protocol == "https-connect" || protocol == "socks5" {
			faults = append(faults, "exit-username")
			if protocol == "https-connect" {
				faults = append(faults, "exit-tls")
			}
		}
		if variant != "wireguard" {
			for _, key := range []string{"jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4"} {
				faults = append(faults, "parameter/"+key)
			}
		}
		for _, fault := range faults {
			t.Run(kill+"/"+fault, func(t *testing.T) {
				p, e := cloneRouterProfile(profile), cloneRouterProfile(entry)
				wireguard := e.External.WireGuard
				if e.External.AmneziaWG != nil {
					wireguard = &e.External.AmneziaWG.ExternalWireGuardConfig
				}
				switch fault {
				case "entry-key":
					wireguard.PrivateKey = testWGKey('y')
				case "entry-peer-key":
					wireguard.PeerPublicKey = testWGKey('z')
				case "entry-id":
					e.ID += "changed"
				case "exit-id":
					p.ID += "changed"
				case "entry-psk":
					wireguard.PresharedKey = testWGKey('y')
				case "entry-address":
					e.Endpoint = "192.0.2.222"
				case "entry-public":
					e.External.ExpectedPublicIP = "198.51.100.21"
				case "entry-option":
					e.DAITAEnabled = !e.DAITAEnabled
				case "exit-key":
					mutateDesktopExternalEntryExit(t, &p, "password")
				case "exit-username":
					mutateDesktopExternalEntryExit(t, &p, "username")
				case "exit-tls":
					mutateDesktopExternalEntryExit(t, &p, "tls")
				case "exit-public":
					p.External.ExpectedPublicIP = "198.51.100.22"
				case "dns":
					p.DNSPort++
				case "mtu":
					p.ManualMTU++
				case "lan":
					p.HomeLANAccess = !p.HomeLANAccess
				case "ipv6":
					p.IPv6Mode = "on"
				default:
					mutateDesktopExternalEntryParameter(t, e.External.AmneziaWG.Parameters, strings.TrimPrefix(fault, "parameter/"))
				}
				if err := validateDesktopMacOSExternalSources(p, e, launch); err == nil {
					t.Fatal("replaced source accepted", fault)
				}
				if err := validateDesktopMacOSExternalSources(profile, entry, launch); err != nil {
					t.Fatal("rejected replacement changed original", err)
				}
			})
		}
	}
}

func TestDesktopExternalWireGuardEntryRestoreKeepsCompleteSourceAndNewSession(t *testing.T) {
	desktopExternalPacketEntryRestore(t, "wireguard")
}
func TestDesktopExternalAmneziaEntryRestoreKeepsCompleteSourceAndNewSession(t *testing.T) {
	for _, variant := range []string{"fast", "strong"} {
		t.Run(variant, func(t *testing.T) { desktopExternalPacketEntryRestore(t, variant) })
	}
}
func desktopExternalPacketEntryRestore(t *testing.T, variant string) {
	desktopExternalPacketEntryExitRestore(t, variant, "shadowsocks")
}
func TestDesktopExternalPacketEntryCONNECTRestoreKeepsCompleteSourceAndNewSession(t *testing.T) {
	for _, variant := range []string{"wireguard", "fast", "strong"} {
		for _, protocol := range []string{"http-connect", "https-connect"} {
			t.Run(variant+"/"+protocol, func(t *testing.T) { desktopExternalPacketEntryExitRestore(t, variant, protocol) })
		}
	}
}
func TestDesktopExternalPacketEntryHysteriaRestoreKeepsCompleteSourceAndNewSession(t *testing.T) {
	for _, variant := range []string{"wireguard", "fast", "strong"} {
		t.Run(variant, func(t *testing.T) { desktopExternalPacketEntryExitRestore(t, variant, "hysteria2") })
	}
}
func TestDesktopExternalPacketEntrySOCKSRestoreKeepsCompleteSourceAndNewSession(t *testing.T) {
	for _, variant := range []string{"wireguard", "fast", "strong"} {
		t.Run(variant, func(t *testing.T) { desktopExternalPacketEntryExitRestore(t, variant, "socks5") })
	}
}
func desktopExternalPacketEntryExitRestore(t *testing.T, variant, protocol string) {
	for _, kill := range []string{"on-connect", "always"} {
		_, _, initial := desktopExternalPacketEntryExitFixture(t, kill, variant, protocol)
		exit, err := standardExitFromExternalProfile(initial.external.profile)
		if err != nil {
			t.Fatal(err)
		}
		saved := &speedLabExternalRestore{source: append([]byte(nil), initial.external.source...), profile: cloneRouterProfile(initial.external.profile), entry: cloneRouterProfile(initial.external.entry), direct: false, execution: "local", root: "captured-root", network: "captured-physical-network", mtu: 1360}
		restored, err := compileSpeedLabExternalRestore(saved, exit)
		if err != nil {
			t.Fatal(err)
		}
		if restored.external.session == initial.external.session || restored.profileID != saved.entry.ID || restored.policyProfileID != saved.profile.ID || desktopExternalPathProfileID(restored) != saved.profile.ID || restored.external.direct || restored.external.selection != "local" || restored.external.expected.EntryID != saved.entry.ID || !restored.external.expected.EntryProven || restored.external.predecessor != "" || restored.external.expected.EntryNodeID != "" || restored.external.network != saved.network || restored.root != saved.root || desktopOwnedNodeProfileToken(restored.external.profile) != desktopOwnedNodeProfileToken(saved.profile) || desktopOwnedNodeProfileToken(restored.external.entry) != desktopOwnedNodeProfileToken(saved.entry) || string(restored.external.source) != string(saved.source) {
			t.Fatal("restore substituted original two-node source or reused its native session")
		}
		if err := prepareDesktopExternalPhysicalCaptured(restored, "darwin"); err != nil || restored.external.physical == nil {
			t.Fatal("restored graph lost captured firstroot", err)
		}
		if restored.external.mtu == nil || restored.external.mtu.restoreMTU != 1360 {
			t.Fatal("restore discarded original selected MTU")
		}
		faults := []string{"entry-key", "entry-ip", "final-key", "source", "server"}
		if protocol == "hysteria2" {
			faults = append(faults, "final-tls")
		}
		if protocol == "http-connect" || protocol == "https-connect" || protocol == "socks5" {
			faults = append(faults, "final-username")
			if protocol == "https-connect" {
				faults = append(faults, "final-tls")
			}
		}
		if variant != "wireguard" {
			for _, key := range []string{"jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4"} {
				faults = append(faults, "parameter/"+key)
			}
		}
		for _, fault := range faults {
			t.Run(kill+"/restore-"+fault, func(t *testing.T) {
				copy := *saved
				copy.profile = cloneRouterProfile(saved.profile)
				copy.entry = cloneRouterProfile(saved.entry)
				copy.source = append([]byte(nil), saved.source...)
				wireguard := copy.entry.External.WireGuard
				if copy.entry.External.AmneziaWG != nil {
					wireguard = &copy.entry.External.AmneziaWG.ExternalWireGuardConfig
				}
				switch fault {
				case "entry-key":
					wireguard.PrivateKey = testWGKey('z')
				case "entry-ip":
					wireguard.Endpoint = "192.0.2.21:51820"
				case "final-key":
					mutateDesktopExternalEntryExit(t, &copy.profile, "password")
				case "final-username":
					mutateDesktopExternalEntryExit(t, &copy.profile, "username")
				case "final-tls":
					mutateDesktopExternalEntryExit(t, &copy.profile, "tls")
				case "source":
					copy.source = []byte(`{}`)
				case "server":
					copy.execution = "server"
				default:
					mutateDesktopExternalEntryParameter(t, copy.entry.External.AmneziaWG.Parameters, strings.TrimPrefix(fault, "parameter/"))
				}
				if next, err := compileSpeedLabExternalRestore(&copy, exit); err == nil || next != nil {
					t.Fatal("changed restore source acquired another runtime", fault)
				}
			})
		}
	}
}

func mutateDesktopExternalEntryParameter(t *testing.T, parameters map[string]string, key string) {
	t.Helper()
	if strings.HasPrefix(key, "h") {
		parameters[key] = "50000000-59999999"
		return
	}
	n, err := strconv.Atoi(parameters[key])
	if err != nil {
		t.Fatal(err)
	}
	parameters[key] = strconv.Itoa(n + 1)
}

func mutateDesktopExternalEntryExit(t *testing.T, profile *common.RouterProfile, field string) {
	t.Helper()
	switch profile.External.Protocol {
	case "shadowsocks":
		profile.External.Shadowsocks.Password += "changed"
	case "socks5":
		if field == "username" {
			profile.External.SOCKS5.Username += "changed"
		} else {
			profile.External.SOCKS5.Password += "changed"
		}
	case "hysteria2":
		if field == "tls" {
			profile.External.Hysteria2.TLSServerName = "different.example"
		} else {
			profile.External.Hysteria2.Password += "changed"
		}
	case "http-connect", "https-connect":
		proxy := profile.External.HTTPConnect
		if profile.External.Protocol == "https-connect" {
			proxy = profile.External.HTTPSConnect
		}
		switch field {
		case "username":
			proxy.Username += "changed"
		case "tls":
			proxy.TLSServerName = "different.example"
		default:
			proxy.Password += "changed"
		}
	default:
		t.Fatal("unknown captured stream exit")
	}
}
