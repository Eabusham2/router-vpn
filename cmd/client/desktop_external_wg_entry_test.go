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
	return desktopExternalPacketEntryLayerExitFixture(t, kill, variant, protocol, "")
}
func desktopExternalPacketEntryLayerExitFixture(t *testing.T, kill, variant, protocol, layer string, finalVariants ...string) (common.RouterProfile, common.RouterProfile, *desktopNodeLaunch) {
	t.Helper()
	profile, exit := desktopExternalNativeFixture(t, protocol)
	if protocol == "amneziawg" {
		profile.External.AmneziaWG.PresharedKey, profile.External.AmneziaWG.PersistentKeepalive = testWGKey('r'), 25
		variant := "strong"
		if len(finalVariants) != 0 {
			variant = finalVariants[0]
		}
		if variant == "fast" {
			profile.External.AmneziaWG.Parameters["jc"], profile.External.AmneziaWG.Parameters["jmin"], profile.External.AmneziaWG.Parameters["jmax"], profile.External.AmneziaWG.Parameters["s4"] = "0", "20", "40", "8"
		} else if variant != "strong" {
			t.Fatal("unknown final import")
		}
		var err error
		exit, err = standardExitFromExternalProfile(profile)
		if err != nil {
			t.Fatal(err)
		}
	}
	if layer != "" {
		profile = desktopLayerProfile(t, protocol, layer)
		var err error
		exit, err = standardExitFromExternalProfile(profile)
		if err != nil {
			t.Fatal(err)
		}
	}
	entry, _ := desktopExternalNativeFixture(t, "wireguard")
	entry.ID = "captured-wg-entry"
	if protocol == "wireguard" || protocol == "amneziawg" {
		entry.External.WireGuard.MTU = 1420
		entry.External.WireGuard.PrivateKey, entry.External.WireGuard.PeerPublicKey, entry.External.WireGuard.PresharedKey = testWGKey('i'), testWGKey('j'), testWGKey('k')
	}
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
	if protocol == "amneziawg" {
		profile.ManualMTU = 1328
	}
	if protocol == "hysteria2" || protocol == "socks5" || protocol == "wireguard" || protocol == "amneziawg" {
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
func TestDesktopExternalPacketEntryHysteriaLayersRetainBothSourcesAndMeasurementOwner(t *testing.T) {
	for _, variant := range []string{"wireguard", "fast", "strong"} {
		for _, layer := range []string{common.StartLayerAES256GCM, common.StartLayerAES256GCMXOR} {
			t.Run(variant+"/"+layer, func(t *testing.T) { desktopExternalPacketEntryLayerExitRetainsSources(t, variant, "hysteria2", layer) })
		}
	}
}
func desktopExternalPacketEntryExitRetainsSources(t *testing.T, variant, protocol string) {
	desktopExternalPacketEntryLayerExitRetainsSources(t, variant, protocol, "")
}
func desktopExternalPacketEntryLayerExitRetainsSources(t *testing.T, variant, protocol, layer string, finalVariants ...string) {
	for _, kill := range []string{"on-connect", "always"} {
		profile, entry, launch := desktopExternalPacketEntryLayerExitFixture(t, kill, variant, protocol, layer, finalVariants...)
		if err := prepareDesktopExternalPhysicalCaptured(launch, "darwin"); err != nil || launch.external.physical == nil {
			t.Fatal("captured packet-entry graph has no complete retained physical owner", err)
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
		if layer != "" {
			faults = append(faults, "layer-key", "layer-mode", "layer-private", "layer-host", "layer-port")
		}
		if protocol == "wireguard" || protocol == "amneziawg" {
			faults = append(faults, "exit-peer-key", "exit-psk", "exit-address", "exit-client-address", "exit-allowed-ips", "exit-mtu")
		}
		if protocol == "amneziawg" {
			for _, key := range []string{"jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4"} {
				faults = append(faults, "exit-parameter/"+key)
			}
			faults = append(faults, "exit-keepalive")
		}
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
				case "layer-key", "layer-mode", "layer-private", "layer-host", "layer-port":
					mutateDesktopExternalEntryLayer(&p, fault)
				case "exit-key":
					mutateDesktopExternalEntryExit(t, &p, "password")
				case "exit-address", "exit-client-address", "exit-allowed-ips", "exit-mtu", "exit-keepalive":
					mutateDesktopExternalEntryExit(t, &p, strings.TrimPrefix(fault, "exit-"))
				case "exit-peer-key":
					mutateDesktopExternalEntryExit(t, &p, "peer-key")
				case "exit-psk":
					mutateDesktopExternalEntryExit(t, &p, "psk")
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
					if strings.HasPrefix(fault, "exit-parameter/") {
						mutateDesktopExternalEntryParameter(t, p.External.AmneziaWG.Parameters, strings.TrimPrefix(fault, "exit-parameter/"))
					} else {
						mutateDesktopExternalEntryParameter(t, e.External.AmneziaWG.Parameters, strings.TrimPrefix(fault, "parameter/"))
					}
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
func TestDesktopExternalPacketEntryHysteriaLayersRestoreKeepsCompleteSourceAndNewSession(t *testing.T) {
	for _, variant := range []string{"wireguard", "fast", "strong"} {
		for _, layer := range []string{common.StartLayerAES256GCM, common.StartLayerAES256GCMXOR} {
			t.Run(variant+"/"+layer, func(t *testing.T) { desktopExternalPacketEntryLayerExitRestore(t, variant, "hysteria2", layer) })
		}
	}
}
func desktopExternalPacketEntryExitRestore(t *testing.T, variant, protocol string) {
	desktopExternalPacketEntryLayerExitRestore(t, variant, protocol, "")
}
func desktopExternalPacketEntryLayerExitRestore(t *testing.T, variant, protocol, layer string, finalVariants ...string) {
	for _, kill := range []string{"on-connect", "always"} {
		_, _, initial := desktopExternalPacketEntryLayerExitFixture(t, kill, variant, protocol, layer, finalVariants...)
		exit, err := standardExitFromExternalProfile(initial.external.profile)
		if err != nil {
			t.Fatal(err)
		}
		mtu := initial.external.profile.ManualMTU
		saved := &speedLabExternalRestore{source: append([]byte(nil), initial.external.source...), profile: cloneRouterProfile(initial.external.profile), entry: cloneRouterProfile(initial.external.entry), direct: false, execution: "local", root: "captured-root", network: "captured-physical-network", mtu: mtu}
		if err := captureSpeedLabExternalRestoreSeal(saved, initial.external); err != nil {
			t.Fatal(err)
		}
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
		if restored.external.mtu == nil || restored.external.mtu.restoreMTU != mtu {
			t.Fatal("restore discarded original selected MTU")
		}
		faults := []string{"entry-key", "entry-ip", "final-key", "source", "server"}
		if layer != "" {
			faults = append(faults, "layer-key", "layer-mode", "layer-private", "layer-host", "layer-port")
		}
		if protocol == "wireguard" || protocol == "amneziawg" {
			faults = append(faults, "final-peer-key", "final-psk", "final-address", "final-client-address", "final-allowed-ips", "final-mtu")
		}
		if protocol == "amneziawg" {
			for _, key := range []string{"jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4"} {
				faults = append(faults, "final-parameter/"+key)
			}
			faults = append(faults, "final-keepalive")
		}
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
				case "layer-key", "layer-mode", "layer-private", "layer-host", "layer-port":
					mutateDesktopExternalEntryLayer(&copy.profile, fault)
				case "final-key":
					mutateDesktopExternalEntryExit(t, &copy.profile, "password")
				case "final-address", "final-client-address", "final-allowed-ips", "final-mtu", "final-keepalive":
					mutateDesktopExternalEntryExit(t, &copy.profile, strings.TrimPrefix(fault, "final-"))
				case "final-peer-key":
					mutateDesktopExternalEntryExit(t, &copy.profile, "peer-key")
				case "final-psk":
					mutateDesktopExternalEntryExit(t, &copy.profile, "psk")
				case "final-username":
					mutateDesktopExternalEntryExit(t, &copy.profile, "username")
				case "final-tls":
					mutateDesktopExternalEntryExit(t, &copy.profile, "tls")
				case "source":
					copy.source = []byte(`{}`)
				case "server":
					copy.execution = "server"
				default:
					if strings.HasPrefix(fault, "final-parameter/") {
						mutateDesktopExternalEntryParameter(t, copy.profile.External.AmneziaWG.Parameters, strings.TrimPrefix(fault, "final-parameter/"))
					} else {
						mutateDesktopExternalEntryParameter(t, copy.entry.External.AmneziaWG.Parameters, strings.TrimPrefix(fault, "parameter/"))
					}
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
	case "wireguard", "amneziawg":
		packet := profile.External.WireGuard
		if profile.External.AmneziaWG != nil {
			packet = &profile.External.AmneziaWG.ExternalWireGuardConfig
		}
		switch field {
		case "address":
			packet.Endpoint = "198.51.100.241:51821"
			profile.Endpoint = "198.51.100.241"
		case "client-address":
			packet.Addresses = []string{"10.81.0.2/32", "fd81::2/128"}
		case "allowed-ips":
			packet.AllowedIPs = []string{"0.0.0.0/0"}
		case "keepalive":
			packet.PersistentKeepalive++
		case "mtu":
			packet.MTU++
		case "peer-key":
			packet.PeerPublicKey = testWGKey('z')
		case "psk":
			packet.PresharedKey = testWGKey('y')
		default:
			packet.PrivateKey = testWGKey('z')
		}
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

func mutateDesktopExternalEntryLayer(profile *common.RouterProfile, fault string) {
	switch fault {
	case "layer-key":
		profile.External.StartLayer.Transport["password"] = testWGKey('p')
	case "layer-mode":
		profile.StartLayer = common.StartLayerOff
	case "layer-private":
		profile.External.StartLayer.API = "http://10.77.0.2:8787"
	case "layer-host":
		profile.External.StartLayer.Transport["server"] = "198.51.100.21"
	case "layer-port":
		profile.External.StartLayer.Transport["server_port"] = float64(8390)
	}
}

func TestDesktopExternalPacketEntryHysteriaLayersPreserveUnsupportedGraphs(t *testing.T) {
	for _, fault := range []string{"entry-layer", "server", "auto", "predecessor", "wrong-protocol", "unknown-layer", "unpaired-layer"} {
		t.Run(fault, func(t *testing.T) {
			_, _, launch := desktopExternalPacketEntryLayerExitFixture(t, "always", "strong", "hysteria2", common.StartLayerAES256GCMXOR)
			switch fault {
			case "entry-layer":
				launch.external.entry.StartLayer = common.StartLayerAES256GCM
			case "server", "auto":
				launch.external.selection = fault
			case "predecessor":
				launch.external.predecessor = "captured-other-source"
			case "wrong-protocol":
				launch.external.profile.External.Protocol = "shadowsocks"
			case "unknown-layer":
				launch.external.profile.StartLayer = "xor-only"
			case "unpaired-layer":
				launch.external.profile.External.StartLayer = nil
			}
			if desktopExternalPacketEntryOwner(launch.external) {
				t.Fatal("unsupported layer composition acquired retained entry owner", fault)
			}
		})
	}
}

func TestDesktopExternalPacketEntryWireGuardRetainsBothSourcesAndMeasurementOwner(t *testing.T) {
	for _, variant := range []string{"wireguard", "fast", "strong"} {
		t.Run(variant, func(t *testing.T) { desktopExternalPacketEntryExitRetainsSources(t, variant, "wireguard") })
	}
}
func TestDesktopExternalPacketEntryWireGuardRestoreKeepsCompleteSourceAndNewSession(t *testing.T) {
	for _, variant := range []string{"wireguard", "fast", "strong"} {
		t.Run(variant, func(t *testing.T) { desktopExternalPacketEntryExitRestore(t, variant, "wireguard") })
	}
}

func TestDesktopExternalPacketEntryWireGuardPreservesUnsupportedGraphs(t *testing.T) {
	for _, fault := range []string{"entry-layer", "final-layer", "server", "auto", "predecessor", "openvpn-final", "same-id", "off"} {
		t.Run(fault, func(t *testing.T) {
			_, _, launch := desktopExternalPacketEntryExitFixture(t, "always", "strong", "wireguard")
			switch fault {
			case "entry-layer":
				launch.external.entry.StartLayer = common.StartLayerAES256GCM
			case "final-layer":
				launch.external.profile.StartLayer = common.StartLayerAES256GCM
			case "server", "auto":
				launch.external.selection = fault
			case "predecessor":
				launch.external.predecessor = strings.Repeat("a", 64)
			case "openvpn-final":
				launch.external.profile.External.Protocol = "openvpn"
			case "same-id":
				launch.external.entry.ID = launch.external.profile.ID
			case "off":
				launch.external.profile.KillSwitchPolicy = "off"
			}
			if desktopExternalPacketEntryOwner(launch.external) {
				t.Fatal("packet final expanded an unimplemented ownership boundary", fault)
			}
		})
	}
	// The full captured compiler still enforces the nested packet envelope.
	profile, entry, _ := desktopExternalPacketEntryExitFixture(t, "always", "wireguard", "wireguard")
	profile.ManualMTU = 1376
	exit, err := standardExitFromExternalProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if launch, err := compileDesktopExternalCaptured(context.Background(), profile, entry, exit, false, "", nil, nil, nil); err == nil || launch != nil {
		t.Fatal("oversized final MTU bypassed captured entry capacity")
	}
}

func TestDesktopExternalPacketEntryAmneziaRetainsBothSourcesAndMeasurementOwner(t *testing.T) {
	for _, entry := range []string{"wireguard", "fast", "strong"} {
		for _, final := range []string{"fast", "strong"} {
			t.Run(entry+"/"+final, func(t *testing.T) {
				desktopExternalPacketEntryLayerExitRetainsSources(t, entry, "amneziawg", "", final)
			})
		}
	}
}
func TestDesktopExternalPacketEntryAmneziaRestoreKeepsCompleteSourceAndNewSession(t *testing.T) {
	for _, entry := range []string{"wireguard", "fast", "strong"} {
		for _, final := range []string{"fast", "strong"} {
			t.Run(entry+"/"+final, func(t *testing.T) { desktopExternalPacketEntryLayerExitRestore(t, entry, "amneziawg", "", final) })
		}
	}
}
func TestDesktopExternalPacketEntryAmneziaPreservesUnsupportedGraphs(t *testing.T) {
	t.Run("padding-mtu", desktopExternalPacketEntryAmneziaPreservesExactPaddingMTUBound)
	for _, fault := range []string{"entry-layer", "final-layer", "server", "auto", "predecessor", "openvpn-final", "same-id", "off"} {
		t.Run(fault, func(t *testing.T) {
			_, _, launch := desktopExternalPacketEntryLayerExitFixture(t, "always", "fast", "amneziawg", "", "strong")
			switch fault {
			case "entry-layer":
				launch.external.entry.StartLayer = common.StartLayerAES256GCM
			case "final-layer":
				launch.external.profile.StartLayer = common.StartLayerAES256GCM
			case "server", "auto":
				launch.external.selection = fault
			case "predecessor":
				launch.external.predecessor = strings.Repeat("a", 64)
			case "openvpn-final":
				launch.external.profile.External.Protocol = "openvpn"
			case "same-id":
				launch.external.entry.ID = launch.external.profile.ID
			case "off":
				launch.external.profile.KillSwitchPolicy = "off"
			}
			if desktopExternalPacketEntryOwner(launch.external) {
				t.Fatal("unimplemented graph acquired original packet owner", fault)
			}
		})
	}
}

// A selected fixed inner MTU must fit the captured final transport padding;
// changing variants cannot silently clamp the user's policy.
func desktopExternalPacketEntryAmneziaPreservesExactPaddingMTUBound(t *testing.T) {
	for _, final := range []string{"fast", "strong"} {
		t.Run(final, func(t *testing.T) {
			profile, entry, _ := desktopExternalPacketEntryLayerExitFixture(t, "always", "strong", "amneziawg", "", final)
			limit := 1328
			if final == "fast" {
				limit = 1344
			}
			profile.ManualMTU = limit
			exit, err := standardExitFromExternalProfile(profile)
			if err != nil {
				t.Fatal(err)
			}
			original, err := compileDesktopExternalCaptured(context.Background(), profile, entry, exit, false, "", nil, nil, nil)
			if err != nil || original == nil {
				t.Fatal("exact final padding bound refused", err)
			}
			profile.ManualMTU++
			if next, err := compileDesktopExternalCaptured(context.Background(), profile, entry, exit, false, "", nil, nil, nil); err == nil || next != nil {
				t.Fatal("oversized selected AWG MTU silently changed")
			}
		})
	}
}
