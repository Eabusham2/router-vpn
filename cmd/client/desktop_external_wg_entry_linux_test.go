//go:build linux

package main

import (
	"context"
	"reflect"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"testing"
)

func TestDesktopLinuxWireGuardEntryRetainsBothSavedSources(t *testing.T) {
	for _, kill := range []string{"on-connect", "always"} {
		t.Run(kill, func(t *testing.T) {
			profile, entry, launch := desktopExternalPacketEntryFixture(t, kill, "wireguard")
			if !desktopLinuxExternalEligible(launch) {
				t.Fatal("original WG/SS pair was not admitted")
			}
			if err := prepareDesktopExternalPhysicalCaptured(launch, "linux"); err != nil || launch.external.physical == nil {
				t.Fatal(err)
			}
			a := &app{profiles: common.RouterProfileStore{Profiles: []common.RouterProfile{profile, entry}}}
			h := &desktopLinuxNodeHost{launch: launch, revision: desktopOwnedNodeProfileToken(profile), externalEntryRevision: desktopOwnedNodeProfileToken(entry),
				savedOptions: [3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled}, externalEntryOptions: [3]bool{entry.DAITAEnabled, entry.JumboTUN, entry.SocksEnabled}}
			if err := h.externalSourcesLocked(a); err != nil {
				t.Fatal(err)
			}
			capture, err := launch.external.physical.Capture()
			if err != nil || capture.EntryID != entry.ID || capture.Protocol != "shadowsocks" || len(capture.PhysicalRoots) != 1 || capture.PhysicalRoots[0].Tag != "external-entry" || capture.SelectedDNS.Physical || capture.SelectedDNS.Detour != mobilemultihop.ExternalFinalTag {
				t.Fatal("entry acquired final DNS or physical permission", err, capture)
			}
			for _, fault := range []string{"entry-key", "entry-peer", "entry-psk", "entry-address", "entry-public", "entry-option", "exit-key", "exit-public", "dns", "mtu", "entry-missing", "final-missing"} {
				t.Run(fault, func(t *testing.T) {
					p, e := cloneRouterProfile(profile), cloneRouterProfile(entry)
					switch fault {
					case "entry-key":
						e.External.WireGuard.PrivateKey = testWGKey('y')
					case "entry-peer":
						e.External.WireGuard.PeerPublicKey = testWGKey('z')
					case "entry-psk":
						e.External.WireGuard.PresharedKey = testWGKey('x')
					case "entry-address":
						e.External.WireGuard.Endpoint = "198.51.100.90:8443"
					case "entry-public":
						e.External.ExpectedPublicIP = "198.51.100.21"
					case "entry-option":
						e.DAITAEnabled = !e.DAITAEnabled
					case "exit-key":
						p.External.Shadowsocks.Password = testWGKey('r')
					case "exit-public":
						p.External.ExpectedPublicIP = "198.51.100.22"
					case "dns":
						p.DNSPort++
					case "mtu":
						p.ManualMTU++
					case "entry-missing":
						e.ID = "missing"
					case "final-missing":
						p.ID = "missing"
					}
					a.profiles.Profiles = []common.RouterProfile{p, e}
					if h.externalSourcesLocked(a) == nil {
						t.Fatal("replaced two-source host accepted", fault)
					}
					a.profiles.Profiles = []common.RouterProfile{profile, entry}
					if err := h.externalSourcesLocked(a); err != nil {
						t.Fatal("original source changed", err)
					}
				})
			}
			measure, err := capturedDesktopMeasurementRuntime(launch)
			if err != nil || measure.node != profile.ID {
				t.Fatal("measurement selected physical entry", err)
			}
			resolver, err := capturedDesktopDNSRuntime(launch)
			if err != nil || resolver.node != profile.ID {
				t.Fatal("DNS selected physical entry", err)
			}
			exit, err := standardExitFromExternalProfile(profile)
			if err != nil {
				t.Fatal(err)
			}
			saved := &speedLabExternalRestore{source: append([]byte(nil), launch.external.source...), profile: cloneRouterProfile(launch.external.profile), entry: cloneRouterProfile(launch.external.entry), execution: "local", root: "retained-root", network: "retained-network", mtu: 1360}
			if err := captureSpeedLabExternalRestoreSeal(saved, launch.external); err != nil {
				t.Fatal(err)
			}
			restored, err := compileSpeedLabExternalRestore(saved, exit)
			if err != nil || !desktopLinuxExternalEligible(restored) || restored.external.session == launch.external.session || !reflect.DeepEqual(restored.external.source, launch.external.source) {
				t.Fatal("restore lost complete original pair", err)
			}
			if err := prepareDesktopExternalPhysicalCaptured(restored, "linux"); err != nil || restored.external.physical == nil {
				t.Fatal("restore lost physical entry", err)
			}
			if validateDesktopLinuxExternalSource(profile, restored, entry) != nil || restored.external.mtu == nil || restored.external.mtu.restoreMTU != 1360 {
				t.Fatal("restore replaced selected MTU or private source")
			}
		})
	}
}

func TestDesktopLinuxWireGuardEntryKeepsOtherGraphsClosed(t *testing.T) {
	for _, fault := range []string{"server", "auto", "off", "predecessor", "entry-layer", "final-layer", "final-protocol", "entry-protocol"} {
		t.Run(fault, func(t *testing.T) {
			_, _, launch := desktopExternalPacketEntryFixture(t, "always", "wireguard")
			switch fault {
			case "server", "auto":
				launch.external.selection = fault
			case "off":
				launch.external.profile.KillSwitchPolicy = "off"
			case "predecessor":
				launch.external.predecessor = "another graph"
			case "entry-layer":
				launch.external.entry.StartLayer = common.StartLayerAES256GCM
			case "final-layer":
				launch.external.profile.StartLayer = common.StartLayerAES256GCM
			case "final-protocol":
				launch.external.profile.External.Protocol = "hysteria2"
			case "entry-protocol":
				launch.external.entry.External.Protocol = "amneziawg"
			}
			if desktopLinuxExternalEligible(launch) {
				t.Fatal("expanded unrelated graph", fault)
			}
		})
	}
}

func TestDesktopLinuxWireGuardEntryFinalProfileObservation(t *testing.T) {
	f := newLinuxSpeedLabPathFixture(t)
	profile, entry, launch := desktopExternalPacketEntryFixture(t, "always", "wireguard")
	if err := prepareDesktopExternalPhysicalCaptured(launch, "linux"); err != nil {
		t.Fatal(err)
	}
	launch.command = f.a.cmd
	f.h.external = launch.external.physical
	f.h.externalEntryRevision = desktopOwnedNodeProfileToken(entry)
	f.h.externalEntryOptions = [3]bool{entry.DAITAEnabled, entry.JumboTUN, entry.SocksEnabled}
	f.h.launch = launch
	f.h.revision = desktopOwnedNodeProfileToken(profile)
	f.h.savedOptions = [3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled}
	f.a.profiles = common.RouterProfileStore{SelectedID: profile.ID, Profiles: []common.RouterProfile{cloneRouterProfile(profile), cloneRouterProfile(entry)}}
	f.a.state.RouterID, f.a.state.RuntimeMode = profile.ID, launch.mode
	identity := mtuViewIdentity{Session: "original", Profile: profile.ID}
	if err := desktopLinuxMTUViewAppCurrentLocked(f.a, f.h, identity); err != nil {
		t.Fatal("view used physical entry identity", err)
	}
	identity.Profile = entry.ID
	if desktopLinuxMTUViewAppCurrentLocked(f.a, f.h, identity) == nil {
		t.Fatal("entry borrowed final view identity")
	}
	// This checks the actual shared public preflight comparison; native source
	// admission and the live TUN remain independently mandatory.
	f.a.state.Connected = false
	operation, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.a.connectionContext = operation
	preflight := &desktopLinuxNodeConnectPreflight{app: f.a, host: f.h, controller: f.a.localController, operation: operation, command: f.a.cmd, state: f.a.state, selected: profile.ID}
	if err := preflight.currentAppLocked(); err != nil {
		t.Fatal("public preflight used physical entry", err)
	}
	f.a.profiles.Profiles[1].External.WireGuard.PresharedKey = testWGKey('q')
	if preflight.currentAppLocked() == nil {
		t.Fatal("changed entry import reached public Stop preflight")
	}
	f.a.profiles.Profiles[1] = cloneRouterProfile(entry)
	f.a.profiles.Profiles[0].DNSPort++
	if preflight.currentAppLocked() == nil {
		t.Fatal("changed final policy acquired captured preflight")
	}
}
