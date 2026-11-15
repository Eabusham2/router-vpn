package main

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"testing/synctest"

	"router-vpn/internal/common"
)

// Execute shipping capture, source validation, final policy/journal selection
// and restoration. The separate generated Windows WFP gate proves native I/O.
func TestDesktopWindowsOpenVPNEntryRetainsOriginalPair(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			profile, entry, launch := desktopExternalOpenVPNEntryFixture(t, network)
			if !desktopWindowsExternalGraphEligible(profile, entry, false, "") || !desktopWindowsExternalEligible(launch) || !desktopExternalRetainedEntryForOS(launch.external, "windows") {
				t.Fatal("captured Windows ordinary OpenVPN entry lost its retained host")
			}
			if err := prepareDesktopExternalPhysicalCaptured(launch, "windows"); err != nil {
				t.Fatal(err)
			}
			selection, err := desktopProtectionSelectionFor(nil, launch.external.physical)
			if err != nil || selection.profileID != profile.ID || selection.profileID == entry.ID || selection.source != launch.external.physical.Metadata().SourceSHA256 {
				t.Fatal("Windows OpenVPN journal selection lost final policy or original graph", err)
			}
			capture, err := launch.external.physical.Capture()
			if err != nil || capture.SelectedDNS.Physical || capture.SelectedDNS.Detour != "custom-exit" || len(capture.PhysicalRoots) != 1 || capture.PhysicalRoots[0].Tag != "external-entry" || capture.PhysicalRoots[0].Type != "openvpn-client" || len(capture.PhysicalRoots[0].Destinations) != 1 || capture.PhysicalRoots[0].Destinations[0].Network != network {
				t.Fatal("Windows OpenVPN final acquired physical or DNS ownership", err)
			}
			a := &app{profiles: common.RouterProfileStore{Profiles: []common.RouterProfile{profile, entry}}}
			owner := &desktopWindowsExternalRuntime{app: a, launch: launch, entryToken: desktopOwnedNodeProfileToken(entry)}
			if err := owner.sourcesCurrentLocked(profile); err != nil {
				t.Fatal(err)
			}
			if err := validateDesktopWindowsExternalSourceContext(context.Background(), profile, launch); err != nil {
				t.Fatal(err)
			}
			for _, fault := range []string{"entry-config", "entry-credentials", "entry-options", "entry-missing", "entry-mtu", "final-key", "final-id", "dns", "mtu", "execution"} {
				p, e := cloneRouterProfile(profile), cloneRouterProfile(entry)
				switch fault {
				case "entry-config":
					e.External.OpenVPN.Config += "# changed source\n"
				case "entry-credentials":
					e.External.OpenVPN.Password += "changed"
				case "entry-options":
					e.SocksEnabled = !e.SocksEnabled
				case "entry-missing":
					e.ID = "foreign"
				case "entry-mtu":
					e.ManualMTU--
				case "final-key":
					p.External.Shadowsocks.Password = testWGKey('x')
				case "final-id":
					p.ID = "foreign"
				case "dns":
					p.DNSPort++
				case "mtu":
					p.ManualMTU--
				case "execution":
					p.MultihopExecution = "server"
				}
				a.profiles.Profiles = []common.RouterProfile{p, e}
				if owner.sourcesCurrentLocked(p) == nil {
					t.Fatal("Windows OpenVPN retained a replaced source", fault)
				}
				a.profiles.Profiles = []common.RouterProfile{profile, entry}
				if owner.sourcesCurrentLocked(profile) != nil {
					t.Fatal("stale refusal changed retained original")
				}
			}
			originalPhysicalID := launch.profileID
			launch.profileID = profile.ID
			if owner.sourcesCurrentLocked(profile) == nil {
				t.Fatal("final identity replaced the physical OpenVPN entry")
			}
			launch.profileID = originalPhysicalID
			exit, err := standardExitFromExternalProfile(profile)
			if err != nil {
				t.Fatal(err)
			}
			saved := &speedLabExternalRestore{source: append([]byte(nil), launch.external.source...), profile: cloneRouterProfile(launch.external.profile), entry: cloneRouterProfile(launch.external.entry), execution: "local", root: "retained-root", network: "retained-network", mtu: 1360}
			if err := captureSpeedLabExternalRestoreSeal(saved, launch.external); err != nil {
				t.Fatal(err)
			}
			restored, err := compileSpeedLabExternalRestore(saved, exit)
			if err != nil || !desktopWindowsExternalEligible(restored) || restored.external.session == launch.external.session || !reflect.DeepEqual(restored.external.source, launch.external.source) {
				t.Fatal("Windows restore substituted original pair or session", err)
			}
			if err := prepareDesktopExternalPhysicalCaptured(restored, "windows"); err != nil || restored.external.mtu == nil || restored.external.mtu.restoreMTU != 1360 {
				t.Fatal("Windows restore omitted captured policy/MTU", err)
			}
		})
	}
}

func TestDesktopWindowsOpenVPNEntryPublicLifecycle(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for _, policy := range []string{"on-connect", "always"} {
			t.Run(network+"/"+policy, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					f := newDesktopWindowsExternalFixture(t, policy)
					p, e, _ := desktopExternalOpenVPNEntryFixture(t, network)
					p.ID, p.KillSwitchPolicy = "windows-openvpn-final-"+network+"-"+policy, policy
					f.base.a.profiles.Profiles = append(f.base.a.profiles.Profiles, p, e)
					f.base.a.profiles.SelectedID = p.ID
					if err := f.base.a.persistProfilesLocked(); err != nil {
						t.Fatal(err)
					}
					response := windowsSSEntryConnect(f, p, e)
					if response.Code != http.StatusOK {
						t.Fatal("OpenVPN entry public retained connect failed", response.Code, response.Body.String())
					}
					value, found := desktopExternalRetainedLaunches.Load(f.base.a)
					if !found {
						t.Fatal("OpenVPN entry lost original retained registry")
					}
					launch := value.(*desktopNodeLaunch)
					if launch.profileID != e.ID || launch.policyProfileID != p.ID || f.base.a.state.RouterID != p.ID || launch.external.windows.current(true) != nil || launch.external.windows.entryToken != desktopOwnedNodeProfileToken(e) {
						t.Fatal("OpenVPN retained host lost physical/final source ownership")
					}
					proof, err := f.base.a.readDesktopExternalProof(launch)
					if err != nil || !proof.EntryProven || proof.EntryID != e.ID || proof.EntryNodeID != "" || !proof.DNSProven {
						t.Fatal("OpenVPN retained proof lost entry/final identity", err)
					}
					synctest.Wait()
					child := f.children[0]
					child.mu.Lock()
					child.closeErr = errors.New("controlled original OpenVPN child close refusal")
					child.mu.Unlock()
					if err := launch.external.windows.Close(context.Background()); err == nil {
						t.Fatal("OpenVPN entry published unjoined retirement")
					}
					child.mu.Lock()
					child.closeErr = nil
					child.mu.Unlock()
					if err := launch.external.windows.Close(context.Background()); err != nil {
						t.Fatal("OpenVPN exact child retry did not join", err)
					}
					if err := child.Alive(); err == nil {
						t.Fatal("OpenVPN original child survived retirement")
					}
				})
			})
		}
	}
}

func TestDesktopWindowsOpenVPNEntryRejectsUnsupportedCapture(t *testing.T) {
	profile, entry, _ := desktopExternalOpenVPNEntryFixture(t, "tcp")
	for _, fault := range []string{"multiple-remotes", "entry-layer", "final-layer", "server-execution", "same-owner", "unprotected", "non-SS2022-final", "direct-with-entry"} {
		t.Run(fault, func(t *testing.T) {
			p, e := cloneRouterProfile(profile), cloneRouterProfile(entry)
			direct := false
			switch fault {
			case "multiple-remotes":
				e.External.OpenVPN.Config += "\nremote 203.0.113.26 1194 udp\n"
			case "entry-layer":
				e.StartLayer = common.StartLayerAES256GCM
			case "final-layer":
				p.StartLayer = common.StartLayerAES256GCM
			case "server-execution":
				p.MultihopExecution = "server"
			case "same-owner":
				e.ID = p.ID
			case "unprotected":
				p.KillSwitch, p.KillSwitchPolicy = false, "off"
			case "non-SS2022-final":
				p.External.Shadowsocks.Method = "aes-256-gcm"
			case "direct-with-entry":
				direct = true
			}
			if desktopWindowsExternalGraphEligible(p, e, direct, "") {
				t.Fatal("unsupported OpenVPN pair acquired Windows host admission")
			}
		})
	}
}
