package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobiletor"
)

func desktopTorOrdinaryFixture(t *testing.T, f *desktopTorConnectFixture, protocol string) common.RouterProfile {
	t.Helper()
	var entry common.RouterProfile
	if protocol == "openvpn" {
		var err error
		entry, err = externalProfileFromCreateRequest(desktopOpenVPNCreateFixture(t, common.StartLayerOff))
		if err != nil {
			t.Fatal(err)
		}
	} else {
		entry, _ = desktopExternalNativeFixture(t, protocol)
	}
	entry.ID, entry.Name = "ordinary-entry", "Captured ordinary provider"
	// The entry's independent default is intentionally not the Tor path's
	// resolver. The runtime must derive that copy without modifying this source.
	entry.DNSMode, entry.DNSProtocol, entry.DNSHost, entry.DNSPort = "home", "udp", "", 53
	entry.DNSServerName, entry.DNSPath = "", ""
	entry.KillSwitch, entry.KillSwitchPolicy = false, "off"
	entry.MTUPolicy, entry.ManualMTU = "auto", 0
	f.a.mu.Lock()
	f.a.profiles.Profiles[1] = cloneRouterProfile(entry)
	p := &f.a.profiles.Profiles[0]
	p.MultihopEnabled, p.MultihopEntryID, p.MultihopExitID, p.MultihopEntryMode = true, entry.ID, p.ID, protocol
	f.a.mu.Unlock()
	return entry
}

func TestDesktopTorOrdinaryPublicConnectUsesCapturedProtocolDNSAndProof(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn"} {
		for _, route := range []string{"tor-saved", "external-explicit"} {
			t.Run(protocol+"/"+route, func(t *testing.T) {
				f := newDesktopTorConnectFixture(t)
				entry := desktopTorOrdinaryFixture(t, f, protocol)
				f.unified = route == "external-explicit"
				profile := &f.a.profiles.Profiles[0]
				q := externalProfileConnectRequest{ProfileID: profile.ID, Base: "auto", ExpectedSelectedNodeID: &f.a.profiles.SelectedID}
				if f.unified {
					profile.MultihopEnabled = false
					profile.MultihopEntryID, profile.MultihopExitID, profile.MultihopEntryMode = "", "", ""
					q.EntryID, q.EntryMode, q.Execution = entry.ID, protocol, "local"
				}
				original := cloneRouterProfile(*profile)
				q.ExpectedProfileTokens = map[string]string{profile.ID: publicProfileToken(original), entry.ID: publicProfileToken(entry)}
				response := f.request(t, q)
				if response.Code != http.StatusOK {
					t.Fatal(response.Code, response.Body.String())
				}
				owner := f.launch.tor
				if owner.predecessor == nil || !owner.predecessor.native.IsExternal() || owner.predecessor.native.IsRouter() || owner.predecessor.native.Proof() != nil ||
					owner.expected.EntryID != entry.ID || owner.expected.EntryMode != protocol || owner.expected.EntryProofKind != mobiletor.ExternalPredecessorProofKind ||
					owner.predecessor.profileToken != desktopTorSourceIdentityToken(entry) || !reflect.DeepEqual(f.a.profiles.Profiles[1], entry) {
					t.Fatal("ordinary entry acquired Router identity or changed its saved credentials")
				}
				var runtimeEntry common.RouterProfile
				if json.Unmarshal([]byte(owner.predecessor.native.Profile()), &runtimeEntry) != nil || runtimeEntry.DNSMode != original.DNSMode || runtimeEntry.DNSProtocol != original.DNSProtocol || runtimeEntry.DNSHost != original.DNSHost || runtimeEntry.DNSPort != original.DNSPort ||
					owner.expected.DNS.Address != original.DNSHost || owner.expected.DNS.Port != original.DNSPort || owner.expected.DNSDetour != mobiletor.ProfileOutboundTag || runtimeEntry.MultihopEnabled {
					t.Fatal("ordinary entry or Tor DNS did not retain the active selected resolver")
				}
				proof, err := f.a.readDesktopTorProof(f.launch)
				if err != nil || proof.EntryProof == nil || proof.EntryProof.EntryKind != mobiletor.ExternalPredecessorProofKind || proof.EntryProof.EntrySHA256 != owner.predecessor.native.Fingerprint() {
					t.Fatal("public Connect did not require the exact ordinary proof receipt", err)
				}
				if !f.a.state.Connected || f.a.profiles.Profiles[0].MultihopEntryMode != protocol || !strings.Contains(response.Body.String(), `"choice_saved":true`) {
					t.Fatal("proved ordinary path was not retained as the saved choice")
				}
				observed := observedConnection{Connected: true, Phase: "connected", Mode: "external-node", RuntimeMode: f.launch.mode, RouterID: original.ID, Profile: f.a.profiles.Profiles[0]}
				dns := proveSelectedDNSWithLookup(context.Background(), f.a, observed, f.launch.mode, func(context.Context, string) ([]string, error) {
					t.Fatal("ordinary Tor path escaped to the host resolver")
					return nil, nil
				})
				if dns.Status != "passed" {
					t.Fatal("Tor selected DNS receipt lost its external predecessor", dns)
				}
				if err := f.a.stopModeWithIntent(true); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestDesktopTorOrdinaryPublicPreflightRejectsChangedSourceBeforeStop(t *testing.T) {
	for _, fault := range []string{"selected", "entry-secret", "entry-public-token", "tor-secret", "home", "strict", "conflicting-base", "conflicting-mode", "server", "compare"} {
		t.Run(fault, func(t *testing.T) {
			f := speedLabTorPipelineFixture(t)
			entry := desktopTorOrdinaryFixture(t, f, "shadowsocks")
			previous := connectSpeedLabTorPrior(t, f, true)
			originalDNS, _ := activeDNSRuntimeIdentities.Load(f.a)
			f.a.mu.Lock()
			candidate := cloneRouterProfile(f.a.profiles.Profiles[0])
			candidate.ID = "candidate-tor"
			f.a.profiles.Profiles = append(f.a.profiles.Profiles, candidate)
			selected := f.a.profiles.SelectedID
			q := externalProfileConnectRequest{ProfileID: candidate.ID, EntryID: entry.ID, EntryMode: "shadowsocks", Base: "auto", ExpectedSelectedNodeID: &selected}
			q.ExpectedProfileTokens = map[string]string{previous.profileID: publicProfileToken(f.a.profiles.Profiles[0]), candidate.ID: publicProfileToken(candidate), entry.ID: publicProfileToken(entry)}
			switch fault {
			case "home":
				f.a.profiles.Profiles[2].DNSMode = "home"
			case "strict":
				f.a.profiles.Profiles[2].KillSwitchPolicy = "always"
			case "conflicting-base":
				q.Base = "wg"
			case "conflicting-mode":
				q.EntryMode = "hysteria2"
			case "server", "compare":
				q.Execution = fault
			case "entry-public-token":
				q.ExpectedProfileTokens[entry.ID] = strings.Repeat("f", 64)
			}
			if fault == "home" || fault == "strict" {
				q.ExpectedProfileTokens[candidate.ID] = publicProfileToken(f.a.profiles.Profiles[2])
			}
			f.a.mu.Unlock()
			preflight := f.driver.preflight
			f.driver.preflight = func(ctx context.Context, binary string, args, environment []string, directory string) error {
				if err := preflight(ctx, binary, args, environment, directory); err != nil {
					return err
				}
				if f.preflight != 2 {
					return nil
				}
				f.a.mu.Lock()
				defer f.a.mu.Unlock()
				switch fault {
				case "selected":
					f.a.profiles.SelectedID = entry.ID
				case "entry-secret":
					f.a.profiles.Profiles[1].External.Shadowsocks.Password = testWGKey('z')
				case "tor-secret":
					f.a.profiles.Profiles[2].External.TorBridge.Bridges[0] = strings.Replace(f.a.profiles.Profiles[2].External.TorBridge.Bridges[0], ":443", ":444", 1)
				}
				return nil
			}
			response := f.request(t, q)
			if response.Code == http.StatusOK || f.a.cmd != previous.command || desktopNodeProcessExited(previous) {
				t.Fatal("failed ordinary preparation replaced the prior runtime", fault, response.Code, response.Body.String())
			}
			if dns, _ := activeDNSRuntimeIdentities.Load(f.a); dns != originalDNS {
				t.Fatal("failed ordinary preparation replaced the prior DNS owner")
			}
			if f.launch != previous {
				if f.launch.command != nil && f.launch.command.Process != nil {
					t.Fatal("retired ordinary candidate started")
				}
				if _, err := os.Lstat(f.launch.directory); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("failed ordinary candidate retained private inputs", err)
				}
			}
		})
	}
}

func TestDesktopTorOrdinaryEndpointBootstrapCapturesOnceBeforeNativeLaunch(t *testing.T) {
	f := newDesktopTorConnectFixture(t)
	entry := desktopTorOrdinaryFixture(t, f, "shadowsocks")
	entry.Endpoint, entry.External.Shadowsocks.Server = "entry.example.test", "entry.example.test"
	f.a.profiles.Profiles[1] = cloneRouterProfile(entry)
	lookups := 0
	f.driver.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		lookups++
		if ctx.Err() != nil || host != entry.Endpoint || f.preflight != 0 || f.commands != 0 {
			t.Fatal("unowned endpoint lookup or lookup after native admission")
		}
		return []netip.Addr{netip.MustParseAddr("198.51.100.40")}, nil
	}
	response := f.request(t, externalProfileConnectRequest{ProfileID: f.a.profiles.SelectedID, Base: "auto"})
	if response.Code != http.StatusOK || lookups != 1 || f.launch.tor.predecessor.endpoint != "198.51.100.40" ||
		f.launch.tor.predecessor.entry.Endpoint != entry.Endpoint || !reflect.DeepEqual(entry, f.a.profiles.Profiles[1]) {
		t.Fatal("public host path did not freeze the ordinary endpoint separately from the saved source", response.Code, response.Body.String())
	}
	if err := f.a.stopModeWithIntent(true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(f.launch.directory, "tor-profile.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("completed owned entry retained a stale runtime input", err)
	}
}
