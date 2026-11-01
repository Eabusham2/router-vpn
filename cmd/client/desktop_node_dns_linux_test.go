//go:build linux

package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

// These are sealed-source comparisons, not a fabricated native DNS success.
// The complete installed-host case exercises the original session and TUN.
func TestDesktopLinuxNodeDNSCapturedObservation(t *testing.T) {
	for _, scenario := range []string{"original", "different-runtime-options", "disconnected", "phase", "node", "runtime", "observed-runtime", "credential", "dns", "mtu", "ipv6",
		"daita", "jumbo", "socks", "resolver-protocol", "resolver-port", "resolver-name", "source", "missing-source"} {
		t.Run(scenario, func(t *testing.T) {
			host, profile := linuxHostProofFixture(t)
			host.launch.mode = "wg"
			host.revision = desktopOwnedNodeProfileToken(profile)
			host.options = [3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled}
			host.savedOptions = host.options
			observed := observedConnection{Connected: true, Phase: "connected", RouterID: profile.ID, RuntimeMode: "wg", Profile: profile}
			selected, err := expectedDNSSelection(profile)
			if err != nil {
				t.Fatal(err)
			}
			runtimeID := "wg"
			switch scenario {
			case "different-runtime-options":
				host.options[0], host.options[1], host.options[2] = !host.options[0], !host.options[1], !host.options[2]
			case "disconnected":
				observed.Connected = false
			case "phase":
				observed.Phase = "starting"
			case "node":
				observed.RouterID += "-replacement"
			case "runtime":
				runtimeID = "shadowsocks"
			case "observed-runtime":
				observed.RuntimeMode = "shadowsocks"
			case "credential":
				observed.Profile.APIToken += "-replacement"
			case "dns":
				observed.Profile.AdGuardIPv4 = "192.168.50.134"
			case "mtu":
				observed.Profile.ManualMTU++
			case "ipv6":
				observed.Profile.IPv6Mode = "off"
			case "daita":
				observed.Profile.DAITAEnabled = !profile.DAITAEnabled
			case "jumbo":
				observed.Profile.JumboTUN = !profile.JumboTUN
			case "socks":
				observed.Profile.SocksEnabled = !profile.SocksEnabled
			case "resolver-protocol":
				selected.Protocol = "tls"
			case "resolver-port":
				selected.Port++
			case "resolver-name":
				selected.ServerName = "replacement.example"
			case "source":
				host.source = []byte(strings.ReplaceAll(string(host.source), "private-token", "other-token"))
			case "missing-source":
				host.source = nil
			}
			if err := host.matchesDNSObservation(observed, runtimeID, selected); (err == nil) != (scenario == "original" || scenario == "different-runtime-options") {
				t.Fatal("Linux DNS observation accepted another captured node, resolver or policy", scenario, err)
			}
		})
	}
}

// The ordinary resolver path is deliberately valid and returns a successful
// answer. A partial or foreign Linux owner must refuse it, not fall through.
// No fake native receipt is accepted and no native success is asserted here.
func TestDesktopLinuxNodeDNSCannotFallBackFromRetainedOwner(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOMEVPN_ROOT", root)
	profile := common.RouterProfile{ID: "node", DNSMode: "custom", DNSProtocol: "udp", DNSHost: "9.9.9.9", DNSPort: 53, IPv6Mode: "on"}
	observed := observedConnection{Connected: true, Phase: "connected", RouterID: profile.ID, Mode: "shadowsocks", RuntimeMode: "shadowsocks", Profile: profile}
	for _, scenario := range []string{"legacy", "unused-parent", "unproved-empty-session", "missing-gate", "wrong-parent-kind", "foreign-session", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			a := &app{profiles: common.RouterProfileStore{SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}},
				state: state{Connected: true, Phase: "connected", RouterID: profile.ID, Mode: "shadowsocks", RuntimeMode: "shadowsocks"}}
			config := filepath.Join(root, "run", scenario, "sing-box.json")
			writeDNSRuntimeTestConfig(t, config, "custom", profile.DNSHost, profile.DNSPort)
			if err := registerActiveDNSRuntimeConfig(a, profile.ID, "shadowsocks", config); err != nil {
				t.Fatal(err)
			}
			defer activeDNSRuntimeIdentities.Delete(a)
			if scenario != "legacy" {
				p := &desktopLinuxNodeParent{gate: make(chan struct{}, 1)}
				p.gate <- struct{}{}
				a.localController = &ownedDesktopController{nodeParent: p}
				if scenario == "wrong-parent-kind" {
					a.localController.nodeParent = &desktopLinuxNodeSession{}
				} else if scenario == "missing-gate" {
					p.gate = nil
				} else if scenario != "unused-parent" {
					p.session = &desktopLinuxNodeSession{gate: make(chan struct{}, 1), parent: &desktopLinuxNodeParentCapture{}}
					p.session.gate <- struct{}{}
					if scenario != "unproved-empty-session" {
						p.session.active = &desktopLinuxNodeHost{}
					}
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "cancelled" {
				cancel()
			}
			calls := 0
			result := proveSelectedDNSWithLookup(ctx, a, observed, "shadowsocks", func(context.Context, string) ([]string, error) {
				calls++
				return []string{"203.0.113.1"}, nil
			})
			legacy := scenario == "legacy" || scenario == "unused-parent"
			if legacy && (result.Status != "passed" || calls != 1) {
				t.Fatal("an unused retained session stole another active DNS path", result, calls)
			}
			if !legacy && (result.Status != "failed" || calls != 0 || result.LatencyMs != 0) {
				t.Fatal("unproved retained Linux owner fell through to an unrelated resolver", result, calls)
			}
		})
	}
}
