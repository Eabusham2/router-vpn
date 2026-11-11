//go:build linux

package main

import (
	"context"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func TestDesktopLinuxImportedCaptureSealAndArguments(t *testing.T) {
	_, selected := desktopImportedFixture(t, "wireguard", "shadowsocks")
	selected.Exit.KillSwitch, selected.Exit.KillSwitchPolicy = true, "always"
	selected.Control = cloneRouterProfile(selected.Exit)
	a := &app{profiles: common.RouterProfileStore{SelectedID: selected.Control.ID, Profiles: []common.RouterProfile{selected.Entry, selected.Exit}},
		state: state{DAITA: selected.Control.DAITAEnabled, Jumbo: selected.Control.JumboTUN, Socks: selected.Control.SocksEnabled}}
	source, err := captureDesktopLinuxImportedSourcesLocked(context.Background(), a, selected)
	if err != nil {
		t.Fatal(err)
	}
	capture := &desktopLinuxImportedCapture{parent: &desktopLinuxNodeParentCapture{}, sources: source, network: "original-network"}
	capture.seal = capture.sourceDigest()
	if capture.Seal() == "" {
		t.Fatal("original capture has no seal")
	}
	source.original[selected.Entry.ID] = strings.Repeat("0", 64)
	if capture.Seal() != "" {
		t.Fatal("changed independent source retained its original seal")
	}
	directory, args := desktopNodeProcessArgumentsFixture(t)
	args[0] = "routervpn-imported"
	if _, err := validateDesktopLinuxProtectedArguments(args, directory); err != nil {
		t.Fatal(err)
	}
	changed := append(append([]string(nil), args...), "--linux-parent-channel", "9")
	if _, err := validateDesktopLinuxProtectedArguments(changed, directory); err == nil {
		t.Fatal("caller-controlled inherited channel admitted")
	}
}

func TestDesktopLinuxImportedSourceEligibility(t *testing.T) {
	_, selected := desktopImportedFixture(t, "wireguard", "shadowsocks")
	selected.Entry.StartLayer, selected.Exit.StartLayer = "off", "off"
	selected.Exit.KillSwitch, selected.Exit.KillSwitchPolicy = true, "always"
	selected.Control = cloneRouterProfile(selected.Exit)
	if !desktopLinuxImportedEligible(selected) {
		t.Fatal("sealed Linux graph was rejected")
	}
	for name, mutate := range map[string]func(*multihopSelection){
		"entry-mode":  func(s *multihopSelection) { s.EntryMode = "socks5" },
		"final-mode":  func(s *multihopSelection) { s.ExitMode = "hysteria2" },
		"entry-layer": func(s *multihopSelection) { s.Entry.StartLayer = "aes-256-gcm" },
		"final-layer": func(s *multihopSelection) { s.Exit.StartLayer = "aes-256-gcm" },
		"control":     func(s *multihopSelection) { s.Control.APIToken += "changed" },
		"protection":  func(s *multihopSelection) { s.Control.KillSwitchPolicy, s.Exit.KillSwitchPolicy = "off", "off" },
		"same-node":   func(s *multihopSelection) { s.Entry.ID = s.Exit.ID },
	} {
		t.Run(name, func(t *testing.T) {
			s := selected
			mutate(&s)
			if desktopLinuxImportedEligible(s) {
				t.Fatal("changed graph admitted")
			}
		})
	}
}

func TestDesktopLinuxImportedSourcesRequireIndependentRevisions(t *testing.T) {
	_, selected := desktopImportedFixture(t, "wireguard", "shadowsocks")
	selected.Entry.StartLayer, selected.Exit.StartLayer = "off", "off"
	selected.Exit.KillSwitch, selected.Exit.KillSwitchPolicy = true, "always"
	selected.Control = cloneRouterProfile(selected.Exit)
	for _, id := range []string{selected.Entry.ID, selected.Exit.ID} {
		t.Run(id, func(t *testing.T) {
			a := &app{profiles: common.RouterProfileStore{SelectedID: selected.Control.ID, Profiles: []common.RouterProfile{cloneRouterProfile(selected.Entry), cloneRouterProfile(selected.Exit)}},
				state: state{DAITA: selected.Control.DAITAEnabled, Jumbo: selected.Control.JumboTUN, Socks: selected.Control.SocksEnabled}}
			source, err := captureDesktopLinuxImportedSourcesLocked(context.Background(), a, selected)
			if err != nil {
				t.Fatal(err)
			}
			for i := range a.profiles.Profiles {
				if a.profiles.Profiles[i].ID == id {
					a.profiles.Profiles[i].Endpoint = "192.0.2.250"
				}
			}
			if source.currentLocked(a, false) == nil || source.currentLocked(a, true) == nil {
				t.Fatal("same-ID replacement admitted")
			}
		})
	}
}

func TestDesktopLinuxImportedTemporarySourcesRequireAppliedProjectionAndOwner(t *testing.T) {
	for _, scenario := range []string{"complete", "original-restored", "projection-changed", "entry-changed", "owner-replaced", "runtime-options", "cancelled", "cancel-intent"} {
		t.Run(scenario, func(t *testing.T) {
			f := newSpeedLabImportedFixture(t, "wireguard")
			f.q.ExitMode = "shadowsocks"
			for i := range f.a.profiles.Profiles {
				if f.a.profiles.Profiles[i].ID == f.q.ExitID {
					f.a.profiles.Profiles[i].KillSwitch, f.a.profiles.Profiles[i].KillSwitchPolicy = true, "always"
				}
			}
			f.original = cloneRouterProfileStore(f.a.profiles)
			prepared, err := f.a.prepareSpeedLabImportedMultihopWithRuntime(f.caller, f.q, f.driver)
			if err != nil {
				t.Fatal(err)
			}
			defer prepared.releaseUnused()
			selected := prepared.selection
			// The fixture's existing entry/final are Off; the selected source is
			// distinct from the saved original's Server/WG projection.
			ctx := context.WithValue(f.caller, desktopImportedPreparationContextKey{}, prepared)
			source, err := captureDesktopLinuxImportedSourcesLocked(ctx, f.a, selected)
			if err != nil {
				t.Fatal(err)
			}
			if source.currentLocked(f.a, true) == nil {
				t.Fatal("unapplied temporary graph admitted")
			}
			f.suspend(t)
			if _, err := prepared.apply(f.caller, f.a, f.q); err != nil {
				t.Fatal(err)
			}
			if err := source.currentLocked(f.a, true); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "original-restored":
				f.a.profiles = cloneRouterProfileStore(f.original)
			case "projection-changed":
				for i := range f.a.profiles.Profiles {
					if f.a.profiles.Profiles[i].ID == selected.Exit.ID {
						f.a.profiles.Profiles[i].DNSHost = "192.0.2.99"
					}
				}
			case "entry-changed":
				for i := range f.a.profiles.Profiles {
					if f.a.profiles.Profiles[i].ID == selected.Entry.ID {
						f.a.profiles.Profiles[i].Endpoint = "192.0.2.99"
					}
				}
			case "owner-replaced":
				replacement := *f.owner
				speedLabTemporaryOwners.Store(f.a, &replacement)
			case "runtime-options":
				f.a.state.Socks = !f.a.state.Socks
			case "cancelled":
				f.cancel()
			case "cancel-intent":
				f.a.connectionCancelIntent = prepared.operation
			}
			if err := source.currentLocked(f.a, true); (err == nil) != (scenario == "complete") {
				t.Fatalf("scenario %s: %v", scenario, err)
			}
		})
	}
}
