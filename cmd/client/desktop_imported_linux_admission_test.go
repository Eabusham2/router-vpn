//go:build linux

package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func linuxImportedAdmissionFixture(t *testing.T) (*app, multihopSelection) {
	t.Helper()
	_, selected := desktopImportedFixture(t, "wireguard", "shadowsocks")
	selected.Entry.StartLayer, selected.Exit.StartLayer = "off", "off"
	selected.Exit.KillSwitch, selected.Exit.KillSwitchPolicy = true, "always"
	selected.Control = cloneRouterProfile(selected.Exit)
	a := &app{profiles: common.RouterProfileStore{SelectedID: selected.Control.ID,
		Profiles: []common.RouterProfile{cloneRouterProfile(selected.Entry), cloneRouterProfile(selected.Exit)}},
		state: state{DAITA: selected.Control.DAITAEnabled, Jumbo: selected.Control.JumboTUN, Socks: selected.Control.SocksEnabled}}
	return a, selected
}

// The unprivileged public route must reach the real installed-parent boundary.
// Only the mandatory installed TUN fixture supplies a valid native parent and
// proves a successful connection; this test never substitutes an accepting one.
func TestDesktopLinuxImportedPublicCaptureRequiresInstalledParent(t *testing.T) {
	for _, scenario := range []string{"missing-controller", "missing-parent", "foreign-parent"} {
		t.Run(scenario, func(t *testing.T) {
			a, selected := linuxImportedAdmissionFixture(t)
			before := cloneRouterProfileStore(a.profiles)
			wanted := "requires its authenticated installed controller"
			if scenario != "missing-controller" {
				a.localController = &ownedDesktopController{}
				wanted = "has no retained native bootstrap"
			}
			if scenario == "foreign-parent" {
				a.localController.nodeParent = &desktopLinuxNodeParent{controller: &ownedDesktopController{}}
			}
			captured, err := captureNativeMultihopForAppContext(context.Background(), a, selected, []string{selected.ExitMode})
			if err == nil || !strings.Contains(err.Error(), wanted) {
				t.Fatal("public capture did not reach its original installed-parent validation", err)
			}
			if captured.Native != nil || !reflect.DeepEqual(captured, selected) || !reflect.DeepEqual(a.profiles, before) || a.cmd != nil || a.state.Connected {
				t.Fatal("unproved public capture changed the selection, saved sources or connection")
			}
			if _, exists := nativeMultihopOwners.Load(a); exists {
				t.Fatal("unproved public capture published a runtime owner")
			}
		})
	}
}

func TestDesktopLinuxImportedPublicCaptureKeepsBoundedGraph(t *testing.T) {
	for _, fault := range []string{"entry-mode", "final-mode", "entry-layer", "final-layer", "control", "protection", "same-node", "missing-mode", "extra-mode", "wrong-mode"} {
		t.Run(fault, func(t *testing.T) {
			a, selected := linuxImportedAdmissionFixture(t)
			modes := []string{selected.ExitMode}
			switch fault {
			case "entry-mode":
				selected.EntryMode = "amneziawg"
			case "final-mode":
				selected.ExitMode = "hysteria2"
				modes = []string{selected.ExitMode}
			case "entry-layer":
				selected.Entry.StartLayer = "aes-256-gcm"
			case "final-layer":
				selected.Exit.StartLayer = "aes-256-gcm"
				selected.Control = cloneRouterProfile(selected.Exit)
			case "control":
				selected.Control.APIToken += "changed"
			case "protection":
				selected.Exit.KillSwitch, selected.Exit.KillSwitchPolicy = false, "off"
				selected.Control = cloneRouterProfile(selected.Exit)
			case "same-node":
				selected.Entry.ID = selected.Exit.ID
			case "missing-mode":
				modes = nil
			case "extra-mode":
				modes = append(modes, "hysteria2")
			case "wrong-mode":
				modes = []string{"hysteria2"}
			}
			captured, err := captureNativeMultihopForAppContext(context.Background(), a, selected, modes)
			if err == nil || !strings.Contains(err.Error(), "bounded original protected WG-to-SS selection") || captured.Native != nil {
				t.Fatal("unsupported graph escaped the concrete Linux admission boundary", err)
			}
		})
	}
}

func TestDesktopLinuxImportedPublicCaptureHonorsCallerWhileHostLocked(t *testing.T) {
	a, selected := linuxImportedAdmissionFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.mu.Lock()
	locked := true
	defer func() {
		if locked {
			a.mu.Unlock()
		}
	}()
	done := make(chan error, 1)
	go func() {
		_, err := captureNativeMultihopForAppContext(ctx, a, selected, []string{selected.ExitMode})
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("public capture lost its original caller cancellation", err)
		}
	case <-time.After(2 * time.Second):
		a.mu.Unlock()
		locked = false
		<-done
		t.Fatal("cancelled public capture waited for unrelated application ownership")
	}
}

func TestDesktopLinuxImportedPlatformDispatchKeepsOtherOwners(t *testing.T) {
	a, selected := linuxImportedAdmissionFixture(t)
	for _, scenario := range []string{"paired-entry", "explicit-host", "missing-app", "missing-caller"} {
		t.Run(scenario, func(t *testing.T) {
			current := selected
			owner := a
			ctx := context.Background()
			a.nodeConnectionHost = nil
			if scenario == "paired-entry" {
				current.Entry.NodeKind = "router-vpn"
			} else if scenario == "explicit-host" {
				a.nodeConnectionHost = &desktopNodeConnectionHost{}
			} else if scenario == "missing-app" {
				owner = nil
			} else {
				ctx = nil
			}
			captured, handled, err := captureDesktopImportedPlatformContext(ctx, owner, current, []string{current.ExitMode})
			refused := scenario == "missing-app" || scenario == "missing-caller"
			if handled != refused || (err != nil) != refused || !reflect.DeepEqual(captured, current) {
				t.Fatal("Linux dispatch borrowed another host or lost an invalid original caller", handled, err)
			}
		})
	}
}
