package main

import (
	"errors"
	"os/exec"
	"reflect"
	"testing"

	"router-vpn/internal/common"
)

func TestOrderedNodeCannotReachOrdinaryModePreparationOrStop(t *testing.T) {
	p := catalogNodeChainProfile()
	previous := exec.Command("unstarted-original-command")
	a := &app{profiles: common.RouterProfileStore{SelectedID: p.ID, Profiles: []common.RouterProfile{p}},
		cmd: previous, state: state{Connected: true, Phase: "connected", RuntimeMode: "original", RouterID: p.ID}}
	before := a.state
	if err := a.startModeAttempt("not-a-real-mode", false); !errors.Is(err, errOrderedNodeChainDispatch) {
		t.Fatalf("ordinary dispatcher did not reject full ordered selection before mode preparation: %v", err)
	}
	if a.cmd != previous || !reflect.DeepEqual(a.state, before) || previous.Process != nil {
		t.Fatal("ordered rejection stopped or changed the original connection")
	}
}

func TestOrderedNodeCannotBecomeLegacyPairThroughExplicitRequest(t *testing.T) {
	control := catalogNodeChainProfile()
	first := catalogTokenProfile()
	first.ID = "first"
	profiles := []common.RouterProfile{first, control}
	request := multihopConnectRequest{EntryID: first.ID, ExitID: control.ID, EntryMode: "wg", ExitMode: "shadowsocks", Base: "wg", Execution: "local"}
	for name, resolver := range map[string]func(common.RouterProfile, []common.RouterProfile, multihopConnectRequest) (multihopSelection, error){
		"native": resolveNativeMultihopSelection, "legacy": resolveMultihopSelection,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := resolver(control, profiles, request); !errors.Is(err, errOrderedNodeChainDispatch) {
				t.Fatalf("middle node was discarded by explicit pair request: %v", err)
			}
			pair := cloneRouterProfile(control)
			pair.MultihopNodes = nil
			pair.MultihopEntryID, pair.MultihopExitID = first.ID, pair.ID
			if _, err := resolver(pair, []common.RouterProfile{first, pair}, request); err != nil {
				t.Fatalf("existing pair behavior changed: %v", err)
			}
		})
	}
}

func TestOrderedStartupCannotFallbackToDirectLastOrAuto(t *testing.T) {
	for _, mode := range []string{"last", "auto", "smart-auto"} {
		t.Run(mode, func(t *testing.T) {
			p := catalogNodeChainProfile()
			p.AutoConnect, p.StartupMode = true, mode
			a := &app{profiles: common.RouterProfileStore{SelectedID: p.ID, Profiles: []common.RouterProfile{p}}}
			before := cloneRouterProfileStore(a.profiles)
			capture, err := a.captureStartupPolicy()
			if capture != nil || !errors.Is(err, errOrderedNodeChainDispatch) || a.cmd != nil || !reflect.DeepEqual(before, a.profiles) {
				t.Fatalf("ordered startup entered direct strategy fallback: %v", err)
			}
			p.MultihopEnabled = false
			a.profiles.Profiles[0] = p
			capture, err = a.captureStartupPolicy()
			if err != nil || capture == nil {
				t.Fatalf("explicitly disabled saved chain changed ordinary startup: %v", err)
			}
		})
	}
}
