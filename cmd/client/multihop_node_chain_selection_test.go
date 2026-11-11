package main

import (
	"context"
	"fmt"
	"testing"

	"router-vpn/internal/common"
)

func capturedNodeChainSelectionFixture(t *testing.T, count int) (*app, multihopSelection) {
	t.Helper()
	a, nodes := desktopNodeChainCaptureFixture(t, count)
	control, _ := a.profileByIDLocked(a.profiles.SelectedID)
	selection, err := resolveDesktopNodeChainSelection(control, a.profiles.Profiles, nodes, "local")
	if err != nil {
		t.Fatal(err)
	}
	selection, err = captureNativeMultihopSelection(context.Background(), clientRoot(a), selection, []string{"shadowsocks"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return a, selection
}

func TestNativeNodeChainSelectionRetainsAllMembersAndOriginalGraph(t *testing.T) {
	for _, count := range []int{3, 4, 8} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			a, selection := capturedNodeChainSelectionFixture(t, count)
			if len(selection.Nodes) != count || len(nativeMultihopCapturedProfiles(selection)) != count+1 || selection.Native.chain == nil ||
				selection.Control.ID != selection.Nodes[count-1].Profile.ID || selection.Entry.ID != selection.Nodes[0].Profile.ID ||
				selection.Exit.ID != selection.Nodes[count-1].Profile.ID || selection.Native.source != selection.Native.chain.chain.SourceSHA256() {
				t.Fatal("native selection reduced the ordered source to a pair")
			}
			if err := selection.Native.validate(selection); err != nil {
				t.Fatal(err)
			}
			if !nativeMultihopLiveProfilesCurrentContext(context.Background(), a, selection) {
				t.Fatal("exact ordered catalog was rejected")
			}
			setActiveMultihopGraph(a, selection)
			defer clearActiveMultihopGraph(a)
			graph, found := getActiveMultihopGraph(a)
			if !found || graph.ChainNodes != count || graph.SourceSHA != selection.Native.source || graph.ImportedEntry {
				t.Fatal("existing graph owner lost ordered identity")
			}
			altered := graph
			altered.ChainNodes--
			if sameMTUMultihopGraph(graph, altered) {
				t.Fatal("MTU owner adopted another selected prefix count")
			}
			// Capture itself confers no platform authority. Until a concrete
			// chain owner is supplied, the legacy pair compiler cannot add its
			// proof ports or rewrite this sealed TUN after projection.
			if launch, err := compileRetainedNativeMultihopLaunch(selection, nil); err == nil || launch != nil {
				t.Fatal("ordered graph entered legacy pair compilation")
			}
			copy := cloneDesktopNodeChainMembers(selection.Nodes)
			copy[1].Profile.APIToken = "replacement-token"
			if selection.Nodes[1].Profile.APIToken == "replacement-token" {
				t.Fatal("member clone changed original credentials")
			}
		})
	}
}

func TestNativeNodeChainSelectionRejectsMiddleChangesAndTruncation(t *testing.T) {
	for _, fault := range []string{"credential", "mode", "order", "missing", "source", "config", "physical", "pair-cast", "control"} {
		t.Run(fault, func(t *testing.T) {
			_, selected := capturedNodeChainSelectionFixture(t, 3)
			selection := selected
			selection.Nodes = cloneDesktopNodeChainMembers(selected.Nodes)
			switch fault {
			case "credential":
				selection.Nodes[1].Profile.APIToken = "replacement-middle-token"
			case "mode":
				selection.Nodes[1].Mode = "shadowsocks"
			case "order":
				selection.Nodes[0], selection.Nodes[1] = selection.Nodes[1], selection.Nodes[0]
			case "missing":
				selection.Nodes = selection.Nodes[:2]
			case "source":
				selection.Native.source = "replacement-source"
			case "config":
				selection.Native.configs[selection.ExitMode] += "\n"
			case "physical":
				selection.Native.entryPhysical[0].Host = "203.0.113.99"
			case "pair-cast":
				selection.Nodes = nil
			case "control":
				selection.Control = common.CloneRouterProfile(selection.Entry)
			}
			if err := selection.Native.validate(selection); err == nil {
				t.Fatal("altered ordered native capture remained valid")
			}
		})
	}
	a, selected := capturedNodeChainSelectionFixture(t, 3)
	selected.Nodes, selected.Native = nil, nil
	if _, err := captureNativeMultihopSelection(context.Background(), clientRoot(a), selected, []string{"shadowsocks"}, nil); err == nil {
		t.Fatal("fresh legacy capture silently dropped saved middle members")
	}
}

func TestNativeNodeChainRestoreCatalogRequiresEveryCapturedMember(t *testing.T) {
	for _, fault := range []string{"measurement-only", "middle-credential", "middle-resolver", "middle-mtu", "missing-middle", "truncated-capture"} {
		t.Run(fault, func(t *testing.T) {
			a, selection := capturedNodeChainSelectionFixture(t, 3)
			switch fault {
			case "measurement-only":
				a.profiles.Profiles[1].EffectiveMTU++
			case "middle-credential":
				a.profiles.Profiles[1].APIToken = "relinked-middle"
			case "middle-resolver":
				a.profiles.Profiles[1].AdGuardIPv4 = "192.168.50.134"
			case "middle-mtu":
				a.profiles.Profiles[1].MTUPolicy, a.profiles.Profiles[1].ManualMTU = "manual", 1300
			case "missing-middle":
				a.profiles.Profiles = append(a.profiles.Profiles[:1], a.profiles.Profiles[2:]...)
			case "truncated-capture":
				selection.Nodes = nil
			}
			if nativeMultihopLiveProfilesCurrentContext(context.Background(), a, selection) != (fault == "measurement-only") {
				t.Fatal("restore catalog check lost a selected middle policy")
			}
		})
	}
}

func TestNativeNodeChainSelectionRequiresFinalControlAndExplicitLocal(t *testing.T) {
	a, nodes := desktopNodeChainCaptureFixture(t, 3)
	control, _ := a.profileByIDLocked(a.profiles.SelectedID)
	for _, execution := range []string{"", "auto", "server"} {
		if _, err := resolveDesktopNodeChainSelection(control, a.profiles.Profiles, nodes, execution); err == nil {
			t.Fatal("ordered native selection silently chose execution", execution)
		}
	}
	foreign := common.CloneRouterProfile(control)
	foreign.ID = "third-control"
	profiles := append(cloneRouterProfileStore(a.profiles).Profiles, foreign)
	if _, err := resolveDesktopNodeChainSelection(foreign, profiles, nodes, "local"); err == nil {
		t.Fatal("third control borrowed final native authority")
	}
}
