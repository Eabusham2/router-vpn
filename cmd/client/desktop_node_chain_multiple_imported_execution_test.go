package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"router-vpn/internal/macosprocess"
	"router-vpn/internal/mobilemultihop"
)

func desktopMultipleImportedExecutionLaunchFixture(t *testing.T, layout desktopIndependentImportedLayout, target, choice string) (*desktopNodeLaunch, *desktopNodeChainExecutionLaunch) {
	t.Helper()
	a, nodes := desktopIndependentImportedFixture(t, layout, "wg", "off")
	selection, err := resolveDesktopNodeChainSelection(a.profiles.Profiles[layout.count-1], a.profiles.Profiles, nodes, choice)
	if err != nil {
		t.Fatal(err)
	}
	captured, err := captureNativeNodeChainSelection(context.Background(), clientRoot(a), selection, []string{"shadowsocks"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	launch, err := newDesktopNodeChainLaunch(captured, strings.Repeat("b", 32), target)
	if err != nil {
		t.Fatal(err)
	}
	execution, err := newDesktopNodeChainExecutionSource(launch.chain, choice)
	if err != nil {
		t.Fatal("multiple imported execution preparation", err)
	}
	return launch, execution
}

func TestDesktopMultipleImportedExecutionOriginalPreparation(t *testing.T) {
	for _, target := range []string{"linux", "windows", "darwin"} {
		for _, index := range []int{0, 1, 2, 4, 5} {
			for _, choice := range []string{"server", "auto"} {
				layout := desktopIndependentImportedLayouts[index]
				t.Run(target+"/"+layout.name+"/"+choice, func(t *testing.T) {
					launch, execution := desktopMultipleImportedExecutionLaunchFixture(t, layout, target, choice)
					if execution.multiplePhysical == nil || execution.physical != nil || execution.connectPhysical != nil || execution.socksPhysical != nil || execution.openvpnPhysical != nil {
						t.Fatal("multiple imported source acquired another physical family")
					}
					original, source, metadata, err := execution.multiplePhysical.ReadOriginalSourceValidated(execution.preparation)
					if err != nil || original != launch.chain.policy || source != launch.chain.selection.Native.chain.chain || metadata.TargetOS != target || len(metadata.Prefixes) != layout.count {
						t.Fatal("execution lost complete original source", err)
					}
					var header struct {
						Schema int `json:"schema"`
					}
					if json.Unmarshal([]byte(execution.preparation.Source()), &header) != nil || header.Schema != 6 {
						t.Fatal("typed child preparation lost schema six")
					}
					if err := execution.attach(launch); err != nil {
						t.Fatal(err)
					}
					if err := validateDesktopNodeChainLaunch(context.Background(), launch); err != nil {
						t.Fatal("attached original preparation", err)
					}
					if target == "darwin" {
						_, physical, _, err := execution.multiplePhysical.PhysicalReadValidated()
						if err != nil {
							t.Fatal(err)
						}
						scope := macosprocess.Scope{Family: macosprocess.NodeChainExecutionFamily, Session: physical.SessionID, Source: physical.SourceSHA256, Config: physical.ConfigSHA256, Workspace: "/original-private-runtime"}
						if _, err := desktopMacOSMultipleImportedExecutionProcessArguments(scope, execution.preparation, execution.multiplePhysical); err != nil {
							t.Fatal(err)
						}
						copy := *execution.multiplePhysical
						if args, err := desktopMacOSMultipleImportedExecutionProcessArguments(scope, execution.preparation, &copy); err == nil || args != nil {
							t.Fatal("copied physical owner authorized child")
						}
					}
				})
			}
		}
	}
}

func TestDesktopMultipleImportedExecutionRefusesReplacedOwner(t *testing.T) {
	for _, fault := range []string{"copied-physical", "foreign-preparation", "mixed-family", "copied-local", "changed-position"} {
		t.Run(fault, func(t *testing.T) {
			launch, execution := desktopMultipleImportedExecutionLaunchFixture(t, desktopIndependentImportedLayouts[2], "windows", "auto")
			if err := execution.attach(launch); err != nil {
				t.Fatal(err)
			}
			changed := *execution
			original := *launch.chain
			changed.original = &original
			original.execution = &changed
			switch fault {
			case "copied-physical":
				copy := *changed.multiplePhysical
				changed.multiplePhysical = &copy
			case "foreign-preparation":
				other, err := mobilemultihop.ParseDesktopNodeChainMultipleImportedExecutionPreparation(changed.preparation.Source())
				if err != nil {
					t.Fatal(err)
				}
				changed.preparation = other
			case "mixed-family":
				changed.physical = &mobilemultihop.DesktopNodeChainExecutionPhysicalPolicy{}
			case "copied-local":
				copy := *original.policy
				original.policy = &copy
			case "changed-position":
				original.selection.Nodes = cloneDesktopNodeChainMembers(original.selection.Nodes)
				original.selection.Nodes[1], original.selection.Nodes[3] = original.selection.Nodes[3], original.selection.Nodes[1]
			}
			if changed.validateSource() == nil {
				t.Fatal("replaced source retained execution authority")
			}
			if execution.validateSource() != nil {
				t.Fatal("negative control damaged original owner")
			}
		})
	}
}
