package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func TestDesktopImportedPrefixExecutionSelectionBounds(t *testing.T) {
	for prefixes := 1; prefixes <= common.MultihopMaximumNodes-2; prefixes++ {
		for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
			t.Run(fmt.Sprintf("%d-%s", prefixes, mode), func(t *testing.T) {
				a, nodes := desktopNodeChainCaptureFixture(t, prefixes+2)
				installDesktopOrderedImported(t, a, nodes)
				for i := 0; i < prefixes; i++ {
					nodes[i].Mode = mode
				}
				control, _ := a.profileByIDLocked(a.profiles.SelectedID)
				for _, requested := range []string{"server", "auto"} {
					selection, err := resolveDesktopNodeChainSelection(control, a.profiles.Profiles, nodes, requested)
					if err != nil || desktopOrderedExecutionMembers(selection.Nodes, requested) != nil {
						t.Fatal("eligible original packet prefixes refused", requested, err)
					}
					if !reflect.DeepEqual(nodeChainSelectedReferences(selection.Nodes), nodes) {
						t.Fatal("selection replaced original order")
					}
				}
			})
		}
	}
}

func TestDesktopImportedPrefixExecutionMixedPreparation(t *testing.T) {
	for _, prefixes := range []int{2, 6} {
		for _, target := range []string{"linux", "windows"} {
			for _, requested := range []string{"server", "auto"} {
				t.Run(fmt.Sprintf("%d-%s-%s", prefixes, target, requested), func(t *testing.T) {
					modes := make([]string, prefixes+2)
					for i := 0; i < prefixes; i++ {
						modes[i] = []string{"wg", "awg2-fast", "awg2-strong"}[i%3]
					}
					modes[prefixes], modes[prefixes+1] = "shadowsocks", "shadowsocks"
					a, launch := desktopImportedPrefixExecutionLaunchFixture(t, prefixes+2, target, "2022-blake3-aes-256-gcm", 32, modes...)
					owner, err := newDesktopNodeChainExecutionSource(launch.chain, requested)
					if err != nil {
						t.Fatal(err)
					}
					var source mobilemultihop.NodeChainSource
					if json.Unmarshal([]byte(owner.preparation.LocalSource()), &source) != nil || source.Schema != 2 || len(source.Nodes) != prefixes+2 || len(source.IdentitySources) != prefixes+2 {
						t.Fatal("original source inventory omitted")
					}
					proofs := owner.preparation.ProofInventory()
					if len(proofs) != len(source.Nodes) {
						t.Fatal("proof inventory omitted")
					}
					for i, proof := range proofs {
						if proof.ProfileID != launch.chain.selection.Nodes[i].Profile.ID || proof.Mode != modes[i] || (source.IdentitySources[i] == "") != (i == prefixes) || (proof.NodeKind == "external") != (i == prefixes) || (proof.NodeID == "") != (i == prefixes) {
							t.Fatalf("proof/source position %d changed", i)
						}
					}
					original, err := owner.physical.OriginalDesktopPolicy()
					if err != nil || original != launch.chain.policy || original.OriginalChain() != launch.chain.selection.Native.chain.chain {
						t.Fatal("physical authority replaced", err)
					}
					_, meta, capture, err := owner.readPolicy()
					if err != nil || meta.TargetOS != target || !reflect.DeepEqual(meta.Prefixes, proofs) || capture.SelectedDNS.Detour != mobilemultihop.SelectorTag || capture.SelectedDNS.Physical {
						t.Fatal("desktop proof or DNS source changed", err)
					}
					if err = owner.attach(launch); err != nil || owner.bound(launch) != nil {
						t.Fatal("original owner attachment failed", err)
					}
					// A later paired source is still authoritative; adding an imported suffix
					// cannot turn a changed raw packet asset into the retained original graph.
					position := prefixes - 1
					name := "wg.conf"
					if modes[position] != "wg" {
						name = "awg.conf"
					}
					path := filepath.Join(clientRoot(a), "generated", launch.chain.selection.Nodes[position].Profile.ID, modes[position], name)
					raw, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					if err = os.WriteFile(path, append(raw, '\n'), 0600); err != nil {
						t.Fatal(err)
					}
					if launch.chain.selection.Native.validateNodeChainSelection(launch.chain.selection) == nil {
						t.Fatal("changed later packet source retained authority")
					}
				})
			}
		}
	}
}

// A single literal import moved away from the penultimate slot needs a fresh
// schema-six capture. The original schema-two launch cannot change order.
func captureDesktopReorderedImportedPrefix(t *testing.T, a *app, original multihopSelection, members []desktopNodeChainMember, requested string) (multihopSelection, error) {
	t.Helper()
	reordered := original
	reordered.Nodes = members
	if original.Native.validateNodeChainSelection(reordered) == nil {
		t.Fatal("moved import reused its original penultimate capture", requested)
	}
	selected, err := resolveDesktopNodeChainSelection(original.Control, a.profiles.Profiles, nodeChainSelectedReferences(members), requested)
	if err != nil {
		t.Fatal("valid moved import lost catalog admission", requested, err)
	}
	return captureNativeNodeChainSelection(context.Background(), clientRoot(a), selected, []string{"shadowsocks"}, nil)
}

func TestDesktopImportedPrefixExecutionRecapturesMovedSource(t *testing.T) {
	a, launch := desktopImportedPrefixExecutionLaunchFixture(t, 4, "linux", "2022-blake3-aes-256-gcm", 32)
	original := launch.chain.selection
	members := cloneDesktopNodeChainMembers(original.Nodes)
	members[1], members[2] = members[2], members[1]
	for _, requested := range []string{"server", "auto"} {
		t.Run(requested, func(t *testing.T) {
			fresh, err := captureDesktopReorderedImportedPrefix(t, a, original, members, requested)
			if err != nil {
				t.Fatal("valid moved import lost original-source capture", requested, err)
			}
			launch, err := newDesktopNodeChainLaunch(fresh, strings.Repeat("b", 32), "linux")
			if err != nil {
				t.Fatal(err)
			}
			execution, err := newDesktopNodeChainExecutionSource(launch.chain, requested)
			if err != nil || execution == nil || execution.multiplePhysical == nil || execution.physical != nil {
				t.Fatal("valid moved import lost its typed execution preparation", requested, err)
			}
			policy, chain, metadata, err := execution.multiplePhysical.ReadOriginalSourceValidated(execution.preparation)
			if err != nil || policy != launch.chain.policy || chain != fresh.Native.chain.chain || chain == original.Native.chain.chain || len(metadata.Prefixes) != len(members) {
				t.Fatal("moved import lost its fresh original source", requested, err)
			}
			for i, member := range members {
				proof := metadata.Prefixes[i]
				if proof.ProfileID != member.Profile.ID || proof.Mode != member.Mode || proof.NodeID != member.Profile.NodeProofID || (proof.NodeKind == "external") != (i == 1) {
					t.Fatal("moved import changed proof order or source", requested, i)
				}
			}
		})
	}
}

func TestDesktopImportedPrefixExecutionRejectsChangedShape(t *testing.T) {
	a, launch := desktopImportedPrefixExecutionLaunchFixture(t, 8, "linux", "2022-blake3-aes-256-gcm", 32)
	for _, fault := range []string{"prefix-mode", "two-imports", "wrong-position", "custom-entry", "imported-final", "duplicate-id", "duplicate-proof", "missing-proof", "hostname", "paired-import", "wrong-final", "over-bound", "connect-family", "socks-family"} {
		t.Run(fault, func(t *testing.T) {
			members := cloneDesktopNodeChainMembers(launch.chain.selection.Nodes)
			middle := len(members) - 2
			switch fault {
			case "prefix-mode":
				members[2].Mode = "shadowsocks"
			case "two-imports":
				// This duplicates one imported profile identity, not two independent imports.
				members[2].Profile = common.CloneRouterProfile(members[middle].Profile)
				members[2].Mode = "shadowsocks"
			case "wrong-position":
				members[2], members[middle] = members[middle], members[2]
				for _, requested := range []string{"server", "auto"} {
					_, err := captureDesktopReorderedImportedPrefix(t, a, launch.chain.selection, members, requested)
					if err == nil || err.Error() != "entry MTU cannot carry the dual-stack nested WireGuard packet" {
						t.Fatal("fresh eight-member source lost its actual nested MTU rejection", requested, err)
					}
				}
				return
			case "custom-entry":
				members[0], members[middle] = members[middle], members[0]
			case "imported-final":
				members[len(members)-1], members[middle] = members[middle], members[len(members)-1]
			case "duplicate-id":
				members[2].Profile.ID = members[0].Profile.ID
			case "duplicate-proof":
				members[2].Profile.NodeProofID = members[0].Profile.NodeProofID
			case "missing-proof":
				members[2].Profile.NodeProofID = ""
			case "hostname":
				members[middle].Profile.External.Shadowsocks.Server = "middle.example.test"
				members[middle].Profile.Endpoint = "middle.example.test"
			case "paired-import":
				members[middle].Profile.NodeProofID = members[0].Profile.NodeProofID
			case "wrong-final":
				members[len(members)-1].Mode = "hysteria2"
			case "over-bound":
				members = append(members[:middle], append([]desktopNodeChainMember{members[0]}, members[middle:]...)...)
			case "connect-family":
				members[middle].Mode = "http-connect"
			case "socks-family":
				members[middle].Mode = "socks5"
			}
			for _, requested := range []string{"server", "auto"} {
				if desktopOrderedExecutionMembers(members, requested) == nil {
					t.Fatal("changed imported graph accepted", requested)
				}
			}
		})
	}
	if err := launch.chain.selection.Native.validateNodeChainSelection(launch.chain.selection); err != nil {
		t.Fatal("negative controls mutated original capture", err)
	}
}
