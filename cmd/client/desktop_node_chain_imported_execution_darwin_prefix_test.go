package main

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func desktopDarwinImportedPrefixFixture(t *testing.T, method string, keyBytes, prefixes int, modes ...string) (*app, *desktopNodeLaunch) {
	t.Helper()
	a, nodes := desktopNodeChainCaptureFixture(t, prefixes+2)
	if len(modes) != 0 {
		installOrderedAWGAssets(t, a, nodes, modes, "off")
	}
	installDesktopOrderedImportedCipher(t, a, nodes, method, keyBytes)
	for i := range a.profiles.Profiles {
		a.profiles.Profiles[i].KillSwitch, a.profiles.Profiles[i].KillSwitchPolicy = true, "on-connect"
	}
	control, _ := a.profileByIDLocked(a.profiles.SelectedID)
	selection, err := resolveDesktopNodeChainSelection(control, a.profiles.Profiles, nodes, "local")
	if err != nil {
		t.Fatal(err)
	}
	selection, err = captureNativeMultihopSelection(context.Background(), clientRoot(a), selection, []string{"shadowsocks"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	launch, err := newDesktopNodeChainLaunch(selection, strings.Repeat("a", 32), "darwin")
	if err != nil {
		t.Fatal(err)
	}
	return a, launch
}

// Exercise the shipping Darwin admission and the actual complete source
// compiler. This is not an installed PF/utun or physical-network fixture.
func TestDesktopDarwinImportedPrefixExecutionAdmission(t *testing.T) {
	modes := []string{"wg", "awg2-fast", "awg2-strong"}
	methods := []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"}
	for prefixes := 2; prefixes <= common.MultihopMaximumNodes-2; prefixes++ {
		for variant, mode := range modes {
			t.Run(fmt.Sprintf("%d-%s", prefixes, mode), func(t *testing.T) {
				selected := make([]string, prefixes+2)
				for i := 0; i < prefixes; i++ {
					selected[i] = mode
				}
				selected[prefixes], selected[prefixes+1] = "shadowsocks", "shadowsocks"
				method := methods[(prefixes+variant)%len(methods)]
				keyBytes := 32
				if method == methods[0] {
					keyBytes = 16
				}
				_, launch := desktopDarwinImportedPrefixFixture(t, method, keyBytes, prefixes, selected...)
				for _, requested := range []string{"server", "auto"} {
					if !desktopDarwinImportedTrioExecutionMembers(launch.chain.selection.Nodes, requested) {
						t.Fatal("original complete Darwin imported prefixes lost admission", requested)
					}
					owner, err := newDesktopNodeChainExecutionSource(launch.chain, requested)
					if err != nil {
						t.Fatal("complete Darwin execution source preparation failed", err)
					}
					var source mobilemultihop.NodeChainSource
					if json.Unmarshal([]byte(owner.preparation.LocalSource()), &source) != nil || source.Schema != 2 || len(source.Nodes) != prefixes+2 || len(source.IdentitySources) != prefixes+2 {
						t.Fatal("Darwin preparation omitted an original member")
					}
					_, meta, capture, err := owner.readPolicy()
					proofs := owner.preparation.ProofInventory()
					if err != nil || meta.TargetOS != "darwin" || len(meta.Prefixes) != prefixes+2 || !reflect.DeepEqual(meta.Prefixes, proofs) || capture.SelectedDNS.Physical || capture.SelectedDNS.Detour != mobilemultihop.SelectorTag || owner.preparation.Execution() != requested {
						t.Fatal("Darwin preparation replaced the selected path or DNS policy", err)
					}
					for i, proof := range proofs {
						if proof.ProfileID != launch.chain.selection.Nodes[i].Profile.ID || proof.Mode != selected[i] || (proof.NodeKind == "external") != (i == prefixes) || (proof.NodeID == "") != (i == prefixes) || (source.IdentitySources[i] == "") != (i == prefixes) {
							t.Fatal("Darwin preparation changed an original source position", i)
						}
					}
					original, err := owner.physical.OriginalDesktopPolicy()
					if err != nil || original != launch.chain.policy || original.OriginalChain() != launch.chain.selection.Native.chain.chain {
						t.Fatal("Darwin preparation substituted the original physical authority", err)
					}
				}
			})
		}
	}
}

func TestDesktopDarwinImportedPrefixExecutionCompleteLayers(t *testing.T) {
	for _, prefixes := range []int{2, 6} {
		t.Run(fmt.Sprint(prefixes), func(t *testing.T) {
			modes := make([]string, prefixes+2)
			for i := 0; i < prefixes; i++ {
				modes[i] = []string{"wg", "awg2-fast", "awg2-strong"}[i%3]
			}
			modes[prefixes], modes[prefixes+1] = "shadowsocks", "shadowsocks"
			_, launch := desktopDarwinImportedPrefixFixture(t, "2022-blake3-aes-256-gcm", 32, prefixes, modes...)
			members := cloneDesktopNodeChainMembers(launch.chain.selection.Nodes)
			for i := range members {
				if i != prefixes {
					members[i].Profile.StartLayer = []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"}[i%3]
				}
			}
			for _, requested := range []string{"server", "auto"} {
				if !desktopDarwinImportedTrioExecutionMembers(members, requested) {
					t.Fatal("Darwin admission refused independent complete paired Start Layers", requested)
				}
			}
			for i := range members {
				if i == prefixes {
					continue
				}
				for _, layer := range []string{"aes-256-gcm ", "AES-256-GCM+XOR-WHITENING", "unknown"} {
					changed := cloneDesktopNodeChainMembers(members)
					changed[i].Profile.StartLayer = layer
					if desktopDarwinImportedTrioExecutionMembers(changed, "server") || desktopDarwinImportedTrioExecutionMembers(changed, "auto") {
						t.Fatal("Darwin admission ignored a later paired Start Layer", i, layer)
					}
				}
			}
		})
	}
}

func TestDesktopDarwinImportedPrefixExecutionBoundedSource(t *testing.T) {
	_, launch := desktopDarwinImportedPrefixFixture(t, "2022-blake3-aes-256-gcm", 32, 6)
	original := launch.chain.selection.Nodes
	if !desktopDarwinImportedTrioExecutionMembers(original, "server") {
		t.Fatal("complete Darwin source fixture did not qualify")
	}
	for _, fault := range []string{"empty", "two", "nine", "paired-only", "second-import", "wrong-position", "later-mode", "later-id", "later-proof", "missing-proof", "middle-layer", "hostname", "endpoint", "credential", "final"} {
		t.Run(fault, func(t *testing.T) {
			members := cloneDesktopNodeChainMembers(original)
			switch fault {
			case "empty":
				members = nil
			case "two":
				members = members[:2]
			case "nine":
				members = append(members[:6], append([]desktopNodeChainMember{members[0]}, members[6:]...)...)
			case "paired-only":
				members[6].Profile = cloneRouterProfile(members[5].Profile)
			case "second-import":
				members[2].Profile, members[2].Mode = cloneRouterProfile(members[6].Profile), "shadowsocks"
			case "wrong-position":
				members[2], members[6] = members[6], members[2]
			case "later-mode":
				members[4].Mode = "hysteria2"
			case "later-id":
				members[4].Profile.ID = members[0].Profile.ID
			case "later-proof":
				members[4].Profile.NodeProofID = members[0].Profile.NodeProofID
			case "missing-proof":
				members[4].Profile.NodeProofID = ""
			case "middle-layer":
				members[6].Profile.StartLayer = "aes-256-gcm"
			case "hostname":
				members[6].Profile.External.Shadowsocks.Server, members[6].Profile.Endpoint = "middle.example.test", "middle.example.test"
			case "endpoint":
				members[6].Profile.Endpoint = "203.0.113.199"
			case "credential":
				members[6].Profile.External.Shadowsocks.Password += "\n"
			case "final":
				members[7].Mode = "hysteria2"
			}
			for _, requested := range []string{"server", "auto"} {
				if desktopDarwinImportedTrioExecutionMembers(members, requested) {
					t.Fatal("Darwin admission accepted a changed complete source", fault, requested)
				}
			}
		})
	}
	for _, requested := range []string{"local", "", "compare"} {
		if desktopDarwinImportedTrioExecutionMembers(original, requested) {
			t.Fatal("Darwin imported execution accepted an unrelated choice", requested)
		}
	}
	if launch.chain.selection.Native.validateNodeChainSelection(launch.chain.selection) != nil {
		t.Fatal("Darwin negative controls mutated the original captured source")
	}
}
