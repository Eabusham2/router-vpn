package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"router-vpn/internal/mobilemultihop"
)

// Use the real saved catalog, member compiler and complete desktop policy.
// No native process, proof, lease or physical readiness is fabricated here.
func desktopImportedExecutionLaunchFixture(t *testing.T, target, method string, keyBytes int) (*app, *desktopNodeLaunch) {
	t.Helper()
	return desktopImportedPrefixExecutionLaunchFixture(t, 3, target, method, keyBytes)
}

func desktopImportedPrefixExecutionLaunchFixture(t *testing.T, count int, target, method string, keyBytes int, modes ...string) (*app, *desktopNodeLaunch) {
	t.Helper()
	a, nodes := desktopNodeChainCaptureFixture(t, count)
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
	launch, err := newDesktopNodeChainLaunch(selection, strings.Repeat("a", 32), target)
	if err != nil {
		t.Fatal(err)
	}
	return a, launch
}

func TestDesktopImportedTrioExecutionOriginalPreparation(t *testing.T) {
	for _, target := range []string{"linux", "windows"} {
		for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
			for _, requested := range []string{"server", "auto"} {
				t.Run(target+"/"+method+"/"+requested, func(t *testing.T) {
					keyBytes := 32
					if method == "2022-blake3-aes-128-gcm" {
						keyBytes = 16
					}
					_, launch := desktopImportedExecutionLaunchFixture(t, target, method, keyBytes)
					owner, err := newDesktopNodeChainExecutionSource(launch.chain, requested)
					if err != nil {
						t.Fatal("original literal imported trio preparation refused", err)
					}
					var source mobilemultihop.NodeChainSource
					if json.Unmarshal([]byte(owner.preparation.LocalSource()), &source) != nil || source.Schema != 2 || len(source.Nodes) != 3 || len(source.IdentitySources) != 3 || source.IdentitySources[1] != "" || source.IdentitySources[0] == "" || source.IdentitySources[2] == "" {
						t.Fatal("preparation replaced original imported identity inventory")
					}
					original, err := owner.physical.OriginalDesktopPolicy()
					if err != nil || original != launch.chain.policy || original.OriginalChain() != launch.chain.selection.Native.chain.chain {
						t.Fatal("preparation replaced original physical policy", err)
					}
					_, meta, capture, err := owner.readPolicy()
					if err != nil || meta.TargetOS != target || meta.Prefixes[1].NodeKind != "external" || meta.Prefixes[1].NodeID != "" || meta.Prefixes[1].Mode != "shadowsocks" || capture.SelectedDNS.Detour != mobilemultihop.SelectorTag || capture.SelectedDNS.Physical {
						t.Fatal("imported preparation changed target/proof or selected DNS", err)
					}
					if err := owner.attach(launch); err != nil {
						t.Fatal(err)
					}
					if owner.preparation.Execution() != requested || launch.chain.execution != owner || owner.bound(launch) != nil {
						t.Fatal("attachment changed original execution owner")
					}
					fresh, err := mobilemultihop.NewDesktopNodeChainExecutionPreparation(original, requested)
					if err != nil {
						t.Fatal(err)
					}
					owner.preparation = fresh
					if owner.validateSource() == nil {
						t.Fatal("equal serialized preparation replaced original physical authority")
					}
				})
			}
		}
	}
}

func TestDesktopImportedTrioExecutionSelectionAndSourceRefusals(t *testing.T) {
	for _, requested := range []string{"server", "auto"} {
		t.Run(requested, func(t *testing.T) {
			a, launch := desktopImportedExecutionLaunchFixture(t, "linux", "2022-blake3-aes-256-gcm", 32)
			original := launch.chain.selection
			selected := nodeChainSelectedReferences(original.Nodes)
			if _, err := resolveDesktopNodeChainSelection(original.Control, a.profiles.Profiles, selected, requested); err != nil {
				t.Fatal("original literal trio lost public selection admission", err)
			}
			for _, fault := range []string{"hostname", "mapped", "noncanonical", "zero", "multicast", "wrong-endpoint", "bad-key", "layer", "paired-id", "duplicate-proof", "duplicate-id", "long", "other-mode", "wrong-final"} {
				t.Run(fault, func(t *testing.T) {
					members := cloneDesktopNodeChainMembers(original.Nodes)
					middle := &members[1].Profile
					switch fault {
					case "hostname":
						middle.External.Shadowsocks.Server, middle.Endpoint = "ss.example.test", "ss.example.test"
					case "mapped":
						middle.External.Shadowsocks.Server, middle.Endpoint = "::ffff:203.0.113.24", "::ffff:203.0.113.24"
					case "noncanonical":
						middle.External.Shadowsocks.Server, middle.Endpoint = "2001:0db8::24", "2001:0db8::24"
					case "zero":
						middle.External.Shadowsocks.Server, middle.Endpoint = "0.0.0.0", "0.0.0.0"
					case "multicast":
						middle.External.Shadowsocks.Server, middle.Endpoint = "224.0.0.1", "224.0.0.1"
					case "wrong-endpoint":
						middle.Endpoint = "203.0.113.199"
					case "bad-key":
						middle.External.Shadowsocks.Password += "\n"
					case "layer":
						middle.StartLayer = "aes"
					case "paired-id":
						middle.NodeProofID = members[0].Profile.NodeProofID
					case "duplicate-proof":
						members[2].Profile.NodeProofID = members[0].Profile.NodeProofID
					case "duplicate-id":
						members[2].Profile.ID = members[0].Profile.ID
					case "long":
						members = append([]desktopNodeChainMember{members[0]}, members...)
					case "other-mode":
						members[1].Mode = "openvpn"
					case "wrong-final":
						members[2].Mode = "hysteria2"
					}
					if desktopOrderedExecutionMembers(members, requested) == nil {
						t.Fatal("imported execution accepted a changed original source", fault)
					}
				})
			}
		})
	}
}
