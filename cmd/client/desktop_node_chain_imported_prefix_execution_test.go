package main

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"router-vpn/internal/mobilemultihop"
)

func TestDesktopImportedPrefixExecutionOriginalPreparation(t *testing.T) {
	for _, target := range []string{"linux", "windows"} {
		for _, count := range []int{4, 8} {
			for _, requested := range []string{"server", "auto"} {
				t.Run(fmt.Sprintf("%s/%d/%s", target, count, requested), func(t *testing.T) {
					a, launch := desktopImportedPrefixExecutionLaunchFixture(t, count, target, "2022-blake3-aes-256-gcm", 32)
					selected := launch.chain.selection
					if _, err := resolveDesktopNodeChainSelection(selected.Control, a.profiles.Profiles, nodeChainSelectedReferences(selected.Nodes), requested); err != nil {
						t.Fatal("complete imported execution source refused", err)
					}
					owner, err := newDesktopNodeChainExecutionSource(launch.chain, requested)
					if err != nil {
						t.Fatal(err)
					}
					var source mobilemultihop.NodeChainSource
					if json.Unmarshal([]byte(owner.preparation.LocalSource()), &source) != nil || source.Schema != 2 || len(source.Nodes) != count || source.IdentitySources[count-2] != "" {
						t.Fatal("complete imported execution identity inventory changed")
					}
					for i, id := range source.IdentitySources {
						if (id == "") != (i == count-2) {
							t.Fatal("private prefix identity lost", i)
						}
					}
					original, err := owner.physical.OriginalDesktopPolicy()
					if err != nil || original != launch.chain.policy || original.OriginalChain() != selected.Native.chain.chain {
						t.Fatal("complete imported source replaced physical owner", err)
					}
					_, meta, capture, err := owner.readPolicy()
					if err != nil || len(meta.Prefixes) != count || meta.Prefixes[count-2].NodeKind != "external" || meta.Prefixes[count-2].NodeID != "" || capture.SelectedDNS.Detour != mobilemultihop.SelectorTag || capture.SelectedDNS.Physical {
						t.Fatal("complete prefix proof or DNS changed", err)
					}
					if err := owner.attach(launch); err != nil {
						t.Fatal(err)
					}
					fresh, err := mobilemultihop.NewDesktopNodeChainExecutionPreparation(original, requested)
					if err != nil {
						t.Fatal(err)
					}
					owner.preparation = fresh
					if owner.validateSource() == nil {
						t.Fatal("equal source replaced original prefix preparation")
					}
					if !desktopDarwinImportedTrioExecutionMembers(selected.Nodes, requested) {
						t.Fatal("complete imported source lost Darwin shape admission")
					}
				})
			}
		}
	}
}

func TestDesktopImportedPrefixExecutionSourceRefusals(t *testing.T) {
	a, launch := desktopImportedPrefixExecutionLaunchFixture(t, 8, "windows", "2022-blake3-aes-256-gcm", 32)
	_ = a
	for _, fault := range []string{"old-middle", "second-import", "middle-key", "hostname", "prefix-mode", "prefix-proof", "prefix-id", "final-mode", "too-many", "connect-long"} {
		t.Run(fault, func(t *testing.T) {
			members := cloneDesktopNodeChainMembers(launch.chain.selection.Nodes)
			switch fault {
			case "old-middle":
				members[1], members[6] = members[6], members[1]
			case "second-import":
				members[1] = members[6]
				members[1].Profile.ID = "extra-import"
			case "middle-key":
				members[6].Profile.External.Shadowsocks.Password += "\n"
			case "hostname":
				members[6].Profile.Endpoint = "ss.example.test"
				members[6].Profile.External.Shadowsocks.Server = "ss.example.test"
			case "prefix-mode":
				members[3].Mode = "hysteria2"
			case "prefix-proof":
				members[3].Profile.NodeProofID = members[0].Profile.NodeProofID
			case "prefix-id":
				members[3].Profile.ID = members[0].Profile.ID
			case "final-mode":
				members[7].Mode = "hysteria2"
			case "too-many":
				members = append([]desktopNodeChainMember{members[0]}, members...)
			case "connect-long":
				members[6].Mode = "http-connect"
			}
			for _, requested := range []string{"server", "auto"} {
				if fault == "old-middle" || fault == "second-import" {
					// These layouts now require the distinct schema-six family.
					// They must still be refused by the original singleton hint.
					if desktopDarwinImportedTrioExecutionMembers(members, requested) {
						t.Fatal("singleton hint admitted the multiple imported family", fault)
					}
					continue
				}
				if desktopOrderedExecutionMembers(members, requested) == nil {
					t.Fatal("complete imported execution accepted changed source", fault)
				}
			}
		})
	}
}

func TestDesktopImportedPrefixExecutionRefusesForeignNativeMiddle(t *testing.T) {
	for _, fault := range []string{"omitted", "foreign"} {
		t.Run(fault, func(t *testing.T) {
			f, s := prepareDesktopImportedPrefixExecutionModel(t, 4, "auto", "server")
			replacement := ""
			if fault == "foreign" {
				_, other := desktopImportedPrefixExecutionLaunchFixture(t, 4, "windows", "2022-blake3-aes-128-gcm", 16)
				raw, err := other.chain.policy.OriginalChain().LaunchInput()
				if err != nil {
					t.Fatal(err)
				}
				var source mobilemultihop.NodeChainSource
				if json.Unmarshal([]byte(raw), &source) != nil {
					t.Fatal("foreign source")
				}
				replacement = source.Nodes[2]
			}
			f.executionModel.importedSourceOverride = &replacement
			if s.startContext(f.operation) == nil || f.starts != 0 || desktopOwnedNodeProcess(s.launch) != nil || f.a.state.Connected {
				t.Fatal("foreign imported prefix source acquired native process")
			}
			if err := s.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDesktopImportedPrefixExecutionSavedBounds(t *testing.T) {
	a, nodes := savedNodeChainFixture(t, 8)
	installDesktopOrderedImported(t, a, nodes)
	response := postSetup(t, a, "/api/connection-profile/setup/save", map[string]any{"name": "Complete original prefix", "mode": "shadowsocks", "multihop_enabled": true, "multihop_execution": "server", "multihop_nodes": nodes})
	if response.Code != 200 {
		t.Fatal("complete imported Save refused", response.Code, response.Body.String())
	}
	store, err := loadConnectionProfileStore(a)
	if err != nil || len(store.Profiles) != 1 {
		t.Fatal(err)
	}
	original := store.Profiles[0]
	for _, fault := range []string{"old-middle", "wrong-prefix", "other-family", "missing-token"} {
		t.Run(fault, func(t *testing.T) {
			raw, _ := json.Marshal(original)
			var changed connectionProfileRecord
			if json.Unmarshal(raw, &changed) != nil {
				t.Fatal("fixture")
			}
			switch fault {
			case "old-middle":
				changed.NodeChain[1], changed.NodeChain[6] = changed.NodeChain[6], changed.NodeChain[1]
			case "wrong-prefix":
				changed.NodeChain[3].Mode = "hysteria2"
				changed.Prefs.MultihopNodes[3].Mode = "hysteria2"
			case "other-family":
				changed.NodeChain[6].Mode = "socks5"
				changed.Prefs.MultihopNodes[6].Mode = "socks5"
			case "missing-token":
				changed.NodeChain[3].ProfileToken = ""
			}
			if validateSavedNodeChain(changed) == nil {
				t.Fatal("saved complete prefix accepted changed source", fault)
			}
		})
	}
	before := cloneRouterProfileStore(a.profiles)
	response = postSetup(t, a, "/api/connection-profile/setup/update", map[string]any{"id": original.ID, "name": "Updated complete prefix", "mode": "shadowsocks", "multihop_enabled": true, "multihop_execution": "auto", "multihop_nodes": nodes})
	if response.Code != 200 {
		t.Fatal("complete prefix Update", response.Code, response.Body.String())
	}
	response = postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": original.ID})
	if response.Code != 200 {
		t.Fatal("complete prefix Load", response.Code, response.Body.String())
	}
	final, _ := profileByID(a.profiles.Profiles, a.profiles.SelectedID)
	if final.MultihopExecution != "auto" || !reflect.DeepEqual(final.MultihopNodes, nodes) {
		t.Fatal("complete prefix Update/Load lost choice or nodes")
	}
	for i, p := range a.profiles.Profiles {
		if p.APIToken != before.Profiles[i].APIToken || p.NodeProofID != before.Profiles[i].NodeProofID || !reflect.DeepEqual(p.External, before.Profiles[i].External) {
			t.Fatal("profile replaced original credentials", i)
		}
	}
	response = postSetup(t, a, "/api/connection-profile/setup/delete", map[string]any{"id": original.ID})
	if response.Code != 200 {
		t.Fatal("complete prefix Delete", response.Code, response.Body.String())
	}
}
