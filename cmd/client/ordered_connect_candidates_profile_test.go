package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/nativecomposite"
)

func orderedCONNECTCandidateProposalFixture(t *testing.T, prefix, protocol, layer string) (*app, []desktopNodeChainMember, common.RouterProfile) {
	t.Helper()
	a, members, candidate := orderedImportedCandidateProposalFixture(t, prefix, protocol, layer)
	orderedCandidateSSServiceFixture(t, a, members[len(members)-1].Profile)
	return a, members, candidate
}

func orderedCandidateSSServiceFixture(t *testing.T, a *app, final common.RouterProfile) {
	t.Helper()
	directory := filepath.Join(clientRoot(a), "generated", final.ID, "shadowsocks")
	raw, err := os.ReadFile(filepath.Join(directory, "sing-box.json"))
	if err != nil {
		t.Fatal(err)
	}
	var graph map[string]any
	if err := json.Unmarshal(raw, &graph); err != nil {
		t.Fatal(err)
	}
	out := graph["outbounds"].([]any)[0].(map[string]any)
	sourceSHA, keySHA := sha256.Sum256(raw), sha256.Sum256([]byte(out["password"].(string)))
	claim, err := json.Marshal(map[string]any{"schema": 1, "node_id": final.NodeProofID, "configured_image": nativecomposite.SSServiceImage, "uot_version": 2,
		"endpoint": out["server"], "port": out["server_port"], "method": out["method"], "source_sha256": hex.EncodeToString(sourceSHA[:]), "key_sha256": hex.EncodeToString(keySHA[:])})
	if err != nil {
		t.Fatal(err)
	}
	if err := nativecomposite.ValidateSSServiceCompanion(raw, claim, final.NodeProofID); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, nativecomposite.SSServiceAsset), claim, 0600); err != nil {
		t.Fatal(err)
	}
}

func orderedCONNECTCandidateCompile(t *testing.T, a *app, members []desktopNodeChainMember, candidate common.RouterProfile) (common.RouterProfile, []common.RouterProfile, []common.MultihopNodeSelection, *desktopNodeChainCONNECTCapture) {
	t.Helper()
	control, nodes, err := orderedCandidateProposal(members, 0, candidate, a.profiles.Profiles)
	if err != nil {
		t.Fatal("original CONNECT candidate proposal", err)
	}
	profiles := cloneRouterProfileStore(a.profiles).Profiles
	for i := range profiles {
		if profiles[i].ID == control.ID {
			profiles[i] = common.CloneRouterProfile(control)
		}
	}
	compiled, err := captureOrderedCandidateProposal(context.Background(), clientRoot(a), control, profiles, nodes)
	if err != nil {
		t.Fatal("complete typed CONNECT proposal compilation", err)
	}
	typed, ok := compiled.(*desktopNodeChainCONNECTCapture)
	if !ok || typed == nil || typed.original == nil || typed.original.chain != nil {
		t.Fatal("CONNECT proposal borrowed generic runtime authority")
	}
	return control, profiles, nodes, typed
}

func TestOrderedCONNECTCandidateProposalRetainsExactFutureSource(t *testing.T) {
	for _, prefix := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, protocol := range []string{"http-connect", "https-connect"} {
			for _, layer := range []string{"off", "aes-256-gcm+xor-whitening"} {
				t.Run(prefix+"/"+protocol+"/"+layer, func(t *testing.T) {
					a, members, candidate := orderedCONNECTCandidateProposalFixture(t, prefix, protocol, layer)
					before, state, command := cloneRouterProfileStore(a.profiles), a.state, a.cmd
					control, profiles, nodes, compiled := orderedCONNECTCandidateCompile(t, a, members, candidate)
					wanted := []common.MultihopNodeSelection{{ID: members[0].Profile.ID, Mode: prefix}, {ID: candidate.ID, Mode: protocol}, {ID: members[2].Profile.ID, Mode: "shadowsocks"}}
					if !reflect.DeepEqual(nodes, wanted) || control.ID != members[2].Profile.ID || !reflect.DeepEqual(control.MultihopNodes, wanted) {
						t.Fatal("proposal lost original prefix, CONNECT mode or paired final")
					}
					var source mobilemultihop.NodeChainSource
					if json.Unmarshal([]byte(compiled.original.input), &source) != nil || source.Schema != 4 || source.Execution != "local" || len(source.Nodes) != 3 || len(source.IdentitySources) != 3 || source.IdentitySources[1] != "" {
						t.Fatal("proposal lost distinct schema4 or lent paired identity to CONNECT")
					}
					config, capture, endpoint, err := desktopImportedEntrySource(context.Background(), candidate, nil)
					if err != nil || endpoint != candidate.Endpoint {
						t.Fatal("original imported candidate capture failed", err)
					}
					input, err := mobilemultihop.NodeChainImportedCONNECTMemberInput(config, capture)
					if err != nil || source.Nodes[1] != input {
						t.Fatal("future proposal changed original CONNECT source bytes", err)
					}
					_, meta, err := compiled.source.ReadValidated()
					if err != nil || meta.NativeAdmission != "closed" || len(meta.Proofs) != 3 || meta.Proofs[0].Mode != prefix || meta.Proofs[1].Mode != protocol || meta.Proofs[1].StartLayer != "off" || meta.Proofs[2].Mode != "shadowsocks" || meta.Proofs[0].StartLayer != layer || meta.Proofs[2].StartLayer != layer {
						t.Fatal("future source changed independent policy or invented native admission", err)
					}
					var graph map[string]any
					if err := json.Unmarshal([]byte(compiled.config), &graph); err != nil {
						t.Fatal(err)
					}
					selectedDNS := 0
					for _, raw := range graph["dns"].(map[string]any)["servers"].([]any) {
						resolver := raw.(map[string]any)
						if resolver["tag"] == meta.DNS.ResolverTag {
							selectedDNS++
							if resolver["type"] != "udp" || resolver["server"] != members[2].Profile.AdGuardIPv4 || resolver["detour"] != meta.Proofs[2].Tag {
								t.Fatal("future CONNECT proposal changed original selected Home UDP DNS")
							}
						}
					}
					if selectedDNS != 1 {
						t.Fatal("future proposal lost original selected resolver")
					}
					if err := compiled.validate(context.Background(), control, profiles); err != nil {
						t.Fatal(err)
					}
					if _, err := mobilemultihop.NewNodeChain(compiled.original.input); err == nil {
						t.Fatal("CONNECT future source passed generic family admission")
					}
					if !reflect.DeepEqual(before, a.profiles) || a.state != state || a.cmd != command {
						t.Fatal("proposal compilation changed the saved catalog or active path")
					}
				})
			}
		}
	}
}

func TestOrderedCONNECTCandidateProfileRoundTripKeepsPoliciesAndSourceReferences(t *testing.T) {
	for _, protocol := range []string{"http-connect", "https-connect"} {
		t.Run(protocol, func(t *testing.T) {
			a, members, candidate := orderedCONNECTCandidateProposalFixture(t, "awg2-strong", protocol, "off")
			before := cloneRouterProfileStore(a.profiles)
			control, profiles, nodes, compiled := orderedCONNECTCandidateCompile(t, a, members, candidate)
			record, err := a.orderedCandidateProfileRecordLocked(control, "Next original CONNECT path")
			if err != nil {
				t.Fatal("complete CONNECT next-profile capture", err)
			}
			if record.Mode != "shadowsocks" || len(record.NodeChain) != 3 || record.NodeChain[1].Mode != protocol || record.NodeChain[1].NodeKind != "external" || record.NodeChain[1].NodeProofID != "" || !reflect.DeepEqual(record.Prefs.MultihopNodes, nodes) {
				t.Fatal("saved CONNECT profile lost complete typed member references")
			}
			raw, err := json.Marshal(record)
			request := createRequestFor(protocol)
			if err != nil || strings.Contains(string(raw), request.Password) || strings.Contains(string(raw), request.Username) {
				t.Fatal("saved candidate profile copied transport credentials")
			}
			// Exercise the actual source-checked append/rollback transaction only.
			// This fixture does not grant physical or native DOWN authority.
			publication, err := appendOrderedCandidateProfile(a, record, func() error { return compiled.validate(context.Background(), control, profiles) })
			if err != nil || publication == nil {
				t.Fatal("original future-profile append", err)
			}
			orderedCandidateStoredRecordMatches(t, a, record)
			if !reflect.DeepEqual(before, a.profiles) {
				t.Fatal("future save changed the active catalog")
			}
			loaded := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": record.ID})
			if loaded.Code != http.StatusOK {
				t.Fatal("CONNECT future profile Load failed", loaded.Code, loaded.Body.String())
			}
			middle, found := a.profileByIDLocked(candidate.ID)
			final, finalFound := a.profileByIDLocked(control.ID)
			if !found || !finalFound || !reflect.DeepEqual(middle, candidate) || !reflect.DeepEqual(final.MultihopNodes, nodes) || a.cmd != nil || a.state.Connected {
				t.Fatal("future CONNECT Load changed captured middle source or connected")
			}
			if err := publication.rollback(); err != nil {
				t.Fatal("original future append rollback", err)
			}
			if store, err := loadConnectionProfileStore(a); err != nil || len(store.Profiles) != 0 {
				t.Fatal("rollback did not restore original profile store", err)
			}
		})
	}
}

func TestOrderedCONNECTCandidateProposalRejectsUnsupportedPlacement(t *testing.T) {
	for _, protocol := range []string{"http-connect", "https-connect"} {
		for _, fault := range []string{"later-prefix", "candidate-is-prefix", "candidate-is-final", "hostname", "start-layer", "wrong-protocol", "unpaired-final", "wrong-final-mode", "missing-candidate", "duplicate-source"} {
			t.Run(protocol+"/"+fault, func(t *testing.T) {
				a, members, candidate := orderedCONNECTCandidateProposalFixture(t, "wg", protocol, "off")
				position := 0
				switch fault {
				case "later-prefix":
					position = 1
				case "candidate-is-prefix":
					candidate.ID = members[0].Profile.ID
				case "candidate-is-final":
					candidate.ID = members[2].Profile.ID
				case "hostname":
					candidate.Endpoint = "proxy.example.test"
					if protocol == "http-connect" {
						candidate.External.HTTPConnect.Host = candidate.Endpoint
					} else {
						candidate.External.HTTPSConnect.Host = candidate.Endpoint
					}
				case "start-layer":
					candidate.StartLayer = "aes-256-gcm"
				case "wrong-protocol":
					candidate.External.Protocol = "socks5"
				case "unpaired-final":
					members[2].Profile = candidate
				case "wrong-final-mode":
					members[2].Mode = "http-connect"
				case "missing-candidate":
					a.profiles.Profiles = a.profiles.Profiles[:3]
				case "duplicate-source":
					a.profiles.Profiles = append(a.profiles.Profiles, candidate)
				}
				if fault != "missing-candidate" && fault != "duplicate-source" {
					a.profiles.Profiles[3] = candidate
				}
				if _, _, err := orderedCandidateProposal(members, position, candidate, a.profiles.Profiles); err == nil {
					t.Fatal("unsupported CONNECT future path admitted", fault)
				}
			})
		}
	}
}

func TestOrderedCONNECTCandidateProposalRetainsOriginalValidationUntilSave(t *testing.T) {
	for _, fault := range []string{"credential", "policy", "final-dns", "source-order", "prefix-asset", "final-asset", "cancelled"} {
		t.Run(fault, func(t *testing.T) {
			a, members, candidate := orderedCONNECTCandidateProposalFixture(t, "wg", "https-connect", "off")
			control, profiles, _, compiled := orderedCONNECTCandidateCompile(t, a, members, candidate)
			ctx := context.Background()
			switch fault {
			case "credential":
				profiles[3].External.HTTPSConnect.Password += "-changed"
			case "policy":
				profiles[3].ManualMTU--
			case "final-dns":
				profiles[2].AdGuardIPv4 = "192.168.50.134"
			case "source-order":
				control.MultihopNodes[0], control.MultihopNodes[1] = control.MultihopNodes[1], control.MultihopNodes[0]
			case "prefix-asset", "final-asset":
				path := filepath.Join(clientRoot(a), "generated", members[0].Profile.ID, "wg", "wg.conf")
				if fault == "final-asset" {
					path = filepath.Join(clientRoot(a), "generated", members[2].Profile.ID, "shadowsocks", "sing-box.json")
				}
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, append(raw, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if compiled.validate(ctx, control, profiles) == nil {
				t.Fatal("future Save adopted changed original CONNECT source", fault)
			}
		})
	}
}

func TestOrderedCONNECTCandidateSaveHTTPRequiresFreshOriginalOwner(t *testing.T) {
	for _, protocol := range []string{"http-connect", "https-connect"} {
		t.Run(protocol, func(t *testing.T) {
			a, nodes := desktopNodeChainCaptureFixture(t, 3)
			for i := range a.profiles.Profiles {
				a.profiles.Profiles[i].KillSwitch, a.profiles.Profiles[i].KillSwitchPolicy = true, "on-connect"
			}
			orderedCandidateSSServiceFixture(t, a, a.profiles.Profiles[2])
			selection, err := resolveDesktopNodeChainSelection(a.profiles.Profiles[2], a.profiles.Profiles, nodes, "local")
			if err != nil {
				t.Fatal(err)
			}
			selection, err = captureNativeMultihopSelection(context.Background(), clientRoot(a), selection, []string{"shadowsocks"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			f := newDesktopNodeChainOwnedFixtureWith(t, a, selection)
			f.a.cfg.StateFile = filepath.Join(clientRoot(f.a), "startup-owned-last.json")
			f.stagePublish(t)
			if err := startDesktopOwnedNodeChainLaunch(f.operation, f.operation, f.a, f.launch); err != nil {
				t.Fatal(err)
			}
			if err := proveDesktopNodeChainContext(f.operation, f.a, f.selection, f.launch.command); err != nil {
				t.Fatal(err)
			}
			f.a.mu.Lock()
			f.a.state.Connected, f.a.state.Phase = true, "connected"
			f.a.mu.Unlock()
			candidate := orderedImportedCandidateAdd(t, f.a, protocol)
			sessionTrackers.Store(f.a, &sessionTracker{a: f.a, session: &connectionSession{ID: "original-imported-candidate", Connected: true, Phase: "connected", PathProof: "passed", RouterID: f.selection.Control.ID}})
			identity, _, err := captureSpeedLabIdentityContext(context.Background(), f.a)
			if err != nil {
				t.Fatal(err)
			}
			catalog, err := captureDesktopNodeChainCandidates(context.Background(), f.a, identity, 0, []string{candidate.ID})
			if err != nil {
				t.Fatal("original imported candidate catalog", err)
			}
			testOrderedCandidateSaveHTTPRequiresFreshOriginalOwner(t, f, catalog, candidate.ID)
		})
	}
}

func TestOrderedCONNECTCandidateProposalRequiresOriginalFinalService(t *testing.T) {
	for _, fault := range []string{"missing", "changed-owner", "changed-source"} {
		t.Run(fault, func(t *testing.T) {
			a, members, candidate := orderedCONNECTCandidateProposalFixture(t, "wg", "https-connect", "off")
			control, profiles, nodes, original := orderedCONNECTCandidateCompile(t, a, members, candidate)
			path := filepath.Join(clientRoot(a), "generated", members[2].Profile.ID, "shadowsocks", nativecomposite.SSServiceAsset)
			if fault == "missing" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			} else {
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var claim map[string]any
				if err := json.Unmarshal(raw, &claim); err != nil {
					t.Fatal(err)
				}
				if fault == "changed-owner" {
					claim["node_id"] = members[0].Profile.NodeProofID
				} else {
					claim["source_sha256"] = strings.Repeat("0", 64)
				}
				raw, err = json.Marshal(claim)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if original.validate(context.Background(), control, profiles) == nil {
				t.Fatal("future Save retained replaced original service declaration")
			}
			if _, err := captureOrderedCandidateProposal(context.Background(), clientRoot(a), control, profiles, nodes); err == nil {
				t.Fatal("CONNECT future path invented original final UoT authority")
			}
		})
	}
}
