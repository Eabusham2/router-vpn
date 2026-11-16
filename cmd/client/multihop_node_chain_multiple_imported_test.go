package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/mobilemultihop"
)

type desktopIndependentImportedLayout struct {
	name      string
	count     int
	positions []int
}

var desktopIndependentImportedLayouts = []desktopIndependentImportedLayout{
	{"earlier", 4, []int{1}}, {"adjacent", 4, []int{1, 2}},
	{"separated", 5, []int{1, 3}}, {"paired-suffix", 6, []int{1, 3}},
	{"maximum-sparse", 8, []int{1, 4, 6}}, {"maximum-public", 8, []int{1, 2, 3, 4, 5, 6}},
}

// Each member first passes the real external import constructor. Distinct
// endpoints, keys and expected public identities make source substitution
// observable. No live provider or native transport is claimed by this fixture.
func installDesktopIndependentImports(t *testing.T, a *app, nodes []common.MultihopNodeSelection, positions []int) {
	t.Helper()
	for _, position := range positions {
		q := createRequestFor("shadowsocks")
		q.Name, q.Server, q.Port = fmt.Sprintf("Independent import %d", position), fmt.Sprintf("203.0.113.%d", 70+position), 23000+position
		q.ExpectedPublicIP = fmt.Sprintf("198.51.100.%d", 70+position)
		q.Method, q.Secret = "2022-blake3-aes-256-gcm", base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string(rune('a'+position)), 32)))
		profile, err := externalProfileFromCreateRequest(q)
		if err != nil {
			t.Fatal("independent import constructor", err)
		}
		profile.ID, profile.StartLayer = nodes[position].ID, "off"
		profile.DNSMode, profile.DNSProtocol, profile.DNSHost, profile.DNSPort = "custom", "udp", "192.0.2.53", 5353+position
		profile.MTUPolicy, profile.ManualMTU = "auto", 0
		if err := common.NormalizeRouterProfile(&profile); err != nil {
			t.Fatal(err)
		}
		if !desktopNodeChainImportedExecutionMiddle(profile) {
			t.Fatal("independent literal import lost its existing exact source admission")
		}
		a.profiles.Profiles[position] = profile
		nodes[position].Mode = "shadowsocks"
	}
	a.profiles.Profiles[len(nodes)-1].MultihopNodes = append([]common.MultihopNodeSelection(nil), nodes...)
}

func desktopIndependentImportedFixture(t *testing.T, layout desktopIndependentImportedLayout, mode, layer string) (*app, []common.MultihopNodeSelection) {
	t.Helper()
	a, nodes := desktopNodeChainCaptureFixture(t, layout.count)
	modes := make([]string, layout.count)
	for i := range modes {
		modes[i] = mode
	}
	modes[len(modes)-1] = "shadowsocks"
	installOrderedAWGAssets(t, a, nodes, modes, layer)
	installDesktopIndependentImports(t, a, nodes, layout.positions)
	return a, nodes
}

func TestDesktopMultipleImportedCompleteNativeCapture(t *testing.T) {
	for _, layout := range desktopIndependentImportedLayouts {
		for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
			t.Run(layout.name+"/"+mode, func(t *testing.T) {
				a, nodes := desktopIndependentImportedFixture(t, layout, mode, "aes-256-gcm+xor-whitening")
				before := cloneRouterProfileStore(a.profiles)
				capture := captureNodeChainTest(t, a, nodes)
				var source mobilemultihop.NodeChainSource
				if json.Unmarshal([]byte(capture.input), &source) != nil || source.Schema != 6 || len(source.Nodes) != layout.count || len(source.IdentitySources) != layout.count {
					t.Fatal("complete independent capture lost its schema or identity inventory")
				}
				proofs := capture.chain.ProofInventory()
				public, _, err := capture.chain.PublicMeasurementCaptures()
				if err != nil || len(proofs) != layout.count || len(public) != len(layout.positions) {
					t.Fatal("complete independent proof inventory lost", err)
				}
				for i, position := range layout.positions {
					if source.IdentitySources[position] != "" || proofs[position].ProfileID != nodes[position].ID || proofs[position].NodeID != "" || public[i].Position != position || public[i].SourceSHA256 != proofs[position].SourceSHA256 {
						t.Fatal("imported position borrowed another private identity")
					}
					view := publicProfileFor(a.profiles.Profiles[position])
					if view.External == nil || !view.External.OrderedLocalImportedNodes {
						t.Fatal("complete literal source was not advertised to native editor")
					}
					raw, _ := json.Marshal(view)
					if strings.Contains(string(raw), a.profiles.Profiles[position].External.Shadowsocks.Password) {
						t.Fatal("public independent capability copied credentials")
					}
				}
				for _, platform := range []string{"linux", "windows", "darwin"} {
					projected, err := capture.project(context.Background(), platform, 0)
					if err != nil || !reflect.DeepEqual(projected.ProofInventory(), proofs) {
						t.Fatal("desktop projection lost complete imported source", platform, err)
					}
				}
				if !reflect.DeepEqual(before, a.profiles) {
					t.Fatal("native source capture mutated linked profiles")
				}
				request := orderedPublicRequest(t, a, nodes)
				a.mu.Lock()
				selection, err := a.resolveNativeMultihopRequestLocked(request)
				a.mu.Unlock()
				if err != nil || len(selection.Nodes) != layout.count {
					t.Fatal("public request did not retain every independent member", err)
				}
				selection, err = captureNativeNodeChainSelection(context.Background(), clientRoot(a), selection, []string{"shadowsocks"}, nil)
				if err != nil || selection.Native.validate(selection) != nil || !nativeMultihopLiveProfilesCurrentContext(context.Background(), a, selection) {
					t.Fatal("complete request did not reach native capture", err)
				}
				position := layout.positions[0]
				a.profiles.Profiles[position].External.Shadowsocks.Password = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32)))
				if nativeMultihopLiveProfilesCurrentContext(context.Background(), a, selection) || capture.validate(context.Background(), a.profiles.Profiles[layout.count-1], a.profiles.Profiles) == nil {
					t.Fatal("replaced early import retained complete native authority")
				}
			})
		}
	}
}

func TestDesktopMultipleImportedRefusesChangedShapeAndAuthority(t *testing.T) {
	for _, fault := range []string{"first", "final", "hostname-first", "hostname-last", "middle-protocol", "paired-identity", "missing-source", "duplicate-id", "server", "compare"} {
		t.Run(fault, func(t *testing.T) {
			layout := desktopIndependentImportedLayouts[2]
			a, nodes := desktopIndependentImportedFixture(t, layout, "wg", "off")
			captureNodeChainTest(t, a, nodes)
			execution := "local"
			switch fault {
			case "first":
				nodes[0], nodes[1] = nodes[1], nodes[0]
			case "final":
				nodes[3], nodes[4] = nodes[4], nodes[3]
			case "hostname-first", "hostname-last":
				position := 1
				if fault == "hostname-last" {
					position = 3
				}
				a.profiles.Profiles[position].Endpoint = "independent.example.test"
				a.profiles.Profiles[position].External.Shadowsocks.Server = "independent.example.test"
			case "middle-protocol":
				nodes[3].Mode = "socks5"
			case "paired-identity":
				a.profiles.Profiles[1].NodeProofID = a.profiles.Profiles[0].NodeProofID
			case "missing-source":
				a.profiles.Profiles[3].External = nil
			case "duplicate-id":
				nodes[3].ID = nodes[1].ID
			case "server":
				execution = "server"
			case "compare":
				execution = "auto"
			}
			if _, err := captureDesktopNodeChain(context.Background(), clientRoot(a), a.profiles.Profiles[layout.count-1], a.profiles.Profiles, nodes, execution, nil); err == nil {
				t.Fatal("changed independent authority reached native compiler")
			}
		})
	}
}

func TestConnectionProfileMultipleImportedTransactionalRestore(t *testing.T) {
	for _, layout := range desktopIndependentImportedLayouts {
		t.Run(layout.name, func(t *testing.T) {
			a, nodes := desktopIndependentImportedFixture(t, layout, "awg2-fast", "aes-256-gcm")
			for _, position := range layout.positions {
				a.profiles.Profiles[position].MTUPolicy = "manual"
				a.profiles.Profiles[position].ManualMTU = 1380 + position
			}
			original := cloneRouterProfileStore(a.profiles)
			id := saveOrderedConnectionFixture(t, a, nodes)
			store, err := loadConnectionProfileStore(a)
			if err != nil || len(store.Profiles) != 1 || len(store.Profiles[0].NodeChain) != layout.count {
				t.Fatal("saved independent source inventory lost", err)
			}
			raw, err := os.ReadFile(connectionProfileStorePath(a))
			if err != nil {
				t.Fatal(err)
			}
			for _, position := range layout.positions {
				captured := store.Profiles[0].NodeChain[position]
				if captured.NodeKind != "external" || captured.Preferences != nil || captured.External == nil || len(captured.Sources) != 1 || captured.Sources[0].Mode != "external-shadowsocks" || strings.Contains(string(raw), original.Profiles[position].External.Shadowsocks.Password) {
					t.Fatal("saved independent node lost its reference or copied credentials")
				}
				a.profiles.Profiles[position].DNSPort = 53
				a.profiles.Profiles[position].ManualMTU = 1500
			}
			response := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
			if response.Code != http.StatusOK {
				t.Fatal("complete independent profile restore", response.Code, response.Body.String())
			}
			for _, position := range layout.positions {
				if !reflect.DeepEqual(a.profiles.Profiles[position].External, original.Profiles[position].External) || a.profiles.Profiles[position].DNSPort != original.Profiles[position].DNSPort || a.profiles.Profiles[position].ManualMTU != original.Profiles[position].ManualMTU {
					t.Fatal("restore substituted one import for another")
				}
			}
			for _, position := range layout.positions {
				originalKey := a.profiles.Profiles[position].External.Shadowsocks.Password
				a.profiles.Profiles[position].External.Shadowsocks.Password = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
				before := cloneRouterProfileStore(a.profiles)
				response = postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
				if response.Code == http.StatusOK || !reflect.DeepEqual(before, a.profiles) {
					t.Fatal("failed independent restore published a partial update")
				}
				a.profiles.Profiles[position].External.Shadowsocks.Password = originalKey
			}
		})
	}
}

func TestConnectionProfileMultipleImportedRejectsUncapturedSave(t *testing.T) {
	for _, layout := range desktopIndependentImportedLayouts {
		for _, position := range layout.positions {
			t.Run(fmt.Sprintf("%s/%d", layout.name, position), func(t *testing.T) {
				a, nodes := desktopIndependentImportedFixture(t, layout, "wg", "off")
				saveOrderedConnectionFixture(t, a, nodes)
				beforeFile, err := os.ReadFile(connectionProfileStorePath(a))
				if err != nil {
					t.Fatal(err)
				}
				member := &a.profiles.Profiles[position]
				member.Endpoint, member.External.Shadowsocks.Server = "Original.Import.Example", "Original.Import.Example"
				member.DNSMode, member.DNSProtocol, member.DNSHost, member.DNSPort = "custom", "tcp", "192.0.2.53", 53
				if !desktopNodeChainImported(*member, "shadowsocks") || desktopNodeChainImportedExecutionMiddle(*member) {
					t.Fatal("negative save fixture lost its valid old single-import hostname source")
				}
				before := cloneRouterProfileStore(a.profiles)
				response := postSetup(t, a, "/api/connection-profile/setup/save", map[string]any{
					"name": "Uncaptured independent hostname", "mode": "shadowsocks", "multihop_enabled": true,
					"multihop_execution": "local", "multihop_nodes": nodes,
				})
				afterFile, readErr := os.ReadFile(connectionProfileStorePath(a))
				if response.Code == http.StatusOK || readErr != nil || string(beforeFile) != string(afterFile) || !reflect.DeepEqual(before, a.profiles) {
					t.Fatal("saved independent hostname without its complete source admission")
				}
			})
		}
	}
}

func TestStartupMultipleImportedRetainsEveryOriginalReference(t *testing.T) {
	for _, layout := range desktopIndependentImportedLayouts {
		t.Run(layout.name, func(t *testing.T) {
			a, nodes := startupOrderedTestApp(t, layout.count)
			installDesktopIndependentImports(t, a, nodes, layout.positions)
			capture := startupNodeChainCaptureForTest(t, a)
			receipt := startupOrderedReceipt(t, capture)
			if receipt.NodeChain.Schema != 6 || len(receipt.NodeChain.Nodes) != layout.count {
				t.Fatal("Last lost its complete independent source shape")
			}
			raw, _ := json.Marshal(receipt)
			var decoded startupSelection
			if json.Unmarshal(raw, &decoded) != nil || !reflect.DeepEqual(decoded, receipt) {
				t.Fatal("Last did not preserve exact independent references")
			}
			for _, position := range layout.positions {
				member := receipt.NodeChain.Nodes[position]
				if member.NodeKind != "external" || member.NodeProofID != "" || len(member.Sources) != 1 || member.Sources[0].Mode != "external-shadowsocks" || strings.Contains(string(raw), a.profiles.Profiles[position].External.Shadowsocks.Password) {
					t.Fatal("Last substituted imported ownership or copied credentials")
				}
			}
			control := a.profiles.Profiles[layout.count-1]
			reopened, err := captureStartupNodeChain(a, control, a.profiles.Profiles, &receipt)
			if err != nil || !reflect.DeepEqual(reopened.receipt(), receipt.NodeChain) {
				t.Fatal("Last failed exact complete recapture", err)
			}
			for _, schema := range []int{1, 2, 3, 4, 5} {
				var legacy startupSelection
				_ = json.Unmarshal(raw, &legacy)
				legacy.NodeChain.Schema = schema
				if validateStartupNodeChainSelection(legacy) == nil {
					t.Fatal("independent Last borrowed an older source schema")
				}
			}
			for _, position := range layout.positions {
				capture = startupNodeChainCaptureForTest(t, a)
				key := a.profiles.Profiles[position].External.Shadowsocks.Password
				a.profiles.Profiles[position].External.Shadowsocks.Password = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("y", 32)))
				if capture.current(a) == nil {
					t.Fatal("Last retained a replaced independent import")
				}
				a.profiles.Profiles[position].External.Shadowsocks.Password = key
			}
		})
	}
}

func TestDesktopMultipleImportedMeasurementKeepsEveryPublicPosition(t *testing.T) {
	for _, layout := range desktopIndependentImportedLayouts {
		t.Run(layout.name, func(t *testing.T) {
			a, nodes := desktopIndependentImportedFixture(t, layout, "wg", "off")
			members, err := resolveDesktopNodeChainMembers(a.profiles.Profiles[layout.count-1], a.profiles.Profiles, nodes, "local")
			if err != nil {
				t.Fatal(err)
			}
			status := hopmeasure.Status{Complete: true, Drained: true, Stage: "complete"}
			for position, member := range members {
				role, kind := "intermediate", "private-node"
				if position == 0 {
					role = "entry"
				}
				if position == layout.count-1 {
					role = "exit"
				}
				if member.Profile.NodeKind == "external" {
					kind = "public-path"
				}
				status.Results = append(status.Results, hopmeasure.Result{ID: member.Profile.ID, Role: role, Kind: kind, Ready: true,
					Idle:     &hopmeasure.Latency{Samples: 6, Min: 1, Median: 2, Average: 2, P90: 3, Max: 3},
					Download: &hopmeasure.Transfer{Bytes: 65536, Seconds: 0.5, Mbps: 1.048576}, Upload: &hopmeasure.Transfer{Bytes: 65536, Seconds: 1, Mbps: 0.524288}})
			}
			rows, err := desktopNodeChainMeasurementRows(status, members, 65536)
			if err != nil || len(rows) != layout.count {
				t.Fatal("independent measurement lost complete source positions", err)
			}
			for _, position := range layout.positions {
				if !strings.Contains(rows[position].Speed.Proof, "public benchmark") || strings.Contains(rows[position].Speed.Proof, "authenticated bytes") {
					t.Fatal("independent public transfer borrowed private-node meaning")
				}
			}
			for position := range members {
				changed := status
				changed.Results = append([]hopmeasure.Result(nil), status.Results...)
				changed.Results[position].Kind = "public-path"
				if status.Results[position].Kind == "public-path" {
					changed.Results[position].Kind = "private-node"
				}
				if _, err := desktopNodeChainMeasurementRows(changed, members, 65536); err == nil {
					t.Fatal("measurement result substituted an original private/public source kind")
				}
			}
		})
	}
}
