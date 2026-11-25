package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/mobilemultihop"
)

// Original production import constructors and private file readers build every
// member. These parent/controller tests do not claim encrypted native traffic.
func desktopExternalFinalFixture(t *testing.T, count int, dns string) (*app, []common.MultihopNodeSelection) {
	t.Helper()
	return desktopExternalFinalModeFixture(t, count, dns, "wg")
}

func desktopExternalFinalModeFixture(t *testing.T, count int, dns, mode string) (*app, []common.MultihopNodeSelection) {
	t.Helper()
	a, nodes := desktopNodeChainCaptureFixture(t, count)
	if mode != "wg" {
		modes := make([]string, count)
		for i := range modes {
			modes[i] = "shadowsocks"
		}
		modes[0] = mode
		installOrderedAWGAssets(t, a, nodes, modes, "off")
	}
	a.cfg.StateFile = filepath.Join(clientRoot(a), "external-final-state.json")
	positions := make([]int, count-1)
	for i := range positions {
		positions[i] = i + 1
	}
	installDesktopIndependentImports(t, a, nodes, positions)
	for i := range a.profiles.Profiles {
		p := &a.profiles.Profiles[i]
		p.MultihopEnabled, p.MultihopNodes = false, nil
		p.MultihopEntryID, p.MultihopExitID, p.MultihopEntryMode = "", "", ""
		p.KillSwitch, p.KillSwitchPolicy = true, "on-connect"
		p.StartLayer, p.StartupMode = "off", "manual"
	}
	entry, exit := &a.profiles.Profiles[0], &a.profiles.Profiles[count-1]
	entry.MultihopEnabled, entry.MultihopExecution = true, "local"
	entry.MultihopNodes = append([]common.MultihopNodeSelection(nil), nodes...)
	exit.DNSMode, exit.DNSProtocol, exit.DNSHost, exit.DNSPort = dns, "udp", "", 53
	if dns == "custom" {
		exit.DNSProtocol, exit.DNSHost, exit.DNSPort = "tcp", "198.51.100.198", 5353
	}
	for i := range a.profiles.Profiles {
		if err := common.NormalizeRouterProfile(&a.profiles.Profiles[i]); err != nil {
			t.Fatal(err)
		}
	}
	a.profiles.SelectedID, a.state.RouterID = entry.ID, entry.ID
	return a, nodes
}

func desktopExternalFinalSelection(t *testing.T, a *app, nodes []common.MultihopNodeSelection) multihopSelection {
	t.Helper()
	control, _ := a.profileByIDLocked(a.profiles.SelectedID)
	selection, err := resolveDesktopNodeChainSelection(control, a.profiles.Profiles, nodes, "local")
	if err != nil {
		t.Fatal("external final selection", err)
	}
	selection, err = captureNativeNodeChainSelection(t.Context(), clientRoot(a), selection, []string{"shadowsocks"}, nil)
	if err != nil {
		t.Fatal("original external final capture", err)
	}
	return selection
}

func TestDesktopExternalFinalCompleteSourceAndProjection(t *testing.T) {
	for _, count := range []int{3, 4, 9} {
		for _, dns := range []string{"home", "custom"} {
			t.Run(fmt.Sprintf("%d/%s", count, dns), func(t *testing.T) {
				a, nodes := desktopExternalFinalFixture(t, count, dns)
				before := cloneRouterProfileStore(a.profiles)
				s := desktopExternalFinalSelection(t, a, nodes)
				if s.Control.ID != nodes[0].ID || s.Exit.ID != nodes[count-1].ID || !s.Native.chain.chain.HasExternalFinal() || !reflect.DeepEqual(before, a.profiles) {
					t.Fatal("ordered external final changed the original control, exit or catalog")
				}
				for _, target := range []string{"linux", "windows", "darwin"} {
					launch, err := newDesktopNodeChainLaunch(s, strings.Repeat("a", 32), target)
					if err != nil {
						t.Fatal("launch", target, err)
					}
					if err := validateDesktopNodeChainLaunch(t.Context(), launch); err != nil {
						t.Fatal(target, err)
					}
					_, meta, capture, err := launch.chain.readPolicy()
					if err != nil || !desktopNodeChainMetadataMatchesSelection(meta, s) || launch.profileID != s.Exit.ID || launch.policyProfileID != s.Control.ID {
						t.Fatal("distinct runtime/control ownership", target, err)
					}
					wantDNS := meta.FinalTag
					if dns == "home" {
						wantDNS = meta.Prefixes[0].Tag
					}
					if capture.SelectedDNS.Mode != dns || capture.SelectedDNS.Detour != wantDNS || len(capture.PhysicalRoots) != 1 {
						t.Fatal("source DNS or physical entry changed", capture.SelectedDNS)
					}
					parsed, err := mobilemultihop.ParseDesktopNodeChainLaunchInput(launch.chain.input)
					if err != nil || !parsed.OriginalChain().HasExternalFinal() || parsed.Config() != string(launch.config) {
						t.Fatal("native replay", err)
					}
					if target == "darwin" {
						b, err := newDesktopMacOSNodeChainSelection(launch.chain)
						if err != nil || b.Schema != 4 || b.ControlProfileID != s.Control.ID || b.ProfileID != s.Exit.ID {
							t.Fatal("Darwin entry control", err)
						}
					}
				}
				old := a.profiles.Profiles[count-1].External.ExpectedPublicIP
				a.profiles.Profiles[count-1].External.ExpectedPublicIP = "198.51.100.210"
				if s.Native.chain.currentContext(t.Context(), a) == nil {
					t.Fatal("changed external public identity kept source authority")
				}
				a.profiles.Profiles[count-1].External.ExpectedPublicIP = old
				if err := s.Native.chain.currentContext(t.Context(), a); err != nil {
					t.Fatal("unchanged original capture", err)
				}
			})
		}
	}
}

func installDesktopExternalFinalHost(t *testing.T, a *app) {
	t.Helper()
	t.Setenv("HOMEVPN_PORTABLE", "0")
	manifest := filepath.Join(clientRoot(a), "runtime", "native", "NATIVE-RUNTIME.json")
	if err := os.MkdirAll(filepath.Dir(manifest), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopExternalFinalAWGCaptureAndRestore(t *testing.T) {
	for _, mode := range []string{"awg2-fast", "awg2-strong"} {
		t.Run(mode, func(t *testing.T) {
			a, nodes := desktopExternalFinalModeFixture(t, 9, "custom", mode)
			s := desktopExternalFinalSelection(t, a, nodes)
			if s.EntryMode != mode || s.Base != "awg" || s.Control.ID != nodes[0].ID || s.Exit.ID != nodes[8].ID {
				t.Fatal("source changed original AWG variant or control")
			}
			for _, target := range []string{"linux", "darwin", "windows"} {
				launch, err := newDesktopNodeChainLaunch(s, strings.Repeat("a", 32), target)
				if err != nil {
					t.Fatal(target, err)
				}
				if err := validateDesktopNodeChainLaunch(t.Context(), launch); err != nil {
					t.Fatal(target, err)
				}
				_, meta, capture, err := launch.chain.readPolicy()
				if err != nil || meta.Prefixes[0].Mode != mode || capture.SelectedDNS.Detour != meta.FinalTag || len(capture.PhysicalRoots) != 1 || meta.ExternalFinal == nil {
					t.Fatal("actual entry, selected DNS or public final changed", target, err)
				}
			}
			id := saveOrderedConnectionFixture(t, a, nodes)
			store, err := loadConnectionProfileStore(a)
			if err != nil || len(store.Profiles) != 1 {
				t.Fatal("saved AWG external-final route", err)
			}
			record := store.Profiles[0]
			if validateSavedExternalFinalNodeChain(record) != nil || !externalFinalEntrySources(mode, "off", record.NodeChain[0].Sources) {
				t.Fatal("saved route lost both original sources")
			}
			if r := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id}); r.Code != http.StatusOK {
				t.Fatal("reload", r.Code, r.Body.String())
			}
			installDesktopExternalFinalHost(t, a)
			control, _ := a.profileByIDLocked(nodes[0].ID)
			capture, err := captureStartupNodeChain(a, control, a.profiles.Profiles, nil)
			if err != nil {
				t.Fatal("Last", err)
			}
			last := startupSelection{RouterID: control.ID, RuntimeMode: "shadowsocks", LogicalMode: "multihop", Base: s.Base, ProfileToken: startupExternalProfileToken(control), UpdatedAt: time.Now().UTC(), PathKind: startupNodeChainPathKind, NodeChain: capture.receipt()}
			if _, err := captureStartupNodeChain(a, control, a.profiles.Profiles, &last); err != nil {
				t.Fatal("lost AWG Last sources", err)
			}
			last.NodeChain.Nodes[0].Sources = last.NodeChain.Nodes[0].Sources[:1]
			if validateStartupExternalFinalNodeChain(last) == nil {
				t.Fatal("AWG Last accepted only the pairing identity")
			}
			if err := os.Remove(filepath.Join(clientRoot(a), "generated", nodes[0].ID, mode, "awg.conf")); err != nil {
				t.Fatal(err)
			}
			before := cloneRouterProfileStore(a.profiles)
			if r := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id}); r.Code == http.StatusOK || !reflect.DeepEqual(before, a.profiles) {
				t.Fatal("missing original AWG asset did not refuse named Load atomically")
			}
		})
	}
}

func TestDesktopExternalFinalEntryLayerRestore(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				a, nodes := desktopExternalFinalModeFixture(t, 9, "custom", mode)
				a.profiles.Profiles[0].StartLayer = layer
				s := desktopExternalFinalSelection(t, a, nodes)
				if s.EntryMode != mode || s.Control.StartLayer != layer {
					t.Fatal("selection changed first packet or layer")
				}
				first := s.Native.chain.chain.ProofInventory()[0]
				if first.StartLayer != layer || first.Mode != mode || !desktopPublicCandidateMembers(s.Nodes, "local", len(nodes)-2) {
					t.Fatal("public candidate lost original entry layer")
				}
				for _, target := range []string{"linux", "darwin", "windows"} {
					launch, err := newDesktopNodeChainLaunch(s, strings.Repeat("e", 32), target)
					if err != nil {
						t.Fatal(target, err)
					}
					if err = validateDesktopNodeChainLaunch(t.Context(), launch); err != nil {
						t.Fatal(target, err)
					}
					_, meta, policy, err := launch.chain.readPolicy()
					if err != nil || meta.Prefixes[0].StartLayer != layer || len(policy.PhysicalRoots) != 1 || policy.SelectedDNS.Detour != meta.FinalTag {
						t.Fatal(target, err)
					}
				}
				id := saveOrderedConnectionFixture(t, a, nodes)
				store, err := loadConnectionProfileStore(a)
				if err != nil || len(store.Profiles) != 1 {
					t.Fatal("named save", err)
				}
				record := store.Profiles[0]
				if !externalFinalEntrySources(mode, layer, record.NodeChain[0].Sources) {
					t.Fatal("missing independent layer asset")
				}
				a.profiles.Profiles[0].StartLayer = "off"
				reply := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
				if reply.Code != http.StatusOK || a.profiles.Profiles[0].StartLayer != layer {
					t.Fatal("named restore", reply.Code)
				}
				installDesktopExternalFinalHost(t, a)
				control, _ := a.profileByIDLocked(nodes[0].ID)
				capture, err := captureStartupNodeChain(a, control, a.profiles.Profiles, nil)
				if err != nil {
					t.Fatal(err)
				}
				last := startupSelection{RouterID: control.ID, RuntimeMode: "shadowsocks", LogicalMode: "multihop", Base: s.Base, ProfileToken: startupExternalProfileToken(control), UpdatedAt: time.Now().UTC(), PathKind: startupNodeChainPathKind, NodeChain: capture.receipt()}
				if last.NodeChain.Nodes[0].StartLayer != layer {
					t.Fatal("Last discarded first layer")
				}
				if _, err = captureStartupNodeChain(a, control, a.profiles.Profiles, &last); err != nil {
					t.Fatal("exact layered Last", err)
				}
				other := "aes-256-gcm"
				if layer == other {
					other = "aes-256-gcm+xor-whitening"
				}
				last.NodeChain.Nodes[0].StartLayer = other
				if _, err = captureStartupNodeChain(a, control, a.profiles.Profiles, &last); err == nil {
					t.Fatal("Last substituted the other layer with the same asset")
				}
				last.NodeChain.Nodes[0].StartLayer = ""
				if validateStartupExternalFinalNodeChain(last) == nil {
					t.Fatal("Last used a layer asset without its original selection")
				}
				layerFile := filepath.Join(clientRoot(a), "generated", control.ID, "shadowsocks", "sing-box.json")
				if err = os.WriteFile(layerFile, []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
				if s.Native.chain.currentContext(t.Context(), a) == nil {
					t.Fatal("live capture accepted a changed layer")
				}
				if r := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id}); r.Code == http.StatusOK {
					t.Fatal("named restore accepted a changed layer")
				}
			})
		}
	}
}

func TestDesktopExternalFinalExplicitRequestAndRevisions(t *testing.T) {
	a, nodes := desktopExternalFinalFixture(t, 4, "home")
	tokens := map[string]string{}
	for _, p := range a.profiles.Profiles {
		tokens[p.ID] = publicProfileToken(p)
	}
	request := map[string]any{"nodes": nodes, "execution": "local", "external_final": true, "expected_selected_node_id": nodes[0].ID, "expected_profile_tokens": tokens}
	raw, _ := json.Marshal(request)
	var q multihopConnectRequest
	if err := json.Unmarshal(raw, &q); err != nil {
		t.Fatal(err)
	}
	if s, err := a.resolveNativeMultihopRequestLocked(q); err != nil || s.Control.ID != nodes[0].ID || s.Exit.ID != nodes[3].ID {
		t.Fatal("original request", err)
	}
	for _, fault := range []string{"missing-intent", "false-intent", "server", "auto", "selected-exit", "unknown-field", "stale-import", "paired-final"} {
		t.Run(fault, func(t *testing.T) {
			var bad map[string]any
			_ = json.Unmarshal(raw, &bad)
			switch fault {
			case "missing-intent":
				delete(bad, "external_final")
			case "false-intent":
				bad["external_final"] = false
			case "server", "auto":
				bad["execution"] = fault
			case "selected-exit":
				bad["expected_selected_node_id"] = nodes[3].ID
			case "unknown-field":
				bad["ExternalFinal"] = true
			case "stale-import":
				bad["expected_profile_tokens"].(map[string]any)[nodes[2].ID] = strings.Repeat("f", 64)
			case "paired-final":
				bad["nodes"].([]any)[3].(map[string]any)["id"] = nodes[0].ID
			}
			body, _ := json.Marshal(bad)
			var altered multihopConnectRequest
			if err := json.Unmarshal(body, &altered); err == nil {
				if _, err := a.resolveNativeMultihopRequestLocked(altered); err == nil {
					t.Fatal("changed explicit source was accepted")
				}
			}
		})
	}
}

func TestDesktopExternalFinalSaveLoadAndLast(t *testing.T) {
	for _, count := range []int{3, 9} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			a, nodes := desktopExternalFinalFixture(t, count, "custom")
			id := saveOrderedConnectionFixture(t, a, nodes)
			store, err := loadConnectionProfileStore(a)
			if err != nil || len(store.Profiles) != 1 || validateSavedExternalFinalNodeChain(store.Profiles[0]) != nil || store.Profiles[0].NodeID != nodes[0].ID {
				t.Fatal("complete saved external exit", err)
			}
			bytes, err := os.ReadFile(connectionProfileStorePath(a))
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"private-api-", "api_token", "password", "private_key"} {
				if strings.Contains(strings.ToLower(string(bytes)), secret) {
					t.Fatal("saved source leaked", secret)
				}
			}
			for i := range a.profiles.Profiles {
				a.profiles.Profiles[i].DNSMode, a.profiles.Profiles[i].DNSHost, a.profiles.Profiles[i].DNSPort = "custom", "1.1.1.1", 53
			}
			loaded := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
			if loaded.Code != http.StatusOK {
				t.Fatal("restore", loaded.Code, loaded.Body.String())
			}
			if a.profiles.SelectedID != nodes[0].ID || a.profiles.Profiles[count-1].DNSHost != "198.51.100.198" || a.profiles.Profiles[count-1].DNSProtocol != "tcp" || a.profiles.Profiles[count-1].DNSPort != 5353 {
				t.Fatal("restore lost original exit DNS or paired control")
			}
			before := cloneRouterProfileStore(a.profiles)
			a.profiles.Profiles[count-1].External.Shadowsocks.Password = strings.Repeat("x", 44)
			changed := cloneRouterProfileStore(a.profiles)
			refused := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
			if refused.Code == http.StatusOK || !reflect.DeepEqual(changed, a.profiles) {
				t.Fatal("changed external secret partially restored")
			}
			a.profiles = before
			installDesktopExternalFinalHost(t, a)
			control, _ := a.profileByIDLocked(a.profiles.SelectedID)
			capture, err := captureStartupNodeChain(a, control, a.profiles.Profiles, nil)
			if err != nil {
				t.Fatal("Last source", err)
			}
			last := startupSelection{RouterID: control.ID, RuntimeMode: "shadowsocks", LogicalMode: "multihop", Base: "wg", ProfileToken: startupExternalProfileToken(control), UpdatedAt: time.Now().UTC(), PathKind: startupNodeChainPathKind, NodeChain: capture.receipt()}
			body, _ := json.Marshal(last)
			var restored startupSelection
			if err := json.Unmarshal(body, &restored); err != nil || !reflect.DeepEqual(last, restored) {
				t.Fatal("Last replay", err)
			}
			if _, err := captureStartupNodeChain(a, control, a.profiles.Profiles, &restored); err != nil {
				t.Fatal("exact Last source", err)
			}
			for _, fault := range []string{"exit-control", "private-final", "server", "wrong-first-source"} {
				var bad startupSelection
				_ = json.Unmarshal(body, &bad)
				switch fault {
				case "exit-control":
					bad.RouterID = nodes[count-1].ID
				case "private-final":
					bad.NodeChain.Nodes[count-1].NodeKind = ""
				case "server":
					bad.NodeChain.Execution = "server"
				case "wrong-first-source":
					bad.NodeChain.Nodes[0].Sources[0].Mode = "shadowsocks"
				}
				if validateStartupNodeChainSelection(bad) == nil {
					t.Fatal("Last accepted", fault)
				}
			}
		})
	}
}

func TestDesktopExternalFinalLatencyReceiptAndHistory(t *testing.T) {
	for _, count := range []int{3, 9} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			a, refs := desktopExternalFinalFixture(t, count, "home")
			s := desktopExternalFinalSelection(t, a, refs)
			launch, err := newDesktopNodeChainLaunch(s, strings.Repeat("a", 32), "linux")
			if err != nil {
				t.Fatal(err)
			}
			_, meta, _, err := launch.chain.readPolicy()
			if err != nil {
				t.Fatal(err)
			}
			nodes, err := desktopOrderedLatencyInventory(s, meta)
			if err != nil || len(nodes) != count {
				t.Fatal("original inventory", err)
			}
			for _, node := range nodes {
				r := desktopOrderedReceiptFixtureFor(node.Position, count, node.Kind)
				if node.Position == count-1 {
					r.Result.Role, r.Result.Kind, r.Result.Label, r.Result.Benchmark.Measurement, r.Result.Benchmark.Endpoint = desktopOrderedExternalFinalLatencyMeaning(node.Position, count, node.Kind)
				}
				r.NodeID, r.Result.ID = node.NodeID, node.NodeID
				r.SourceSHA256, r.ConfigSHA256 = meta.OriginalSourceSHA256, meta.ConfigSHA256
				capture := desktopOrderedLatencyCapture{SessionID: "session-1-1", ProfileID: s.Control.ID, ProfileToken: liveMeasurementProfileToken(s.Control), SourceSHA256: r.SourceSHA256, ConfigSHA256: r.ConfigSHA256, GenerationSHA256: r.GenerationSHA256, ExternalFinalNodeID: s.Exit.ID}
				if count > 8 {
					capture.ExtendedLocalNodes = count
				}
				q := desktopOrderedLatencyRequest{Capture: capture, NodeID: r.NodeID, Position: r.Position, Request: r.Request}
				result := desktopNodeChainMeasurementResult{desktopNodeChainMeasurementRequest: desktopNodeChainMeasurementRequest{Schema: 2, Operation: "ordered-latency-50", Request: r.Request, NodeID: r.NodeID, Position: r.Position, Deadline: time.Now().Add(time.Minute).UnixMilli()}, CompletedAt: r.MeasuredAt, Saved: &r, Status: hopmeasure.Status{Request: r.Request, Stage: "complete", Complete: true, Drained: true, Results: []hopmeasure.Result{r.Result}}}
				if !capture.admitsPosition(r.Position) || validateDesktopOrderedLatencyResult(q, node, result, time.Now()) != nil {
					t.Fatal("full original receipt", r.Position)
				}
				if err := node.saveCapturedHistory(a, capture, r, func() error { return nil }); err != nil {
					t.Fatal("exact public/private history", err)
				}
				for _, fault := range []string{"missing-exit", "wrong-exit", "selected-owner", "wrong-role", "wrong-metric", "partial"} {
					badQ, badR := q, result
					saved := copyDesktopOrderedReceipt(r)
					badR.Saved = &saved
					switch fault {
					case "missing-exit":
						badQ.Capture.ExternalFinalNodeID = ""
					case "wrong-exit":
						badQ.Capture.ExternalFinalNodeID = s.Control.ID
					case "selected-owner":
						badQ.Capture.SelectedCaptureJSON = "{}"
					case "wrong-role":
						saved.Result.Role = "foreign"
					case "wrong-metric":
						saved.Result.Benchmark.Measurement = "icmp"
					case "partial":
						saved.Result.Benchmark.Attempts = 49
					}
					badR.Status.Results = []hopmeasure.Result{saved.Result}
					if validateDesktopOrderedLatencyResult(badQ, node, badR, time.Now()) == nil {
						t.Fatal("changed exit receipt", fault)
					}
				}
			}
			history, err := readDesktopOrderedHistory(a)
			if err != nil || len(history.Receipts) != count || history.Receipts[count-1].Result.Kind != "public-path" {
				t.Fatal("complete reopened history", err)
			}
			bad := meta
			bad.ExternalFinal = nil
			if _, err := desktopOrderedLatencyInventory(s, bad); err == nil {
				t.Fatal("metadata without original public exit accepted")
			}
		})
	}
}

func TestDesktopExternalFinalLatencyController(t *testing.T) {
	for _, count := range []int{3, 9} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			dns := "home"
			if count == 9 {
				dns = "custom"
			}
			a, nodes := desktopExternalFinalFixture(t, count, dns)
			selection := desktopExternalFinalSelection(t, a, nodes)
			desktopOrderedLatencyControllerFixture(t, a, selection, count-1)
			if err := selection.Native.validate(selection); err != nil {
				t.Fatal("measurement changed the captured external exit", err)
			}
		})
	}
}

func TestDesktopExternalFinalThroughputMeaning(t *testing.T) {
	a, nodes := desktopExternalFinalFixture(t, 9, "home")
	selection := desktopExternalFinalSelection(t, a, nodes)
	status := hopmeasure.Status{Stage: "complete", Complete: true, Drained: true}
	for position, member := range selection.Nodes {
		kind := "private-node"
		if position > 0 {
			kind = "public-path"
		}
		role, _, label, _, _ := desktopOrderedLatencyMeaning(position, len(nodes), kind)
		if position == len(nodes)-1 {
			role, _, label, _, _ = desktopOrderedExternalFinalLatencyMeaning(position, len(nodes), kind)
		}
		status.Results = append(status.Results, hopmeasure.Result{ID: member.Profile.ID, Role: role, Kind: kind, Label: label, Ready: true,
			Idle:     &hopmeasure.Latency{Samples: 6, Min: 1, Median: 2, Average: 2, P90: 3, Max: 3},
			Download: &hopmeasure.Transfer{Bytes: 65536, Seconds: 0.5, Mbps: 1.048576}, Upload: &hopmeasure.Transfer{Bytes: 65536, Seconds: 1, Mbps: 0.524288}})
	}
	rows, err := desktopNodeChainMeasurementRows(status, selection.Nodes, 65536)
	if err != nil || len(rows) != len(nodes) || rows[8].Role != "exit" || rows[8].RouterID != selection.Exit.ID || !strings.Contains(rows[8].Speed.Proof, "public benchmark") {
		t.Fatal("independent external throughput", err)
	}
	if _, err := desktopNodeChainThroughputRows(status, selection.Nodes, 65536, "server"); err == nil {
		t.Fatal("Local source was promoted to Server")
	}
	for _, fault := range []string{"private-exit", "wrong-label", "wrong-role", "missing-final", "wrong-bytes"} {
		raw, _ := json.Marshal(status)
		var bad hopmeasure.Status
		_ = json.Unmarshal(raw, &bad)
		switch fault {
		case "private-exit":
			bad.Results[8].Kind = "private-node"
		case "wrong-label":
			bad.Results[8].Label = "private API"
		case "wrong-role":
			bad.Results[8].Role = "intermediate"
		case "missing-final":
			bad.Results = bad.Results[:8]
		case "wrong-bytes":
			bad.Results[8].Upload.Bytes--
		}
		if _, err := desktopNodeChainMeasurementRows(bad, selection.Nodes, 65536); err == nil {
			t.Fatal("changed public final measurement", fault)
		}
	}
}

func TestDesktopExternalFinalConnectThroughput(t *testing.T) {
	a, nodes := desktopExternalFinalFixture(t, 3, "custom")
	selection := desktopExternalFinalSelection(t, a, nodes)
	f := newDesktopNodeChainOwnedFixtureWith(t, a, selection)
	t.Cleanup(func() {
		ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		if err := retireDesktopOrderedLatencyFixture(ctx, a, f.launch.command); err != nil {
			t.Error("external throughput did not join", err)
		}
	})
	f.stagePublish(t)
	if err := startDesktopOwnedNodeChainLaunch(f.operation, f.operation, a, f.launch); err != nil {
		t.Fatal(err)
	}
	if err := proveDesktopNodeChainContext(f.operation, a, selection, f.launch.command); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	a.state.Connected, a.state.Phase = true, "connected"
	a.mu.Unlock()
	sessionTrackers.Store(a, &sessionTracker{a: a, session: &connectionSession{ID: "session-1-1", Connected: true, Phase: "connected", PathProof: "passed", RouterID: selection.Control.ID}})
	ctx, stop := context.WithTimeout(t.Context(), 30*time.Second)
	defer stop()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		a.connectionSpeedTest(w, httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/connection/speed-test", strings.NewReader(`{"bytes":8388608}`)))
		done <- w
	}()
	raw := waitDesktopSelectedCandidateParentFile(t, ctx, f, "node-chain-measure-request.json", done)
	var request desktopNodeChainMeasurementRequest
	if json.Unmarshal(raw, &request) != nil || request.Schema != 1 || request.Bytes != 8<<20 || request.Capture.Identity.SourceSHA256 != selection.Native.source {
		t.Fatal("external throughput borrowed a private pair or another source")
	}
	status := hopmeasure.Status{Request: request.Request, Stage: "complete", Complete: true, Drained: true}
	for i, member := range selection.Nodes {
		kind, role, label := "public-path", "intermediate", fmt.Sprintf("Cumulative path through custom node %d of 3 → Cloudflare edge", i+1)
		if i == 0 {
			kind, role, label = "private-node", "entry", "Cumulative path through node 1 of 3"
		}
		if i == 2 {
			role = "exit"
		}
		status.Results = append(status.Results, hopmeasure.Result{ID: member.Profile.ID, Role: role, Kind: kind, Label: label, Ready: true,
			Idle:     &hopmeasure.Latency{Samples: 6, Min: 1, Median: 2, Average: 2, P90: 3, Max: 3},
			Download: &hopmeasure.Transfer{Bytes: 8 << 20, Seconds: 1, Mbps: 67.108864}, Upload: &hopmeasure.Transfer{Bytes: 8 << 20, Seconds: 2, Mbps: 33.554432}})
	}
	raw, _ = json.Marshal(desktopNodeChainMeasurementResult{desktopNodeChainMeasurementRequest: request, CompletedAt: time.Now().UnixMilli(), Status: status})
	if err := writeDesktopRuntimeFile(f.launch, "node-chain-measure-result.json", raw, false); err != nil {
		t.Fatal(err)
	}
	if err := f.launch.directoryRoot.Remove("node-chain-measure-request.json"); err != nil {
		t.Fatal(err)
	}
	response := <-done
	var value connectionSpeedResult
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &value) != nil || value.RouterID != selection.Exit.ID || value.Bytes != 8<<20 ||
		value.DownloadMbps != 67.108864 || value.UploadMbps != 33.554432 || !strings.Contains(value.Proof, "public benchmark") || mtuSuspended(a) {
		t.Fatal("Connect lost the original public exit throughput", response.Code, response.Body.String())
	}
}
