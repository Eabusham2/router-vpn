package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/hopmeasure"
)

// Real profile captures, controller handlers and private history storage are
// exercised here. The native reply mailbox remains the controlled fixture in
// desktopExtendedThroughputPublicReplay; encrypted peer tests qualify traffic.
func TestDesktopLocalPrivateStreamRoles(t *testing.T) {
	for _, count := range []int{9, 16} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			a, nodes := desktopNodeChainCaptureFixture(t, count)
			a.cfg.StateFile = filepath.Join(t.TempDir(), "startup.json")
			roles, imported := make([]string, count), []int{}
			for i := range nodes {
				roles[i] = "private-node"
				if i == 0 {
					continue
				}
				nodes[i].Mode = "shadowsocks"
				if i < count-1 && i%4 >= 2 {
					roles[i] = "public-path"
					imported = append(imported, i)
					continue
				}
				file := filepath.Join(clientRoot(a), "generated", nodes[i].ID, "shadowsocks", "sing-box.json")
				raw, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				oldKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'s'}, 32))
				newKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(160 + i)}, 32))
				if strings.Count(string(raw), oldKey) != 1 {
					t.Fatal("fixture lost its independent private cipher")
				}
				if err := os.WriteFile(file, []byte(strings.Replace(string(raw), oldKey, newKey, 1)), 0600); err != nil {
					t.Fatal(err)
				}
			}
			installDesktopIndependentImports(t, a, nodes, imported)
			selection, err := resolveDesktopNodeChainSelection(a.profiles.Profiles[count-1], a.profiles.Profiles, nodes, "local")
			if err != nil {
				t.Fatal(err)
			}
			selection, err = captureNativeNodeChainSelection(t.Context(), clientRoot(a), selection, []string{"shadowsocks"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			chain := selection.Native.chain.chain
			canonical, _ := json.Marshal(roles)
			if !chain.HasPairedStreamInterior() || chain.ExtendedLocalRolesJSON() != string(canonical) {
				t.Fatal("original native source changed private and public stream identities")
			}
			launch, err := newDesktopNodeChainLaunch(selection, strings.Repeat("a", 32), "linux")
			if err != nil {
				t.Fatal(err)
			}
			_, meta, _, err := launch.chain.readPolicy()
			if err != nil {
				t.Fatal(err)
			}
			inventory, err := desktopOrderedLatencyInventory(selection, meta)
			if err != nil || len(inventory) != count {
				t.Fatal("original latency inventory", err)
			}
			status := hopmeasure.Status{Stage: "complete", Complete: true, Drained: true}
			for i, node := range inventory {
				if node.Kind != roles[i] {
					t.Fatal("original role changed", i)
				}
				r := desktopOrderedReceiptFixtureFor(i, count, roles[i])
				r.NodeID, r.Result.ID = node.NodeID, node.NodeID
				r.SourceSHA256, r.ConfigSHA256 = chain.SourceSHA256(), meta.ConfigSHA256
				capture := desktopOrderedLatencyCapture{SourceSHA256: r.SourceSHA256, ConfigSHA256: r.ConfigSHA256, GenerationSHA256: r.GenerationSHA256, ExtendedLocalNodes: count, LocalRolesJSON: string(canonical)}
				if err := node.saveCapturedHistory(a, capture, r, func() error { return nil }); err != nil {
					t.Fatal("current native source could not retain its fifty-response history", i, err)
				}
				for _, fault := range []string{"missing", "changed", "packet", "selected", "space"} {
					bad := capture
					switch fault {
					case "missing":
						bad.LocalRolesJSON = ""
					case "changed":
						changed := append([]string(nil), roles...)
						changed[1], changed[2] = changed[2], changed[1]
						raw, _ := json.Marshal(changed)
						bad.LocalRolesJSON = string(raw)
					case "packet":
						bad.PairedPrefixNodes = 1
					case "selected":
						bad.SelectedCaptureJSON = "{}"
					case "space":
						bad.LocalRolesJSON += " "
					}
					if node.saveCapturedHistory(a, bad, r, func() error { return nil }) == nil {
						t.Fatal("history accepted changed original role capture", i, fault)
					}
				}
				tr := hopmeasure.Transfer{Bytes: 8 << 20, Seconds: 1, Mbps: float64(8<<20) * 8 / 1e6}
				status.Results = append(status.Results, hopmeasure.Result{ID: node.NodeID, Role: node.Role, Kind: node.Kind, Ready: true,
					Idle: &hopmeasure.Latency{Samples: 6, Min: 1, Median: 2, Average: 2, P90: 3, Max: 4}, Download: &tr, Upload: &tr})
			}
			get, post := desktopExtendedThroughputPublicReplay(t, a, selection, status)
			for _, raw := range [][]byte{get, post} {
				var result struct {
					Source desktopOrderedPerformanceSource `json:"ordered_local_source"`
					Rows   []speedLabHopMeasurement        `json:"hops"`
				}
				if json.Unmarshal(raw, &result) != nil || result.Source.PairedWireGuard || result.Source.PairedPrefixNodes != 0 || result.Source.LocalRolesJSON != string(canonical) || len(result.Source.NodeIDs) != count {
					t.Fatal("throughput changed its complete original roles")
				}
				for i, row := range result.Rows {
					for _, label := range []string{row.SpeedLabel, row.LatencyLabel} {
						if strings.Contains(label, "to the public benchmark") != (roles[i] == "public-path") {
							t.Fatal("throughput borrowed another role's endpoint", i)
						}
					}
				}
			}
		})
	}
}

func TestDesktopLocalRolesRequestRetainsPhysicalBound(t *testing.T) {
	for _, count := range []int{9, 16, 96} {
		roles := make([]string, count)
		for i := range roles {
			roles[i] = "private-node"
			if i > 0 && i < count-1 && i%4 >= 2 {
				roles[i] = "public-path"
			}
		}
		canonical, _ := json.Marshal(roles)
		capture := desktopOrderedLatencyCapture{SessionID: "session-123-456", ProfileID: "original-exit", ProfileToken: strings.Repeat("a", 64), SourceSHA256: strings.Repeat("b", 64), ConfigSHA256: strings.Repeat("c", 64), GenerationSHA256: strings.Repeat("d", 64), ExtendedLocalNodes: count, LocalRolesJSON: string(canonical)}
		request := desktopOrderedLatencyRequest{Capture: capture, NodeID: "original-late", Position: count - 2, Request: strings.Repeat("e", 32)}
		raw, _ := json.Marshal(request)
		if len(raw) >= 4096 {
			t.Fatal("canonical roles exceeded the unchanged ordinary request bound")
		}
		parsed, err := readDesktopOrderedLatencyRequest(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/speed-lab/ordered-latency", bytes.NewReader(raw)))
		if err != nil || !reflect.DeepEqual(parsed, request) || capture.admitsPosition(count) {
			t.Fatal("canonical request lost its original count or roles", count, err)
		}
		for i := 1; i < count-1; i++ {
			roles[i] = "public-path"
		}
		allPublic, _ := json.Marshal(roles)
		for _, malformed := range []string{"null", "[]", " " + string(canonical), string(allPublic)} {
			bad := capture
			bad.LocalRolesJSON = malformed
			if bad.admitsPosition(count - 2) {
				t.Fatal("contradictory or noncanonical roles admitted", count)
			}
		}
	}
}
