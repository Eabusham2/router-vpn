package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func orderedPublicRequest(t *testing.T, a *app, nodes []common.MultihopNodeSelection) multihopConnectRequest {
	t.Helper()
	selected := a.profiles.SelectedID
	q := multihopConnectRequest{Nodes: append([]common.MultihopNodeSelection(nil), nodes...), Execution: "local",
		desktopProfileExpectations: desktopProfileExpectations{ExpectedSelectedNodeID: &selected, ExpectedProfileTokens: map[string]string{}}}
	for _, node := range nodes {
		profile, found := a.profileByIDLocked(node.ID)
		if !found {
			t.Fatal("test source missing")
		}
		q.ExpectedProfileTokens[node.ID] = publicProfileToken(profile)
	}
	raw, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeMultihopConnectRequest(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestNativeNodeChainPublicJSONCannotDowngradeMalformedCapture(t *testing.T) {
	token := strings.Repeat("a", 64)
	good := `{"nodes":[{"id":"first","mode":"awg2-fast"},{"id":"last","mode":"shadowsocks"}],"execution":"local","expected_selected_node_id":"last","expected_profile_tokens":{"first":"` + token + `","last":"` + token + `"}}`
	if q, err := decodeMultihopConnectRequest(strings.NewReader(good)); err != nil || !q.ordered() || len(q.Nodes) != 2 || q.Nodes[0].Mode != "awg2-fast" {
		t.Fatal("complete public ordered request rejected", err)
	}
	for name, raw := range map[string]string{
		"null-nodes":        strings.Replace(good, `[{"id":"first","mode":"awg2-fast"},{"id":"last","mode":"shadowsocks"}]`, `null`, 1),
		"empty-nodes":       strings.Replace(good, `[{"id":"first","mode":"awg2-fast"},{"id":"last","mode":"shadowsocks"}]`, `[]`, 1),
		"one-node":          strings.Replace(good, `{"id":"first","mode":"awg2-fast"},`, ``, 1),
		"case-nodes":        strings.Replace(good, `"nodes"`, `"Nodes"`, 1),
		"duplicate-nodes":   strings.Replace(good, `"execution":"local"`, `"nodes":[],"execution":"local"`, 1),
		"row-duplicate":     strings.Replace(good, `"id":"first"`, `"id":"first","id":"last"`, 1),
		"row-case":          strings.Replace(good, `"id":"first"`, `"ID":"first"`, 1),
		"row-extra":         strings.Replace(good, `"id":"first"`, `"id":"first","password":"private"`, 1),
		"row-null":          strings.Replace(good, `"mode":"awg2-fast"`, `"mode":null`, 1),
		"duplicate-member":  strings.Replace(good, `"id":"first"`, `"id":"last"`, 1),
		"bad-mode":          strings.Replace(good, `awg2-fast`, `AWG2-fast`, 1),
		"missing-execution": strings.Replace(good, `"execution":"local",`, ``, 1),
		"server":            strings.Replace(good, `"local"`, `"server"`, 1),
		"compare":           strings.Replace(good, `"local"`, `"auto"`, 1),
		"mixed-pair":        strings.Replace(good, `"execution":"local"`, `"entry_id":"first","execution":"local"`, 1),
		"mixed-empty-pair":  strings.Replace(good, `"execution":"local"`, `"base":"","execution":"local"`, 1),
		"unknown":           strings.Replace(good, `"execution":"local"`, `"bypass":true,"execution":"local"`, 1),
		"partial-capture":   strings.Replace(good, `"expected_selected_node_id":"last",`, ``, 1),
		"null-selected":     strings.Replace(good, `"expected_selected_node_id":"last"`, `"expected_selected_node_id":null`, 1),
		"empty-selected":    strings.Replace(good, `"expected_selected_node_id":"last"`, `"expected_selected_node_id":""`, 1),
		"wrong-final":       strings.Replace(good, `"expected_selected_node_id":"last"`, `"expected_selected_node_id":"first"`, 1),
		"case-capture":      strings.Replace(good, `"expected_profile_tokens"`, `"Expected_Profile_Tokens"`, 1),
		"duplicate-token":   strings.Replace(good, `"first":"`+token+`"`, `"first":"`+token+`","first":"`+token+`"`, 1),
		"short-token":       strings.Replace(good, token, "abc", 1),
		"uppercase-token":   strings.Replace(good, token, strings.ToUpper(token), 1),
		"null-token":        strings.Replace(good, `"`+token+`"`, `null`, 1),
		"trailing":          good + ` {}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeMultihopConnectRequest(strings.NewReader(raw)); err == nil {
				t.Fatal("ambiguous request downgraded or admitted")
			}
		})
	}
	legacy, err := decodeMultihopConnectRequest(strings.NewReader(`{"entry_id":"first","exit_id":"last","execution":"local"}`))
	if err != nil || legacy.ordered() || legacy.present() || legacy.EntryID != "first" || legacy.ExitID != "last" {
		t.Fatal("legacy pair without expectations changed", err)
	}
}

func TestNativeNodeChainPublicRequestCapturesEveryOriginalSource(t *testing.T) {
	for _, count := range []int{2, 3, 4, 8} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			a, nodes := desktopNodeChainCaptureFixture(t, count)
			modes := make([]string, count)
			for i := 0; i < count-1; i++ {
				modes[i] = []string{"awg2-fast", "awg2-strong", "wg"}[i%3]
			}
			modes[count-1] = "shadowsocks"
			installOrderedAWGAssets(t, a, nodes, modes, "off")
			q := orderedPublicRequest(t, a, nodes)
			before := cloneRouterProfileStore(a.profiles)
			a.mu.Lock()
			selection, err := a.resolveNativeMultihopRequestLocked(q)
			a.mu.Unlock()
			if err != nil || len(selection.Nodes) != count || selection.EntryMode != modes[0] || selection.Base != "awg" || !reflect.DeepEqual(before, a.profiles) {
				t.Fatal("public selection changed exact modes or its original source", err)
			}
			selection, err = captureNativeNodeChainSelection(context.Background(), clientRoot(a), selection, []string{"shadowsocks"}, nil)
			if err != nil || selection.Native.validate(selection) != nil || !nativeMultihopLiveProfilesCurrentContext(context.Background(), a, selection) {
				t.Fatal("public selection did not reach the actual shared compiler and original current-source validation", err)
			}
			for i, proof := range selection.Native.chain.chain.ProofInventory() {
				if proof.Mode != modes[i] || proof.NodeID != before.Profiles[i].NodeProofID {
					t.Fatal("public selection changed a native proof identity or transport")
				}
			}
			a.profiles.Profiles[0].APIToken += "-replacement"
			if nativeMultihopLiveProfilesCurrentContext(context.Background(), a, selection) {
				t.Fatal("compiled public selection adopted replacement credentials")
			}
		})
	}
}

func TestNativeNodeChainPublicDraftKeepsOriginalSavedPreferences(t *testing.T) {
	for _, saved := range []string{"ordered", "pair"} {
		t.Run(saved, func(t *testing.T) {
			a, nodes := desktopNodeChainCaptureFixture(t, 4)
			installOrderedAWGAssets(t, a, nodes, []string{"wg", "awg2-fast", "awg2-strong", "shadowsocks"}, "off")
			if saved == "pair" {
				control := &a.profiles.Profiles[3]
				control.MultihopNodes = nil
				control.MultihopEntryID, control.MultihopExitID, control.MultihopEntryMode = nodes[0].ID, nodes[3].ID, "wg"
			}
			nodes[0], nodes[2] = nodes[2], nodes[0]
			q := orderedPublicRequest(t, a, nodes)
			before := cloneRouterProfileStore(a.profiles)
			a.mu.Lock()
			selection, err := a.resolveNativeMultihopRequestLocked(q)
			a.mu.Unlock()
			if err != nil || selection.Entry.ID != nodes[0].ID || selection.EntryMode != "awg2-strong" {
				t.Fatal("explicit edited order was replaced with saved preferences", err)
			}
			selection, err = captureNativeNodeChainSelection(context.Background(), clientRoot(a), selection, []string{"shadowsocks"}, nil)
			if err != nil || selection.Native.validate(selection) != nil || !reflect.DeepEqual(before, a.profiles) || !nativeMultihopLiveProfilesCurrentContext(context.Background(), a, selection) {
				t.Fatal("edited draft changed private saved preferences or lost its original native source", err)
			}
			selection.Nodes[0], selection.Nodes[1] = selection.Nodes[1], selection.Nodes[0]
			if selection.Native.validate(selection) == nil {
				t.Fatal("compiled edited draft allowed its order to change")
			}
		})
	}
}

func TestNativeNodeChainPublicCaptureRejectsCatalogReplacement(t *testing.T) {
	for _, fault := range []string{"selected", "credential", "missing-token", "extra-token", "missing-member", "duplicate-member", "unsupported-prefix", "external-member", "wrong-proof", "hostname-middle"} {
		t.Run(fault, func(t *testing.T) {
			a, nodes := desktopNodeChainCaptureFixture(t, 3)
			q := orderedPublicRequest(t, a, nodes)
			switch fault {
			case "selected":
				a.profiles.SelectedID = nodes[0].ID
			case "credential":
				a.profiles.Profiles[1].APIToken += "-relinked"
			case "missing-token":
				delete(q.ExpectedProfileTokens, nodes[1].ID)
			case "extra-token":
				q.ExpectedProfileTokens["unrelated"] = strings.Repeat("a", 64)
			case "missing-member":
				a.profiles.Profiles = append(a.profiles.Profiles[:1], a.profiles.Profiles[2:]...)
			case "duplicate-member":
				a.profiles.Profiles = append(a.profiles.Profiles, a.profiles.Profiles[1])
			case "unsupported-prefix":
				q.Nodes[1].Mode = "shadowsocks"
			case "external-member":
				a.profiles.Profiles[1].NodeKind = "external"
				q.ExpectedProfileTokens[nodes[1].ID] = publicProfileToken(a.profiles.Profiles[1])
			case "wrong-proof":
				a.profiles.Profiles[1].NodeProofID = ""
				q.ExpectedProfileTokens[nodes[1].ID] = publicProfileToken(a.profiles.Profiles[1])
			case "hostname-middle":
				a.profiles.Profiles[1].Endpoint = "middle.example.test"
				q.ExpectedProfileTokens[nodes[1].ID] = publicProfileToken(a.profiles.Profiles[1])
			}
			before := cloneRouterProfileStore(a.profiles)
			a.mu.Lock()
			_, err := a.resolveNativeMultihopRequestLocked(q)
			a.mu.Unlock()
			if err == nil || !reflect.DeepEqual(before, a.profiles) || a.cmd != nil {
				t.Fatal("invalid captured public graph changed state or was admitted", err)
			}
		})
	}
}

func orderedPublicHandlerFixture(t *testing.T) (*app, []common.MultihopNodeSelection) {
	t.Helper()
	a, nodes := desktopNodeChainCaptureFixture(t, 3)
	// This marker selects only the shipping dispatcher. No installed bundle,
	// privileged host, native proof or physical traffic is provided by this test.
	directory := filepath.Join(clientRoot(a), "runtime", "native")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "NATIVE-RUNTIME.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOMEVPN_PORTABLE", "0")
	return a, nodes
}

func TestNativeNodeChainPublicHandlerRefusesBeforeRuntimeAndKeepsCancellation(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("ordered public host is not enabled on this platform")
	}
	for _, fault := range []string{"stale-middle", "partial-capture", "cancelled", "legacy-host"} {
		t.Run(fault, func(t *testing.T) {
			a, nodes := orderedPublicHandlerFixture(t)
			q := orderedPublicRequest(t, a, nodes)
			expected := http.StatusConflict
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch fault {
			case "stale-middle":
				a.profiles.Profiles[1].APIToken += "-replacement"
			case "partial-capture":
				q.ExpectedProfileTokens = nil
				expected = http.StatusBadRequest
			case "cancelled":
				cancel()
			case "legacy-host":
				expected = http.StatusBadRequest
			}
			raw, err := json.Marshal(q)
			if err != nil {
				t.Fatal(err)
			}
			called := false
			refuse := func() { called = true; t.Error("invalid admission entered a runtime boundary") }
			driver := nativeMultihopConnectRuntime{
				capture: func(_ *app, s multihopSelection, _ []string) (multihopSelection, error) {
					refuse()
					return s, errors.New("unavailable")
				},
				preflight: func(*app, multihopSelection, *desktopExecutionDescriptor) (*desktopNodeLaunch, error) {
					refuse()
					return nil, errors.New("unavailable")
				},
				stage: func(*app, multihopSelection, *desktopNodeLaunch) error { refuse(); return errors.New("unavailable") },
				proof: func(*app, multihopSelection, *exec.Cmd) error { refuse(); return errors.New("unavailable") },
			}
			before := cloneRouterProfileStore(a.profiles)
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/api/multihop/connect", bytes.NewReader(raw)).WithContext(ctx)
			if fault == "legacy-host" {
				if runtime.GOOS != "linux" {
					expected = http.StatusNotImplemented
				}
				a.multihopConnect(response, request)
			} else {
				a.nativeMultihopConnectOwned(response, request, driver)
			}
			if response.Code != expected || called || a.cmd != nil || a.state.Connected || !reflect.DeepEqual(before, a.profiles) {
				t.Fatal("public refusal crossed runtime/state boundary", response.Code, response.Body.String())
			}
		})
	}
}

func TestNativeNodeChainStatusStatesActualHostAndModeBounds(t *testing.T) {
	a, _ := orderedPublicHandlerFixture(t)
	response := httptest.NewRecorder()
	a.nativeMultihopStatus(response, httptest.NewRequest(http.MethodGet, "/api/multihop/status", nil))
	var value struct {
		Supported  bool     `json:"ordered_nodes_supported"`
		Prefixes   []string `json:"ordered_prefix_modes"`
		Exits      []string `json:"ordered_exit_modes"`
		Executions []string `json:"ordered_executions"`
		Maximum    int      `json:"ordered_max_nodes"`
		Connected  bool     `json:"connected"`
	}
	if json.Unmarshal(response.Body.Bytes(), &value) != nil || value.Supported != (runtime.GOOS == "linux" || runtime.GOOS == "windows") || value.Connected || value.Maximum != 8 ||
		!reflect.DeepEqual(value.Prefixes, []string{"wg", "awg2-fast", "awg2-strong"}) || !reflect.DeepEqual(value.Exits, []string{"shadowsocks", "hysteria2"}) || !reflect.DeepEqual(value.Executions, []string{"local"}) {
		t.Fatal("status invented host authority or lost exact admitted modes", response.Body.String())
	}
}
