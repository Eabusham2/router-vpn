package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func TestSpeedLabNativeEntryCatalogAndCapturedCurrentMode(t *testing.T) {
	// Select the shipped native branch without claiming this fixture receipt
	// validates a runnable engine; packaged runtime proof is a separate gate.
	root := t.TempDir()
	t.Setenv("HOMEVPN_ROOT", root)
	manifest := filepath.Join(root, "runtime", "native", "NATIVE-RUNTIME.json")
	if err := os.MkdirAll(filepath.Dir(manifest), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	a := &app{profiles: common.RouterProfileStore{SelectedID: "control", Profiles: []common.RouterProfile{
		{ID: "control", NodeKind: "router-vpn", MultihopEnabled: true, MultihopEntryID: "entry", MultihopExitID: "exit", MultihopEntryMode: "wg"},
		{ID: "entry", NodeKind: "router-vpn", MultihopEntryMode: "max-quic-awg"},
		{ID: "exit", NodeKind: "router-vpn"},
	}}, state: state{Mode: "multihop", Connected: true, Phase: "connected", RouterID: "exit", Base: "native"}}
	activeMultihopGraphs.Store(a, activeMultihopGraph{Execution: "server", EntryID: "entry", ExitID: "exit", EntryMode: "split", Base: "native", ExitMode: "shadowsocks"})
	t.Cleanup(func() { activeMultihopGraphs.Delete(a) })
	read := func() map[string]any {
		t.Helper()
		rr := httptest.NewRecorder()
		a.speedLabOptions(rr, httptest.NewRequest(http.MethodGet, "/api/speed-lab/options", nil))
		if rr.Code != http.StatusOK {
			t.Fatal(rr.Body.String())
		}
		var value map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	value := read()
	var modes []string
	for _, raw := range value["supported_entry_modes"].([]any) {
		modes = append(modes, raw.(string))
	}
	if !reflect.DeepEqual(modes, mobilemultihop.NodeMultihopEntryModes()) {
		t.Fatal("native Router entry catalog differs from the shared compiler")
	}
	current := value["current"].(map[string]any)
	if current["entry_mode"] != "split" || current["execution"] != "server" || current["base"] != "native" {
		t.Fatal("live entry mode was replaced by selected/saved node metadata")
	}
	a.state.Connected = false
	current = read()["current"].(map[string]any)
	if current["entry_mode"] != nil || current["execution"] != nil {
		t.Fatal("disconnected options exposed a stale graph as an active entry")
	}
}
