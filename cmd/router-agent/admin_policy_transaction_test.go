package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// The subprocess models nft's documented atomic -f transaction boundary, not
// kernel packet filtering. Rejecting a proposed batch leaves its prior tables
// untouched; a separate successful deletion has already committed.
func adminTransactionNFT(t *testing.T) (string, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("nft process fixture uses a POSIX Python launcher")
	}
	dir := t.TempDir()
	state := filepath.Join(dir, "tables.json")
	if err := os.WriteFile(state, []byte("{\"unrelated\":[\"original household policy\"]}"), 0600); err != nil {
		t.Fatal(err)
	}
	fixture := "#!/usr/bin/env python3\n" + `
import json, os, pathlib, sys
if sys.argv[1:] != ["-f", "-"]:
    raise SystemExit("unexpected nft invocation")
path = pathlib.Path(os.environ["ROUTER_TEST_NFT_STATE"])
tables = json.loads(path.read_text())
script = sys.stdin.read()
with open(os.environ["ROUTER_TEST_NFT_CALLS"], "a") as log:
    log.write(json.dumps(script) + "\n")
if os.environ.get("ROUTER_TEST_NFT_REJECT") == "1" and "add table " in script:
    raise SystemExit("injected replacement transaction failure")
for line in script.splitlines():
    parts = line.split()
    if len(parts) < 4 or parts[2] != "inet":
        raise SystemExit("fixture refused unknown table scope")
    action, kind, _, table = parts[:4]
    if table not in ("router_vpn_admin", "router_vpn_server_control"):
        raise SystemExit("fixture refused unrelated table mutation")
    if (action, kind) == ("add", "table"):
        tables.setdefault(table, [])
    elif (action, kind) == ("delete", "table"):
        del tables[table]
    elif (action, kind) == ("flush", "table"):
        tables[table] = []
    elif (action, kind) == ("add", "chain"):
        pass
    elif (action, kind) == ("add", "rule"):
        tables[table].append(line)
    else:
        raise SystemExit("fixture refused unsupported nft operation")
path.write_text(json.dumps(tables))
`
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(fixture), 0700); err != nil {
		t.Fatal(err)
	}
	calls := filepath.Join(dir, "calls.jsonl")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ROUTER_TEST_NFT_STATE", state)
	t.Setenv("ROUTER_TEST_NFT_CALLS", calls)
	return state, calls
}

func adminTransactionTables(t *testing.T, path string) map[string][]string {
	t.Helper()
	var tables map[string][]string
	if err := json.Unmarshal(mustReadFile(t, path), &tables); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tables["unrelated"], []string{"original household policy"}) {
		t.Fatal("admin transaction changed unrelated household table")
	}
	return tables
}

func TestAdminPolicyTransactionRejectsInitialCreationWithoutPartialTable(t *testing.T) {
	for _, kind := range []string{"peer-policy", "server-control"} {
		t.Run(kind, func(t *testing.T) {
			state, calls := adminTransactionNFT(t)
			before := adminTransactionTables(t, state)
			t.Setenv("ROUTER_TEST_NFT_REJECT", "1")
			var err error
			if kind == "peer-policy" {
				a := testMutationServer(t)
				a.state = defaultAdminState()
				err = a.applyPolicy()
			} else {
				s := &adminServerControl{cfg: cfg{WANInterface: "eth0"}, state: defaultServerControlState()}
				err = s.apply()
			}
			if err == nil || !strings.Contains(err.Error(), "replacement transaction failure") {
				t.Fatalf("failed initial transaction was hidden: %v", err)
			}
			if !reflect.DeepEqual(before, adminTransactionTables(t, state)) {
				t.Fatal("failed initial transaction left a partial table")
			}
			if got := len(strings.Split(strings.TrimSpace(string(mustReadFile(t, calls))), "\n")); got != 1 {
				t.Fatalf("initialization used %d separate transactions", got)
			}
		})
	}
}

func TestAdminPolicyTransactionPreservesPriorBanOnReplacementFailure(t *testing.T) {
	for _, action := range []string{"ban", "revoke"} {
		t.Run(action, func(t *testing.T) {
			state, calls := adminTransactionNFT(t)
			a := testMutationServer(t)
			a.state = defaultAdminState()
			a.state.BannedPeers = []adminPeerPolicy{{Interface: "wg0", PublicKey: "original", AllowedIPs: []string{"10.77.0.2"}}}
			if err := a.applyPolicy(); err != nil {
				t.Fatal(err)
			}
			if err := a.persistLocked(); err != nil {
				t.Fatal(err)
			}
			before, disk := adminTransactionTables(t, state), string(mustReadFile(t, a.statePath))
			// Reasserting a policy must replace its rules rather than accumulate.
			if err := a.applyPolicy(); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, adminTransactionTables(t, state)) {
				t.Fatal("reassert duplicated or changed prior ban")
			}
			transactions := strings.Split(strings.TrimSpace(string(mustReadFile(t, calls))), "\n")
			t.Setenv("ROUTER_TEST_NFT_REJECT", "1")
			request := httptest.NewRequest(http.MethodPost, "/api/admin/clients/"+action,
				strings.NewReader(`{"interface":"wg0","public_key":"next","allowed_ips":["10.77.0.3/32"]}`))
			request.RemoteAddr = "127.0.0.1:12345"
			request.Header.Set("Authorization", "Bearer "+a.token)
			response := httptest.NewRecorder()
			if action == "ban" {
				a.ban(response, request)
			} else {
				a.revoke(response, request)
			}
			if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "replacement transaction failure") {
				t.Fatalf("failed policy reported success: %d %s", response.Code, response.Body.String())
			}
			if !reflect.DeepEqual(before, adminTransactionTables(t, state)) {
				t.Fatal("failed replacement removed the prior ban")
			}
			if len(transactions) != 2 {
				t.Fatalf("initialization/reassert used %d separate transactions", len(transactions))
			}
			if string(mustReadFile(t, a.statePath)) != disk || len(a.state.BannedPeers) != 1 || len(a.state.RevokedPeers) != 0 {
				t.Fatal("failed replacement changed durable or in-memory peer policy")
			}
		})
	}
}

func TestServerControlTransactionPreservesStopOnReplacementFailure(t *testing.T) {
	state, calls := adminTransactionNFT(t)
	s := &adminServerControl{cfg: cfg{WANInterface: "eth0", ReservedPorts: []int{443, 51820}},
		statePath: filepath.Join(t.TempDir(), "server-control.json"), state: defaultServerControlState()}
	if err := s.setState(true, false); err != nil {
		t.Fatal(err)
	}
	before, disk := adminTransactionTables(t, state), string(mustReadFile(t, s.statePath))
	if len(before[serverControlTable]) == 0 {
		t.Fatal("fixture did not install initial Stop policy")
	}
	if err := s.apply(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, adminTransactionTables(t, state)) {
		t.Fatal("reassert duplicated or changed Stop policy")
	}
	initialTransactions := len(strings.Split(strings.TrimSpace(string(mustReadFile(t, calls))), "\n"))
	t.Setenv("ROUTER_TEST_NFT_REJECT", "1")
	if err := s.setState(false, false); err == nil {
		t.Fatal("failed Resume reported success")
	}
	if !reflect.DeepEqual(before, adminTransactionTables(t, state)) {
		t.Fatal("failed Resume removed the prior Stop guard")
	}
	if initialTransactions != 2 {
		t.Fatalf("initialization/reassert used %d separate transactions", initialTransactions)
	}
	if !s.state.Paused || string(mustReadFile(t, s.statePath)) != disk {
		t.Fatal("failed Resume changed durable or in-memory paused state")
	}
	t.Setenv("ROUTER_TEST_NFT_REJECT", "0")
	if err := s.setState(false, false); err != nil {
		t.Fatal(err)
	}
	if len(adminTransactionTables(t, state)[serverControlTable]) != 0 {
		t.Fatal("successful Resume retained old drops")
	}
}
