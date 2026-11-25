//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
)

const reviewProfileLoadBase = "/api/connection-profile/setup/load/"

type reviewProfileLoadFixture struct {
	app     *app
	mux     *http.ServeMux
	request map[string]any
}

func reviewProfileLoadJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func reviewProfileLoadRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func reviewProfileLoadWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := atomicWritePrivate(path, b); err != nil {
		t.Fatal(err)
	}
}

func reviewProfileLoadServe(mux http.Handler, path string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func reviewProfileLoadRoutes(a *app) *http.ServeMux {
	mux := http.NewServeMux()
	registerConnectionProfileSetupRoutes(mux, a)
	mux.HandleFunc("/api/profile/select", a.selectProfile)
	return mux
}

func reviewProfileLoadNew(t *testing.T, pair bool) reviewProfileLoadFixture {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOMEVPN_ROOT", root)
	a := &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(root, "routers.json")}, state: state{Mode: "off", Phase: "off"}}
	a.profiles = common.RouterProfileStore{SelectedID: "target", Profiles: []common.RouterProfile{
		{ID: "source", Name: "Original", Endpoint: "203.0.113.20"},
		{ID: "target", Name: "Saved target", Endpoint: "203.0.113.21"},
	}}
	if pair {
		p := &a.profiles.Profiles[0]
		p.MultihopEnabled, p.MultihopEntryID, p.MultihopExitID = true, "target", "source"
	}
	if err = a.persistProfiles(); err != nil {
		t.Fatal(err)
	}
	if err = a.loadProfiles(); err != nil {
		t.Fatal(err)
	}
	a.state.RouterID = a.profiles.SelectedID
	mux := reviewProfileLoadRoutes(a)
	const mode = "custom:Night"
	w := reviewProfileLoadServe(mux, "/api/connection-profile/setup/save", reviewProfileLoadJSON(t, map[string]any{
		"name": "Night routing", "mode": mode, "custom_layers": []string{"wireguard", "reality"}, "multihop_enabled": false,
	}))
	var saved struct {
		Profile struct {
			ID string `json:"id"`
		} `json:"profile"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &saved) != nil || !validProfileID(saved.Profile.ID) {
		t.Fatalf("Save fixture: %d %s", w.Code, w.Body.String())
	}
	w = reviewProfileLoadServe(mux, "/api/profile/select", []byte(`{"id":"source"}`))
	if w.Code != 200 {
		t.Fatalf("Select source: %d %s", w.Code, w.Body.String())
	}
	p, _ := a.profileByIDLocked("source")
	tokens, err := a.connectionProfileTokensLocked(p)
	if err != nil {
		t.Fatal(err)
	}
	return reviewProfileLoadFixture{a, mux, map[string]any{
		"id": saved.Profile.ID, "expected_mode": mode, "expected_selected_node_id": "source", "expected_profile_tokens": tokens,
		"operation_id": strings.Repeat("a", 32), "expected_revision": "0",
	}}
}

func (f reviewProfileLoadFixture) phase(t *testing.T, phase string, body any) profileLoadTransactionResponse {
	t.Helper()
	w := reviewProfileLoadServe(f.mux, reviewProfileLoadBase+phase, reviewProfileLoadJSON(t, body))
	var out profileLoadTransactionResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.OK {
		t.Fatalf("%s: %d %s", phase, w.Code, w.Body.String())
	}
	return out
}

func reviewProfileLoadOwner(t profileLoadTransactionReceipt) map[string]string {
	return map[string]string{"operation_id": t.OperationID, "generation": t.Generation, "receipt_sha256": t.ReceiptSHA256}
}

func TestReviewProfileLoadPreservesForeignProfileWrites(t *testing.T) {
	for _, field := range []string{"endpoint", "name", "order", "history", "mtu"} {
		t.Run(field, func(t *testing.T) {
			f := reviewProfileLoadNew(t, false)
			owner := f.phase(t, "prepare", f.request)
			path := f.app.cfg.ProfilesFile
			var disk map[string]any
			if err := json.Unmarshal(reviewProfileLoadRead(t, path), &disk); err != nil {
				t.Fatal(err)
			}
			profiles := disk["profiles"].([]any)
			source := profiles[0].(map[string]any)
			switch field {
			case "endpoint":
				source["endpoint"] = "203.0.113.40"
			case "name":
				source["name"] = "Renamed in another writer"
			case "order":
				profiles[0], profiles[1] = profiles[1], profiles[0]
			case "history":
				source["use_count"] = 7
				source["last_used_at"] = "2026-10-01T12:00:00Z"
			case "mtu":
				source["effective_mtu"] = 1350
			}
			newer := reviewProfileLoadJSON(t, disk)
			reviewProfileLoadWrite(t, path, newer)
			w := reviewProfileLoadServe(f.mux, reviewProfileLoadBase+"commit", reviewProfileLoadJSON(t, reviewProfileLoadOwner(owner.Transaction)))
			if w.Code != http.StatusConflict || !bytes.Equal(reviewProfileLoadRead(t, path), newer) || f.app.profiles.SelectedID != "source" || f.app.profileLoad.State != "prepared" {
				t.Fatalf("Load failed to retain %s: HTTP %d, selected %s, owner %s", field, w.Code, f.app.profiles.SelectedID, f.app.profileLoad.State)
			}
		})
	}
}

func TestReviewProfileLoadRequiresCapturedInventory(t *testing.T) {
	for _, key := range []string{"both", "expected_selected_node_id", "expected_profile_tokens"} {
		t.Run(key, func(t *testing.T) {
			f := reviewProfileLoadNew(t, false)
			before := reviewProfileLoadRead(t, f.app.cfg.ProfilesFile)
			if key == "both" {
				delete(f.request, "expected_selected_node_id")
				delete(f.request, "expected_profile_tokens")
			} else {
				delete(f.request, key)
			}
			w := reviewProfileLoadServe(f.mux, reviewProfileLoadBase+"prepare", reviewProfileLoadJSON(t, f.request))
			if w.Code != http.StatusBadRequest || f.app.profileLoad != nil || !bytes.Equal(before, reviewProfileLoadRead(t, f.app.cfg.ProfilesFile)) {
				t.Fatalf("missing %s: %d %s", key, w.Code, w.Body.String())
			}
		})
	}
}

func TestReviewProfileLoadCanonicalNestedTokenReplay(t *testing.T) {
	f := reviewProfileLoadNew(t, true)
	first := f.phase(t, "prepare", f.request)
	tokens := f.request["expected_profile_tokens"].(map[string]string)
	if len(tokens) != 2 {
		t.Fatal("fixture did not capture its two current path nodes")
	}
	f.request["expected_profile_tokens"] = json.RawMessage(fmt.Sprintf(`{"target":%q,"source":%q}`, tokens["target"], tokens["source"]))
	replay := f.phase(t, "prepare", f.request)
	if first.Transaction != replay.Transaction || replay.Revision != first.Revision || !bytes.Equal(replay.Snapshot, first.Snapshot) {
		t.Fatal("nested key order changed the original receipt")
	}
}

func TestReviewProfileLoadLegacyReadAndDamagedMetadataRecovery(t *testing.T) {
	f := reviewProfileLoadNew(t, false)
	path := connectionProfileStorePath(f.app)
	var named map[string]any
	if err := json.Unmarshal(reviewProfileLoadRead(t, path), &named); err != nil {
		t.Fatal(err)
	}
	named["version"] = 1
	old := reviewProfileLoadJSON(t, named)
	reviewProfileLoadWrite(t, path, old)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	prepared := f.phase(t, "prepare", f.request)
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) || !bytes.Equal(old, reviewProfileLoadRead(t, path)) {
		t.Fatal("preview replaced the original old-schema named store")
	}
	meta := connectionProfileSetupMetaPath(f.app)
	if err = os.Rename(meta, meta+".prior"); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(meta, 0700); err != nil {
		t.Fatal(err)
	}
	owner := reviewProfileLoadOwner(prepared.Transaction)
	status := f.phase(t, "status", owner)
	if status.Transaction != prepared.Transaction {
		t.Fatal("damaged named metadata lost the prepared receipt")
	}
	w := reviewProfileLoadServe(f.mux, reviewProfileLoadBase+"commit", reviewProfileLoadJSON(t, owner))
	if w.Code == 200 {
		t.Fatal("commit used damaged named metadata")
	}
	if got := f.phase(t, "abort", owner); got.Transaction.State != "aborted" || got.Transaction.Finished {
		t.Fatal("could not abort original prepared owner")
	}
	if got := f.phase(t, "finish", owner); !got.Transaction.Finished || f.app.profiles.SelectedID != "source" {
		t.Fatal("could not finish rolled-back Load")
	}
}

func TestReviewProfileLoadRetainsFutureExtension(t *testing.T) {
	f := reviewProfileLoadNew(t, false)
	var disk map[string]any
	path := f.app.cfg.ProfilesFile
	if err := json.Unmarshal(reviewProfileLoadRead(t, path), &disk); err != nil {
		t.Fatal(err)
	}
	disk["future_store_field"] = map[string]any{"keep": true}
	original := reviewProfileLoadJSON(t, disk)
	reviewProfileLoadWrite(t, path, original)
	restarted := &app{cfg: f.app.cfg, state: state{Phase: "off"}}
	if err := restarted.loadProfiles(); err != nil || restarted.profiles.SelectedID != "source" {
		t.Fatalf("could not open preserved portable extension: %v", err)
	}
	w := reviewProfileLoadServe(reviewProfileLoadRoutes(restarted), reviewProfileLoadBase+"prepare", reviewProfileLoadJSON(t, f.request))
	if w.Code == 200 || restarted.profileLoad != nil || !bytes.Equal(original, reviewProfileLoadRead(t, path)) {
		t.Fatal("staged Load discarded an unfamiliar extension")
	}
}

func TestReviewProfileLoadRestartAndPrivateConsumers(t *testing.T) {
	f := reviewProfileLoadNew(t, false)
	a := f.app
	path := a.cfg.ProfilesFile
	// The historical relay-control decoder accepted this small store, then
	// rejected the very same profiles after adding a retained Load receipt.
	pad := (8 << 10) - len(reviewProfileLoadRead(t, path)) - 200
	if pad < 1 {
		t.Fatal("fixture legacy catalog already exceeds old transport bound")
	}
	a.profiles.Profiles[1].APIToken = strings.Repeat("f", pad)
	if err := a.persistProfiles(); err != nil {
		t.Fatal(err)
	}
	if size := len(reviewProfileLoadRead(t, path)); size > 8<<10 {
		t.Fatalf("legacy size %d exceeds old bound", size)
	}
	prepared := f.phase(t, "prepare", f.request)
	if size := len(reviewProfileLoadRead(t, path)); size <= 8<<10 {
		t.Fatalf("receipt fixture is only %d bytes", size)
	}
	owner := reviewProfileLoadOwner(prepared.Transaction)
	service := newLinuxStandardService(filepath.Dir(path), nil, nil)
	for _, finished := range []bool{false, true} {
		restarted := &app{cfg: a.cfg, state: state{Phase: "off", Mode: "off"}}
		if err := restarted.loadProfiles(); err != nil {
			t.Fatal(err)
		}
		f = reviewProfileLoadFixture{app: restarted, mux: reviewProfileLoadRoutes(restarted)}
		status := f.phase(t, "status", owner).Transaction
		if status.Finished != finished || status.Generation != prepared.Transaction.Generation || status.ReceiptSHA256 != prepared.Transaction.ReceiptSHA256 {
			t.Fatalf("restart lost exact owner: %+v", status)
		}
		if err := service.loadProfiles(); err != nil {
			t.Fatalf("installed Linux service lost readable catalog: %v", err)
		}
		err := service.app.guardProfileLoadPendingContext(context.Background())
		if (err == nil) != finished || service.app.profileLoad == nil || service.app.profileLoad.Finished != finished {
			t.Fatalf("Linux service admission differs from retained owner: %v", err)
		}
		if finished {
			var saved struct {
				Tokens map[string]string `json:"profile_tokens"`
			}
			if err := json.Unmarshal(prepared.Snapshot, &saved); err != nil {
				t.Fatal(err)
			}
			target, exists := restarted.profileByIDLocked("target")
			if !exists || saved.Tokens["target"] == "" || saved.Tokens["target"] != publicProfileToken(target) {
				t.Fatal("the prepared target token no longer identifies the loaded node after restart")
			}
		}
		comparison, err := captureDesktopComparisonStore(restarted, restarted.profiles)
		if !finished {
			if err == nil {
				t.Fatal("comparison admitted unfinished Load")
			}
			commit := f.phase(t, "commit", owner)
			if commit.Transaction.State != "committed" || restarted.profiles.SelectedID != "target" {
				t.Fatal("commit did not install the saved target")
			}
			f.phase(t, "finish", owner)
			continue
		}
		if err != nil {
			t.Fatalf("completed receipt blocked ordinary external comparison: %v", err)
		}
		if err = comparison.write(restarted.profiles); err != nil {
			t.Fatal(err)
		}
		if err = restarted.loadProfiles(); err != nil || restarted.profileLoad == nil || !restarted.profileLoad.Finished || restarted.profileLoad.Generation != status.Generation {
			t.Fatalf("comparison write lost durable revision: %v", err)
		}
	}
}

func TestReviewProfileLoadSwiftLoopback(t *testing.T) {
	binary := os.Getenv("ROUTERVPN_PROFILE_LOAD_SWIFT")
	if binary == "" {
		t.Skip("set ROUTERVPN_PROFILE_LOAD_SWIFT to a compiled AppKit protocol fixture")
	}
	for _, fault := range []string{"none", "reject", "after-prepare", "after-commit"} {
		t.Run(fault, func(t *testing.T) {
			f := reviewProfileLoadNew(t, false)
			server := httptest.NewServer(f.mux)
			defer server.Close()
			delete(f.request, "operation_id")
			delete(f.request, "expected_revision")
			root := t.TempDir()
			request := filepath.Join(root, "request.json")
			reviewProfileLoadWrite(t, request, reviewProfileLoadJSON(t, f.request))
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, binary, server.URL, request, fault, filepath.Join(root, "appkit-journal"))
			result, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("Swift loopback: %v\n%s", err, result)
			}
			t.Logf("%s", result)
			committed := fault == "none" || fault == "after-commit"
			f.app.mu.Lock()
			settled := f.app.profileLoad != nil && f.app.profileLoad.Finished && (f.app.profileLoad.State == "committed") == committed && (f.app.profiles.SelectedID == "target") == committed
			f.app.mu.Unlock()
			if !settled {
				t.Fatalf("Swift result disagrees with durable controller selection in %s", fault)
			}
		})
	}
}
