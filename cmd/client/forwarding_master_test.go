package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"router-vpn/internal/common"
)

func TestValidatedPrivateRouterAPI(t *testing.T) {
	good := []string{"http://127.0.0.1:8787", "http://10.77.0.1:8787", "http://[fd77:77::1]:8787"}
	for _, raw := range good {
		if _, err := validatedPrivateRouterAPI(raw); err != nil {
			t.Fatalf("expected private API %q to pass: %v", raw, err)
		}
	}
	bad := []string{"", "https://8.8.8.8:8787", "http://example.com:8787", "http://10.77.0.1:8787/admin", "ftp://10.77.0.1:8787", "http://user@10.77.0.1:8787"}
	for _, raw := range bad {
		if _, err := validatedPrivateRouterAPI(raw); err == nil {
			t.Fatalf("expected private API %q to fail", raw)
		}
	}
}

func TestDesktopForwardingMasterGetAndPut(t *testing.T) {
	var enabled atomic.Bool
	var mutations atomic.Int32
	var forcedReply atomic.Value
	forcedReply.Store("")
	token := "node-token-abcdefghijklmnopqrstuvwxyz012345"
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != desktopForwardingMasterPath {
			t.Fatalf("unexpected remote path %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Fatalf("missing node token")
		}
		switch r.Method {
		case http.MethodGet:
		case http.MethodPut:
			var body struct {
				Enabled *bool `json:"enabled"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Enabled == nil {
				t.Fatalf("invalid PUT body: %v", err)
			}
			enabled.Store(*body.Enabled)
			mutations.Add(1)
		default:
			t.Fatalf("unexpected method %s", r.Method)
		}
		w.Header().Set("content-type", "application/json")
		if raw := forcedReply.Load().(string); raw != "" {
			_, _ = w.Write([]byte(raw))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "enabled": enabled.Load(), "peer": "10.77.0.2", "proof": "test"})
	}))
	defer remote.Close()

	profile := common.RouterProfile{ID: "home", Name: "Home", NodeKind: "router-vpn", RouterAPI: remote.URL, APIToken: token, BaseTunnel: "wg"}
	a := &app{
		profiles: common.RouterProfileStore{SelectedID: "home", Profiles: []common.RouterProfile{profile}},
		state:    state{Connected: true, Mode: "wg", LogicalMode: "wg", RuntimeMode: "wg", Base: "wg", RouterID: "home", Phase: "connected"},
	}
	// Forwarding Master is intentionally gated behind the same selected-path
	// proof as live telemetry. Seed the exact tracker used by the handler instead
	// of bypassing that production safety boundary in the test.
	tracker := &sessionTracker{a: a}
	sessionTrackers.Store(a, tracker)
	defer sessionTrackers.Delete(a)
	tracker.declareRequest("wg", "wg")
	tracker.observe(observedConnection{Connected: true, Phase: "connected", Mode: "wg", LogicalMode: "wg", RuntimeMode: "wg", Base: "wg", RouterID: "home", Profile: profile})
	proved := tracker.snapshot(0)
	if proved.ID == "" || !proved.Connected || proved.Phase != "connected" || proved.PathProof != "passed" {
		t.Fatalf("test did not establish a proved forwarding session: %+v", proved)
	}

	getReq := httptest.NewRequest(http.MethodGet, desktopForwardingMasterPath, nil)
	getRec := httptest.NewRecorder()
	a.forwardingMaster(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET failed: %d %s", getRec.Code, getRec.Body.String())
	}
	var getBody map[string]any
	if err := json.Unmarshal(getRec.Body.Bytes(), &getBody); err != nil || getBody["enabled"] != false {
		t.Fatalf("unexpected GET body: %s", getRec.Body.String())
	}

	request := func(method string, body any) *httptest.ResponseRecorder {
		t.Helper()
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		out := httptest.NewRecorder()
		a.forwardingMaster(out, httptest.NewRequest(method, desktopForwardingMasterPath, bytes.NewReader(raw)))
		return out
	}
	router, path := getBody["router_id"], getBody["path_token"]
	if router != profile.ID || !desktopOrderedDigest.MatchString(fmt.Sprint(path)) {
		t.Fatal("missing original owner", getBody)
	}
	put := func(owner, proof any, wanted bool) *httptest.ResponseRecorder {
		return request(http.MethodPut, map[string]any{"enabled": wanted, "router_id": owner, "path_token": proof})
	}
	putRec := put(router, path, true)
	var putBody map[string]any
	if putRec.Code != 200 || json.Unmarshal(putRec.Body.Bytes(), &putBody) != nil ||
		putBody["enabled"] != true || putBody["router_id"] != router || putBody["path_token"] != path {
		t.Fatal("PUT did not confirm the original displayed owner", putRec.Code, putRec.Body.String())
	}
	for _, body := range []map[string]any{
		{"enabled": false}, {"router_id": router, "path_token": path}, {"enabled": nil, "router_id": router, "path_token": path},
		{"enabled": false, "router_id": "another-home", "path_token": path}, {"enabled": false, "router_id": router, "path_token": strings.Repeat("0", 64)},
	} {
		if out := request(http.MethodPut, body); out.Code < 400 || mutations.Load() != 1 {
			t.Fatal("foreign or incomplete request reached router", out.Code)
		}
	}
	for _, response := range []string{`{"ok":true}`, `{"ok":true,"enabled":null}`, `{"ok":true,"enabled":"false"}`} {
		forcedReply.Store(response)
		for _, out := range []*httptest.ResponseRecorder{request(http.MethodGet, nil), put(router, path, false)} {
			if out.Code != http.StatusBadGateway {
				t.Fatal("incomplete remote state verified", response, out.Code, out.Body.String())
			}
		}
	}
	forcedReply.Store("")
	before := mutations.Load()
	reconnect := func(node common.RouterProfile) {
		tracker.observe(observedConnection{Phase: "off"})
		a.mu.Lock()
		a.state.RouterID, a.profiles.SelectedID = node.ID, node.ID
		a.mu.Unlock()
		tracker.declareRequest("wg", "wg")
		tracker.observe(observedConnection{Connected: true, Phase: "connected", Mode: "wg", LogicalMode: "wg", RuntimeMode: "wg", Base: "wg", RouterID: node.ID, Profile: node})
	}
	other := profile
	other.ID = "other-home"
	a.profiles.Profiles = append(a.profiles.Profiles, other)
	for _, node := range []common.RouterProfile{other, profile} {
		reconnect(node)
		if out := put(router, path, true); out.Code != http.StatusConflict || mutations.Load() != before {
			t.Fatal("stale displayed router or session mutated after reconnect", out.Code)
		}
	}
	// A changed ordered route can retain the same final, mode and session.
	a.mu.Lock()
	a.state.Mode = "multihop"
	a.mu.Unlock()
	setActiveMultihopGraph(a, multihopSelection{Entry: other, Exit: profile, Base: "wg", EntryMode: "wg", ExitMode: "shadowsocks"})
	defer clearActiveMultihopGraph(a)
	out := request(http.MethodGet, nil)
	var original map[string]any
	if out.Code != 200 || json.Unmarshal(out.Body.Bytes(), &original) != nil {
		t.Fatal("missing ordered forwarding state", out.Code, out.Body.String())
	}
	changed, _ := getActiveMultihopGraph(a)
	changed.EntryID = "changed-entry"
	activeMultihopGraphs.Store(a, changed)
	if out := put(router, original["path_token"], true); out.Code != http.StatusConflict || mutations.Load() != before {
		t.Fatal("different ordered path reached router", out.Code)
	}

}

func TestDesktopForwardingMasterRejectsExternalOrDisconnected(t *testing.T) {
	cases := []app{
		{profiles: common.RouterProfileStore{SelectedID: "x", Profiles: []common.RouterProfile{{ID: "x", NodeKind: "external", RouterAPI: "http://127.0.0.1:8787", APIToken: "x"}}}, state: state{Connected: true, Mode: "external", RouterID: "x"}},
		{profiles: common.RouterProfileStore{SelectedID: "x", Profiles: []common.RouterProfile{{ID: "x", NodeKind: "router-vpn", RouterAPI: "http://127.0.0.1:8787", APIToken: "x"}}}, state: state{Connected: false, Mode: "off", RouterID: "x"}},
	}
	for i := range cases {
		req := httptest.NewRequest(http.MethodGet, desktopForwardingMasterPath, nil)
		rec := httptest.NewRecorder()
		cases[i].forwardingMaster(rec, req)
		if rec.Code != http.StatusConflict {
			t.Fatalf("case %d expected conflict, got %d: %s", i, rec.Code, rec.Body.String())
		}
	}
}
