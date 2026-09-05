package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
	enabled := false
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
			enabled = *body.Enabled
		default:
			t.Fatalf("unexpected method %s", r.Method)
		}
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "enabled": enabled, "peer": "10.77.0.2", "proof": "test"})
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

	putReq := httptest.NewRequest(http.MethodPut, desktopForwardingMasterPath, strings.NewReader(`{"enabled":true}`))
	putRec := httptest.NewRecorder()
	a.forwardingMaster(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT failed: %d %s", putRec.Code, putRec.Body.String())
	}
	var putBody map[string]any
	if err := json.Unmarshal(putRec.Body.Bytes(), &putBody); err != nil || putBody["enabled"] != true {
		t.Fatalf("unexpected PUT body: %s", putRec.Body.String())
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
