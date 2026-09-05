package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func TestProfileSpeedTestRejectsNonActiveSingleHopNode(t *testing.T) {
	a := &app{
		profiles: common.RouterProfileStore{
			SelectedID: "node-b",
			Profiles: []common.RouterProfile{
				{ID: "node-a", Name: "Node A", NodeKind: "router-vpn", RouterAPI: "http://127.0.0.1:1", APIToken: "token-a"},
				{ID: "node-b", Name: "Node B", NodeKind: "router-vpn", RouterAPI: "http://127.0.0.1:2", APIToken: "token-b"},
			},
		},
		state: state{Connected: true, Mode: "wg", RuntimeMode: "wg", RouterID: "node-a", Phase: "connected"},
	}

	req := httptest.NewRequest(http.MethodPost, "/api/profile/speed-test", strings.NewReader(`{"id":"node-b","bytes":1024}`))
	rr := httptest.NewRecorder()
	a.profileSpeedTest(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("profile speed test status = %d, want %d; body=%q", rr.Code, http.StatusConflict, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "does not match the active single-hop session") {
		t.Fatalf("profile speed test body = %q, want live-node identity rejection", rr.Body.String())
	}
}
