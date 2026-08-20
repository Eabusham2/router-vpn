package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

func testForwardingClientServer(t *testing.T) *server {
	t.Helper()
	_, tunnel, err := net.ParseCIDR("10.77.0.0/24")
	if err != nil { t.Fatal(err) }
	return &server{cfg: cfg{Token: "client-token", TunnelCIDRs: []string{"10.77.0.0/24"}}, nets: []*net.IPNet{tunnel}}
}

func testForwardingRequest(method, body string) *http.Request {
	r := httptest.NewRequest(method, "http://router.invalid"+clientForwardingMasterPath, strings.NewReader(body))
	r.RemoteAddr = "10.77.0.2:43123"
	r.Header.Set("Authorization", "Bearer client-token")
	if body != "" { r.Header.Set("Content-Type", "application/json") }
	return r
}

func TestValidatedAdminMutationBaseRequiresLoopback(t *testing.T) {
	if _, err := validatedAdminMutationBase("192.168.50.133:8790"); err == nil {
		t.Fatal("non-loopback admin mutation address was accepted")
	}
	if got, err := validatedAdminMutationBase("127.0.0.1:8790"); err != nil || got != "http://127.0.0.1:8790" {
		t.Fatalf("loopback address rejected: %q %v", got, err)
	}
}

func TestClientForwardingMasterGetAndPut(t *testing.T) {
	const adminToken = "0123456789abcdef0123456789abcdef"
	tokenPath := t.TempDir()+"/admin.token"
	if err := os.WriteFile(tokenPath, []byte(adminToken+"\n"), 0600); err != nil { t.Fatal(err) }
	var master atomic.Bool
	master.Store(true)
	var calls atomic.Int32

	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/api/admin/settings" { http.Error(w,"wrong path",404); return }
		if r.Header.Get("Authorization") != "Bearer "+adminToken { http.Error(w,"forbidden",403); return }
		if r.Method == http.MethodPut {
			var q struct{ ForwardingMaster *bool `json:"forwarding_master"` }
			if json.NewDecoder(r.Body).Decode(&q) != nil || q.ForwardingMaster == nil { http.Error(w,"bad json",400); return }
			master.Store(*q.ForwardingMaster)
		} else if r.Method != http.MethodGet { http.Error(w,"method",405); return }
		w.Header().Set("Content-Type","application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok":true,"settings":map[string]any{"forwarding_master":master.Load()}})
	}))
	defer admin.Close()
	adminAddr := strings.TrimPrefix(admin.URL,"http://")
	ip, _, err := net.SplitHostPort(adminAddr)
	if err != nil || net.ParseIP(ip) == nil || !net.ParseIP(ip).IsLoopback() { t.Fatalf("httptest did not bind loopback: %s",adminAddr) }
	t.Setenv("ROUTER_VPN_ADMIN_MUTATION_LISTEN", adminAddr)
	t.Setenv("ROUTER_VPN_ADMIN_TOKEN_FILE", tokenPath)

	s := testForwardingClientServer(t)

	getRec := httptest.NewRecorder()
	s.clientForwardingMaster(getRec, testForwardingRequest(http.MethodGet,""))
	if getRec.Code != http.StatusOK { t.Fatalf("GET status=%d body=%s",getRec.Code,getRec.Body.String()) }
	var getBody map[string]any
	if err := json.Unmarshal(getRec.Body.Bytes(),&getBody); err != nil { t.Fatal(err) }
	if enabled, ok := getBody["enabled"].(bool); !ok || !enabled { t.Fatalf("GET did not prove master on: %#v",getBody) }
	if strings.Contains(getRec.Body.String(),adminToken) { t.Fatal("admin token leaked to tunnel client response") }

	putRec := httptest.NewRecorder()
	s.clientForwardingMaster(putRec, testForwardingRequest(http.MethodPut,`{"enabled":false}`))
	if putRec.Code != http.StatusOK { t.Fatalf("PUT status=%d body=%s",putRec.Code,putRec.Body.String()) }
	var putBody map[string]any
	if err := json.Unmarshal(putRec.Body.Bytes(),&putBody); err != nil { t.Fatal(err) }
	if enabled, ok := putBody["enabled"].(bool); !ok || enabled { t.Fatalf("PUT did not prove master off: %#v",putBody) }
	if master.Load() { t.Fatal("fake admin state was not changed") }
	if calls.Load() != 2 { t.Fatalf("admin calls=%d want 2",calls.Load()) }
}

func TestClientForwardingMasterRejectsNonTunnelPeer(t *testing.T) {
	s := testForwardingClientServer(t)
	r := testForwardingRequest(http.MethodGet,"")
	r.RemoteAddr = "192.168.50.10:4444"
	rec := httptest.NewRecorder()
	s.clientForwardingMaster(rec,r)
	if rec.Code != http.StatusForbidden { t.Fatalf("status=%d want 403",rec.Code) }
}

func TestClientForwardingMasterRejectsUnknownFields(t *testing.T) {
	s := testForwardingClientServer(t)
	rec := httptest.NewRecorder()
	s.clientForwardingMaster(rec,testForwardingRequest(http.MethodPut,`{"enabled":true,"admin_token":"nope"}`))
	if rec.Code != http.StatusBadRequest { t.Fatalf("status=%d want 400",rec.Code) }
}
