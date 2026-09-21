package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

func forwardingAdminFixture(t *testing.T, handler http.Handler) {
	t.Helper()
	admin := httptest.NewServer(handler)
	t.Cleanup(admin.Close)
	tokenPath := t.TempDir() + "/admin.token"
	if err := os.WriteFile(tokenPath, []byte(strings.Repeat("a", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ROUTER_VPN_ADMIN_MUTATION_LISTEN", strings.TrimPrefix(admin.URL, "http://"))
	t.Setenv("ROUTER_VPN_ADMIN_TOKEN_FILE", tokenPath)
}

func TestForwardingMasterRejectsAmbiguousClientBodiesBeforeAdmin(t *testing.T) {
	var calls atomic.Int32
	forwardingAdminFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"settings":{"forwarding_master":false}}`))
	}))
	for _, body := range []string{
		`{"enabled":false}{"enabled":true}`,
		`{"enabled":true,"enabled":false}`,
		`{"enabled":false} trailing`,
		`{"enabled":null}`,
		`{"enabled":0}`,
		`{"enabled":"false"}`,
		`{}`,
		`[]`,
		`{"enabled":false,"path":"/api/admin/keys"}`,
		`{"enabled":false}` + strings.Repeat(" ", 4096),
	} {
		t.Run(body[:min(len(body), 80)], func(t *testing.T) {
			before := calls.Load()
			rec := httptest.NewRecorder()
			testForwardingClientServer(t).clientForwardingMaster(rec, testForwardingRequest(http.MethodPut, body))
			if rec.Code != http.StatusBadRequest || calls.Load() != before {
				t.Fatalf("status=%d admin calls=%d (before=%d), body=%s", rec.Code, calls.Load(), before, rec.Body.String())
			}
		})
	}
}

func TestForwardingMasterNeverFollowsAdminRedirects(t *testing.T) {
	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetCalls.Add(1)
		_, _ = w.Write([]byte(`{"ok":true,"settings":{"forwarding_master":false}}`))
	}))
	defer target.Close()
	forwardingAdminFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Same host, different port is especially important: Go can preserve the
		// Authorization header across that redirect by default.
		http.Redirect(w, r, target.URL+"/unexpected-admin-route", http.StatusTemporaryRedirect)
	}))
	for _, method := range []string{http.MethodGet, http.MethodPut} {
		body := ""
		if method == http.MethodPut {
			body = `{"enabled":false}`
		}
		rec := httptest.NewRecorder()
		testForwardingClientServer(t).clientForwardingMaster(rec, testForwardingRequest(method, body))
		if rec.Code != http.StatusBadGateway || targetCalls.Load() != 0 {
			t.Fatalf("method=%s status=%d redirected calls=%d", method, rec.Code, targetCalls.Load())
		}
	}
}

func TestForwardingMasterRequiresExplicitBooleanFromAdmin(t *testing.T) {
	for _, body := range []string{
		`{"ok":true}`,
		`{"ok":true,"settings":{}}`,
		`{"ok":true,"settings":{"forwarding_master":null}}`,
		`{"ok":true,"settings":{"forwarding_master":"false"}}`,
		`{"ok":true,"settings":{"forwarding_master":0}}`,
	} {
		t.Run(body, func(t *testing.T) {
			forwardingAdminFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
			}))
			for _, method := range []string{http.MethodGet, http.MethodPut} {
				payload := ""
				if method == http.MethodPut {
					payload = `{"enabled":false}`
				}
				rec := httptest.NewRecorder()
				testForwardingClientServer(t).clientForwardingMaster(rec, testForwardingRequest(method, payload))
				if rec.Code != http.StatusBadGateway {
					t.Fatalf("method=%s status=%d body=%s", method, rec.Code, rec.Body.String())
				}
			}
		})
	}
}

func TestForwardingMasterAcceptsOnlyAnExplicitFalseNotAnAbsentState(t *testing.T) {
	var calls atomic.Int32
	forwardingAdminFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"settings":{"forwarding_master":false}}`))
	}))
	rec := httptest.NewRecorder()
	testForwardingClientServer(t).clientForwardingMaster(rec, testForwardingRequest(http.MethodPut, " {\n\"enabled\": false\n} \n"))
	if rec.Code != http.StatusOK || calls.Load() != 1 || !strings.Contains(rec.Body.String(), `"enabled":false`) {
		t.Fatalf("valid false request rejected: %d %s", rec.Code, rec.Body.String())
	}
}
