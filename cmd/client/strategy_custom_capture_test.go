package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCustomStrategyBindsDisplayedRouter(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		message    string
	}{
		{"stale", `{"expected_selected_node_id":"entry","layers":["wireguard"]}`, 409, "selected Router VPN node changed"},
		{"empty", `{"expected_selected_node_id":""}`, 400, "invalid selected Router VPN node"},
		{"null", `{"expected_selected_node_id":null}`, 400, "invalid selected Router VPN node"},
		{"invalid", `{"expected_selected_node_id":["home"]}`, 400, "invalid selected Router VPN node"},
		{"matched", `{"expected_selected_node_id":"home","layers":[]}`, 503, "CUSTOM requires at least one requested layer"},
		{"legacy", `{"layers":[]}`, 503, "CUSTOM requires at least one requested layer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := setupProfileTestApp(t)
			response := httptest.NewRecorder()
			a.strategyCustom(response, httptest.NewRequest(http.MethodPost, "/api/strategy/custom", strings.NewReader(tc.body)))
			if response.Code != tc.status || !strings.Contains(response.Body.String(), tc.message) {
				t.Fatalf("got %d %s", response.Code, response.Body)
			}
			if a.state.Phase != "off" || a.profiles.SelectedID != "home" {
				t.Fatal("a refused CUSTOM request changed the selected node or started an attempt")
			}
		})
	}
}

func TestCustomStrategyOwnsNodeWhileRequestIsRead(t *testing.T) {
	a := setupProfileTestApp(t)
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		defer r.Close()
		response := httptest.NewRecorder()
		a.strategyCustom(response, httptest.NewRequest(http.MethodPost, "/api/strategy/custom", r))
		done <- response
	}()
	// The decoder consumes the prefix only after this request owns the
	// connection transaction. It cannot complete until the final brace arrives.
	if _, err := io.WriteString(w, `{"expected_selected_node_id":"home",`); err != nil {
		t.Fatal(err)
	}
	switched := httptest.NewRecorder()
	a.selectProfile(switched, httptest.NewRequest(http.MethodPost, "/api/profile/select", strings.NewReader(`{"id":"entry"}`)))
	if switched.Code != http.StatusConflict {
		t.Fatalf("concurrent selection: %d %s", switched.Code, switched.Body)
	}
	if _, err := io.WriteString(w, `"layers":[]}`); err != nil {
		t.Fatal(err)
	}
	if response := <-done; response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "CUSTOM requires at least one requested layer") {
		t.Fatalf("original selection: %d %s", response.Code, response.Body)
	}
}
