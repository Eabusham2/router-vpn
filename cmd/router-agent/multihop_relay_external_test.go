package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"router-vpn/internal/multihoprelay"
)

func externalRelayHTTPFixture(t *testing.T) (multihoprelay.Exit, multihoprelay.Request) {
	t.Helper()
	exit := multihoprelay.Exit{ID: "saved-external", Mode: "shadowsocks", Transport: map[string]any{
		"type": "shadowsocks", "tag": "exit", "server": "203.0.113.20", "server_port": 8388,
		"method": "aes-256-gcm", "password": "exact captured external password",
	}, External: &multihoprelay.ExternalExit{ExpectedPublicIP: "203.0.113.88", ResponseProbe: multihoprelay.ResponseProbe{URL: "https://203.0.113.20/response", ServerName: "node.example"}}}
	request, err := multihoprelay.AuthenticateExternalRequest(exit, multihoprelay.Request{
		SessionID: strings.Repeat("c", 32), EntryNodeID: strings.Repeat("a", 64), ExitID: exit.ID, ExitMode: exit.Mode,
		Port: 26240, Username: strings.Repeat("d", 48), Password: strings.Repeat("e", 48),
	})
	if err != nil {
		t.Fatal(err)
	}
	return exit, request
}

// Exercise the registered HTTP handler, exact decoder, private peer/token gate,
// and production lease manager together. Only native process startup is doubled.
func TestExternalRelayHTTPRetainsAuthenticatedLeaseLifecycle(t *testing.T) {
	exit, captured := externalRelayHTTPFixture(t)
	runner := &layerRunner{}
	manager, err := multihoprelay.New(multihoprelay.Config{ListenIP: "10.77.0.1", FirstPort: 26240, LastPort: 26241, Exits: []multihoprelay.Exit{exit}}, captured.EntryNodeID, runner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	_, subnet, _ := net.ParseCIDR("10.77.0.0/24")
	s := &server{cfg: cfg{Token: "private-route-token", NodeID: captured.EntryNodeID}, nets: []*net.IPNet{subnet}, relay: manager}
	mux := http.NewServeMux()
	registerMultihopRelayRoute(mux, s)
	call := func(method string, value multihoprelay.Request, peer, token string) *httptest.ResponseRecorder {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(method, multihopRelayPath, strings.NewReader(string(raw)))
		request.RemoteAddr = peer
		request.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		if response.Header().Get("Cache-Control") != "no-store" || strings.Contains(response.Body.String(), exit.Transport["password"].(string)) {
			t.Fatal("relay response was cacheable or exposed the saved external password")
		}
		return response
	}
	const peer, token = "10.77.0.2:4321", "private-route-token"
	for _, auth := range []struct{ peer, token string }{{peer, "wrong-token"}, {"192.0.2.1:4321", token}} {
		if response := call(http.MethodPut, captured, auth.peer, auth.token); response.Code != http.StatusForbidden || runner.starts != 0 {
			t.Fatal("external lease bypassed private peer/token authorization")
		}
	}
	if response := call(http.MethodPut, captured, peer, token); response.Code != 400 || !strings.Contains(response.Body.String(), "upgrade") || runner.starts != 0 {
		t.Fatal("legacy external request did not require an explicit upgrade")
	}
	get := httptest.NewRequest(http.MethodGet, multihopRelayPath+"?external_packet=1", nil)
	get.RemoteAddr = peer
	get.Header.Set("Authorization", "Bearer "+token)
	challengeResponse := httptest.NewRecorder()
	mux.ServeHTTP(challengeResponse, get)
	var caps multihoprelay.Capabilities
	if challengeResponse.Code != 200 || json.Unmarshal(challengeResponse.Body.Bytes(), &caps) != nil || caps.PacketChallenge == nil || caps.Validate(captured.EntryNodeID) != nil {
		t.Fatal("proxy challenge discovery failed")
	}
	captured, err = multihoprelay.ChallengeExternalRequest(exit, captured, *caps.PacketChallenge)
	if err != nil {
		t.Fatal(err)
	}
	response := call(http.MethodPut, captured, peer, token)
	if response.Code != http.StatusOK {
		t.Fatalf("captured authenticated external request never reached the manager: status %d: %s", response.Code, response.Body.String())
	}
	var lease multihoprelay.Lease
	if json.Unmarshal(response.Body.Bytes(), &lease) != nil || lease.Request != captured || lease.NodeID != captured.EntryNodeID || lease.ExitNodeID != "" || runner.starts != 1 {
		t.Fatal("HTTP lease lost the captured external authentication or invented a Router exit identity")
	}
	var graph map[string]any
	if json.Unmarshal(runner.body, &graph) != nil || graph["dns"] != nil || graph["endpoints"] != nil {
		t.Fatal("external relay changed the client's DNS or added a packet interface")
	}
	outputs := graph["outbounds"].([]any)
	inputs := graph["inbounds"].([]any)
	if len(outputs) != 1 || len(inputs) != 1 {
		t.Fatal("external relay did not retain one isolated listener and transport")
	}
	transport := outputs[0].(map[string]any)
	listener := inputs[0].(map[string]any)
	if transport["type"] != "shadowsocks" || transport["server"] != exit.Transport["server"] || transport["server_port"] != float64(8388) || transport["method"] != exit.Transport["method"] || transport["password"] != exit.Transport["password"] || listener["type"] != "socks" || listener["listen"] != "10.77.0.1" || listener["listen_port"] != float64(captured.Port) {
		t.Fatal("external HTTP lease substituted its captured transport, credentials or private listener")
	}
	users := listener["users"].([]any)
	if len(users) != 1 || users[0].(map[string]any)["username"] != captured.Username || users[0].(map[string]any)["password"] != captured.Password {
		t.Fatal("external relay lost its unique authenticated listener proposal")
	}
	if response = call(http.MethodPut, captured, peer, token); response.Code != http.StatusOK || runner.starts != 1 {
		t.Fatal("external renewal replaced the captured process")
	}
	wrong := captured
	wrong.ExternalAuthentication = strings.Repeat("0", 64)
	if response = call(http.MethodDelete, wrong, peer, token); response.Code != http.StatusForbidden || !runner.process.alive {
		t.Fatal("changed external authentication could retire another lease")
	}
	if response = call(http.MethodPut, captured, "10.77.0.3:4321", token); response.Code != http.StatusForbidden || runner.starts != 1 || !runner.process.alive {
		t.Fatal("another tunnel peer could replace the owned listener")
	}
	if response = call(http.MethodDelete, captured, peer, token); response.Code != http.StatusOK || runner.process.alive || runner.process.stops != 1 {
		t.Fatal("authenticated external cleanup was not acknowledged")
	}
	var stopped struct {
		Node    string `json:"node_id"`
		Session string `json:"session_id"`
		Stopped bool   `json:"stopped"`
	}
	if json.Unmarshal(response.Body.Bytes(), &stopped) != nil || !stopped.Stopped || stopped.Node != captured.EntryNodeID || stopped.Session != captured.SessionID {
		t.Fatal("cleanup acknowledgement lost its exact entry/session identity")
	}
	if response = call(http.MethodDelete, captured, peer, token); response.Code != http.StatusOK || runner.process.stops != 1 {
		t.Fatal("external cleanup is not idempotent")
	}
	for _, field := range []string{"missing", "authentication", "fingerprint", "session", "listener"} {
		changed := captured
		wantStatus := http.StatusForbidden
		switch field {
		case "missing":
			changed.ExternalFingerprint, changed.ExternalAuthentication = "", ""
			wantStatus = http.StatusBadRequest
		case "authentication":
			changed.ExternalAuthentication = strings.Repeat("0", 64)
		case "fingerprint":
			changed.ExternalFingerprint = strings.Repeat("0", 64)
		case "session":
			changed.SessionID = strings.Repeat("f", 32)
		case "listener":
			changed.Password = strings.Repeat("f", 48)
		}
		if response = call(http.MethodPut, changed, peer, token); response.Code != wantStatus || runner.starts != 1 {
			t.Fatalf("captured authentication was reusable after changing %s", field)
		}
	}
}

func TestExternalRelayRequestRequiresExactAuthenticationPair(t *testing.T) {
	exit, captured := externalRelayHTTPFixture(t)
	manager, err := multihoprelay.New(multihoprelay.Config{ListenIP: "10.77.0.1", FirstPort: 26240, LastPort: 26241, Exits: []multihoprelay.Exit{exit}}, captured.EntryNodeID, &layerRunner{})
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := manager.PacketChallenge(netip.MustParseAddr("10.77.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	captured, err = multihoprelay.ChallengeExternalRequest(exit, captured, challenge)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(captured)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeRelayRequest(strings.NewReader(string(raw)))
	if err != nil || decoded != captured {
		t.Fatal("valid external proof was rejected or changed", err)
	}
	for _, key := range []string{"external_fingerprint", "external_authentication"} {
		for _, value := range []any{nil, "", strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("A", 64), strings.Repeat("g", 64), false, 7, map[string]any{}, []any{}} {
			var fields map[string]any
			if json.Unmarshal(raw, &fields) != nil {
				t.Fatal("invalid test request")
			}
			fields[key] = value
			changed, _ := json.Marshal(fields)
			if _, err := decodeRelayRequest(strings.NewReader(string(changed))); err == nil {
				t.Fatalf("invalid %s accepted: %T", key, value)
			}
		}
		var fields map[string]any
		_ = json.Unmarshal(raw, &fields)
		delete(fields, key)
		changed, _ := json.Marshal(fields)
		if _, err := decodeRelayRequest(strings.NewReader(string(changed))); err == nil {
			t.Fatalf("partial external proof accepted without %s", key)
		}
		duplicate := strings.TrimSuffix(string(raw), "}") + `,"` + key + `":"` + strings.Repeat("a", 64) + `"}`
		if _, err := decodeRelayRequest(strings.NewReader(duplicate)); err == nil {
			t.Fatalf("duplicate %s accepted", key)
		}
	}
	for _, changed := range []string{string(raw) + `{}`, strings.TrimSuffix(string(raw), "}") + `,"transport":{}}`} {
		if _, err := decodeRelayRequest(strings.NewReader(changed)); err == nil {
			t.Fatal("external authentication accepted an embedded transport or trailing request")
		}
	}
}
