package main

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"router-vpn/internal/awgpolicy"
	"router-vpn/internal/multihoprelay"
)

// This fixture exercises the registered HTTP route, its exact decoder, and the
// production manager. Only native process startup is doubled; no encrypted
// packet delivery is inferred from an accepted lease.
func packetPinHTTPFixture(t *testing.T, mode string, clampedAlias bool) (*http.ServeMux, *layerRunner, multihoprelay.Request) {
	t.Helper()
	private := []byte(strings.Repeat("a", 32))
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	public := base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
	if clampedAlias {
		private[0] ^= 7
		private[31] ^= 128
	}
	peer, err := ecdh.X25519().NewPrivateKey([]byte(strings.Repeat("b", 32)))
	if err != nil {
		t.Fatal(err)
	}
	transport := map[string]any{"type": "wireguard", "mtu": 1280,
		"private_key": base64.StdEncoding.EncodeToString(private), "address": []string{"10.88.0.2/32"},
		"peers": []any{map[string]any{"address": "192.0.2.2", "port": 51820,
			"public_key": base64.StdEncoding.EncodeToString(peer.PublicKey().Bytes()), "allowed_ips": []string{"0.0.0.0/0", "::/0"}}}}
	if awgpolicy.IsMode(mode) {
		transport["type"] = awgpolicy.Type
		transport["amnezia"] = map[string]string{"jc": "3", "jmin": "40", "jmax": "900", "s1": "56", "s2": "48", "s3": "24", "s4": "32", "h1": "10000000-19999999", "h2": "20000000-29999999", "h3": "30000000-39999999", "h4": "40000000-49999999"}
	}
	entry := strings.Repeat("a", 64)
	item := multihoprelay.Exit{ID: "exit", Mode: mode, NodeID: strings.Repeat("b", 64), DNS: "10.88.0.1", Transport: transport}
	runner := &layerRunner{}
	manager, err := multihoprelay.New(multihoprelay.Config{ListenIP: "10.77.0.1", FirstPort: 26240, LastPort: 26241, Exits: []multihoprelay.Exit{item}}, entry, runner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	_, subnet, _ := net.ParseCIDR("10.77.0.0/24")
	server := &server{cfg: cfg{Token: "private-packet-token", NodeID: entry}, nets: []*net.IPNet{subnet}, relay: manager}
	mux := http.NewServeMux()
	registerMultihopRelayRoute(mux, server)
	request := multihoprelay.Request{SessionID: strings.Repeat("c", 32), EntryNodeID: entry, ExitID: item.ID, ExitMode: mode,
		ExpectedPacketPublicKey: public, Port: 26241, Username: strings.Repeat("d", 48), Password: strings.Repeat("e", 48)}
	return mux, runner, request
}

func packetPinHTTPCall(t *testing.T, mux *http.ServeMux, method string, raw []byte) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, multihopRelayPath, strings.NewReader(string(raw)))
	request.RemoteAddr = "10.77.0.2:4321"
	request.Header.Set("Authorization", "Bearer private-packet-token")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("private lease response became cacheable")
	}
	return response
}

func TestPacketPinHTTPPreservesDiscoveryCreateRenewAndDelete(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, alias := range []bool{false, true} {
			t.Run(mode+map[bool]string{false: "/canonical", true: "/clamped-alias"}[alias], func(t *testing.T) {
				mux, runner, request := packetPinHTTPFixture(t, mode, alias)
				response := packetPinHTTPCall(t, mux, http.MethodGet, nil)
				var capabilities multihoprelay.Capabilities
				if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &capabilities) != nil || capabilities.Validate(request.EntryNodeID) != nil || len(capabilities.Exits) != 1 || capabilities.Exits[0].PublicKey != request.ExpectedPacketPublicKey {
					t.Fatal("HTTP discovery lost the canonical paired identity", response.Code)
				}
				raw, err := json.Marshal(request)
				if err != nil {
					t.Fatal(err)
				}
				for range 2 {
					response = packetPinHTTPCall(t, mux, http.MethodPut, raw)
					var lease multihoprelay.Lease
					if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &lease) != nil || lease.Request != request || runner.starts != 1 {
						t.Fatalf("captured packet pin did not survive HTTP create/renew: status %d, body %s", response.Code, response.Body.String())
					}
				}
				wrong := request
				wrong.ExpectedPacketPublicKey = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32)))
				changed, _ := json.Marshal(wrong)
				for _, method := range []string{http.MethodPut, http.MethodDelete} {
					if rejected := packetPinHTTPCall(t, mux, method, changed); rejected.Code != http.StatusForbidden || runner.starts != 1 || !runner.process.alive {
						t.Fatal("a different packet pin changed the owned HTTP lease", method, rejected.Code)
					}
				}
				for range 2 {
					if stopped := packetPinHTTPCall(t, mux, http.MethodDelete, raw); stopped.Code != http.StatusOK || runner.process.alive || runner.process.stops != 1 {
						t.Fatal("exact pinned HTTP cleanup did not remain idempotent", stopped.Code)
					}
				}
			})
		}
	}
}

func TestPacketPinHTTPRejectsMalformedAndUnownedFields(t *testing.T) {
	for _, test := range []struct {
		name, replace string
		status        int
	}{
		{"null", `"expected_packet_public_key":null`, 400},
		{"empty", `"expected_packet_public_key":""`, 400},
		{"boolean", `"expected_packet_public_key":true`, 400},
		{"object", `"expected_packet_public_key":{}`, 400},
		{"invalid-key", `"expected_packet_public_key":"invalid"`, 403},
		{"foreign-key", `"expected_packet_public_key":"` + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32))) + `"`, 403},
		{"noncanonical-key", `"expected_packet_public_key":"` + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32))) + `\n"`, 403},
		{"duplicate", `"expected_packet_public_key":"x","expected_packet_public_key":"x"`, 400},
		{"unknown-field", `"expected_packet_public_key":"x","transport":{}`, 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			mux, runner, request := packetPinHTTPFixture(t, "wg", false)
			raw, _ := json.Marshal(request)
			field, _ := json.Marshal(request.ExpectedPacketPublicKey)
			changed := strings.Replace(string(raw), `"expected_packet_public_key":`+string(field), test.replace, 1)
			response := packetPinHTTPCall(t, mux, http.MethodPut, []byte(changed))
			if response.Code != test.status || runner.starts != 0 {
				t.Fatal("malformed or foreign packet pin reached native startup", response.Code, test.status)
			}
		})
	}
	for _, mode := range []string{"shadowsocks", "wireguard", "amneziawg", "unknown"} {
		t.Run("unowned-mode/"+mode, func(t *testing.T) {
			mux, runner, request := packetPinHTTPFixture(t, "wg", false)
			request.ExitMode = mode
			// External modes must still carry their own challenge/authentication;
			// the standalone node packet pin never authorizes that different path.
			raw, _ := json.Marshal(request)
			response := packetPinHTTPCall(t, mux, http.MethodPut, raw)
			if response.Code != http.StatusForbidden && response.Code != http.StatusBadRequest || runner.starts != 0 {
				t.Fatal("packet pin authorized an unrelated mode", mode, response.Code)
			}
		})
	}
}
