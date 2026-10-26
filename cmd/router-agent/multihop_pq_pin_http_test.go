package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"

	"router-vpn/internal/multihoprelay"
)

// Compile the actual paired PQ transport and use the registered HTTP route,
// strict decoder and production lease manager. Only native process startup is
// doubled; these tests prove identity ownership, not a real KEM exchange.
func pqPinHTTPFixture(t *testing.T, mode string, alias bool) (*http.ServeMux, *layerRunner, multihoprelay.Request) {
	t.Helper()
	assets, node := pqPairingFixture(mode)
	raw, err := json.Marshal(assets)
	if err != nil {
		t.Fatal(err)
	}
	var compiled bytes.Buffer
	if err := compilePQRelayProfile(bytes.NewReader(raw), &compiled, mode, node, "198.51.100.2"); err != nil {
		t.Fatal(err)
	}
	var transport map[string]any
	if json.Unmarshal(compiled.Bytes(), &transport) != nil {
		t.Fatal("invalid compiled paired PQ fixture")
	}
	if alias {
		key, _ := base64.StdEncoding.DecodeString(transport["private_key"].(string))
		key[0] ^= 7
		key[31] ^= 128
		transport["private_key"] = base64.StdEncoding.EncodeToString(key)
	}
	entry := strings.Repeat("a", 64)
	item := multihoprelay.Exit{ID: "exit", Mode: mode, NodeID: node, DNS: "10.88.0.1", Transport: transport}
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
	s := &server{cfg: cfg{Token: "private-packet-token", NodeID: entry}, nets: []*net.IPNet{subnet}, relay: manager}
	mux := http.NewServeMux()
	registerMultihopRelayRoute(mux, s)
	caps := manager.Available()
	if len(caps) != 1 {
		t.Fatal("missing paired PQ fixture")
	}
	q := multihoprelay.Request{SessionID: strings.Repeat("c", 32), EntryNodeID: entry, ExitID: "exit", ExitMode: mode,
		ExpectedPacketPublicKey: caps[0]["client_public_key"], ExpectedPQClientIdentity: caps[0]["pq_client_identity"],
		Port: 26241, Username: strings.Repeat("d", 48), Password: strings.Repeat("e", 48)}
	return mux, runner, q
}

func TestPQPinHTTPPreservesBothPublicIdentitiesAcrossTheOwnedLifecycle(t *testing.T) {
	for _, mode := range []string{"wg-pq", "awg2-pq"} {
		for _, alias := range []bool{false, true} {
			t.Run(mode+map[bool]string{false: "/canonical", true: "/clamped-alias"}[alias], func(t *testing.T) {
				mux, runner, q := pqPinHTTPFixture(t, mode, alias)
				response := packetPinHTTPCall(t, mux, http.MethodGet, nil)
				var caps multihoprelay.Capabilities
				if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &caps) != nil || caps.Validate(q.EntryNodeID) != nil || len(caps.Exits) != 1 || caps.Exits[0].PublicKey != q.ExpectedPacketPublicKey || caps.Exits[0].PQIdentity != q.ExpectedPQClientIdentity {
					t.Fatal("HTTP discovery changed a paired public identity", response.Code)
				}
				raw, _ := json.Marshal(q)
				for range 2 {
					response = packetPinHTTPCall(t, mux, http.MethodPut, raw)
					var lease multihoprelay.Lease
					if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &lease) != nil || lease.Request != q || runner.starts != 1 {
						t.Fatal("HTTP create/renew failed to retain both exact public pins", response.Code, response.Body.String())
					}
				}
				for _, changed := range []multihoprelay.Request{
					func() multihoprelay.Request { r := q; r.ExpectedPQClientIdentity = strings.Repeat("f", 64); return r }(),
					func() multihoprelay.Request {
						r := q
						r.ExpectedPacketPublicKey = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32)))
						return r
					}(),
					func() multihoprelay.Request { r := q; r.ExpectedPQClientIdentity = ""; return r }(),
				} {
					body, _ := json.Marshal(changed)
					for _, method := range []string{http.MethodPut, http.MethodDelete} {
						response := packetPinHTTPCall(t, mux, method, body)
						if response.Code != http.StatusForbidden || runner.starts != 1 || !runner.process.alive {
							t.Fatal("changed public pins mutated another owned lease", method, response.Code)
						}
					}
				}
				for range 2 {
					response := packetPinHTTPCall(t, mux, http.MethodDelete, raw)
					if response.Code != http.StatusOK || runner.process.alive || runner.process.stops != 1 {
						t.Fatal("exact PQ cleanup lost idempotence", response.Code)
					}
				}
			})
		}
	}
}

func TestPQPinHTTPRejectsMalformedPartialAndUnownedFields(t *testing.T) {
	for _, test := range []struct {
		name, replacement string
		status            int
	}{
		{"null", `"expected_pq_client_identity":null`, 400},
		{"empty", `"expected_pq_client_identity":""`, 400},
		{"boolean", `"expected_pq_client_identity":true`, 400},
		{"object", `"expected_pq_client_identity":{}`, 400},
		{"invalid", `"expected_pq_client_identity":"invalid"`, 403},
		{"foreign", `"expected_pq_client_identity":"` + strings.Repeat("f", 64) + `"`, 403},
		{"uppercase", `"expected_pq_client_identity":"` + strings.Repeat("A", 64) + `"`, 403},
		{"duplicate", `"expected_pq_client_identity":"x","expected_pq_client_identity":"x"`, 400},
		{"unknown-private-key", `"expected_pq_client_identity":"x","pq_secret":"never-accept"`, 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			mux, runner, q := pqPinHTTPFixture(t, "wg-pq", false)
			raw, _ := json.Marshal(q)
			field, _ := json.Marshal(q.ExpectedPQClientIdentity)
			body := strings.Replace(string(raw), `"expected_pq_client_identity":`+string(field), test.replacement, 1)
			response := packetPinHTTPCall(t, mux, http.MethodPut, []byte(body))
			if response.Code != test.status || runner.starts != 0 {
				t.Fatal("malformed PQ pin reached native startup", response.Code, test.status)
			}
		})
	}
	for _, fault := range []string{"no-packet", "no-pq", "wg", "awg2-fast", "shadowsocks", "wireguard", "amneziawg", "unknown"} {
		t.Run(fault, func(t *testing.T) {
			mux, runner, q := pqPinHTTPFixture(t, "awg2-pq", false)
			switch fault {
			case "no-packet":
				q.ExpectedPacketPublicKey = ""
			case "no-pq":
				q.ExpectedPQClientIdentity = ""
			default:
				q.ExitMode = fault
			}
			body, _ := json.Marshal(q)
			response := packetPinHTTPCall(t, mux, http.MethodPut, body)
			if response.Code != http.StatusForbidden && response.Code != http.StatusBadRequest || runner.starts != 0 {
				t.Fatal("partial or unowned pin passed the HTTP boundary", response.Code)
			}
		})
	}
}
