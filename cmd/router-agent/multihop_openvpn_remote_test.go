package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/multihoprelay"
	"router-vpn/internal/nativeopenvpn"
)

type httpOpenVPNRemoteProcess struct {
	alive   bool
	receipt nativeopenvpn.RemoteReceipt
}

func (p *httpOpenVPNRemoteProcess) Alive() bool                { return p.alive }
func (p *httpOpenVPNRemoteProcess) Stop(context.Context) error { p.alive = false; return nil }
func (p *httpOpenVPNRemoteProcess) OpenVPNRemote(ctx context.Context) (nativeopenvpn.RemoteReceipt, error) {
	return p.receipt, ctx.Err()
}

type httpOpenVPNRemoteRunner struct{ p *httpOpenVPNRemoteProcess }

func (r *httpOpenVPNRemoteRunner) Start(context.Context, []byte, multihoprelay.Lease) (multihoprelay.Process, error) {
	r.p.alive = true
	return r.p, nil
}

func TestOpenVPNRemoteHTTPRequiresOwnedAuthenticatedLeaseAndStrictStatusRequest(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/fixtures/external-openvpn-multihost-client.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		External map[string]any `json:"external"`
	}
	if json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("fixture")
	}
	client, err := multihoprelay.ExternalSelection("provider-exit", "openvpn", fixture.External, nil)
	if err != nil {
		t.Fatal(err)
	}
	profile := fixture.External["openvpn"].(map[string]any)
	private := map[string]any{"protocol": "openvpn", "openvpn": map[string]any{"config": profile["config"], "username": "server-provider", "password": "server-private-password"}, "pairing_private_key": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32)))}
	paired, err := multihoprelay.PairExternalOpenVPN(client.ID, fixture.External, private, nil)
	if err != nil {
		t.Fatal(err)
	}
	node := strings.Repeat("d", 64)
	process := &httpOpenVPNRemoteProcess{receipt: nativeopenvpn.RemoteReceipt{Remote: nativeopenvpn.Remote{Host: "203.0.113.21", Port: 443, Network: "tcp"}, Generation: 2, ConnectedAt: time.Now().UnixMilli()}}
	manager, err := multihoprelay.New(multihoprelay.Config{ListenIP: "10.77.0.1", FirstPort: 26240, LastPort: 26241, TTLSeconds: 90, Exits: []multihoprelay.Exit{paired}}, node, &httpOpenVPNRemoteRunner{p: process})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close(context.Background())
	_, subnet, _ := net.ParseCIDR("10.77.0.0/24")
	server := &server{cfg: cfg{Token: "entry-token", NodeID: node}, nets: []*net.IPNet{subnet}, relay: manager}
	peer := netip.MustParseAddr("10.77.0.2")
	challenge, err := manager.PacketChallenge(peer)
	if err != nil {
		t.Fatal(err)
	}
	request := multihoprelay.Request{SessionID: strings.Repeat("e", 32), EntryNodeID: node, ExitID: client.ID, ExitMode: "openvpn", Port: 26240, Username: strings.Repeat("a", 48), Password: strings.Repeat("b", 48)}
	request, err = multihoprelay.AuthenticateExternalRequest(client, request)
	if err != nil {
		t.Fatal(err)
	}
	request, err = multihoprelay.ChallengeExternalRequest(client, request, challenge)
	if err != nil {
		t.Fatal(err)
	}
	invoke := func(method, path, token, address string, body []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(string(body)))
		r.RemoteAddr = address
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		server.multihopRelay(w, r)
		return w
	}
	body, _ := json.Marshal(request)
	for _, test := range []struct{ token, address string }{{"wrong", "10.77.0.2:1212"}, {"entry-token", "192.0.2.55:1212"}} {
		if w := invoke(http.MethodPost, multihopRelayPath, test.token, test.address, body); w.Code != 403 {
			t.Fatal("unauthenticated status", w.Code)
		}
	}
	if w := invoke(http.MethodPut, multihopRelayPath, "entry-token", "10.77.0.2:1212", body); w.Code != 200 {
		t.Fatal("owned lease rejected", w.Code, w.Body.String())
	}
	success := invoke(http.MethodPost, multihopRelayPath, "entry-token", "10.77.0.2:1212", body)
	var receipt multihoprelay.OpenVPNLeaseRemote
	if success.Code != 200 || json.Unmarshal(success.Body.Bytes(), &receipt) != nil || receipt.Remote != process.receipt || receipt.SessionID != request.SessionID || success.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("wrong fresh remote status", success.Code, success.Body.String())
	}
	for _, secret := range []string{request.Username, request.Password, request.ExternalAuthentication, "server-private-password", "server-provider", "provider_identity", "pairing_private_key"} {
		if strings.Contains(success.Body.String(), secret) {
			t.Fatal("status exposed private material")
		}
	}
	for name, mutation := range map[string]func() []byte{
		"duplicate": func() []byte {
			return []byte(strings.Replace(string(body), `"session_id":`, `"session_id":"foreign","session_id":`, 1))
		},
		"unknown": func() []byte { return []byte(strings.TrimSuffix(string(body), "}") + `,"remote":{"host":"hidden"}}`) },
		"other attempt": func() []byte {
			q := request
			q.ExternalAttempt = strings.Repeat("f", 32)
			data, _ := json.Marshal(q)
			return data
		},
	} {
		t.Run(name, func(t *testing.T) {
			w := invoke(http.MethodPost, multihopRelayPath, "entry-token", "10.77.0.2:1212", mutation())
			if w.Code < 400 {
				t.Fatal("unowned status accepted")
			}
		})
	}
	if w := invoke(http.MethodPost, multihopRelayPath+"?cached=1", "entry-token", "10.77.0.2:1212", body); w.Code != 400 {
		t.Fatal("status query alias accepted")
	}
	if w := invoke(http.MethodPost, multihopRelayPath, "entry-token", "10.77.0.3:1212", body); w.Code != 403 {
		t.Fatal("other tunnel peer read status")
	}
	if w := invoke(http.MethodDelete, multihopRelayPath, "entry-token", "10.77.0.2:1212", body); w.Code != 200 {
		t.Fatal("lease cleanup failed")
	}
	if w := invoke(http.MethodPost, multihopRelayPath, "entry-token", "10.77.0.2:1212", body); w.Code != 403 {
		t.Fatal("deleted lease returned a retained receipt")
	}
}
