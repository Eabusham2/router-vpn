package main

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestApplyWGOutputBuildsTruthfulPeerState(t *testing.T) {
	peers := map[string]*adminPeer{}
	key := "wg0\x00peer-key"
	if err := applyWGOutput(peers, "wg", "latest-handshakes", "wg0 peer-key 1700000000\n"); err != nil { t.Fatal(err) }
	if err := applyWGOutput(peers, "wg", "transfer", "wg0 peer-key 123 456\n"); err != nil { t.Fatal(err) }
	if err := applyWGOutput(peers, "wg", "endpoints", "wg0 peer-key 203.0.113.8:51820\n"); err != nil { t.Fatal(err) }
	if err := applyWGOutput(peers, "wg", "allowed-ips", "wg0 peer-key 10.77.0.2/32,fd77:77::2/128\n"); err != nil { t.Fatal(err) }
	p := peers[key]
	if p == nil { t.Fatal("peer was not created") }
	if p.Source != "wg" || p.Interface != "wg0" || p.PublicKey != "peer-key" { t.Fatalf("identity mismatch: %#v", p) }
	if p.RXBytes != 123 || p.TXBytes != 456 { t.Fatalf("transfer mismatch: %#v", p) }
	if p.Endpoint != "203.0.113.8:51820" { t.Fatalf("endpoint mismatch: %#v", p) }
	if len(p.AllowedIPs) != 2 || p.AllowedIPs[0] != "10.77.0.2/32" { t.Fatalf("allowed IP mismatch: %#v", p) }
}

func TestClassifyPeerUsesHandshakeAgeNotFakeSessionState(t *testing.T) {
	now := time.Now().Unix()
	cases := []struct{ age int64; want string }{{30, "recent-handshake"}, {400, "idle"}, {2000, "stale"}}
	for _, tc := range cases {
		p := &adminPeer{LatestHandshakeUnix: now - tc.age}
		classifyPeer(p)
		if p.State != tc.want { t.Fatalf("age %d: got %q want %q", tc.age, p.State, tc.want) }
	}
	p := &adminPeer{}
	classifyPeer(p)
	if p.State != "never-handshaken" { t.Fatalf("zero handshake classified as %q", p.State) }
}

func TestParseListenersHandlesIPv4IPv6AndWildcards(t *testing.T) {
	out := parseListeners("tcp LISTEN 0 4096 127.0.0.1:8789 0.0.0.0:*\nudp UNCONN 0 0 [::]:51820 [::]:*\ntcp LISTEN 0 128 *:443 *:*\n")
	if len(out) != 3 { t.Fatalf("got %d listeners: %#v", len(out), out) }
	ports := map[int]bool{}
	for _, item := range out { ports[item.Port] = true }
	for _, want := range []int{443, 8789, 51820} {
		if !ports[want] { t.Fatalf("missing listener port %d in %#v", want, out) }
	}
}

func TestAdminAuthorizationIsLoopbackAndSeparateTokenOnly(t *testing.T) {
	a := &adminServer{token: "0123456789abcdef0123456789abcdef"}
	req := httptest.NewRequest("GET", "http://127.0.0.1/api/admin/status", nil)
	req.RemoteAddr = "127.0.0.1:45000"
	req.Header.Set("Authorization", "Bearer "+a.token)
	if !a.authorized(req) { t.Fatal("valid loopback Setup Center token rejected") }

	wrong := httptest.NewRequest("GET", "http://127.0.0.1/api/admin/status", nil)
	wrong.RemoteAddr = "127.0.0.1:45001"
	wrong.Header.Set("Authorization", "Bearer client-forward-token")
	if a.authorized(wrong) { t.Fatal("client forwarding token was accepted as admin token") }

	remote := httptest.NewRequest("GET", "http://127.0.0.1/api/admin/status", nil)
	remote.RemoteAddr = "192.168.50.20:45002"
	remote.Header.Set("Authorization", "Bearer "+a.token)
	if a.authorized(remote) { t.Fatal("non-loopback source was accepted by admin plane") }
}
