package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"router-vpn/internal/multihoprelay"
	"strings"
	"testing"
)

func TestRelayRequestExactDecode(t *testing.T) {
	valid := `{"session_id":"` + strings.Repeat("a", 32) + `","entry_node_id":"` + strings.Repeat("a", 64) + `","exit_id":"exit","exit_mode":"shadowsocks"}`
	if _, e := decodeRelayRequest(strings.NewReader(valid)); e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{valid + `{}`, strings.Replace(valid, `"exit_id":"exit"`, `"exit_id":"exit","exit_id":"other"`, 1), strings.Replace(valid, `"exit_id":"exit"`, `"exit_id":null`, 1), strings.Replace(valid, `"exit_id":"exit"`, `"exit_id":"exit","command":"bad"`, 1), `{}`, `[]`} {
		if _, e := decodeRelayRequest(strings.NewReader(s)); e == nil {
			t.Fatal("ambiguous request", s)
		}
	}
}
func TestRelayRequiresTokenAndTunnelPeer(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.77.0.0/24")
	s := &server{cfg: cfg{Token: "secret-token"}, nets: []*net.IPNet{subnet}}
	for _, test := range []struct {
		ip, token string
		status    int
	}{{"10.77.0.2:1234", "", 403}, {"192.0.2.1:1234", "secret-token", 403}, {"10.77.0.2:1234", "secret-token", 503}} {
		r := httptest.NewRequest("GET", multihopRelayPath, nil)
		r.RemoteAddr = test.ip
		r.Header.Set("Authorization", "Bearer "+test.token)
		w := httptest.NewRecorder()
		s.multihopRelay(w, r)
		if w.Code != test.status {
			t.Fatal(w.Code, test.status)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("caching permitted")
		}
	}
}
func TestRelayRejectsUnauthenticatedReadiness(t *testing.T) {
	for _, method := range []byte{0, 2} {
		ln, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			c, e := ln.Accept()
			if e != nil {
				return
			}
			defer c.Close()
			var h [3]byte
			_, _ = io.ReadFull(c, h[:])
			_, _ = c.Write([]byte{5, method})
			if method == 2 {
				buf := make([]byte, 512)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte{1, 0})
			}
		}()
		addr := ln.Addr().(*net.TCPAddr)
		l := multihoprelay.Lease{Host: "127.0.0.1", Port: addr.Port, Username: "unique-user", Password: "unique-password"}
		e = probeRelayAuthentication(context.Background(), l)
		_ = ln.Close()
		<-done
		if (method == 2) != (e == nil) {
			t.Fatal("wrong readiness", method, e)
		}
	}
}
func TestRelayLeaseDoesNotReturnExitSecrets(t *testing.T) {
	b, _ := json.Marshal(multihoprelay.Lease{Request: multihoprelay.Request{ExitID: "exit", ExitMode: "wg"}})
	if strings.Contains(string(b), "private_key") || strings.Contains(string(b), "transport") {
		t.Fatal("exit material leaked")
	}
}

var _ = http.MethodGet
