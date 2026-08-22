package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdminMutationAuthorizationRequiresLoopbackAndToken(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	a := &adminMutationServer{token: token}

	cases := []struct {
		name       string
		remote     string
		authorize  string
		want       bool
	}{
		{"ipv4-loopback", "127.0.0.1:42000", "Bearer " + token, true},
		{"ipv6-loopback", "[::1]:42000", "Bearer " + token, true},
		{"lan-source", "192.168.50.10:42000", "Bearer " + token, false},
		{"tunnel-source", "10.77.0.2:42000", "Bearer " + token, false},
		{"public-source", "8.8.8.8:42000", "Bearer " + token, false},
		{"wrong-token", "127.0.0.1:42000", "Bearer wrong", false},
		{"missing-token", "127.0.0.1:42000", "", false},
		{"malformed-source", "not-a-socket", "Bearer " + token, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "http://localhost/api/admin/settings", nil)
			r.RemoteAddr = tc.remote
			if tc.authorize != "" {
				r.Header.Set("Authorization", tc.authorize)
			}
			if got := a.authorized(r); got != tc.want {
				t.Fatalf("authorized(%q)=%v want %v", tc.remote, got, tc.want)
			}
		})
	}
}

func TestPersistentAdminListenContractIsLoopbackOnly(t *testing.T) {
	// Both the server and the tunnel-peer forwarding-master bridge use the same
	// loopback-only contract. Keep a direct executable assertion here so a future
	// configuration refactor cannot turn 8790 into a LAN/WAN control plane.
	for _, value := range []string{"127.0.0.1:8790", "[::1]:8790"} {
		if _, err := validatedAdminMutationBase(value); err != nil {
			t.Fatalf("loopback admin mutation listener %q rejected: %v", value, err)
		}
	}
	for _, value := range []string{"0.0.0.0:8790", "[::]:8790", "192.168.50.133:8790", "10.77.0.1:8790"} {
		if _, err := validatedAdminMutationBase(value); err == nil {
			t.Fatalf("non-loopback admin mutation listener %q accepted", value)
		}
	}
}
