package main

import (
	"net"
	"testing"
)

func TestNormalizePairingHost(t *testing.T) {
	for _, tc := range []struct {
		in, want string
	}{
		{"192.168.50.133", "192.168.50.133"},
		{"http://aiboard.local/", "aiboard.local"},
		{"[fd77:77::1]", "fd77:77::1"},
	} {
		got, err := normalizePairingHost(tc.in)
		if err != nil || got != tc.want { t.Fatalf("normalizePairingHost(%q) = %q, %v; want %q", tc.in, got, err, tc.want) }
	}
	for _, bad := range []string{"", "192.168.50.133:8786", "aiboard.local/path", "host?x=1", "user@host"} {
		if _, err := normalizePairingHost(bad); err == nil { t.Fatalf("normalizePairingHost(%q) unexpectedly accepted", bad) }
	}
}

func TestPairingPrivateIP(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "192.168.50.133", "10.77.0.1", "169.254.10.20", "fd77:77::1", "fe80::1"} {
		if !pairingPrivateIP(net.ParseIP(value)) { t.Fatalf("private/local pairing IP %s rejected", value) }
	}
	for _, value := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if pairingPrivateIP(net.ParseIP(value)) { t.Fatalf("public pairing IP %s accepted", value) }
	}
}
