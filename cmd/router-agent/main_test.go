package main

import (
	"fmt"
	"net"
	"net/http/httptest"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func TestForwardValidationPreservesProtocolRangesTargetAndDMZ(t *testing.T) {
	reserved := []int{22, 53, 80, 443, 585, 1080, 8786, 8787, 9443, 14444, 51820}
	valid := []common.ForwardRequest{
		{Protocol: "tcp", From: 5000, To: 5000, TargetPort: 6000},
		{Protocol: "udp", From: 6000, To: 6010},
		{Protocol: "both", From: 7000, To: 7000},
		{Protocol: "both", DMZ: true},
	}
	for _, q := range valid {
		if err := validateForward(q, reserved); err != nil {
			t.Fatalf("valid forward rejected: %+v: %v", q, err)
		}
	}
	invalid := []common.ForwardRequest{
		{Protocol: "icmp", From: 5000, To: 5000},
		{Protocol: "tcp", From: 443, To: 443},
		{Protocol: "udp", From: 6000, To: 6002, TargetPort: 7000},
		{Protocol: "tcp", From: 0, To: 1},
		{Protocol: "tcp", From: 1, To: 5000},
	}
	for _, q := range invalid {
		if err := validateForward(q, reserved); err == nil {
			t.Fatalf("invalid forward accepted: %+v", q)
		}
	}
}

func TestProtectedDMZExcludesSensitivePorts(t *testing.T) {
	reserved := []int{22, 53, 80, 443, 585, 1080, 8786, 8787, 9443, 14444, 51820}
	ranges := allowedRanges(reserved)
	for _, protected := range reserved {
		if rangeContains(ranges, protected) {
			t.Fatalf("Protected DMZ leaked reserved port %d through ranges %v", protected, ranges)
		}
	}
	for _, allowed := range []int{1, 5000, 65535} {
		if !rangeContains(ranges, allowed) {
			t.Fatalf("Protected DMZ unexpectedly omitted allowed port %d from %v", allowed, ranges)
		}
	}
}

func rangeContains(ranges []string, port int) bool {
	for _, r := range ranges {
		var a, b int
		if _, err := fmtSscanfRange(r, &a, &b); err == nil && port >= a && port <= b {
			return true
		}
	}
	return false
}

func fmtSscanfRange(value string, a, b *int) (int, error) {
	if strings.Contains(value, "-") {
		return fmt.Sscanf(value, "%d-%d", a, b)
	}
	n, err := fmt.Sscanf(value, "%d", a)
	*b = *a
	return n, err
}

func TestDNATFormattingIPv4AndIPv6(t *testing.T) {
	if got := formatDNAT(net.ParseIP("10.77.0.2"), 1234); got != "10.77.0.2:1234" {
		t.Fatalf("IPv4 DNAT=%q", got)
	}
	if got := formatDNAT(net.ParseIP("fd77:77::2"), 1234); got != "[fd77:77::2]:1234" {
		t.Fatalf("IPv6 DNAT with port=%q", got)
	}
	if got := formatDNAT(net.ParseIP("fd77:77::2"), 0); got != "fd77:77::2" {
		t.Fatalf("IPv6 DNAT range=%q", got)
	}
}

func TestSensitiveRouterAgentMutationsRequireTokenAndTunnelSource(t *testing.T) {
	s := &server{cfg: cfg{Token: "client-control-token"}}
	_, n4, _ := net.ParseCIDR("10.77.0.0/24")
	_, n6, _ := net.ParseCIDR("fd77:77::/64")
	s.nets = []*net.IPNet{n4, n6}

	req := httptest.NewRequest("POST", "http://router/api/forward", nil)
	req.RemoteAddr = "10.77.0.2:40000"
	if _, err := s.authorized(req); err == nil {
		t.Fatal("missing bearer token was authorized")
	}
	req.Header.Set("Authorization", "Bearer wrong")
	if _, err := s.authorized(req); err == nil {
		t.Fatal("wrong bearer token was authorized")
	}
	req.Header.Set("Authorization", "Bearer client-control-token")
	if ip, err := s.authorized(req); err != nil || !ip.Equal(net.ParseIP("10.77.0.2")) {
		t.Fatalf("valid IPv4 tunnel peer rejected: ip=%v err=%v", ip, err)
	}
	req.RemoteAddr = "192.168.50.50:40000"
	if _, err := s.authorized(req); err == nil {
		t.Fatal("LAN source outside tunnel CIDRs was authorized")
	}
	req.RemoteAddr = "[fd77:77::2]:40000"
	if ip, err := s.authorized(req); err != nil || !ip.Equal(net.ParseIP("fd77:77::2")) {
		t.Fatalf("valid IPv6 tunnel peer rejected: ip=%v err=%v", ip, err)
	}
}
