package mtuprobe

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestAuthenticatedBidirectionalPackets(t *testing.T) {
	now := time.Unix(1800000000, 0)
	token := "fixture-private-token"
	node := strings.Repeat("a", 64)
	for _, size := range []int{68, 128, 1200, 1232, 1252, 1352, 1372, 1452, 8952, 9000} {
		request, err := Request(size, token, node, now)
		if err != nil {
			t.Fatal(err)
		}
		before := append([]byte{}, request...)
		reply, err := Reply(request, token, node, now)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, request) || len(reply) != size || bytes.Equal(reply, request) {
			t.Fatal("reply altered request, amplified, or merely echoed")
		}
		if err = ValidateReply(request, reply, token, node, now); err != nil {
			t.Fatal(err)
		}
		if ValidateReply(request, request, token, node, now) == nil {
			t.Fatal("blind echo accepted")
		}
		next, _ := Request(size, token, node, now)
		if ValidateReply(next, reply, token, node, now) == nil {
			t.Fatal("another request's reply accepted")
		}
		for _, index := range []int{0, 8, 9, 10, 12, 20, 35, 36, 67, size - 1} {
			bad := append([]byte{}, reply...)
			bad[index] ^= 1
			if ValidateReply(request, bad, token, node, now) == nil {
				t.Fatal("tampering accepted", size, index)
			}
		}
	}
}
func TestRejectsWrongKeysExpiryAndLength(t *testing.T) {
	now := time.Unix(1800000000, 0)
	node := strings.Repeat("a", 64)
	req, _ := Request(1400, "private-fixture", node, now)
	for _, delta := range []time.Duration{-3 * time.Second, 16 * time.Second, time.Hour} {
		if _, err := Reply(req, "private-fixture", node, now.Add(delta)); err == nil {
			t.Fatal("expired/future request accepted")
		}
	}
	for _, token := range []string{"", "other-token"} {
		if _, err := Reply(req, token, node, now); err == nil {
			t.Fatal("wrong credential accepted")
		}
	}
	if _, err := Reply(req, "private-fixture", strings.Repeat("b", 64), now); err == nil {
		t.Fatal("wrong node accepted")
	}
	for _, size := range []int{-1, 0, 67, 9001} {
		if _, err := Request(size, "private-fixture", node, now); err == nil {
			t.Fatal("unbounded request")
		}
	}
	for _, packet := range [][]byte{nil, req[:50], req[:1399], append(append([]byte{}, req...), 0)} {
		if _, err := Reply(packet, "private-fixture", node, now); err == nil {
			t.Fatal("truncated/extended packet accepted")
		}
	}
}
func TestPrivateRateAndMemoryBound(t *testing.T) {
	limiter := &Limiter{}
	now := time.Unix(1800000000, 0)
	peer := netip.MustParseAddr("10.77.0.2")
	for i := 0; i < 64; i++ {
		if !limiter.Allow(peer, now) {
			t.Fatal("initial bounded budget lost")
		}
	}
	if limiter.Allow(peer, now) {
		t.Fatal("rate budget exceeded")
	}
	if !limiter.Allow(peer, now.Add(time.Second)) {
		t.Fatal("rate not replenished")
	}
	for _, raw := range []string{"192.0.2.1", "0.0.0.0", "fe80::1", "ff02::1", "fd77::1%en0"} {
		if limiter.Allow(netip.MustParseAddr(raw), now) {
			t.Fatal("unowned peer accepted")
		}
	}
	for i := 1; i < 128; i++ {
		if !limiter.Allow(netip.AddrFrom4([4]byte{10, 78, 0, byte(i)}), now) {
			t.Fatal("peer capacity lost")
		}
	}
	if limiter.Allow(netip.MustParseAddr("10.79.0.1"), now) {
		t.Fatal("unbounded peer table")
	}
	if !limiter.Allow(netip.MustParseAddr("10.79.0.1"), now.Add(time.Minute)) {
		t.Fatal("idle peers not pruned")
	}
}
