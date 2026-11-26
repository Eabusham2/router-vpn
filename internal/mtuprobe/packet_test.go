package mtuprobe

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestMTUPacketBindsSizePeerKeyAndFreshRequest(t *testing.T) {
	now := time.Unix(1800000000, 0)
	token, node := "fixture-private-token", strings.Repeat("a", 64)
	request, err := Request(1400, token, node, now)
	if err != nil || len(request) != 1400 {
		t.Fatal("requested packet size lost", len(request), err)
	}
	before := bytes.Clone(request)
	reply, err := Reply(request, token, node, now)
	if err != nil || len(reply) != len(request) || !bytes.Equal(before, request) {
		t.Fatal("reply changed or amplified the original request", err)
	}
	if err := ValidateReply(request, reply, token, node, now); err != nil {
		t.Fatal(err)
	}
	fresh, err := Request(1400, token, node, now)
	if err != nil {
		t.Fatal(err)
	}
	if ValidateReply(fresh, reply, token, node, now) == nil ||
		ValidateReply(request, request, token, node, now) == nil {
		t.Fatal("replayed response or blind echo accepted")
	}
	reply[len(reply)-1] ^= 1
	if ValidateReply(request, reply, token, node, now) == nil {
		t.Fatal("tampered packet accepted")
	}
	if _, err := Reply(request, "wrong-token", node, now); err == nil {
		t.Fatal("unowned credential accepted")
	}
	if _, err := Reply(request, token, node, now.Add(time.Minute)); err == nil {
		t.Fatal("expired request accepted")
	}
	if _, err := Request(9001, token, node, now); err == nil {
		t.Fatal("oversized packet admitted")
	}
}
