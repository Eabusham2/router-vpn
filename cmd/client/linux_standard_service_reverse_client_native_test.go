//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"errors"
	"os"
	"router-vpn/internal/linuxprotection"
	"strings"
	"testing"
	"time"
)

// The service identity/pidfd and liveness checks are real. The aborted wire
// result explicitly models a positively resolved no-mutation reservation; these
// cases grant no nft authority or claim an actual protected handoff.
func reverseClientPeerFixture(t *testing.T) (*linuxStandardNodeReverseTransfer, *linuxStandardServicePeer) {
	t.Helper()
	peer, _, _ := linuxStandardPeerFixture(t)
	o := &linuxStandardServiceLaunch{peer: peer, request: linuxStandardServiceRequest{Session: strings.Repeat("a", 32)}}
	q := linuxStandardServiceReverseRequest{Intent: linuxprotection.NodeStandardTransfer{ID: strings.Repeat("b", 32), DeadlineNS: time.Now().Add(time.Second).UnixNano(), Source: linuxprotection.NodeSelection{SessionID: strings.Repeat("c", 32), SourceSHA256: strings.Repeat("d", 64), ConfigSHA256: strings.Repeat("e", 64), Policy: "always"}, SourceProfileID: "source", SourceProfileRevision: strings.Repeat("f", 64), SourceReceiptSHA256: strings.Repeat("0", 64), DestinationSession: o.request.Session, DestinationConfigSHA256: strings.Repeat("1", 64), DestinationProfileID: "destination", DestinationProfileSHA256: strings.Repeat("2", 64), Endpoint: "203.0.113.8", Policy: "always"}}
	x := &linuxStandardNodeReverseTransfer{owner: o, request: q, serviceAttempted: true}
	o.reverse = x
	return x, peer
}
func TestLinuxStandardServiceReverseClientKeepsOriginalPeer(t *testing.T) {
	for _, scenario := range []string{"original", "lost-ack-retry", "foreign-peer", "changed-intent", "transport-expiry", "mixed-failure", "late-response", "replacement"} {
		t.Run(scenario, func(t *testing.T) {
			x, peer := reverseClientPeerFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			calls := 0
			genuine := errors.New("actual source changed")
			x.owner.exchange = func(call context.Context, q linuxStandardServiceRequest, _ *os.File, before func()) (linuxStandardServiceResponse, error) {
				calls++
				if before != nil {
					before()
				}
				if call != ctx || q.Reverse != &x.request || q.Session != x.request.Intent.DestinationSession || q.Action != "reverse-abort" {
					t.Fatal("reverse call replaced original scope")
				}
				if scenario == "transport-expiry" {
					cancel()
					return linuxStandardServiceResponse{}, call.Err()
				}
				if scenario == "mixed-failure" {
					cancel()
					return linuxStandardServiceResponse{}, errors.Join(genuine, call.Err())
				}
				if scenario == "lost-ack-retry" && calls == 1 {
					return linuxStandardServiceResponse{}, errors.New("original reply lost")
				}
				r := linuxStandardServiceResponse{authenticatedPeer: peer, Reverse: &linuxStandardServiceReverseResponse{Intent: x.request.Intent, Phase: "aborted"}}
				if scenario == "foreign-peer" {
					r.authenticatedPeer = &linuxStandardServicePeer{}
				}
				if scenario == "changed-intent" {
					r.Reverse.Intent.DeadlineNS++
				}
				if scenario == "late-response" {
					cancel()
				}
				return r, nil
			}
			if scenario == "replacement" {
				x.owner.reverse = nil
			}
			_, err := x.rpcLocked(ctx, "reverse-abort")
			if scenario == "lost-ack-retry" {
				if err == nil || !x.serviceAttempted {
					t.Fatal("lost reply erased original attempt")
				}
				_, err = x.rpcLocked(ctx, "reverse-abort")
			}
			want := scenario == "original" || scenario == "lost-ack-retry"
			if (err == nil) != want {
				t.Fatal("reverse original peer/result classification", err)
			}
			if scenario == "transport-expiry" && (!errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "lost original authenticated")) {
				t.Fatal("pure read expiry invented owner loss", err)
			}
			if scenario == "mixed-failure" && (!errors.Is(err, genuine) || !errors.Is(err, context.Canceled)) {
				t.Fatal("mixed actual source failure was laundered", err)
			}
			if scenario == "replacement" && calls != 0 {
				t.Fatal("replacement sent stale reverse request")
			}
			if x.resolved.Load() || x.committed.Load() {
				t.Fatal("comparison RPC invented source settlement")
			}
		})
	}
}
func TestLinuxStandardServiceReverseStopKeepsBoundedOwner(t *testing.T) {
	x, _ := reverseClientPeerFixture(t)
	s := &desktopLinuxNodeSession{gate: make(chan struct{}, 1), parent: &desktopLinuxNodeParentCapture{}, reverse: x}
	s.gate <- struct{}{}
	x.owner.mu.Lock()
	released := make(chan struct{})
	go func() { time.Sleep(100 * time.Millisecond); x.owner.mu.Unlock(); close(released) }()
	defer func() { <-released }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := s.drainStandardReverse(ctx); !errors.Is(err, context.DeadlineExceeded) || x.resolved.Load() || s.reverse != x {
		t.Fatal("held original gate lost bounded Stop authority", err)
	}
}

func TestLinuxStandardServiceReverseCaptureKeepsBoundedIntent(t *testing.T) {
	a := &app{}
	a.mu.Lock()
	released := make(chan struct{})
	go func() { time.Sleep(100 * time.Millisecond); a.mu.Unlock(); close(released) }()
	defer func() { <-released }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if capture, err := captureStandardReverseParent(ctx, a); capture != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("original connection capture escaped bounded application admission", capture, err)
	}
}
