//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"router-vpn/internal/common"
	"testing"
	"time"
)

func TestLinuxStandardServiceMTUPeerObservationExpiry(t *testing.T) {
	peer, _, _ := linuxStandardPeerFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := peer.Current(ctx); !common.ObservationContextExpired(ctx, err) {
		t.Fatalf("pure actual peer observation expiry became permanent peer replacement: %v", err)
	}
	live, finish := context.WithTimeout(context.Background(), 5*time.Second)
	defer finish()
	if err := peer.Current(live); err != nil {
		t.Fatalf("original healthy peer cannot be checked after expired read: %v", err)
	}
	original := peer.record
	peer.record.StartTicks++
	if err := peer.Current(live); err == nil || common.ObservationContextExpired(live, err) {
		t.Fatalf("actual peer record mismatch was suppressed: %v", err)
	}
	peer.record = original
}
