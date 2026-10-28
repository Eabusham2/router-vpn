package mobiletor

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"
)

func TestPaddingReceiptRequiresExactNativeOwnerPolicyAndActualLifetime(t *testing.T) {
	now := time.Now().Truncate(time.Millisecond)
	session, source := strings.Repeat("a", 64), strings.Repeat("b", 64)
	policy := TorPaddingPolicy{Enabled: true, RateKbps: 64}
	base := PaddingReceipt{Direction: "outgoing", Accounting: "tor-link-cell", SessionSHA256: session, SourceSHA256: source,
		Generation: 3, RateKbps: 64, ChannelCells: 10, ChannelBytes: 5140, ObservedAt: now.Add(-time.Second).UnixMilli(), ExpiresAt: now.Add(3 * time.Second).UnixMilli()}
	proofUntil := now.Add(4 * time.Second)
	if err := ValidatePaddingReceipt(&base, policy, session, source, proofUntil, now); err != nil {
		t.Fatal(err)
	}
	for _, rate := range []int{32, 64, 192} {
		copy := base
		copy.RateKbps = rate
		if err := ValidatePaddingReceipt(&copy, TorPaddingPolicy{Enabled: true, RateKbps: rate}, session, source, proofUntil, now); err != nil {
			t.Fatal("valid bounded native rate was rejected", rate, err)
		}
	}
	for name, mutate := range map[string]func(*PaddingReceipt){
		"direction":        func(r *PaddingReceipt) { r.Direction = "bidirectional" },
		"accounting":       func(r *PaddingReceipt) { r.Accounting = "delivered-bytes" },
		"session":          func(r *PaddingReceipt) { r.SessionSHA256 = strings.Repeat("c", 64) },
		"source":           func(r *PaddingReceipt) { r.SourceSHA256 = strings.Repeat("d", 64) },
		"generation":       func(r *PaddingReceipt) { r.Generation = 0 },
		"generation-max":   func(r *PaddingReceipt) { r.Generation = math.MaxInt64 + 1 },
		"rate":             func(r *PaddingReceipt) { r.RateKbps = 192 },
		"no-channel":       func(r *PaddingReceipt) { r.ChannelCells = 0 },
		"overflow":         func(r *PaddingReceipt) { r.ChannelCells = math.MaxUint64 },
		"small-byte-count": func(r *PaddingReceipt) { r.ChannelBytes = r.ChannelCells*512 - 2 },
		"large-byte-count": func(r *PaddingReceipt) { r.ChannelBytes = r.ChannelCells*514 + 2 },
		"odd-byte-count":   func(r *PaddingReceipt) { r.ChannelBytes-- },
		"future":           func(r *PaddingReceipt) { r.ObservedAt = now.Add(time.Millisecond).UnixMilli() },
		"old":              func(r *PaddingReceipt) { r.ObservedAt = now.Add(-PaddingReceiptMaxAge - time.Millisecond).UnixMilli() },
		"expired":          func(r *PaddingReceipt) { r.ExpiresAt = now.UnixMilli() },
		"extended":         func(r *PaddingReceipt) { r.ExpiresAt = now.Add(PaddingMaxTTL + time.Second).UnixMilli() },
		"past-proof":       func(r *PaddingReceipt) { r.ExpiresAt = proofUntil.Add(time.Millisecond).UnixMilli() },
	} {
		t.Run(name, func(t *testing.T) {
			copy := base
			mutate(&copy)
			if err := ValidatePaddingReceipt(&copy, policy, session, source, proofUntil, now); err == nil {
				t.Fatal("unowned, stale or invalid native padding receipt accepted")
			}
		})
	}
	for _, invalid := range []TorPaddingPolicy{{}, {Enabled: false, RateKbps: 64}, {Enabled: true}, {Enabled: true, RateKbps: -1}, {Enabled: true, RateKbps: 193}} {
		if err := ValidatePaddingReceipt(&base, invalid, session, source, proofUntil, now); err == nil {
			t.Fatal("padding receipt overrode the saved Off or invalid rate selection")
		}
	}
	if ValidatePaddingReceipt(nil, policy, session, source, proofUntil, now) == nil || ValidatePaddingReceipt(&base, policy, session, source, time.Time{}, now) == nil ||
		ValidatePaddingReceipt(&base, policy, session, source, proofUntil, time.Time{}) == nil || ValidatePaddingReceipt(&base, policy, "", source, proofUntil, now) == nil {
		t.Fatal("missing captured owner, receipt or proof deadline was accepted")
	}
	for _, dormant := range []int{0, 32, 192} {
		if err := ValidatePaddingReceipt(nil, TorPaddingPolicy{RateKbps: dormant}, "", "", time.Time{}, now); err != nil {
			t.Fatal("Off unexpectedly acquired a native padding requirement", err)
		}
	}
}

func TestPaddingReceiptUsesOnlyCurrentLeaseCountersAndCopiedNativeObservation(t *testing.T) {
	peer := newPaddingLeasePeer(t)
	until := time.Now().Add(PaddingProofMaxAge)
	lease, err := NewPaddingLease(t.Context(), peer.control, paddingLeaseOptions(until, func(error) { t.Error("explicit cancellation retired a replacement") }))
	if err != nil {
		t.Fatal(err)
	}
	defer joinPaddingLeaseTest(lease)
	if receipt, valid := lease.NativeReceipt(); receipt != nil || valid {
		t.Fatal("an unstarted lease acquired a padding receipt")
	}
	if err := lease.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	first, valid := lease.NativeReceipt()
	if !valid || first == nil || first.SessionSHA256 != paddingTestIdentity.SessionSHA256 || first.SourceSHA256 != paddingTestIdentity.SourceSHA256 || first.Generation != 7 || first.ChannelCells == 0 {
		t.Fatal("actual native control accounting did not produce its captured receipt")
	}
	first.SourceSHA256 = strings.Repeat("f", 64)
	first.ChannelCells = 0
	second, valid := lease.NativeReceipt()
	if !valid || second == nil || second.SourceSHA256 == first.SourceSHA256 || second.ChannelCells == 0 || second.ObservedAt > time.Now().UnixMilli() || second.ExpiresAt > until.UnixMilli() {
		t.Fatal("a caller mutated the retained lease or extended native observation")
	}
	lease.Cancel()
	if receipt, valid := lease.NativeReceipt(); receipt != nil || valid {
		t.Fatal("a cancelled native lease retained cover authority")
	}
	if err := lease.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if receipt, valid := (*PaddingLease)(nil).NativeReceipt(); receipt != nil || valid {
		t.Fatal("a missing native lease acquired cover authority")
	}
}
