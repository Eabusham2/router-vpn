package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/mobiletor"
)

func desktopTorPaddingReceiptFixture(t *testing.T) (*desktopTorRuntime, desktopTorProof, time.Time) {
	t.Helper()
	_, inputs := desktopTorPolicyFixture(t)
	now := time.Now().Truncate(time.Millisecond)
	started := now.Add(-40 * time.Second)
	meta := inputs.Policy().Metadata()
	// This exercises the independent receipt boundary while public enabled
	// admission remains guarded until its native shipping host is complete.
	meta.Padding = mobiletor.TorPaddingPolicy{Enabled: true, RateKbps: 192}
	owner := &desktopTorRuntime{expected: meta, started: started}
	proof := desktopTorFixtureProof(meta, started)
	proof.HeartbeatAt = now.UnixMilli()
	desktopTorPaddingObservation(&proof, now)
	return owner, proof, now
}

func desktopTorPaddingObservation(proof *desktopTorProof, now time.Time) {
	proof.Padding = &mobiletor.PaddingReceipt{Direction: "outgoing", Accounting: "tor-link-cell",
		SessionSHA256: desktopTorDigest([]byte(proof.SessionID)), SourceSHA256: proof.SourceSHA256,
		Generation: 7, RateKbps: proof.Policy.Padding.RateKbps, ChannelCells: 16, ChannelBytes: 16 * 514,
		ObservedAt: now.Add(-time.Millisecond).UnixMilli(), ExpiresAt: now.Add(4 * time.Second).UnixMilli()}
	proof.PaddingProof = &mobiletor.DesktopBridgePaddingProof{DNSCheckedAt: now.Add(-2 * time.Millisecond),
		Proof: mobiletor.Proof{SessionID: proof.SessionID, IP: "203.0.113.19", IsTor: true, DNSProven: true, CheckedAt: now.Add(-time.Millisecond)}}
}

func desktopTorPaddingProofCopy(t *testing.T, proof desktopTorProof) desktopTorProof {
	t.Helper()
	raw, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	var result desktopTorProof
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestDesktopTorPaddingControllerRequiresActualCapturedReceiptAndFreshProof(t *testing.T) {
	owner, initial, now := desktopTorPaddingReceiptFixture(t)
	if _, err := validateDesktopTorProof(torTransitionProofBytes(t, initial), owner, now); err != nil {
		t.Fatal("captured padding receipt rejected", err)
	}
	for _, kind := range []string{"missing-receipt", "missing-proof", "source", "session", "rate", "generation", "direction", "accounting", "no-cells", "wrong-bytes", "old-observation", "future-observation", "expired", "unbounded-lease", "beyond-proof", "no-dns", "no-tor", "wrong-path", "private-exit", "future-proof", "old-dns", "dns-after-exit", "changed-policy"} {
		t.Run(kind, func(t *testing.T) {
			proof := desktopTorPaddingProofCopy(t, initial)
			switch kind {
			case "missing-receipt":
				proof.Padding = nil
			case "missing-proof":
				proof.PaddingProof = nil
			case "source":
				proof.Padding.SourceSHA256 = strings.Repeat("f", 64)
			case "session":
				proof.Padding.SessionSHA256 = strings.Repeat("f", 64)
			case "rate":
				proof.Padding.RateKbps = 64
			case "generation":
				proof.Padding.Generation = 0
			case "direction":
				proof.Padding.Direction = "bidirectional"
			case "accounting":
				proof.Padding.Accounting = "network-bytes"
			case "no-cells":
				proof.Padding.ChannelCells, proof.Padding.ChannelBytes = 0, 0
			case "wrong-bytes":
				proof.Padding.ChannelBytes++
			case "old-observation":
				proof.Padding.ObservedAt = now.Add(-mobiletor.PaddingReceiptMaxAge - time.Millisecond).UnixMilli()
			case "future-observation":
				proof.Padding.ObservedAt = now.Add(time.Millisecond).UnixMilli()
			case "expired":
				proof.Padding.ExpiresAt = now.UnixMilli()
			case "unbounded-lease":
				proof.Padding.ExpiresAt = proof.Padding.ObservedAt + mobiletor.PaddingMaxTTL.Milliseconds() + 1
			case "beyond-proof":
				proof.PaddingProof.DNSCheckedAt = now.Add(-28 * time.Second)
			case "no-dns":
				proof.PaddingProof.Proof.DNSProven = false
			case "no-tor":
				proof.PaddingProof.Proof.IsTor = false
			case "wrong-path":
				proof.PaddingProof.Proof.SessionID = strings.Repeat("c", 32)
			case "private-exit":
				proof.PaddingProof.Proof.IP = "192.168.50.133"
			case "future-proof":
				proof.PaddingProof.Proof.CheckedAt = now.Add(time.Millisecond)
			case "old-dns":
				proof.PaddingProof.DNSCheckedAt = now.Add(-mobiletor.PaddingProofMaxAge)
			case "dns-after-exit":
				proof.PaddingProof.DNSCheckedAt = now
			case "changed-policy":
				proof.Policy.Padding.RateKbps = 64
			}
			if _, err := validateDesktopTorProof(torTransitionProofBytes(t, proof), owner, now); err == nil {
				t.Fatal("unproved padding was accepted", kind)
			}
		})
	}
	for _, execution := range []string{"off", "server"} {
		proof := desktopTorPaddingProofCopy(t, initial)
		captured := &desktopTorRuntime{expected: owner.expected, started: owner.started}
		if execution == "off" {
			captured.expected.Padding.Enabled = false
		} else {
			captured.expected.Execution = "server"
		}
		proof.Policy = captured.expected
		if _, err := validateDesktopTorProof(torTransitionProofBytes(t, proof), captured, now); err == nil {
			t.Fatal("Local receipt borrowed by another execution policy", execution)
		}
	}
}

func TestDesktopTorPaddingControllerRetainsMonotonicCopiesAndOriginalConnectionProof(t *testing.T) {
	owner, initial, now := desktopTorPaddingReceiptFixture(t)
	owner.adopted = &initial
	if err := noteDesktopTorStrictHeartbeat(owner, initial); err != nil {
		t.Fatal(err)
	}
	retainedCells := owner.paddingReceipt.ChannelCells
	initial.Padding.ChannelCells++
	if owner.paddingReceipt.ChannelCells != retainedCells {
		t.Fatal("retained receipt aliased the caller")
	}
	initial.Padding.ChannelCells--
	for _, kind := range []string{"generation", "cells", "bytes", "observation", "dns-time", "path-time", "initial-ip", "initial-time"} {
		t.Run(kind, func(t *testing.T) {
			proof := desktopTorPaddingProofCopy(t, initial)
			switch kind {
			case "generation":
				proof.Padding.Generation++
			case "cells":
				proof.Padding.ChannelCells--
				proof.Padding.ChannelBytes = proof.Padding.ChannelCells * 514
			case "bytes":
				proof.Padding.ChannelBytes -= 2
			case "observation":
				proof.Padding.ObservedAt--
			case "dns-time":
				proof.PaddingProof.DNSCheckedAt = proof.PaddingProof.DNSCheckedAt.Add(-time.Millisecond)
			case "path-time":
				proof.PaddingProof.Proof.CheckedAt = proof.PaddingProof.Proof.CheckedAt.Add(-time.Millisecond)
			case "initial-ip":
				proof.Proof.IP = "203.0.113.20"
			case "initial-time":
				proof.Proof.CheckedAt = proof.Proof.CheckedAt.Add(time.Millisecond)
			}
			if _, err := validateDesktopTorProof(torTransitionProofBytes(t, proof), owner, now); err == nil {
				t.Fatal("retained owner or proof regressed", kind)
			}
		})
	}
	next := desktopTorPaddingProofCopy(t, initial)
	next.Padding.ChannelCells++
	next.Padding.ChannelBytes += 514
	next.PaddingProof.Proof.IP = "203.0.113.21"
	if _, err := validateDesktopTorProof(torTransitionProofBytes(t, next), owner, now); err != nil || next.Proof != initial.Proof {
		t.Fatal("a fresh separate Tor exit witness changed the immutable connection proof", err)
	}
}

func TestDesktopTorPaddingMTUTransitionNeedsCurrentLeaseWithoutRenewingBase(t *testing.T) {
	owner, transition, proof, now := desktopTorTransitionFixture(t)
	owner.expected.Padding = mobiletor.TorPaddingPolicy{Enabled: true, RateKbps: 192}
	proof.Policy, owner.adopted.Policy = owner.expected, owner.expected
	desktopTorPaddingObservation(&proof, now)
	baseHeartbeat, deadline := proof.HeartbeatAt, transition.ExpiresAt
	if !acceptDesktopTorMTUTransition(owner, transition, torTransitionProofBytes(t, proof), now) {
		t.Fatal("current native padding could not accompany a historical MTU base")
	}
	if owner.lastProofHeartbeat != baseHeartbeat || owner.mtuTransition.ExpiresAt != deadline || owner.adopted.Proof != proof.Proof {
		t.Fatal("padding observation refreshed the historical connection or MTU deadline")
	}
	if acceptDesktopTorMTUTransition(owner, transition, torTransitionProofBytes(t, proof), now.Add(6*time.Second)) {
		t.Fatal("bounded MTU transition excused stale or expired padding")
	}
	newer := desktopTorPaddingProofCopy(t, proof)
	desktopTorPaddingObservation(&newer, now.Add(time.Second))
	newer.Padding.ChannelCells++
	newer.Padding.ChannelBytes += 514
	if !acceptDesktopTorMTUTransition(owner, transition, torTransitionProofBytes(t, newer), now.Add(time.Second)) || owner.lastProofHeartbeat != baseHeartbeat {
		t.Fatal("actual padding progress could not advance without renewing the base")
	}
	if acceptDesktopTorMTUTransition(owner, transition, torTransitionProofBytes(t, proof), now.Add(time.Second)) {
		t.Fatal("late historical receipt replaced newer transition padding")
	}
}
