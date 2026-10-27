package multihoprelay

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func torReceiptFixture(t *testing.T) (TorCapture, TorReceipt, time.Time) {
	t.Helper()
	now := time.Now()
	source, request := torFixtureConfig().TorExits[0], torFixtureRequest()
	capture := TorCapture{Schema: 1, Request: request, Source: source, RegistrySHA256: source.registrySHA256(request.EntryNodeID), OwnerID: strings.Repeat("e", 64),
		Peer: "10.77.0.2", Host: "10.77.0.1", Port: 26240, Username: strings.Repeat("a", 48), Password: strings.Repeat("b", 48), BootstrapDeadline: now.Add(TorBootstrapLimit)}
	p := newTorFixtureProcess(capture)
	p.ready.Store(true)
	receipt, _ := p.Snapshot(t.Context(), strings.Repeat("f", 64))
	return capture, receipt, time.Now()
}

func TestTorNativeReceiptRequiresExactPrivateOwnerAndRealProof(t *testing.T) {
	capture, receipt, now := torReceiptFixture(t)
	if err := ValidateTorReceipt(receipt, capture, receipt.Nonce, now, now); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*TorReceipt){
		"schema":             func(r *TorReceipt) { r.Schema = 0 },
		"session":            func(r *TorReceipt) { r.SessionID = strings.Repeat("0", 32) },
		"native-owner":       func(r *TorReceipt) { r.OwnerID = strings.Repeat("0", 64) },
		"peer":               func(r *TorReceipt) { r.Peer = "10.77.0.3" },
		"source":             func(r *TorReceipt) { r.SourceSHA256 = strings.Repeat("0", 64) },
		"registry":           func(r *TorReceipt) { r.RegistrySHA256 = strings.Repeat("0", 64) },
		"dns-policy":         func(r *TorReceipt) { r.DNSPolicySHA256 = strings.Repeat("0", 64) },
		"private-front":      func(r *TorReceipt) { r.FrontSHA256 = strings.Repeat("0", 64) },
		"nonce":              func(r *TorReceipt) { r.Nonce = strings.Repeat("0", 64) },
		"no-sequence":        func(r *TorReceipt) { r.Sequence = 0 },
		"no-front":           func(r *TorReceipt) { r.FrontReady = false },
		"future-heartbeat":   func(r *TorReceipt) { r.HeartbeatAt = now.Add(time.Second).UnixMilli() },
		"old-heartbeat":      func(r *TorReceipt) { r.HeartbeatAt = now.Add(-6 * time.Second).UnixMilli() },
		"predates-challenge": func(r *TorReceipt) { r.HeartbeatAt = now.Add(-2 * time.Second).UnixMilli() },
		"no-tor-proof":       func(r *TorReceipt) { r.IsTor = false },
		"no-dns-proof":       func(r *TorReceipt) { r.DNSProven = false },
		"private-exit":       func(r *TorReceipt) { r.ExitIP = "10.0.0.1" },
		"loopback-exit":      func(r *TorReceipt) { r.ExitIP = "127.0.0.1" },
		"missing-exit":       func(r *TorReceipt) { r.ExitIP = "" },
		"stale-proof":        func(r *TorReceipt) { r.ProofAt = now.Add(-31 * time.Second).UnixMilli() },
		"future-proof":       func(r *TorReceipt) { r.ProofAt = now.Add(time.Second).UnixMilli() },
		"missing-proof-time": func(r *TorReceipt) { r.ProofAt = 0 },
		"not-bootstrapped":   func(r *TorReceipt) { r.Bootstrap = 99 },
		"unopened-front":     func(r *TorReceipt) { r.TrafficAllowed = false },
		"retired":            func(r *TorReceipt) { r.Phase = TorRetired },
		"failed":             func(r *TorReceipt) { r.Phase = TorFailed },
	} {
		t.Run(name, func(t *testing.T) {
			bad := receipt
			mutate(&bad)
			if ValidateTorReceipt(bad, capture, receipt.Nonce, now, now) == nil {
				t.Fatal("foreign, stale or unproved native receipt accepted")
			}
		})
	}
	encoded, err := json.Marshal(receipt)
	if err != nil || strings.Contains(string(encoded), capture.Password) || strings.Contains(string(encoded), capture.Username) || strings.Contains(string(encoded), "score") || strings.Contains(string(encoded), "latency") {
		t.Fatal("receipt leaked credentials or invented a Compare measurement")
	}
}

func TestTorNativePendingReceiptCannotGrantTrafficOrProof(t *testing.T) {
	capture, ready, now := torReceiptFixture(t)
	pending := ready
	pending.Phase, pending.Bootstrap, pending.TrafficAllowed = TorPending, 60, false
	pending.ExitIP, pending.IsTor, pending.DNSProven, pending.ProofAt = "", false, false, 0
	if ValidateTorReceipt(pending, capture, ready.Nonce, now, now) != nil {
		t.Fatal("truthful pending receipt rejected")
	}
	for _, mutate := range []func(*TorReceipt){
		func(r *TorReceipt) { r.TrafficAllowed = true }, func(r *TorReceipt) { r.ExitIP = "203.0.113.20" },
		func(r *TorReceipt) { r.IsTor = true }, func(r *TorReceipt) { r.DNSProven = true },
		func(r *TorReceipt) { r.ProofAt = now.UnixMilli() }, func(r *TorReceipt) { r.Bootstrap = 101 },
	} {
		bad := pending
		mutate(&bad)
		if ValidateTorReceipt(bad, capture, ready.Nonce, now, now) == nil {
			t.Fatal("pending bootstrap was allowed to forward or claim proof")
		}
	}
}

func TestTorNativeCaptureRejectsCrossNodePolicyAndFrontSubstitution(t *testing.T) {
	capture, _, _ := torReceiptFixture(t)
	for _, mutate := range []func(*TorCapture){
		func(c *TorCapture) { c.Request.EntryNodeID = strings.Repeat("0", 64) },
		func(c *TorCapture) { c.Source.SourceSHA256 = strings.Repeat("0", 64) },
		func(c *TorCapture) { c.Request.DNSPolicySHA256 = strings.Repeat("0", 64) },
		func(c *TorCapture) { c.Source.Mode = "tor" }, func(c *TorCapture) { c.Source.ID = "other" },
		func(c *TorCapture) { c.Peer = "203.0.113.2" }, func(c *TorCapture) { c.Host = "0.0.0.0" },
		func(c *TorCapture) { c.Password = c.Username }, func(c *TorCapture) { c.Request.Port = c.Port },
		func(c *TorCapture) { c.BootstrapDeadline = time.Time{} },
	} {
		bad := capture
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("malformed or substituted native source capture accepted")
		}
	}
}
