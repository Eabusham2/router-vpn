package multihoprelay

import (
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

// These typed receipts are explicit native-channel inputs, never a claim that
// a worker proved traffic. The validator and complete captured-source digest
// are shipping code; no runner, subprocess, socket or native diagnostic runs.
func nodeChainReceiptFixture(t *testing.T, suffix int) (NodeChainCapture, NodeChainReceipt, string, time.Time, time.Time) {
	t.Helper()
	capture := chainCaptureFixture(t, suffix)
	now := time.Unix(1794484850, 0).UTC()
	started := now.Add(-500 * time.Millisecond)
	challenge := strings.Repeat("a", 64)
	digest, err := capture.Digest()
	if err != nil {
		t.Fatal("original complete source capture is invalid", err)
	}
	receipt := NodeChainReceipt{Schema: 1, SessionID: capture.Request.SessionID, OwnerID: capture.OwnerID,
		Peer: capture.Peer, SourceSHA256: capture.Source.SourceSHA256, RegistrySHA256: capture.RegistrySHA256,
		DNSPolicySHA256: capture.Source.DNSPolicySHA256, CaptureSHA256: digest, Nonce: challenge, Sequence: 1,
		HeartbeatAt: now.Add(-20 * time.Millisecond).UnixMilli(), Phase: NodeChainReady, FrontReady: true,
		TrafficAllowed: true, DNSProven: true, PublicProven: true, ProofAt: now.Add(-100 * time.Millisecond).UnixMilli()}
	for _, member := range capture.Source.Members {
		receipt.Prefixes = append(receipt.Prefixes, NodeChainPrefixReceipt{Position: member.Position, ProfileID: member.ProfileID,
			NodeID: member.NodeID, Mode: member.Mode, Proven: true, ResponseMS: float64(member.Position) + 0.125})
	}
	return capture, receipt, challenge, started, now
}

func nodeChainPendingReceipt(receipt NodeChainReceipt) NodeChainReceipt {
	receipt = receipt.Clone()
	receipt.Phase, receipt.TrafficAllowed, receipt.DNSProven, receipt.PublicProven = NodeChainPending, false, false, false
	receipt.ProofAt, receipt.Prefixes = 0, nil
	return receipt
}

func TestNodeChainReceiptAcceptsCompleteCapturedPendingAndReady(t *testing.T) {
	for _, suffix := range []int{1, 2, 3, 7} {
		t.Run(fmt.Sprintf("%d-total", suffix+1), func(t *testing.T) {
			capture, ready, challenge, started, now := nodeChainReceiptFixture(t, suffix)
			for _, receipt := range []NodeChainReceipt{nodeChainPendingReceipt(ready), ready} {
				if err := ValidateNodeChainReceipt(receipt, capture, challenge, started, now); err != nil {
					t.Fatal("original complete ordered receipt was refused", receipt.Phase, err)
				}
			}
			if len(ready.Prefixes) != suffix || ready.Prefixes[suffix-1].Mode != "shadowsocks" {
				t.Fatal("fixture omitted original final identity")
			}
		})
	}
}

func TestNodeChainReceiptRejectsChangedOriginalChannelOrProof(t *testing.T) {
	capture, ready, challenge, started, now := nodeChainReceiptFixture(t, 3)
	faults := map[string]func(*NodeChainReceipt){
		"schema":                  func(r *NodeChainReceipt) { r.Schema++ },
		"session":                 func(r *NodeChainReceipt) { r.SessionID = strings.Repeat("b", 32) },
		"owner":                   func(r *NodeChainReceipt) { r.OwnerID = strings.Repeat("b", 64) },
		"peer":                    func(r *NodeChainReceipt) { r.Peer = "10.77.0.3" },
		"source":                  func(r *NodeChainReceipt) { r.SourceSHA256 = strings.Repeat("b", 64) },
		"registry":                func(r *NodeChainReceipt) { r.RegistrySHA256 = strings.Repeat("b", 64) },
		"dns-policy":              func(r *NodeChainReceipt) { r.DNSPolicySHA256 = strings.Repeat("b", 64) },
		"capture":                 func(r *NodeChainReceipt) { r.CaptureSHA256 = strings.Repeat("b", 64) },
		"nonce":                   func(r *NodeChainReceipt) { r.Nonce = strings.Repeat("b", 64) },
		"sequence":                func(r *NodeChainReceipt) { r.Sequence = 0 },
		"front":                   func(r *NodeChainReceipt) { r.FrontReady = false },
		"traffic":                 func(r *NodeChainReceipt) { r.TrafficAllowed = false },
		"dns-proof":               func(r *NodeChainReceipt) { r.DNSProven = false },
		"public-proof":            func(r *NodeChainReceipt) { r.PublicProven = false },
		"no-heartbeat":            func(r *NodeChainReceipt) { r.HeartbeatAt = 0 },
		"future-heartbeat":        func(r *NodeChainReceipt) { r.HeartbeatAt = now.Add(time.Millisecond).UnixMilli() },
		"old-heartbeat":           func(r *NodeChainReceipt) { r.HeartbeatAt = now.Add(-5*time.Second - time.Millisecond).UnixMilli() },
		"pre-challenge-heartbeat": func(r *NodeChainReceipt) { r.HeartbeatAt = started.Add(-time.Second - time.Millisecond).UnixMilli() },
		"no-proof-time":           func(r *NodeChainReceipt) { r.ProofAt = 0 },
		"proof-after-heartbeat":   func(r *NodeChainReceipt) { r.ProofAt = r.HeartbeatAt + 1 },
		"old-proof":               func(r *NodeChainReceipt) { r.ProofAt = now.Add(-30*time.Second - time.Millisecond).UnixMilli() },
		"missing-prefix":          func(r *NodeChainReceipt) { r.Prefixes = r.Prefixes[:len(r.Prefixes)-1] },
		"extra-prefix":            func(r *NodeChainReceipt) { r.Prefixes = append(r.Prefixes, r.Prefixes[0]) },
		"no-prefix":               func(r *NodeChainReceipt) { r.Prefixes = nil },
		"prefix-order":            func(r *NodeChainReceipt) { r.Prefixes[0], r.Prefixes[1] = r.Prefixes[1], r.Prefixes[0] },
		"prefix-position":         func(r *NodeChainReceipt) { r.Prefixes[1].Position = 0 },
		"middle-profile":          func(r *NodeChainReceipt) { r.Prefixes[1].ProfileID += "-replacement" },
		"middle-cryptographic-id": func(r *NodeChainReceipt) { r.Prefixes[1].NodeID = strings.Repeat("b", 64) },
		"middle-mode":             func(r *NodeChainReceipt) { r.Prefixes[1].Mode = "wg" },
		"final-profile":           func(r *NodeChainReceipt) { r.Prefixes[2].ProfileID += "-replacement" },
		"final-cryptographic-id":  func(r *NodeChainReceipt) { r.Prefixes[2].NodeID = strings.Repeat("b", 64) },
		"final-mode":              func(r *NodeChainReceipt) { r.Prefixes[2].Mode = "naive-h2" },
		"unproved-middle":         func(r *NodeChainReceipt) { r.Prefixes[1].Proven = false },
		"zero-response":           func(r *NodeChainReceipt) { r.Prefixes[1].ResponseMS = 0 },
		"negative-response":       func(r *NodeChainReceipt) { r.Prefixes[1].ResponseMS = -1 },
		"overbound-response":      func(r *NodeChainReceipt) { r.Prefixes[1].ResponseMS = 120000.001 },
		"nan-response":            func(r *NodeChainReceipt) { r.Prefixes[1].ResponseMS = math.NaN() },
		"infinite-response":       func(r *NodeChainReceipt) { r.Prefixes[1].ResponseMS = math.Inf(1) },
		"negative-infinity":       func(r *NodeChainReceipt) { r.Prefixes[1].ResponseMS = math.Inf(-1) },
		"failed-phase":            func(r *NodeChainReceipt) { r.Phase = NodeChainFailed },
		"retired-phase":           func(r *NodeChainReceipt) { r.Phase = NodeChainRetired },
		"unknown-phase":           func(r *NodeChainReceipt) { r.Phase = "connected" },
	}
	for name, mutate := range faults {
		t.Run(name, func(t *testing.T) {
			changed := ready.Clone()
			mutate(&changed)
			if err := ValidateNodeChainReceipt(changed, capture, challenge, started, now); err == nil {
				t.Fatal("changed original channel or incomplete native proof was accepted", name)
			}
		})
	}
}

func TestNodeChainReceiptPendingCannotGrantPartialProof(t *testing.T) {
	capture, ready, challenge, started, now := nodeChainReceiptFixture(t, 3)
	for name, mutate := range map[string]func(*NodeChainReceipt){
		"traffic":  func(r *NodeChainReceipt) { r.TrafficAllowed = true },
		"dns":      func(r *NodeChainReceipt) { r.DNSProven = true },
		"public":   func(r *NodeChainReceipt) { r.PublicProven = true },
		"time":     func(r *NodeChainReceipt) { r.ProofAt = ready.ProofAt },
		"one-row":  func(r *NodeChainReceipt) { r.Prefixes = ready.Clone().Prefixes[:1] },
		"all-rows": func(r *NodeChainReceipt) { r.Prefixes = ready.Clone().Prefixes },
	} {
		t.Run(name, func(t *testing.T) {
			pending := nodeChainPendingReceipt(ready)
			mutate(&pending)
			if err := ValidateNodeChainReceipt(pending, capture, challenge, started, now); err == nil {
				t.Fatal("pending native front granted traffic or partial proof", name)
			}
		})
	}
}

func TestNodeChainReceiptFreshnessAndOriginalChallengeBounds(t *testing.T) {
	for _, suffix := range []int{1, 2, 3, 7} {
		t.Run(fmt.Sprintf("%d-total", suffix+1), func(t *testing.T) {
			capture, ready, challenge, _, now := nodeChainReceiptFixture(t, suffix)
			maxAge := time.Duration(15+5*suffix) * time.Second
			ready.HeartbeatAt, ready.ProofAt = now.Add(-5*time.Second).UnixMilli(), now.Add(-maxAge).UnixMilli()
			started := now.Add(-4 * time.Second)
			ready.Prefixes[0].ResponseMS = 120000
			if err := ValidateNodeChainReceipt(ready, capture, challenge, started, now); err != nil {
				t.Fatal("exact original freshness or response bound was refused", err)
			}
			ready.ProofAt--
			if err := ValidateNodeChainReceipt(ready, capture, challenge, started, now); err == nil {
				t.Fatal("older proof exceeded the original full-path freshness budget")
			}
		})
	}
	capture, ready, challenge, started, now := nodeChainReceiptFixture(t, 3)
	for name, call := range map[string]func() error{
		"empty-challenge":     func() error { return ValidateNodeChainReceipt(ready, capture, "", started, now) },
		"malformed-challenge": func() error { return ValidateNodeChainReceipt(ready, capture, "not-hex", started, now) },
		"previous-challenge":  func() error { return ValidateNodeChainReceipt(ready, capture, strings.Repeat("b", 64), started, now) },
		"zero-start":          func() error { return ValidateNodeChainReceipt(ready, capture, challenge, time.Time{}, now) },
		"backwards-clock": func() error {
			return ValidateNodeChainReceipt(ready, capture, challenge, started, started.Add(-time.Millisecond))
		},
	} {
		t.Run(name, func(t *testing.T) {
			if call() == nil {
				t.Fatal("missing, replayed or expired challenge admitted a receipt")
			}
		})
	}
}

func TestNodeChainReceiptBindsFullCaptureAndClonesPrefixes(t *testing.T) {
	capture, ready, challenge, started, now := nodeChainReceiptFixture(t, 3)
	for name, mutate := range map[string]func(*NodeChainCapture){
		"entry-profile":     func(c *NodeChainCapture) { c.Source.EntryID += "-replacement" },
		"start-layer":       func(c *NodeChainCapture) { c.Source.Members[0].StartLayer = "aes-256-gcm" },
		"server-key":        func(c *NodeChainCapture) { c.Source.Members[0].ServerPublicKey = chainCapturePublic(t, 101) },
		"client-key":        func(c *NodeChainCapture) { c.Source.Members[0].ClientPublicKey = chainCapturePublic(t, 102) },
		"local-key":         func(c *NodeChainCapture) { c.Request.LocalPacketPublicKeys[1] = chainCapturePublic(t, 103) },
		"positional-user":   func(c *NodeChainCapture) { c.Request.Users[1].Username = strings.Repeat("b", 48) },
		"positional-secret": func(c *NodeChainCapture) { c.Request.Users[1].Password = strings.Repeat("c", 48) },
		"port":              func(c *NodeChainCapture) { c.Request.Port++ },
		"host":              func(c *NodeChainCapture) { c.Host = "10.77.0.4" },
		"deadline":          func(c *NodeChainCapture) { c.BootstrapDeadline = c.BootstrapDeadline.Add(time.Millisecond) },
		"epoch":             func(c *NodeChainCapture) { c.Request.Epoch = strings.Repeat("b", 64) },
		"acquire-window":    func(c *NodeChainCapture) { c.Request.AcquireExpiresAt++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := capture.Clone()
			mutate(&changed)
			// Keep the substituted capture independently valid. The refusal must
			// bind the prior receipt to its whole original capture, not malformed JSON.
			changed.RegistrySHA256, _ = changed.Source.Digest()
			changed.Request.DescriptorSHA256 = changed.RegistrySHA256
			if err := changed.Validate(); err != nil {
				t.Fatal("capture replacement was not independently valid", err)
			}
			receipt := ready.Clone()
			receipt.RegistrySHA256 = changed.RegistrySHA256
			if err := ValidateNodeChainReceipt(receipt, changed, challenge, started, now); err == nil {
				t.Fatal("receipt was relinked to another complete captured authority", name)
			}
		})
	}
	copy := ready.Clone()
	copy.Prefixes[1].ProfileID += "-changed-copy"
	if reflect.DeepEqual(copy, ready) || ready.Prefixes[1].ProfileID != capture.Source.Members[1].ProfileID ||
		ValidateNodeChainReceipt(ready, capture, challenge, started, now) != nil {
		t.Fatal("receipt clone retained mutable prefix aliases")
	}
}
