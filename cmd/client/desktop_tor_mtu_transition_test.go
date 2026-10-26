package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/mobiletor"
)

func desktopTorTransitionFixture(t *testing.T) (*desktopTorRuntime, mobiletor.DesktopBridgeMTUTransition, desktopTorProof, time.Time) {
	t.Helper()
	_, inputs := desktopTorPolicyFixture(t)
	now := time.Now().Truncate(time.Millisecond)
	started := now.Add(-20 * time.Second)
	baseTime := now.Add(-mobiletor.DesktopBridgeHeartbeatMaxAge - time.Second)
	proof := desktopTorFixtureProof(inputs.Policy().Metadata(), started)
	proof.HeartbeatAt = baseTime.UnixMilli()
	adopted := proof
	request := strings.Repeat("c", 32)
	owner := &desktopTorRuntime{expected: inputs.Policy().Metadata(), started: started, adopted: &adopted,
		mtu: &desktopMTUSession{generation: 1, active: request}, mtuAuthority: desktopTorMTUAuthority{generation: 1, request: request}, lastProofHeartbeat: proof.HeartbeatAt}
	readback := mobiletor.DesktopBridgeMTUReadback{Generation: 1, RequestID: request, Revision: 0,
		InterfaceName: proof.InterfaceName, InterfaceIndex: proof.InterfaceIndex, EffectiveMTU: proof.EffectiveMTU}
	proof.MTUReadback = &readback
	transition := mobiletor.DesktopBridgeMTUTransition{Schema: 1, SessionID: proof.SessionID, SourceSHA256: proof.SourceSHA256, ConfigSHA256: proof.ConfigSHA256,
		Generation: 1, RequestID: request, TransitionID: 1, From: readback, TargetMTU: 1380,
		StartedAt: baseTime.Add(-time.Millisecond).UnixMilli(), ExpiresAt: baseTime.Add(-time.Millisecond).Add(mobiletor.DesktopBridgeMTUTransitionLimit).UnixMilli(), FromHeartbeatAt: proof.HeartbeatAt}
	return owner, transition, proof, now
}

func torTransitionProofBytes(t *testing.T, proof desktopTorProof) []byte {
	t.Helper()
	raw, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestDesktopTorMTUTransitionDoesNotBecomeFreshProofOrMeasuredReadback(t *testing.T) {
	owner, transition, proof, now := desktopTorTransitionFixture(t)
	raw := torTransitionProofBytes(t, proof)
	if _, err := validateDesktopTorProof(raw, owner, now); err == nil {
		t.Fatal("aged transition base was already accepted as current proof")
	}
	if !acceptDesktopTorMTUTransition(owner, transition, raw, now) || !acceptDesktopTorMTUTransition(owner, transition, raw, now.Add(time.Second)) {
		t.Fatal("exact active native transition was not retained within its original deadline")
	}
	if owner.mtuReadback != nil || owner.lastProofHeartbeat != proof.HeartbeatAt || owner.adopted.EffectiveMTU != owner.expected.ConfiguredMTU || owner.mtuTransition.ExpiresAt != transition.ExpiresAt {
		t.Fatal("transition admission fabricated interface progress or refreshed its deadline")
	}
	if _, err := validateDesktopTorProof(raw, owner, now); err == nil {
		t.Fatal("monitor liveness exception became a fresh path proof")
	}
	if acceptDesktopTorMTUTransition(owner, transition, raw, time.UnixMilli(transition.ExpiresAt)) {
		t.Fatal("expired reader transition retained the connection")
	}
}

func TestDesktopTorMTUTransitionRejectsForeignUnprovedAndUnboundedAdmissions(t *testing.T) {
	for _, kind := range []string{"schema", "session", "source", "config", "generation", "request", "from-generation", "from-request", "transition-zero", "target-low", "target-high", "expired", "future", "extended", "before-base", "base-time", "base-interface", "base-index", "base-mtu", "base-revision", "base-policy", "base-dns", "base-health", "base-tor", "inactive", "replacement", "manual", "retired", "newer-proof"} {
		t.Run(kind, func(t *testing.T) {
			owner, transition, proof, now := desktopTorTransitionFixture(t)
			switch kind {
			case "schema":
				transition.Schema++
			case "session":
				transition.SessionID = strings.Repeat("d", 32)
			case "source":
				transition.SourceSHA256 = strings.Repeat("d", 64)
			case "config":
				transition.ConfigSHA256 = strings.Repeat("d", 64)
			case "generation":
				transition.Generation++
			case "request":
				transition.RequestID = strings.Repeat("d", 32)
			case "from-generation":
				transition.From.Generation++
			case "from-request":
				transition.From.RequestID = strings.Repeat("d", 32)
			case "transition-zero":
				transition.TransitionID = 0
			case "target-low":
				transition.TargetMTU = 1279
			case "target-high":
				transition.TargetMTU = 9001
			case "expired":
				transition.ExpiresAt = now.UnixMilli()
			case "future":
				transition.StartedAt = now.Add(2 * time.Second).UnixMilli()
				transition.ExpiresAt = transition.StartedAt + 15000
			case "extended":
				transition.ExpiresAt = transition.StartedAt + 15001
			case "before-base":
				transition.StartedAt = transition.FromHeartbeatAt + 1
			case "base-time":
				proof.HeartbeatAt++
			case "base-interface":
				transition.From.InterfaceName = "replacement"
			case "base-index":
				transition.From.InterfaceIndex++
			case "base-mtu":
				transition.From.EffectiveMTU++
			case "base-revision":
				transition.From.Revision++
			case "base-policy":
				proof.Policy.ConfiguredMTU++
			case "base-dns":
				proof.Proof.DNSProven = false
			case "base-health":
				proof.Healthy = false
			case "base-tor":
				proof.Proof.IsTor = false
			case "inactive":
				owner.mtu.active = ""
			case "replacement":
				owner.mtu.active = strings.Repeat("d", 32)
			case "manual":
				owner.expected.MTUPolicy = "manual"
			case "retired":
				owner.mtuRetiredTransition = transition.TransitionID
			case "newer-proof":
				owner.lastProofHeartbeat = transition.FromHeartbeatAt + 1
			}
			if acceptDesktopTorMTUTransition(owner, transition, torTransitionProofBytes(t, proof), now) {
				t.Fatal("unchecked transition admitted", kind)
			}
		})
	}
}

func TestDesktopTorMTUTransitionCannotRenewRelabelOrOutliveStrictCompletion(t *testing.T) {
	owner, transition, proof, now := desktopTorTransitionFixture(t)
	raw := torTransitionProofBytes(t, proof)
	if !acceptDesktopTorMTUTransition(owner, transition, raw, now) {
		t.Fatal("valid transition rejected")
	}
	for _, kind := range []string{"deadline", "target", "nonce", "higher-id-old-base", "lower-id"} {
		changed := transition
		switch kind {
		case "deadline":
			changed.ExpiresAt--
		case "target":
			changed.TargetMTU++
		case "nonce":
			changed.RequestID = strings.Repeat("e", 32)
		case "higher-id-old-base":
			changed.TransitionID++
		case "lower-id":
			changed.TransitionID--
		}
		if acceptDesktopTorMTUTransition(owner, changed, raw, now) {
			t.Fatal("retained transition was renewed or relabeled", kind)
		}
	}
	completed := proof
	completed.HeartbeatAt = now.UnixMilli()
	noteDesktopTorStrictHeartbeat(owner, completed)
	if owner.mtuRetiredTransition != transition.TransitionID || owner.mtuTransition != nil || acceptDesktopTorMTUTransition(owner, transition, raw, now) {
		t.Fatal("strict completion did not permanently retire its old transition")
	}
}

func TestDesktopTorMTUTransitionPermitsCapturedRestoreOnlyWhileItOwnsTheRequest(t *testing.T) {
	owner, transition, proof, now := desktopTorTransitionFixture(t)
	owner.mtu.active, owner.mtu.restoreMTU = "", 1400
	if !acceptDesktopTorMTUTransition(owner, transition, torTransitionProofBytes(t, proof), now) {
		t.Fatal("captured restoration could not retain its bounded reader change")
	}
	owner.mtu.restoreMTU = 0
	if acceptDesktopTorMTUTransition(owner, transition, torTransitionProofBytes(t, proof), now) {
		t.Fatal("finished restoration renewed an obsolete transition")
	}
}
