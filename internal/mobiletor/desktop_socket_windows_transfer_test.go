//go:build windows && routervpn_windows_wfp

package mobiletor

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func desktopWindowsWFPTarget(t *testing.T, p *DesktopWindowsSocketPolicy) DesktopWindowsProtectionTarget {
	t.Helper()
	digest, err := p.PreparedBaselineSHA256(context.Background(), p.capture)
	if err != nil {
		t.Fatal("exact successor lost actual prepared baseline", err)
	}
	return DesktopWindowsProtectionTarget{Capture: p.capture, Policy: p.options.KillSwitchPolicy, BaselineSHA256: digest}
}

func desktopWindowsWFPJoinCandidate(t *testing.T, p *DesktopWindowsSocketPolicy) {
	t.Helper()
	if p != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := p.Close(ctx); err != nil {
			t.Fatal("exact successor partial owner did not join", err)
		}
	}
}

func desktopWindowsWFPExactRelease(t *testing.T, ctx context.Context, scope []byte, target DesktopWindowsProtectionTarget, explicit bool) {
	t.Helper()
	request, err := newDesktopWindowsProtectionTransactionTarget(ctx, scope, explicit, &target)
	if request != nil {
		err = errors.Join(err, request.Close(ctx))
	}
	if err != nil {
		t.Fatal("exact captured protection retirement did not join", err)
	}
}

func TestDesktopWindowsProtectionTransferBothDirections(t *testing.T) {
	original := desktopWindowsWFPTestOwner(t, "always", false, true)
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	originalTarget := desktopWindowsWFPTarget(t, original)
	if err := readDesktopWindowsRetainedProtection(ctx, originalTarget, original.fixtureScope); err == nil {
		t.Fatal("live native predecessor was mistaken for joined retained protection")
	}
	options := original.options
	options.KillSwitchPolicy = "on-connect"
	live, err := newDesktopWindowsSocketPolicySuccessor(ctx, desktopWindowsWFPTestCapture(t), options, &originalTarget, original.fixtureScope)
	if err == nil {
		desktopWindowsWFPJoinCandidate(t, live)
		t.Fatal("successor adopted an unjoined live native predecessor")
	}
	desktopWindowsWFPJoinCandidate(t, live)
	if err := original.assertBaseline(); err != nil {
		t.Fatal("rejected live successor changed the original baseline", err)
	}
	if err := original.Close(ctx); err != nil {
		t.Fatal(err)
	}
	retained, err := original.RetainedProtectionTarget(ctx)
	if err != nil || retained != originalTarget {
		t.Fatal("joined original source lost its exact target", err)
	}
	trial, err := newDesktopWindowsSocketPolicySuccessor(ctx, desktopWindowsWFPTestCapture(t), options, &originalTarget, original.fixtureScope)
	if trial != nil {
		t.Cleanup(func() { desktopWindowsWFPJoinCandidate(t, trial) })
	}
	if err != nil {
		t.Fatal("exact forward native succession failed", err)
	}
	trialTarget := desktopWindowsWFPTarget(t, trial)
	if err := readDesktopWindowsPreparedProtection(ctx, trial.capture, "on-connect", trialTarget.BaselineSHA256, trial.fixtureScope); err != nil {
		t.Fatal("forward successor lacked complete independent deny proof", err)
	}
	if err := original.Close(ctx); err != nil || trial.assertBaseline() != nil {
		t.Fatal("late original cleanup changed the prepared successor", err)
	}
	if _, err := original.RetainedProtectionTarget(ctx); err == nil {
		t.Fatal("old owner refreshed its retired target to a replacement")
	}
	if err := trial.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := readDesktopWindowsRetainedProtection(ctx, trialTarget, trial.fixtureScope); err != nil {
		t.Fatal("trial close removed its deny before reverse succession", err)
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	late, err := newDesktopWindowsSocketPolicySuccessor(cancelled, desktopWindowsWFPTestCapture(t), original.options, &trialTarget, trial.fixtureScope)
	if err == nil || late != nil {
		desktopWindowsWFPJoinCandidate(t, late)
		t.Fatal("cancelled successor acquired native replacement authority")
	}
	if err := readDesktopWindowsRetainedProtection(ctx, trialTarget, trial.fixtureScope); err != nil {
		t.Fatal("cancelled reverse succession lost retained deny", err)
	}
	restoredCapture := desktopWindowsWFPTestCapture(t)
	restoredCapture.SourceSHA256 = original.capture.SourceSHA256
	restored, err := newDesktopWindowsSocketPolicySuccessor(ctx, restoredCapture, original.options, &trialTarget, trial.fixtureScope)
	if restored != nil {
		t.Cleanup(func() { desktopWindowsWFPJoinCandidate(t, restored) })
	}
	if err != nil {
		t.Fatal("exact reverse native succession failed", err)
	}
	restoredTarget := desktopWindowsWFPTarget(t, restored)
	if restoredTarget.Capture.SourceSHA256 != originalTarget.Capture.SourceSHA256 || restoredTarget.Policy != originalTarget.Policy || restoredTarget.Capture == originalTarget.Capture {
		t.Fatal("restored native source lost its original policy or reused the old generation")
	}
	if err := restored.Close(ctx); err != nil {
		t.Fatal(err)
	}
	desktopWindowsWFPExactRelease(t, ctx, restored.fixtureScope, restoredTarget, false)
	if err := readDesktopWindowsRetainedProtection(ctx, restoredTarget, restored.fixtureScope); err != nil {
		t.Fatal("exact normal release removed Always protection", err)
	}
	desktopWindowsWFPExactRelease(t, ctx, restored.fixtureScope, restoredTarget, true)
	if absent, err := probeDesktopWindowsProtectionAbsent(ctx, restored.fixtureScope); err != nil || !absent {
		t.Fatal("explicit exact test retirement did not prove final absence", err)
	}
}

func TestDesktopWindowsProtectionTransferRejectsChangedTarget(t *testing.T) {
	original := desktopWindowsWFPTestOwner(t, "always", false, true)
	target := desktopWindowsWFPTarget(t, original)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := original.Close(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"session", "source", "network", "policy", "digest", "absent", "reused-capture", "non-retained"} {
		t.Run(name, func(t *testing.T) {
			changed, next, options := target, desktopWindowsWFPTestCapture(t), original.options
			other := desktopWindowsWFPTestCapture(t)
			expected := &changed
			switch name {
			case "session":
				changed.Capture.SessionID = other.SessionID
			case "source":
				changed.Capture.SourceSHA256 = other.SourceSHA256
			case "network":
				changed.Capture.NetworkID = other.NetworkID
			case "policy":
				changed.Policy = "on-connect"
			case "digest":
				changed.BaselineSHA256 = strings.Repeat("1", 64)
			case "absent":
				expected = nil
			case "reused-capture":
				next = target.Capture
			case "non-retained":
				options.RetainBaselineForHandoff = false
			}
			candidate, err := newDesktopWindowsSocketPolicySuccessor(ctx, next, options, expected, original.fixtureScope)
			if err == nil {
				desktopWindowsWFPJoinCandidate(t, candidate)
				t.Fatal("changed native predecessor acquired replacement authority")
			}
			desktopWindowsWFPJoinCandidate(t, candidate)
			if err := readDesktopWindowsRetainedProtection(ctx, target, original.fixtureScope); err != nil {
				t.Fatal("rejected successor changed or removed the exact old deny", err)
			}
		})
	}
	// Missing expected state is not interpreted as an initial installation.
	desktopWindowsWFPExactRelease(t, ctx, original.fixtureScope, target, true)
	missing, err := newDesktopWindowsSocketPolicySuccessor(ctx, desktopWindowsWFPTestCapture(t), original.options, &target, original.fixtureScope)
	if err == nil {
		desktopWindowsWFPJoinCandidate(t, missing)
		t.Fatal("missing predecessor was silently treated as initial absence")
	}
	desktopWindowsWFPJoinCandidate(t, missing)
	initial, err := newDesktopWindowsSocketPolicySuccessor(ctx, desktopWindowsWFPTestCapture(t), original.options, nil, original.fixtureScope)
	if initial != nil {
		t.Cleanup(func() { desktopWindowsWFPJoinCandidate(t, initial) })
	}
	if err != nil {
		t.Fatal("proved initial absence could not create its captured source", err)
	}
	initialTarget := desktopWindowsWFPTarget(t, initial)
	if err := initial.Close(ctx); err != nil {
		t.Fatal(err)
	}
	desktopWindowsWFPExactRelease(t, ctx, original.fixtureScope, initialTarget, true)
}

func TestDesktopWindowsProtectionTransferRetirementRejectsReplacement(t *testing.T) {
	original := desktopWindowsWFPTestOwner(t, "on-connect", false, true)
	originalTarget := desktopWindowsWFPTarget(t, original)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if err := original.Close(ctx); err != nil {
		t.Fatal(err)
	}
	replacement, err := newDesktopWindowsSocketPolicySuccessor(ctx, desktopWindowsWFPTestCapture(t), original.options, &originalTarget, original.fixtureScope)
	if replacement != nil {
		t.Cleanup(func() { desktopWindowsWFPJoinCandidate(t, replacement) })
	}
	if err != nil {
		t.Fatal(err)
	}
	target := desktopWindowsWFPTarget(t, replacement)
	if err := replacement.Close(ctx); err != nil {
		t.Fatal(err)
	}
	for _, explicit := range []bool{false, true} {
		wrong, err := newDesktopWindowsProtectionTransactionTarget(ctx, original.fixtureScope, explicit, &originalTarget)
		if err == nil {
			if wrong != nil {
				_ = wrong.Close(ctx)
			}
			t.Fatal("old target acquired authority over a replacement baseline")
		}
		if wrong != nil {
			if err := wrong.Close(ctx); err != nil {
				t.Fatal("rejected exact retirement did not join its own native lock", err)
			}
		}
		if err := readDesktopWindowsRetainedProtection(ctx, target, original.fixtureScope); err != nil {
			t.Fatal("rejected old-target retirement changed its replacement", err)
		}
	}
	desktopWindowsWFPExactRelease(t, ctx, original.fixtureScope, target, false)
	if absent, err := probeDesktopWindowsProtectionAbsent(ctx, original.fixtureScope); err != nil || !absent {
		t.Fatal("exact on-connect release did not prove absence", err)
	}
}

func TestDesktopWindowsProtectionTransferRejectsAdditionalPermit(t *testing.T) {
	original := desktopWindowsWFPTestOwner(t, "always", false, true)
	target := desktopWindowsWFPTarget(t, original)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if err := original.Close(ctx); err != nil {
		t.Fatal(err)
	}
	engine, err := desktopWFPOpen(false)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	extra := original.rule("unexpected-transfer-permit", 4, false, 99, true, true)
	if err := engine.Add(&extra); err != nil {
		t.Fatal(err)
	}
	removeExtra := true
	defer func() {
		if removeExtra {
			if err := engine.Delete(extra.Key); err != nil {
				t.Error(err)
			}
		}
	}()
	if err := readDesktopWindowsRetainedProtection(ctx, target, original.fixtureScope); err == nil {
		t.Fatal("exact retained target accepted an extra native permit")
	}
	candidate, err := newDesktopWindowsSocketPolicySuccessor(ctx, desktopWindowsWFPTestCapture(t), original.options, &target, original.fixtureScope)
	if candidate != nil {
		t.Cleanup(func() { desktopWindowsWFPJoinCandidate(t, candidate) })
	}
	if err == nil {
		t.Fatal("exact successor replaced an incomplete native predecessor")
	}
	if err := engine.Assert(extra); err != nil {
		t.Fatal("rejected successor removed an unknown prior permit", err)
	}
	if candidate == nil || candidate.Close(ctx) == nil {
		t.Fatal("unresolved native predecessor allowed false cleanup acknowledgement")
	}
	if err := engine.Delete(extra.Key); err != nil {
		t.Fatal(err)
	}
	removeExtra = false
	if err := candidate.Close(ctx); err != nil {
		t.Fatal("exact partial successor could not retry joined cleanup", err)
	}
	if err := readDesktopWindowsRetainedProtection(ctx, target, original.fixtureScope); err != nil {
		t.Fatal("failed successor discarded its original retained deny", err)
	}
	desktopWindowsWFPExactRelease(t, ctx, original.fixtureScope, target, true)
}

func TestDesktopWindowsProtectionTransferJoinedOutcome(t *testing.T) {
	original := desktopWindowsWFPTestOwner(t, "always", false, true)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	target := desktopWindowsWFPTarget(t, original)
	if err := original.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := readDesktopWindowsProtectionExpectation(ctx, nil, original.fixtureScope); err == nil {
		t.Fatal("explicit absence adopted a retained native baseline")
	}
	if _, err := original.RetainedProtectionOutcome(ctx); err == nil {
		t.Fatal("legacy constructor acquired an exact successor outcome")
	}

	// This owner is cancelled before native startup enters. Its only possible
	// success is an independent read of the exact unchanged predecessor; the
	// constructor's in-memory installed flag is never sufficient evidence.
	partial, err := newDesktopWindowsPolicyOwner(ctx, desktopWindowsWFPTestCapture(t), original.options, original.fixtureScope)
	if err != nil {
		t.Fatal(err)
	}
	partial.predecessor, err = newDesktopWindowsProtectionExpected(&target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { desktopWindowsWFPJoinCandidate(t, partial) })
	if _, err := partial.RetainedProtectionOutcome(ctx); err == nil {
		t.Fatal("unjoined partial successor reported a protection outcome")
	}
	if err := partial.Close(ctx); err != nil {
		t.Fatal(err)
	}
	retained, err := partial.RetainedProtectionOutcome(ctx)
	if err != nil || retained == nil || *retained != target {
		t.Fatal("joined unentered successor lost its exact unchanged predecessor", err)
	}
	retained.Capture.SessionID = strings.Repeat("1", 32)
	retained, err = partial.RetainedProtectionOutcome(ctx)
	if err != nil || retained == nil || *retained != target {
		t.Fatal("returned outcome mutated the retained native expectation", err)
	}
	stopped, stop := context.WithCancel(ctx)
	stop()
	if _, err := partial.RetainedProtectionOutcome(stopped); err == nil {
		t.Fatal("cancelled outcome read acknowledged native protection")
	}

	successor, err := newDesktopWindowsSocketPolicySuccessor(ctx, desktopWindowsWFPTestCapture(t), original.options, &target, original.fixtureScope)
	if successor != nil {
		t.Cleanup(func() { desktopWindowsWFPJoinCandidate(t, successor) })
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := successor.RetainedProtectionOutcome(ctx); err == nil {
		t.Fatal("live successor reported a joined protection outcome")
	}
	actual := desktopWindowsWFPTarget(t, successor)
	if err := successor.Close(ctx); err != nil {
		t.Fatal(err)
	}
	retained, err = successor.RetainedProtectionOutcome(ctx)
	if err != nil || retained == nil || *retained != actual {
		t.Fatal("joined successor lost its own retained outcome", err)
	}
	if _, err := partial.RetainedProtectionOutcome(ctx); err == nil {
		t.Fatal("stale partial outcome adopted a replacement native baseline")
	}
	desktopWindowsWFPExactRelease(t, ctx, original.fixtureScope, actual, true)
	if _, err := successor.RetainedProtectionOutcome(ctx); err == nil {
		t.Fatal("removed successor fabricated a retained protection outcome")
	}
	if err := readDesktopWindowsProtectionExpectation(ctx, nil, original.fixtureScope); err != nil {
		t.Fatal("explicit initial absence lacked exact native readback", err)
	}
	absent, err := newDesktopWindowsPolicyOwner(ctx, desktopWindowsWFPTestCapture(t), original.options, original.fixtureScope)
	if err != nil {
		t.Fatal(err)
	}
	absent.predecessor, err = newDesktopWindowsProtectionExpected(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { desktopWindowsWFPJoinCandidate(t, absent) })
	if err := absent.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if outcome, err := absent.RetainedProtectionOutcome(ctx); err != nil || outcome != nil {
		t.Fatal("joined unentered initial source did not prove unchanged absence", err)
	}
}
