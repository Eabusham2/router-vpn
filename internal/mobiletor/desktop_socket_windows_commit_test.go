//go:build windows && routervpn_windows_wfp

package mobiletor

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The failed retirement still owns its dynamic session lock. Observe only its
// expected persistent baseline through a separate read transaction after the
// mutation worker has joined; do not misrepresent this as a retired-session
// receipt or re-enter BFE while the commit callback is holding the write lock.
func desktopWindowsCommitObserve(ctx context.Context, scope []byte, target *DesktopWindowsProtectionTarget) (failure error) {
	expected, err := newDesktopWindowsProtectionExpected(target)
	if err != nil {
		return err
	}
	engine, err := desktopWFPOpen(false)
	if engine != nil {
		defer func() { failure = errors.Join(failure, engine.Close()) }()
	}
	if err != nil {
		return err
	}
	status, _, _ := engine.api.begin.Call(uintptr(engine.handle), 1)
	if err := desktopWFPError("begin independent failed-commit observation", status); err != nil {
		return err
	}
	engine.transaction = true
	actual, err := desktopWindowsReadBaseline(engine, desktopWindowsManagedKey("baseline", scope), scope)
	if err != nil {
		return err
	}
	if err := expected.verify(actual); err != nil {
		return err
	}
	if actual != nil {
		if err := engine.AssertComplete(actual.sublayer, actual.baseline); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func desktopWindowsCommitJoinRetirement(t *testing.T, request *DesktopWindowsProtectionRecovery) {
	t.Helper()
	if request == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := request.Close(ctx); err != nil {
		t.Error("durable retirement fixture did not join its exact native owner", err)
	}
}

func TestDesktopWindowsProtectionCommitNativeRequiresBarrier(t *testing.T) {
	// Invalid target/capture arguments keep these mandatory-callback negatives
	// incapable of opening any unscoped native policy, even under a mutant.
	ctx := context.Background()
	owner, err := NewDesktopWindowsSocketPolicySuccessorWithBarrier(ctx, DesktopSocketCapture{}, DesktopWindowsSocketOptions{}, nil, nil)
	if owner != nil || err == nil || !strings.Contains(err.Error(), "no commit barrier") {
		t.Fatal("durable successor admitted a missing persistence callback", err)
	}
	for _, explicit := range []bool{false, true} {
		var request *DesktopWindowsProtectionRecovery
		if explicit {
			request, err = NewDesktopWindowsProtectionRecoveryTargetWithBarrier(ctx, DesktopWindowsProtectionTarget{}, nil)
		} else {
			request, err = NewDesktopWindowsProtectionReleaseTargetWithBarrier(ctx, DesktopWindowsProtectionTarget{}, nil)
		}
		if request != nil || err == nil || !strings.Contains(err.Error(), "no commit barrier") {
			t.Fatal("durable retirement admitted a missing persistence callback", err)
		}
	}
}

func TestDesktopWindowsProtectionCommitNativeSuccessor(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "initial", true: "retained"}[existing], func(t *testing.T) {
			original := desktopWindowsWFPTestOwner(t, "always", false, true)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			old := desktopWindowsWFPTarget(t, original)
			if err := original.Close(ctx); err != nil {
				t.Fatal(err)
			}
			var expected *DesktopWindowsProtectionTarget
			if existing {
				expected = &old
			} else {
				desktopWindowsWFPExactRelease(t, ctx, original.fixtureScope, old, true)
			}
			next := desktopWindowsWFPTestCapture(t)
			var recorded DesktopWindowsProtectionCommit
			called := 0
			barrier := func(receipt context.Context, change DesktopWindowsProtectionCommit) error {
				called++
				if receipt.Err() != nil || change.Validate() != nil || change.Action != "successor" ||
					!reflect.DeepEqual(change.Previous, expected) || change.Candidate == nil || change.Candidate.Capture != next {
					return errors.New("durable successor callback received another native operation")
				}
				recorded = cloneDesktopWindowsProtectionCommit(change)
				return nil
			}
			candidate, err := newDesktopWindowsSocketPolicySuccessorWithBarrier(ctx, next, original.options, expected, original.fixtureScope, barrier)
			if candidate != nil {
				t.Cleanup(func() { desktopWindowsWFPJoinCandidate(t, candidate) })
			}
			if err != nil {
				t.Fatal("actual durable successor failed", err)
			}
			actual := desktopWindowsWFPTarget(t, candidate)
			if called != 1 || recorded.Candidate == nil || *recorded.Candidate != actual || !reflect.DeepEqual(recorded.Previous, expected) {
				t.Fatal("BFE successor committed without its exact normalized intent")
			}
			if err := candidate.Close(ctx); err != nil {
				t.Fatal(err)
			}
			if err := readDesktopWindowsRetainedProtection(ctx, actual, candidate.fixtureScope); err != nil {
				t.Fatal("durable successor lost its independently joined outcome", err)
			}
			desktopWindowsWFPExactRelease(t, ctx, candidate.fixtureScope, actual, true)
		})
	}
}

func TestDesktopWindowsProtectionCommitNativeSuccessorAbort(t *testing.T) {
	for _, fault := range []string{"persist-failure", "late-cancellation", "foreign-predecessor"} {
		t.Run(fault, func(t *testing.T) {
			original := desktopWindowsWFPTestOwner(t, "always", false, true)
			old := desktopWindowsWFPTarget(t, original)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := original.Close(ctx); err != nil {
				t.Fatal(err)
			}
			attempt, stop := context.WithCancel(ctx)
			defer stop()
			called := 0
			failure := errors.New("captured journal persistence rejected")
			barrier := func(context.Context, DesktopWindowsProtectionCommit) error {
				called++
				if fault == "late-cancellation" {
					stop()
					return nil
				}
				return failure
			}
			expected := old
			if fault == "foreign-predecessor" {
				expected.BaselineSHA256 = strings.Repeat("f", 64)
			}
			candidate, err := newDesktopWindowsSocketPolicySuccessorWithBarrier(attempt, desktopWindowsWFPTestCapture(t), original.options, &expected, original.fixtureScope, barrier)
			desktopWindowsWFPJoinCandidate(t, candidate)
			if err == nil {
				t.Fatal("unacknowledged successor acquired commit authority")
			}
			wantCalls := 1
			if fault == "foreign-predecessor" {
				wantCalls = 0
			}
			if called != wantCalls {
				t.Fatal("successor callback ran outside its actual captured transaction", called)
			}
			if err := readDesktopWindowsRetainedProtection(ctx, old, original.fixtureScope); err != nil {
				t.Fatal("failed durable successor changed its original native baseline", err)
			}
			desktopWindowsWFPExactRelease(t, ctx, original.fixtureScope, old, true)
		})
	}
}

func TestDesktopWindowsProtectionCommitNativeRejectsExtraCandidate(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "initial", true: "retained"}[existing], func(t *testing.T) {
			options, scope := desktopWindowsWFPTestOptions(t, "always")
			options.RetainBaselineForHandoff = true
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			var expected *DesktopWindowsProtectionTarget
			if existing {
				original := desktopWindowsWFPTestOwner(t, "always", false, true)
				target := desktopWindowsWFPTarget(t, original)
				if err := original.Close(ctx); err != nil {
					t.Fatal(err)
				}
				expected = &target
			}
			p, err := newDesktopWindowsPolicyOwner(ctx, desktopWindowsWFPTestCapture(t), options, scope)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				// A deliberately broken Close must not strand this fixture's open
				// write transaction and poison the next case. This emergency abort
				// uses only its captured engine, after the explicit Close assertion
				// below has failed; it is not the retirement proof under test.
				cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
				defer stop()
				_, err := desktopWindowsPolicyCall(p, cleanup, true, func() (struct{}, error) {
					if p.baselineEngine != nil && !p.closed {
						return struct{}{}, p.baselineEngine.Abort()
					}
					return struct{}{}, nil
				})
				if err != nil {
					t.Error("candidate fixture could not abort its exact transaction", err)
				}
				desktopWindowsWFPJoinCandidate(t, p)
				desktopWindowsWFPTestRecovery(t, scope)
			})
			p.predecessor, err = newDesktopWindowsProtectionExpected(expected)
			if err != nil {
				t.Fatal(err)
			}
			called := 0
			p.commitAction = "successor"
			p.commitBarrier = func(context.Context, DesktopWindowsProtectionCommit) error { called++; return nil }
			if err := p.acquireBaselineLock(); err != nil {
				t.Fatal(err)
			}
			p.baselineEngine, err = desktopWFPOpen(false)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.baselineEngine.Begin(); err != nil {
				t.Fatal(err)
			}
			old, err := desktopWindowsReadBaseline(p.baselineEngine, p.sublayer, p.fixtureScope)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.predecessor.verify(old); err != nil {
				t.Fatal("candidate proof fixture found an unrelated previous baseline", err)
			}
			if old != nil {
				if err := desktopWindowsDeleteBaseline(p.baselineEngine, old); err != nil {
					t.Fatal(err)
				}
			}
			if err := p.addCapturedBaseline(); err != nil {
				t.Fatal(err)
			}
			for index := range p.baseline {
				if err := p.baselineEngine.Add(&p.baseline[index]); err != nil {
					t.Fatal(err)
				}
			}
			// The extra actual rule remains uncommitted and has the same
			// test-exe AppID scope even under the production-proof mutant.
			// Close must abort its exact transaction before inspecting the
			// dynamic session through another engine. No exception is committed.
			extra := p.rule("unrecorded-candidate-permit", 4, false, 100, true, true)
			if err := p.baselineEngine.Add(&extra); err != nil {
				t.Fatal(err)
			}
			if err := p.completeSuccessorCommitBarrier(old); err == nil || called != 0 {
				t.Fatal("incomplete candidate rules acquired durable commit acknowledgment", err)
			}
			if !p.baselineEngine.transaction {
				t.Fatal("rejected candidate lost the pending native transaction fixture")
			}
			if err := p.Close(ctx); err != nil {
				t.Fatal("rejected candidate cleanup waited on its own pending transaction", err)
			}
			if !p.closed || p.locked || p.installed || p.baselineEngine.transaction || p.baselineEngine.handle != 0 || p.leaseEngine.handle != 0 {
				t.Fatal("rejected candidate cleanup retained an owned native resource")
			}
			outcome, err := p.RetainedProtectionOutcome(ctx)
			if err != nil || !reflect.DeepEqual(outcome, expected) {
				t.Fatal("rejected candidate changed the exact independently read predecessor", err)
			}
		})
	}
}

func TestDesktopWindowsProtectionCommitNativeRetirement(t *testing.T) {
	for _, name := range []string{"release-on-connect", "preserve-always", "explicit-off"} {
		t.Run(name, func(t *testing.T) {
			policy := "always"
			if name == "release-on-connect" {
				policy = "on-connect"
			}
			original := desktopWindowsWFPTestOwner(t, policy, false, true)
			target := desktopWindowsWFPTarget(t, original)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := original.Close(ctx); err != nil {
				t.Fatal(err)
			}
			called := 0
			var recorded DesktopWindowsProtectionCommit
			request, err := newDesktopWindowsProtectionTransactionTargetWithBarrier(ctx, original.fixtureScope, name == "explicit-off", &target,
				func(_ context.Context, change DesktopWindowsProtectionCommit) error {
					called++
					recorded = cloneDesktopWindowsProtectionCommit(change)
					return nil
				})
			if request != nil {
				t.Cleanup(func() { desktopWindowsCommitJoinRetirement(t, request) })
				err = errors.Join(err, request.Close(ctx))
			}
			if err != nil {
				t.Fatal("durable exact retirement did not join", err)
			}
			if name == "preserve-always" {
				if called != 0 || readDesktopWindowsRetainedProtection(ctx, target, original.fixtureScope) != nil {
					t.Fatal("normal durable release removed or rewrote Always")
				}
				desktopWindowsWFPExactRelease(t, ctx, original.fixtureScope, target, true)
				return
			}
			action := "release"
			if name == "explicit-off" {
				action = "off"
			}
			if called != 1 || recorded.Action != action || recorded.Previous == nil || *recorded.Previous != target || recorded.Candidate != nil {
				t.Fatal("BFE retirement lost its original policy or durable intent")
			}
			if absent, err := probeDesktopWindowsProtectionAbsent(ctx, original.fixtureScope); err != nil || !absent {
				t.Fatal("durable exact removal did not independently prove absence", err)
			}
		})
	}
}

func TestDesktopWindowsProtectionCommitNativeRetirementRetry(t *testing.T) {
	for _, fault := range []string{"persist-failure", "late-cancellation"} {
		t.Run(fault, func(t *testing.T) {
			original := desktopWindowsWFPTestOwner(t, "always", false, true)
			target := desktopWindowsWFPTarget(t, original)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := original.Close(ctx); err != nil {
				t.Fatal(err)
			}
			attempt, stop := context.WithCancel(ctx)
			defer stop()
			var recorded DesktopWindowsProtectionCommit
			called := 0
			var cleanup atomic.Bool
			barrier := func(_ context.Context, change DesktopWindowsProtectionCommit) error {
				if cleanup.Load() {
					return nil // Exact scoped fixture cleanup after its assertions.
				}
				called++
				if called == 1 {
					recorded = cloneDesktopWindowsProtectionCommit(change)
					if fault == "late-cancellation" {
						stop()
						return nil
					}
					return errors.New("captured journal flush failed")
				}
				if !reflect.DeepEqual(change, recorded) {
					return errors.New("native retirement retry changed its durable operation")
				}
				return nil
			}
			request, err := newDesktopWindowsProtectionTransactionTargetWithBarrier(ctx, original.fixtureScope, true, &target, barrier)
			if request != nil {
				t.Cleanup(func() {
					cleanup.Store(true)
					desktopWindowsCommitJoinRetirement(t, request)
				})
			}
			if err != nil || request == nil {
				t.Fatal("durable retirement preparation failed", err)
			}
			// The source callback controls only the actual private journal seam.
			// BFE preparation, failed commit and second attempt all remain native.
			if err := request.Close(attempt); err == nil {
				t.Fatal("unacknowledged exact retirement removed native protection")
			}
			// Join the first worker without retrying its removal. Cancellation can
			// return before the BFE abort; the retained gate proves actual join.
			if _, err := desktopWindowsPolicyCall(request.owner, ctx, true, func() (struct{}, error) { return struct{}{}, nil }); err != nil {
				t.Fatal(err)
			}
			if called != 1 || recorded.Previous == nil || *recorded.Previous != target || recorded.Action != "off" {
				t.Fatal("failed retirement lost its captured accepted intent")
			}
			if err := desktopWindowsCommitObserve(ctx, original.fixtureScope, &target); err != nil {
				t.Fatal("failed durable retirement changed its original native baseline", err)
			}
			if err := request.Close(ctx); err != nil || called != 2 {
				t.Fatal("same native retirement could not retry its exact durable intent", err, called)
			}
			if absent, err := probeDesktopWindowsProtectionAbsent(ctx, original.fixtureScope); err != nil || !absent {
				t.Fatal("retried durable retirement did not prove final absence", err)
			}
		})
	}
}
