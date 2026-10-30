//go:build windows && routervpn_windows_wfp

package mobiletor

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func desktopWindowsObservationClose(t *testing.T, observation *DesktopWindowsProtectionObservation) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := observation.Close(ctx); err != nil {
		t.Error("native observation did not join its exact snapshot", err)
	}
}

func TestDesktopWindowsProtectionObservationNativeOutcomes(t *testing.T) {
	for _, retained := range []bool{false, true} {
		t.Run(map[bool]string{false: "absence", true: "retained"}[retained], func(t *testing.T) {
			_, scope := desktopWindowsWFPTestOptions(t, "always")
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			candidates := []*DesktopWindowsProtectionTarget{nil}
			var policy *DesktopWindowsSocketPolicy
			var captured DesktopWindowsProtectionTarget
			if retained {
				policy = desktopWindowsWFPTestOwner(t, "always", false, true)
				captured = desktopWindowsWFPTarget(t, policy)
				candidates = append(candidates, &captured)
			}
			called := 0
			observation, err := newDesktopWindowsProtectionObservationScoped(candidates, func(ctx context.Context, index int) error {
				called++
				want := 0
				if retained {
					want = 1
				}
				if index != want || ctx.Err() != nil {
					return errors.New("native observation acknowledged another recorded outcome")
				}
				return nil
			}, scope)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { desktopWindowsObservationClose(t, observation) })
			if retained {
				if err := observation.Run(ctx); err == nil || called != 0 {
					t.Fatal("native observation adopted a still-live session")
				}
				if err := policy.Close(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if err := observation.Run(ctx); err != nil || called != 1 {
				t.Fatal("native observation failed its exact recorded outcome", err)
			}
			if err := observation.Run(ctx); err != nil || called != 1 {
				t.Fatal("native observation repeated its durable acknowledgement", err)
			}
			if err := readDesktopWindowsProtectionExpectation(ctx, candidates[len(candidates)-1], scope); err != nil {
				t.Fatal("read-only observation changed the retained native outcome", err)
			}
		})
	}
}

func TestDesktopWindowsProtectionObservationNativeRejectsChangedOutcome(t *testing.T) {
	policy := desktopWindowsWFPTestOwner(t, "always", false, true)
	captured := desktopWindowsWFPTarget(t, policy)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := policy.Close(ctx); err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"absence", "session", "source", "network", "policy", "metadata"} {
		t.Run(change, func(t *testing.T) {
			target := captured
			candidate := &target
			switch change {
			case "absence":
				candidate = nil
			case "session":
				target.Capture.SessionID = strings.Repeat("a", 32)
			case "source":
				target.Capture.SourceSHA256 = strings.Repeat("a", 64)
			case "network":
				target.Capture.NetworkID = strings.Repeat("a", 32)
			case "policy":
				target.Policy = "on-connect"
			case "metadata":
				target.BaselineSHA256 = strings.Repeat("a", 64)
			}
			called := false
			observation, err := newDesktopWindowsProtectionObservationScoped([]*DesktopWindowsProtectionTarget{candidate}, func(context.Context, int) error { called = true; return nil }, policy.fixtureScope)
			if err != nil {
				t.Fatal(err)
			}
			defer desktopWindowsObservationClose(t, observation)
			if err := observation.Run(ctx); err == nil || called {
				t.Fatal("native observation adopted an unrecorded baseline")
			}
			if err := readDesktopWindowsRetainedProtection(ctx, captured, policy.fixtureScope); err != nil {
				t.Fatal("rejected observation changed the exact retained baseline", err)
			}
		})
	}
}

func TestDesktopWindowsProtectionObservationNativeRejectsAdditionalPermit(t *testing.T) {
	policy := desktopWindowsWFPTestOwner(t, "always", false, true)
	captured := desktopWindowsWFPTarget(t, policy)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if err := policy.Close(ctx); err != nil {
		t.Fatal(err)
	}
	engine, err := desktopWFPOpen(false)
	if engine != nil {
		defer engine.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	extra := policy.rule("unexpected-observation-permit", 4, false, 99, true, true)
	if err := engine.Add(&extra); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := engine.Delete(extra.Key); err != nil {
			t.Error(err)
		}
	}()
	called := false
	observation, err := newDesktopWindowsProtectionObservationScoped([]*DesktopWindowsProtectionTarget{&captured}, func(context.Context, int) error { called = true; return nil }, policy.fixtureScope)
	if err != nil {
		t.Fatal(err)
	}
	defer desktopWindowsObservationClose(t, observation)
	if err := observation.Run(ctx); err == nil || called {
		t.Fatal("native observation acknowledged an extra retained permit")
	}
	if err := engine.Assert(extra); err != nil {
		t.Fatal("rejected observation removed a foreign-to-record rule", err)
	}
}

func TestDesktopWindowsProtectionObservationNativeHeldReadOnlySnapshot(t *testing.T) {
	policy := desktopWindowsWFPTestOwner(t, "always", false, true)
	captured := desktopWindowsWFPTarget(t, policy)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := policy.Close(ctx); err != nil {
		t.Fatal(err)
	}
	writer, err := desktopWFPOpen(false)
	if writer != nil {
		defer writer.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	extra := policy.rule("observation-read-only-probe", 4, false, 99, false, true)
	// Only the deliberate read/write mutant can add this test-exe-scoped rule.
	// Delete that exact fixture key after its transaction has been joined.
	defer func() {
		if err := writer.Delete(extra.Key); err != nil {
			t.Error("native snapshot probe could not retire its exact fixture", err)
		}
	}()
	var observation *DesktopWindowsProtectionObservation
	called := 0
	observation, err = newDesktopWindowsProtectionObservationScoped([]*DesktopWindowsProtectionTarget{&captured}, func(context.Context, int) error {
		called++
		native := observation.native.(*desktopWindowsProtectionNativeObservation)
		// These bounded native probes are test-only. Production callbacks only
		// flush their captured journal; they never call BFE while holding it.
		if err := native.engine.Add(&extra); err == nil || !strings.Contains(err.Error(), "0x80320011") {
			return errors.New("native observation callback did not retain a read-only transaction")
		}
		if err := writer.Begin(); err == nil {
			return errors.Join(errors.New("native observation released its snapshot before acknowledgement"), writer.Abort())
		} else if !strings.Contains(err.Error(), "0x80320012") {
			return errors.Join(errors.New("native snapshot writer failed for an unrelated reason"), err)
		}
		return nil
	}, policy.fixtureScope)
	if err != nil {
		t.Fatal(err)
	}
	defer desktopWindowsObservationClose(t, observation)
	if err := observation.Run(ctx); err != nil || called != 1 {
		t.Fatal("exact native snapshot acknowledgement failed", err)
	}
	if err := writer.Begin(); err != nil {
		t.Fatal("native observation retained a write lock after joining", err)
	}
	if err := writer.Abort(); err != nil {
		t.Fatal(err)
	}
	if err := readDesktopWindowsRetainedProtection(ctx, captured, policy.fixtureScope); err != nil {
		t.Fatal("snapshot proof changed the recorded protection", err)
	}
}

func TestDesktopWindowsProtectionObservationNativeRejectsLostSnapshot(t *testing.T) {
	_, scope := desktopWindowsWFPTestOptions(t, "always")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	called := 0
	var observation *DesktopWindowsProtectionObservation
	var err error
	observation, err = newDesktopWindowsProtectionObservationScoped([]*DesktopWindowsProtectionTarget{nil}, func(context.Context, int) error {
		called++
		native := observation.native.(*desktopWindowsProtectionNativeObservation)
		// Simulate the documented BFE-forced abort using the actual kernel,
		// leaving the cached flag untouched. Ordinary cleanup normalizes the
		// next NO_TXN result; durable observation must instead retain failure.
		status, _, _ := native.engine.api.abort.Call(uintptr(native.engine.handle))
		return desktopWFPError("test-only abort of captured snapshot", status)
	}, scope)
	if err != nil {
		t.Fatal(err)
	}
	defer desktopWindowsObservationClose(t, observation)
	if err := observation.Run(ctx); err == nil || !strings.Contains(err.Error(), "lost its snapshot") || called != 1 || observation.native != nil {
		t.Fatal("native lost snapshot acquired durable adoption", err)
	}
	if err := observation.Run(ctx); err == nil || !strings.Contains(err.Error(), "lost its snapshot") || called != 1 {
		t.Fatal("native cleanup converted lost snapshot into adoption or replayed its write", err)
	}
	if err := readDesktopWindowsProtectionExpectation(ctx, nil, scope); err != nil {
		t.Fatal("lost-snapshot observation changed the exact prior state", err)
	}
}
