package mobiletor

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
)

func desktopCommitFixture(policy, seed string) DesktopWindowsProtectionTarget {
	return desktopWindowsProtectionTarget(DesktopSocketCapture{strings.Repeat(seed, 32), strings.Repeat(seed, 64), strings.Repeat("e", 32)}, policy, []byte("native comparison "+seed))
}

func TestDesktopWindowsProtectionCommitValidation(t *testing.T) {
	previous, candidate := desktopCommitFixture("always", "a"), desktopCommitFixture("on-connect", "b")
	onConnect := previous
	onConnect.Policy = "on-connect"
	valid := []DesktopWindowsProtectionCommit{
		{Action: "successor", Candidate: &candidate},
		{Action: "successor", Previous: &previous, Candidate: &candidate},
		{Action: "release", Previous: &onConnect},
		{Action: "off", Previous: &previous},
		{Action: "off", Previous: &onConnect},
	}
	for _, change := range valid {
		if err := change.Validate(); err != nil {
			t.Fatal("valid exact protection commit was rejected", err)
		}
	}
	invalid := map[string]DesktopWindowsProtectionCommit{
		"unknown":             {Action: "force-off", Previous: &previous},
		"empty":               {},
		"missing-successor":   {Action: "successor", Previous: &previous},
		"reused-capture":      {Action: "successor", Previous: &previous, Candidate: &previous},
		"missing-release":     {Action: "release"},
		"release-always":      {Action: "release", Previous: &previous},
		"release-replacement": {Action: "release", Previous: &onConnect, Candidate: &candidate},
		"missing-off":         {Action: "off"},
		"off-replacement":     {Action: "off", Previous: &previous, Candidate: &candidate},
	}
	for _, field := range []string{"session", "source", "network", "policy", "digest"} {
		bad := previous
		switch field {
		case "session":
			bad.Capture.SessionID = "a"
		case "source":
			bad.Capture.SourceSHA256 = "a"
		case "network":
			bad.Capture.NetworkID = "a"
		case "policy":
			bad.Policy = "off"
		case "digest":
			bad.BaselineSHA256 = strings.Repeat("A", 64)
		}
		invalid["previous-"+field] = DesktopWindowsProtectionCommit{Action: "successor", Previous: &bad, Candidate: &candidate}
		invalid["candidate-"+field] = DesktopWindowsProtectionCommit{Action: "successor", Candidate: &bad}
	}
	for name, change := range invalid {
		t.Run(name, func(t *testing.T) {
			called := false
			err := desktopWindowsCompleteProtectionCommit(context.Background(), func(context.Context, DesktopWindowsProtectionCommit) error {
				called = true
				return nil
			}, change)
			if change.Validate() == nil || err == nil || called {
				t.Fatal("invalid protection commit reached durable acknowledgment")
			}
		})
	}
}

func TestDesktopWindowsProtectionCommitCopiesTargets(t *testing.T) {
	previous, candidate := desktopCommitFixture("always", "a"), desktopCommitFixture("on-connect", "b")
	change := DesktopWindowsProtectionCommit{Action: "successor", Previous: &previous, Candidate: &candidate}
	expected := cloneDesktopWindowsProtectionCommit(change)
	for range 2 {
		if err := desktopWindowsCompleteProtectionCommit(context.Background(), func(_ context.Context, actual DesktopWindowsProtectionCommit) error {
			if !reflect.DeepEqual(actual, expected) {
				t.Fatal("commit retry changed its exact comparison targets")
			}
			actual.Previous.Capture.SessionID = strings.Repeat("c", 32)
			actual.Candidate.BaselineSHA256 = strings.Repeat("d", 64)
			return nil
		}, change); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(change, expected) {
			t.Fatal("durable callback mutated retained native commit targets")
		}
	}
}

func TestDesktopWindowsProtectionCommitCancellation(t *testing.T) {
	target := desktopCommitFixture("always", "a")
	change := DesktopWindowsProtectionCommit{Action: "off", Previous: &target}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, cancelled} {
		called := false
		err := desktopWindowsCompleteProtectionCommit(ctx, func(context.Context, DesktopWindowsProtectionCommit) error { called = true; return nil }, change)
		if err == nil || called {
			t.Fatal("cancelled commit acquired a durable callback")
		}
	}
	if err := desktopWindowsCompleteProtectionCommit(context.Background(), nil, change); err == nil {
		t.Fatal("missing callback became a durable acknowledgment")
	}
	failure := errors.New("exact private file flush failed")
	if err := desktopWindowsCompleteProtectionCommit(context.Background(), func(context.Context, DesktopWindowsProtectionCommit) error { return failure }, change); !errors.Is(err, failure) {
		t.Fatal("commit lost its actual persistence failure", err)
	}
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	err := desktopWindowsCompleteProtectionCommit(ctx, func(context.Context, DesktopWindowsProtectionCommit) error { stop(); return failure }, change)
	if !errors.Is(err, failure) || !errors.Is(err, context.Canceled) {
		t.Fatal("late cancellation was converted into commit authority", err)
	}
}

func TestDesktopWindowsProtectionCommitJoinsCallback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		target := desktopCommitFixture("on-connect", "a")
		entered, release := make(chan struct{}), make(chan struct{})
		finished := make(chan error, 1)
		go func() {
			finished <- desktopWindowsCompleteProtectionCommit(ctx, func(context.Context, DesktopWindowsProtectionCommit) error {
				close(entered)
				<-release
				return nil
			}, DesktopWindowsProtectionCommit{Action: "release", Previous: &target})
		}()
		<-entered
		cancel()
		synctest.Wait()
		select {
		case <-finished:
			t.Fatal("cancelled commit returned before its captured callback joined")
		default:
		}
		close(release)
		if err := <-finished; !errors.Is(err, context.Canceled) {
			t.Fatal("joined cancelled callback acquired commit authority", err)
		}
	})
}
