package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"router-vpn/internal/desktopnetwork"
)

// A completed fifty-response operation releases its MTU hold, which correctly
// resumes Auto. Retire that fixture's ordinary workers before its native model
// and TempDir cleanups run. This is test lifetime management, not a substitute
// for the application's native Stop or physical retirement acceptance.
func retireDesktopOrderedLatencyFixture(ctx context.Context, a *app, command *exec.Cmd) error {
	if err := desktopnetwork.LockContext(ctx, &a.operationMu); err != nil {
		return err
	}
	defer a.operationMu.Unlock()
	a.mu.Lock()
	foreign := a.cmd != nil && a.cmd != command
	a.mu.Unlock()
	if foreign {
		return errors.New("ordered fixture cleanup cannot retire a replacement command")
	}
	tracker := cancelSessionTracker(a)
	if tracker != nil {
		if err := tracker.stopDNSProofs(ctx); err != nil {
			return err
		}
		joinSessionTracker(a, tracker)
	}
	release, err := a.holdCapturedMTU(ctx)
	if err != nil {
		return err
	}
	// The existing native fixture still owns and checks its child/protection
	// cleanup. Only its now-terminal application identity is retired here.
	a.mu.Lock()
	a.cmd, a.state.Connected = nil, false
	a.mu.Unlock()
	release()
	if raw, found := routerNodeAutomaticMTUs.Load(a); found {
		owner := raw.(*routerNodeAutomaticMTU)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			owner.mu.Lock()
			waiting := owner.waiting
			owner.mu.Unlock()
			if !waiting {
				routerNodeAutomaticMTUs.CompareAndDelete(a, owner)
				break
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
		}
	}
	return ctx.Err()
}

func TestDesktopOrderedLatencyFixtureCleanupJoinsResumedAuto(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, _ := newMTUTransactionFixture(t)
		command := &exec.Cmd{Path: "original-ordered-fixture"}
		a.cmd = command
		sessionTrackerFor(a).dnsProofRunning = true // The entered MTU boundary is controlled here.
		entered, release := make(chan struct{}), make(chan struct{})
		marker := filepath.Join(filepath.Dir(a.cfg.ProfilesFile), "joined-auto.txt")
		a.startRouterNodeAutomaticMTUWithRun(func(mtuRetestSnapshot) mtuAutomaticResult {
			close(entered)
			<-release
			if err := os.WriteFile(marker, []byte("actual scheduler joined"), 0600); err != nil {
				t.Error(err)
			}
			return mtuAutomaticResult{accepted: true}
		})
		<-entered
		defer func() {
			select {
			case <-release:
			default:
				close(release)
			}
			// Even a deliberately broken retirement must not let this test's
			// held writer outlive its assertion or TempDir cleanup.
			synctest.Wait()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- retireDesktopOrderedLatencyFixture(ctx, a, command) }()
		synctest.Wait()
		select {
		case err := <-done:
			close(release)
			t.Fatal("fixture cleanup escaped its still-entered Auto worker", err)
		default:
		}
		close(release)
		if err := <-done; err != nil {
			t.Fatal("fixture cleanup did not join resumed Auto", err)
		}
		if raw, err := os.ReadFile(marker); err != nil || string(raw) != "actual scheduler joined" {
			t.Fatal("fixture retired before the original worker's final write", err)
		}
		if _, found := routerNodeAutomaticMTUs.Load(a); found {
			t.Fatal("joined fixture retained an automatic worker")
		}
	})
}

func TestDesktopOrderedLatencyFixtureCleanupPreservesReplacement(t *testing.T) {
	a, _ := newMTUTransactionFixture(t)
	original, replacement := &exec.Cmd{Path: "original"}, &exec.Cmd{Path: "replacement"}
	a.cmd = replacement
	tracker := sessionTrackerFor(a)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := retireDesktopOrderedLatencyFixture(ctx, a, original); err == nil {
		t.Fatal("fixture cleanup borrowed another command")
	}
	if a.cmd != replacement || !a.state.Connected || tracker.dnsProofClosed || tracker.lifetime.stopped {
		t.Fatal("refused fixture cleanup changed its replacement")
	}
}

func TestDesktopOrderedLatencyFixtureCleanupJoinsDNSProof(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, tracker, observed, id := dnsPathFixture(t)
		command := a.cmd
		entered, release := make(chan struct{}), make(chan struct{})
		work := startSessionDNSFixture(t, tracker, observed, id, func(ctx context.Context, a *app, s observedConnection, mode string) dnsProofState {
			close(entered)
			<-ctx.Done()
			<-release
			return successfulDNSProof(ctx, a, s, mode)
		})
		defer func() {
			work.cancel()
			select {
			case <-release:
			default:
				close(release)
			}
			<-work.done
		}()
		<-entered
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- retireDesktopOrderedLatencyFixture(ctx, a, command) }()
		synctest.Wait()
		select {
		case err := <-done:
			t.Fatal("fixture cleanup escaped its still-entered DNS proof", err)
		default:
		}
		close(release)
		if err := <-done; err != nil {
			t.Fatal("fixture cleanup did not join selected-DNS work", err)
		}
		select {
		case <-work.done:
		default:
			t.Fatal("fixture retired before its actual DNS worker joined")
		}
		if !tracker.dnsProofClosed || tracker.snapshot(0).DNSProof.Status == "passed" {
			t.Fatal("terminal fixture admitted a late DNS proof")
		}
	})
}
