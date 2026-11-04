//go:build linux && routervpn_controller_privileged

package standardengine

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCleanupOriginalAttemptsRetainOwnerAndDeadlines(t *testing.T) {
	for _, scenario := range []string{"expired-startup", "failed-native", "expired-request", "wrong-source", "torn-request"} {
		t.Run(scenario, func(t *testing.T) {
			file, err := NewCleanupFile()
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			expected := strings.Repeat("b", 64)
			entered := make(chan time.Time, 3)
			joined := make(chan error, 1)
			original := time.Now().Add(time.Second)
			if scenario == "expired-startup" {
				original = time.Now().Add(-time.Second)
			}
			calls := 0
			go func() {
				joined <- RetireOriginal(file, expected, original, true, func(ctx context.Context) (string, error) {
					bound, ok := ctx.Deadline()
					if !ok {
						return "", errors.New("missing original deadline")
					}
					entered <- bound
					calls++
					if calls == 1 && scenario != "expired-startup" {
						return "", errors.New("actual original native close failed")
					}
					return "original-ledger", ctx.Err()
				})
			}()
			if scenario != "expired-startup" {
				select {
				case bound := <-entered:
					if !bound.Equal(original) {
						t.Fatal("initial deadline rebased")
					}
				case <-time.After(time.Second):
					t.Fatal("original callback absent")
				}
			}
			until := time.Now().Add(time.Second)
			for {
				r, err := file.ReadResult(expected)
				if err == nil {
					if r.Complete || r.Sequence != 0 {
						t.Fatal("original failure fabricated completion", r)
					}
					break
				}
				if time.Now().After(until) {
					t.Fatal("pending result absent", err)
				}
				time.Sleep(time.Millisecond)
			}
			request := CleanupRequest{Schema: 1, CaptureSHA256: expected, Sequence: 1, DeadlineNS: time.Now().Add(time.Second).UnixNano()}
			if scenario == "expired-request" {
				request.DeadlineNS = time.Now().Add(-time.Second).UnixNano()
			}
			if scenario == "wrong-source" {
				request.CaptureSHA256 = strings.Repeat("c", 64)
			}
			if err := file.WriteRequest(request); err != nil {
				t.Fatal(err)
			}
			if scenario == "torn-request" {
				if _, err := file.file.WriteAt([]byte{9}, 36); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "expired-request" || scenario == "wrong-source" || scenario == "torn-request" {
				select {
				case <-entered:
					t.Fatal("invalid or expired attempt executed original native callback")
				case err := <-joined:
					t.Fatal("failed original owner lost", err)
				case <-time.After(75 * time.Millisecond):
				}
				request.Sequence = 2
				request.CaptureSHA256 = expected
				request.DeadlineNS = time.Now().Add(time.Second).UnixNano()
				if err := file.WriteRequest(request); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case bound := <-entered:
				if bound.UnixNano() != request.DeadlineNS {
					t.Fatal("issued cleanup deadline changed")
				}
			case <-time.After(time.Second):
				t.Fatal("original cleanup did not retry")
			}
			select {
			case err := <-joined:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("original cleanup not joined")
			}
			result, err := file.ReadResult(expected)
			if err != nil || !result.Complete || result.Sequence != request.Sequence || result.DeadlineNS != request.DeadlineNS || !result.StartupFailed || result.Ledger != "original-ledger" {
				t.Fatal("terminal result lost original attempted owner", result, err)
			}
		})
	}
}

func TestCleanupRejectsOverlongSelfBudgetBeforeNativeCall(t *testing.T) {
	file, err := NewCleanupFile()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	called := false
	err = RetireOriginal(file, strings.Repeat("a", 64), time.Now().Add(10*time.Second), true, func(context.Context) (string, error) { called = true; return "unpermitted", nil })
	if err == nil || called {
		t.Fatal("overlong self cleanup executed native mutation", err)
	}
}
