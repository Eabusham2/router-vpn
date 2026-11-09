package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDesktopMTURecordContextPreservesIdentityObservationCancellation(t *testing.T) {
	for _, expiry := range []string{"cancel", "deadline"} {
		t.Run(expiry, func(t *testing.T) {
			a, launch := desktopMTUControllerFixture(t, "mtu-hold")
			original, err := readDesktopMTURecord(launch)
			if err != nil {
				t.Fatal(err)
			}
			launch.external.mu.Lock()
			var released sync.Once
			unlock := func() { released.Do(launch.external.mu.Unlock) }
			defer unlock()
			parent, cancel := context.WithCancel(context.Background())
			want := context.Canceled
			if expiry == "deadline" {
				cancel()
				parent, cancel = context.WithTimeout(context.Background(), time.Second)
				want = context.DeadlineExceeded
			}
			defer cancel()
			ctx := &desktopNodeMTUWaitingContext{Context: parent, waiting: make(chan struct{})}
			type result struct {
				record desktopMTURecord
				err    error
			}
			done := make(chan result, 1)
			go func() {
				record, err := readDesktopMTURecordContext(ctx, launch)
				done <- result{record, err}
			}()
			// Workspace access is uncontended. Done is first requested only
			// after the actual status was read and decoded, when capture tries
			// the retained external owner's mutex. This is the hosted race.
			select {
			case <-ctx.waiting:
			case <-time.After(2 * time.Second):
				cancel()
				unlock()
				<-done
				t.Fatal("status did not reach its original identity observation")
			}
			if expiry == "cancel" {
				cancel()
			}
			select {
			case actual := <-done:
				if actual.record.Session != original.Session || actual.record.SourceSHA256 != original.SourceSHA256 || actual.record.ConfigSHA256 != original.ConfigSHA256 {
					t.Fatal("expiry did not follow the original decoded native record")
				}
				if !errors.Is(actual.err, want) {
					t.Fatal("identity observation discarded the original caller expiry", actual.err)
				}
			case <-time.After(2 * time.Second):
				unlock()
				<-done
				t.Fatal("expired record observation waited for the original owner lock")
			}
			unlock()
			retry, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			retained, err := readDesktopMTURecordContext(retry, launch)
			if err != nil || retained.Session != original.Session || retained.SourceSHA256 != original.SourceSHA256 || retained.ConfigSHA256 != original.ConfigSHA256 || a.cmd != launch.command {
				t.Fatal("expired observation changed its original healthy runtime", err)
			}
		})
	}
}

func TestDesktopMTURecordContextStillRejectsForeignIdentity(t *testing.T) {
	_, original := desktopMTUControllerFixture(t, "mtu-hold")
	record, err := readDesktopMTURecord(original)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"matching", "schema", "session", "source", "config"} {
		t.Run(field, func(t *testing.T) {
			// Keep a separate real captured workspace so the live fixture's
			// heartbeat cannot overwrite this deliberate foreign-record control.
			launch := desktopWorkspaceCaptureFixture(t)
			launch.external = original.external
			candidate := record
			switch field {
			case "schema":
				candidate.Schema++
			case "session":
				candidate.Session = strings.Repeat("f", 32)
			case "source":
				candidate.SourceSHA256 = strings.Repeat("e", 64)
			case "config":
				candidate.ConfigSHA256 = strings.Repeat("d", 64)
			}
			encoded, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if err := writeDesktopRuntimeFile(launch, "mtu-status.json", encoded, false); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err = readDesktopMTURecordContext(ctx, launch)
			if field == "matching" {
				if err != nil {
					t.Fatal("original native identity was refused", err)
				}
			} else if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("foreign native identity was accepted or mislabeled as caller expiry", err)
			}
		})
	}
}
