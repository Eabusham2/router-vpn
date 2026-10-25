package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDesktopTorDrainObservationDoesNotPairMissingReceiptWithLaterExit(t *testing.T) {
	a, launch, _ := desktopTorRunningFixture(t, "proof")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := a.waitDesktopTorProof(ctx, launch); err != nil {
		t.Fatal(err)
	}
	if desktopNodeProcessExited(launch) {
		t.Fatal("fixture exited before the controlled publication boundary")
	}
	// The reader observes a genuinely absent receipt, then lets this actual
	// captured child publish and exit before returning its earlier observation.
	// Reversing the shipping observer order deterministically combines that
	// old missing receipt with the new exit and reproduces the CI failure.
	closed, exited, err := observeDesktopTorDrain(
		func() bool { return desktopNodeProcessExited(launch) },
		func() (bool, error) {
			before, err := desktopTorStopped(launch)
			if err != nil || before {
				t.Fatal("fixture already had a receipt before its controlled stop", err)
			}
			request, _ := json.Marshal(desktopExternalStop{Schema: 1, SessionID: launch.tor.expected.SessionID, SourceSHA256: launch.tor.expected.SourceSHA256})
			if err := writeDesktopRuntimeFile(launch, "stop.json", request, false); err != nil {
				t.Fatal(err)
			}
			select {
			case <-desktopNodeProcessDone(launch):
			case <-ctx.Done():
				t.Fatal("actual fixture child did not finish its captured stop", ctx.Err())
			}
			return before, nil
		},
	)
	if err != nil || closed || exited {
		t.Fatal("drain observer combined a missing receipt with a later process exit", closed, exited, err)
	}
	closed, exited, err = observeDesktopTorDrain(
		func() bool { return desktopNodeProcessExited(launch) },
		func() (bool, error) { return desktopTorStopped(launch) },
	)
	if err != nil || !closed || !exited {
		t.Fatal("next observation lost the actual joined child and captured receipt", closed, exited, err)
	}
	if err := requestDesktopTorStop(ctx, a, launch, launch.command); err != nil {
		t.Fatal("shipping stop rejected the actual completed drain", err)
	}
}

func TestDesktopTorDrainObservationRejectsMissingWrongAndStaleReceipts(t *testing.T) {
	for _, kind := range []string{"missing", "session", "source", "not-closed"} {
		t.Run(kind, func(t *testing.T) {
			a, launch, _ := desktopTorRunningFixture(t, "without-receipt")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := a.waitDesktopTorProof(ctx, launch); err != nil {
				t.Fatal(err)
			}
			request, _ := json.Marshal(desktopExternalStop{Schema: 1, SessionID: launch.tor.expected.SessionID, SourceSHA256: launch.tor.expected.SourceSHA256})
			if err := writeDesktopRuntimeFile(launch, "stop.json", request, false); err != nil {
				t.Fatal(err)
			}
			select {
			case <-desktopNodeProcessDone(launch):
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if kind != "missing" {
				record := desktopExternalStop{Schema: 1, SessionID: launch.tor.expected.SessionID, SourceSHA256: launch.tor.expected.SourceSHA256, Closed: true}
				switch kind {
				case "session":
					record.SessionID = strings.Repeat("e", 32)
				case "source":
					record.SourceSHA256 = strings.Repeat("e", 64)
				case "not-closed":
					record.Closed = false
				}
				raw, _ := json.Marshal(record)
				if err := writeDesktopRuntimeFile(launch, "stopped.json", raw, false); err != nil {
					t.Fatal(err)
				}
			}
			closed, exited, err := observeDesktopTorDrain(
				func() bool { return desktopNodeProcessExited(launch) },
				func() (bool, error) { return desktopTorStopped(launch) },
			)
			if closed || !exited || (kind != "missing" && err == nil) {
				t.Fatal("an actual process exit substituted for an owned close receipt", closed, exited, err)
			}
			if err := requestDesktopTorStop(ctx, a, launch, launch.command); err == nil {
				t.Fatal("shipping stop accepted an unproved native drain")
			}
			if err := stopDesktopTorRuntime(a, launch, launch.command); err == nil {
				t.Fatal("an unproved native drain deleted its captured inputs")
			}
			if _, err := os.Stat(filepath.Join(launch.directory, "tor-capture.json")); err != nil {
				t.Fatal("rejected drain lost its private inputs", err)
			}
		})
	}
}
