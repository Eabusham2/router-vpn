package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestDesktopNodeClosedReceiptRequiresExactCapturedRuntime(t *testing.T) {
	for _, mutation := range []string{"session", "config", "schema", "open", "extra", "duplicate", "valid"} {
		t.Run(mutation, func(t *testing.T) {
			fixture := newDesktopNodeMTUFixture(t)
			launch := fixture.launch
			record := desktopExternalStop{Schema: 1, SessionID: launch.mtuSession, SourceSHA256: launch.configSHA256, Closed: true}
			switch mutation {
			case "session":
				record.SessionID = strings.Repeat("d", 32)
			case "config":
				record.SourceSHA256 = strings.Repeat("e", 64)
			case "schema":
				record.Schema = 2
			case "open":
				record.Closed = false
			}
			raw, _ := json.Marshal(record)
			if mutation == "extra" {
				raw = append(raw[:len(raw)-1], []byte(`,"unowned":true}`)...)
			}
			if mutation == "duplicate" {
				raw = append(raw[:len(raw)-1], []byte(`,"schema":1}`)...)
			}
			if err := writeDesktopRuntimeFile(launch, "stopped.json", raw, false); err != nil {
				t.Fatal(err)
			}
			closed, err := readDesktopNodeStopped(launch)
			if mutation == "valid" {
				if err != nil || !closed || !launch.nodeStopAcknowledged {
					t.Fatal("exact cleanup receipt rejected", err)
				}
				if desktopNodeProcessExited(launch) {
					t.Fatal("close receipt fabricated process-exit evidence")
				}
			} else if err == nil || closed || launch.nodeStopAcknowledged {
				t.Fatal("foreign or ambiguous native cleanup was accepted", mutation)
			}
		})
	}
}

func TestDesktopNodeStopDoesNotSignalOrWriteIntoReplacementConnection(t *testing.T) {
	fixture := newDesktopNodeMTUFixture(t)
	launch := fixture.launch
	launch.command.Process = &os.Process{Pid: os.Getpid()}
	a := &app{cmd: &exec.Cmd{Path: "replacement"}}
	desktopNodeOwners.Store(a, launch)
	t.Cleanup(func() { desktopNodeOwners.Delete(a) })
	if err := prepareDesktopNodeStop(a, launch.command); err == nil {
		t.Fatal("stale stop adopted the replacement runtime")
	}
	if _, err := launch.directoryRoot.Lstat("stop.json"); !os.IsNotExist(err) {
		t.Fatal("stale stop wrote a native close request", err)
	}
	if launch.nodeWaitDone != nil || launch.nodeStopAcknowledged {
		t.Fatal("stale stop started waiting or accepted unrelated cleanup")
	}
}

func TestMTUViewKeepsFailedCleanupPendingUntilItsRetainedOwnerCloses(t *testing.T) {
	owner, kernel := newMTUCapabilityFixture(t)
	a := owner.a
	t.Cleanup(func() { mtuViewSlots.Delete(a) })
	identity := mtuViewIdentity{Session: owner.snapshot.SessionID, Profile: owner.snapshot.Profile.ID}
	_, operation, err := beginMTUViewOperation(a, context.Background(), mtuViewRequest{Request: strings.Repeat("b", 32)}, identity)
	if err != nil {
		t.Fatal(err)
	}
	kernel.mu.Lock()
	kernel.closeFailures = 100
	kernel.mu.Unlock()
	writer := &mtuViewResponse{ResponseWriter: httptest.NewRecorder(), operation: operation}
	recordMTUViewRollback(writer, mtuLiveSnapshot{OriginalMTU: 1420}, nil)
	http.Error(writer, "measurement canceled", http.StatusConflict)
	finishMTULiveOwner(writer, owner)
	writer.finish()
	operation.mu.Lock()
	if !operation.cleanupPending || !operation.status.Running || operation.status.Complete || operation.status.Measured || operation.status.Phase != "cleanup-pending" {
		t.Fatal("failed close was mislabeled as completed cleanup", operation.status)
	}
	operation.mu.Unlock()
	if _, _, err := beginMTUViewOperation(a, context.Background(), mtuViewRequest{Request: strings.Repeat("c", 32)}, identity); err == nil {
		t.Fatal("replacement measurement started before native cleanup drained")
	}
	kernel.mu.Lock()
	kernel.closeFailures = 0
	kernel.mu.Unlock()
	mtuWaitCondition(t, func() bool {
		operation.mu.Lock()
		defer operation.mu.Unlock()
		return !operation.cleanupPending && operation.status.Complete && !operation.status.Running
	})
	operation.mu.Lock()
	defer operation.mu.Unlock()
	if operation.status.Phase != "restored" || !operation.status.Restored || operation.status.Measured || operation.status.EffectiveMTU != 1420 {
		t.Fatal("cleanup retry lost the exact rollback receipt", operation.status)
	}
	if _, found := mtuLiveOwners.Load(a); found {
		t.Fatal("checked cleanup retained a closed owner")
	}
}
