package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// These fixtures exchange the real private-file parent protocol. Their child
// reports controlled readers; actual platform TUN mutation has separate gates.
type desktopNodeMTUFixture struct {
	launch *desktopNodeLaunch
	base   desktopNodeMTURecord
}

func newDesktopNodeMTUFixture(t *testing.T) *desktopNodeMTUFixture {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "runtime")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	launch := &desktopNodeLaunch{mtuSession: strings.Repeat("1", 32), configSHA256: strings.Repeat("2", 64), command: &exec.Cmd{}}
	if err := captureDesktopRuntimeDirectory(launch, directory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = launch.directoryRoot.Close() })
	fixture := &desktopNodeMTUFixture{launch: launch, base: desktopNodeMTURecord{Schema: 1, Session: launch.mtuSession, Config: launch.configSHA256, Path: strings.Repeat("3", 64), Reader: 1, Interface: "tun-captured", Index: 7, MTU: 1420}}
	if err := fixture.publish(fixture.base, false); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (fixture *desktopNodeMTUFixture) publish(record desktopNodeMTURecord, consume bool) error {
	record.Heartbeat = time.Now().UnixMilli()
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	fixture.launch.workspaceMu.Lock()
	defer fixture.launch.workspaceMu.Unlock()
	if err := desktopExternalDirectoryCurrent(fixture.launch); err != nil {
		return err
	}
	// A fixture-owned sibling is atomically published just like the native
	// writer, so the parent never sees a partially encoded acknowledgement.
	path := filepath.Join(fixture.launch.directory, ".node-mtu-status.json.pending")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		return err
	}
	if err := os.Rename(path, filepath.Join(fixture.launch.directory, "node-mtu-status.json")); err != nil {
		return err
	}
	if consume {
		if err := fixture.launch.directoryRoot.Remove("node-mtu-request.json"); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (fixture *desktopNodeMTUFixture) owner(active bool) *desktopNodeMTUOwner {
	record := fixture.base
	lease := strings.Repeat("a", 32)
	if active {
		record.Active, record.Lease, record.Generation, record.Request = true, lease, 1, strings.Repeat("b", 32)
	}
	return &desktopNodeMTUOwner{launch: fixture.launch, record: record, originalMTU: record.MTU, family: 4, lease: lease}
}

func nodeMTUAck(owner *desktopNodeMTUOwner, action string, value int) (desktopNodeMTUCommand, desktopNodeMTURecord) {
	command := desktopNodeMTUCommand{Schema: 1, Session: owner.record.Session, Config: owner.record.Config, Path: owner.record.Path, Generation: owner.record.Generation + 1, Request: strings.Repeat("c", 32), Lease: owner.lease, Action: action, Reader: owner.record.Reader, MTU: owner.record.MTU, Value: value}
	record := owner.record
	record.Generation, record.Request, record.Lease, record.Failure = command.Generation, command.Request, command.Lease, ""
	record.Active = action == "begin" || action == "set"
	record.Restored = action == "rollback"
	if action == "set" {
		record.MTU, record.Reader, record.Index = value, record.Reader+1, record.Index+1
	}
	if action == "rollback" {
		record.MTU, record.Reader, record.Index = owner.originalMTU, record.Reader+1, record.Index+1
	}
	return command, record
}

func TestDesktopNodeMTUAcknowledgementCannotReplaceCapturedOwnerOrValue(t *testing.T) {
	cases := []struct {
		name, action string
		edit         func(*desktopNodeMTURecord)
	}{
		{"begin-lease", "begin", func(r *desktopNodeMTURecord) { r.Lease = strings.Repeat("d", 32) }},
		{"begin-reader", "begin", func(r *desktopNodeMTURecord) { r.Reader++ }},
		{"begin-value", "begin", func(r *desktopNodeMTURecord) { r.MTU = 1400 }},
		{"begin-inactive", "begin", func(r *desktopNodeMTURecord) { r.Active = false }},
		{"begin-spurious-restore", "begin", func(r *desktopNodeMTURecord) { r.Restored = true }},
		{"set-lease", "set", func(r *desktopNodeMTURecord) { r.Lease = strings.Repeat("d", 32) }},
		{"set-interface", "set", func(r *desktopNodeMTURecord) { r.Interface = "replacement" }},
		{"set-reader-regression", "set", func(r *desktopNodeMTURecord) { r.Reader = 1; r.Index = 8 }},
		{"set-reuses-same-reader", "set", func(r *desktopNodeMTURecord) { r.Reader = 1; r.Index = 7 }},
		{"set-reader-jump", "set", func(r *desktopNodeMTURecord) { r.Reader = 3 }},
		{"set-value", "set", func(r *desktopNodeMTURecord) { r.MTU = 1400 }},
		{"set-inactive", "set", func(r *desktopNodeMTURecord) { r.Active = false }},
		{"commit-active", "commit", func(r *desktopNodeMTURecord) { r.Active = true }},
		{"commit-value", "commit", func(r *desktopNodeMTURecord) { r.MTU = 1400 }},
		{"commit-reader", "commit", func(r *desktopNodeMTURecord) { r.Reader++; r.Index++ }},
		{"rollback-not-restored", "rollback", func(r *desktopNodeMTURecord) { r.Restored = false }},
		{"rollback-wrong-value", "rollback", func(r *desktopNodeMTURecord) { r.MTU = 1380 }},
		{"rollback-still-active", "rollback", func(r *desktopNodeMTURecord) { r.Active = true }},
		{"failed-command-abandoned-lease", "set", func(r *desktopNodeMTURecord) { r.Failure = "failed"; r.Active = false }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDesktopNodeMTUFixture(t)
			owner := fixture.owner(test.action != "begin")
			before := owner.record
			command, ack := nodeMTUAck(owner, test.action, 1380)
			test.edit(&ack)
			owner.pending = &command
			if err := fixture.publish(ack, true); err != nil {
				t.Fatal(err)
			}
			if err := owner.drain(); err == nil {
				t.Fatal("contradictory acknowledgement was accepted", ack)
			}
			if owner.pending != &command || owner.record != before || owner.closed {
				t.Fatal("invalid acknowledgement discarded or replaced its cleanup owner", owner.record)
			}
		})
	}
}

func TestDesktopNodeMTUCommittedReadCannotReactivateOrInventRollback(t *testing.T) {
	for _, mutation := range []string{"reactivated", "restoration-changed"} {
		t.Run(mutation, func(t *testing.T) {
			fixture := newDesktopNodeMTUFixture(t)
			owner := fixture.owner(true)
			owner.record.Active = false
			owner.committed = true
			record := owner.record
			if mutation == "reactivated" {
				record.Active = true
			} else {
				record.Restored = true
			}
			if err := fixture.publish(record, false); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Read(); err == nil {
				t.Fatal("terminal lease changed its retained lifecycle receipt", record)
			}
		})
	}
}

func TestDesktopNodeMTURejectedMutationKeepsVerifiedReaderForRollback(t *testing.T) {
	fixture := newDesktopNodeMTUFixture(t)
	owner := fixture.owner(true)
	command, ack := nodeMTUAck(owner, "set", 1380)
	ack.MTU, ack.Failure = 1420, "new reader returned the original MTU after failure"
	owner.pending = &command
	if err := fixture.publish(ack, true); err != nil {
		t.Fatal(err)
	}
	if err := owner.drain(); err == nil || owner.pending != nil || owner.record.Reader != ack.Reader || owner.record.MTU != 1420 {
		t.Fatal("rejected mutation lost its verified owned rollback reader", owner.record, err)
	}
	if _, err := owner.Read(); err == nil {
		t.Fatal("rejected native operation was advertised as a healthy current measurement")
	}
	fixture.base = ack
	commands := startDesktopNodeMTUFixtureChild(t, fixture, nil)
	actual, err := owner.Restore()
	if err != nil || actual.MTU != 1420 || !owner.record.Restored || owner.record.Active || owner.record.Failure != "" {
		t.Fatal("rejected operation could not complete exact owned rollback", actual, err)
	}
	select {
	case request := <-commands:
		if request.Action != "rollback" || request.Reader != ack.Reader {
			t.Fatal("rollback rediscovered a different reader", request)
		}
	case <-time.After(time.Second):
		t.Fatal("owned rollback was not issued")
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopNodeMTUReadBindsLastOperationReaderAndFailure(t *testing.T) {
	for _, kind := range []string{"valid", "request", "generation", "lease", "reader", "index", "interface", "mtu", "inactive", "failure", "stale-heartbeat", "future-heartbeat", "session", "config", "path"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newDesktopNodeMTUFixture(t)
			owner := fixture.owner(true)
			record := owner.record
			switch kind {
			case "request":
				record.Request = strings.Repeat("d", 32)
			case "generation":
				record.Generation++
			case "lease":
				record.Lease = strings.Repeat("d", 32)
			case "reader":
				record.Reader++
			case "index":
				record.Index++
			case "interface":
				record.Interface = "replacement"
			case "mtu":
				record.MTU = 1380
			case "inactive":
				record.Active = false
			case "failure":
				record.Failure = "native readback failed"
			case "session":
				record.Session = strings.Repeat("d", 32)
			case "config":
				record.Config = strings.Repeat("d", 64)
			case "path":
				record.Path = strings.Repeat("d", 64)
			}
			if err := fixture.publish(record, false); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(kind, "heartbeat") {
				record.Heartbeat = time.Now().Add(-5 * time.Second).UnixMilli()
				if kind == "future-heartbeat" {
					record.Heartbeat = time.Now().Add(5 * time.Second).UnixMilli()
				}
				raw, _ := json.Marshal(record)
				if err := os.WriteFile(filepath.Join(fixture.launch.directory, "node-mtu-status.json"), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			state, err := owner.Read()
			if (err == nil) != (kind == "valid") {
				t.Fatalf("captured read accepted a stale/foreign operation: state=%+v err=%v", state, err)
			}
			if kind == "valid" && state != owner.state() {
				t.Fatal("valid native reader lost its exact identity")
			}
		})
	}
}

func TestDesktopNodeMTUAckWaitsForInputConsumptionAndRejectsStaleNonce(t *testing.T) {
	fixture := newDesktopNodeMTUFixture(t)
	owner := fixture.owner(true)
	command, ack := nodeMTUAck(owner, "set", 1380)
	owner.pending = &command
	raw, _ := json.Marshal(command)
	if err := writeDesktopRuntimeFile(fixture.launch, "node-mtu-request.json", raw, false); err != nil {
		t.Fatal(err)
	}
	if err := fixture.publish(ack, false); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- owner.drain() }()
	select {
	case err := <-done:
		t.Fatal("response preceded exact command consumption", err)
	case <-time.After(35 * time.Millisecond):
	}
	stale := ack
	stale.Request = strings.Repeat("d", 32)
	if err := fixture.publish(stale, true); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		t.Fatal("old/foreign request acknowledgement was adopted", err)
	case <-time.After(35 * time.Millisecond):
	}
	if err := fixture.publish(ack, false); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("exact consumed acknowledgement did not drain")
	}
	if owner.pending != nil || owner.record.Request != command.Request || owner.record.MTU != 1380 {
		t.Fatal("matching operation was not adopted")
	}
}

func startDesktopNodeMTUFixtureChild(t *testing.T, fixture *desktopNodeMTUFixture, mutate func(desktopNodeMTUCommand, *desktopNodeMTURecord)) <-chan desktopNodeMTUCommand {
	t.Helper()
	stop, done := make(chan struct{}), make(chan struct{})
	commands := make(chan desktopNodeMTUCommand, 32)
	failed := make(chan error, 1)
	go func() {
		defer close(done)
		current := fixture.base
		original := current.MTU
		var committed *desktopNodeMTUCommand
		used := map[string]bool{}
		ticker := time.NewTicker(2 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
			}
			raw, err := readDesktopRuntimeFile(fixture.launch, "node-mtu-request.json", 4096)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				failed <- err
				return
			}
			var request desktopNodeMTUCommand
			if decodeRelayControlJSON(raw, &request) != nil || request.Session != current.Session || request.Config != current.Config || request.Path != current.Path || request.Generation != current.Generation+1 || request.Reader != current.Reader || request.MTU != current.MTU || used[request.Request] {
				failed <- fmt.Errorf("parent issued a stale or replayed native request: %+v", request)
				return
			}
			used[request.Request] = true
			next := current
			next.Generation, next.Request, next.Failure, next.Restored = request.Generation, request.Request, "", false
			if request.Action == "begin" {
				if current.Active || request.Value != 0 {
					failed <- errors.New("invalid begin")
					return
				}
				next.Lease, next.Active = request.Lease, true
				original, committed = current.MTU, nil
			} else if request.Action == "revert-unconfirmed-commit" {
				if current.Active || current.Restored || committed == nil || request.Lease != current.Lease || request.CommitRequest != committed.Request || request.CommitGeneration != committed.Generation || request.RevertToken == "" || request.RevertToken != committed.RevertToken || request.Value != original {
					failed <- errors.New("parent tried to revert an unowned or confirmed native commit")
					return
				}
				next.Active, next.Restored = false, true
				if next.MTU != original {
					next.MTU, next.Reader, next.Index = original, next.Reader+1, next.Index+1
				}
				committed = nil
			} else {
				if !current.Active || request.Lease != current.Lease {
					failed <- errors.New("parent followed a different native lease")
					return
				}
				switch request.Action {
				case "set":
					next.MTU, next.Reader, next.Index = request.Value, next.Reader+1, next.Index+1
				case "commit":
					next.Active = false
					if request.RevertToken != "" {
						capture := request
						committed = &capture
					}
				case "rollback":
					next.Active, next.Restored = false, true
					if next.MTU != original {
						next.MTU, next.Reader, next.Index = original, next.Reader+1, next.Index+1
					}
				default:
					failed <- errors.New("invalid native action")
					return
				}
			}
			if mutate != nil {
				mutate(request, &next)
			}
			if err := fixture.publish(next, true); err != nil {
				failed <- err
				return
			}
			current = next
			commands <- request
		}
	}()
	t.Cleanup(func() {
		close(stop)
		<-done
		select {
		case err := <-failed:
			t.Error(err)
		default:
		}
	})
	return commands
}

func TestDesktopNodeMTUActualMailboxMutationCommitAndRollback(t *testing.T) {
	for _, ending := range []string{"commit", "restore", "close"} {
		t.Run(ending, func(t *testing.T) {
			fixture := newDesktopNodeMTUFixture(t)
			commands := startDesktopNodeMTUFixtureChild(t, fixture, nil)
			kernel, err := openDesktopNodeMTUOwner(fixture.launch, mtuLiveSnapshot{Interface: fixture.base.Interface, Family: 4, OriginalMTU: 1420}, strings.Repeat("a", 32))
			if err != nil {
				t.Fatal(err)
			}
			owner := kernel.(*desktopNodeMTUOwner)
			state, err := owner.Read()
			if err != nil {
				t.Fatal(err)
			}
			wrong := state
			wrong.Index++
			if _, err := owner.Change(wrong, 1380); err == nil {
				t.Fatal("foreign expected reader mutated native TUN")
			}
			for _, invalid := range []int{1279, 9001} {
				if _, err := owner.Change(state, invalid); err == nil {
					t.Fatal("invalid native MTU accepted")
				}
			}
			next, err := owner.Change(state, 1380)
			if err != nil || next.MTU != 1380 || next.Identity == state.Identity || next.Index == state.Index {
				t.Fatal("new reader did not replace only its captured predecessor", next, err)
			}
			switch ending {
			case "commit":
				if err := owner.Commit(); err != nil {
					t.Fatal(err)
				}
			case "restore":
				restored, err := owner.Restore()
				if err != nil || restored.MTU != 1420 || restored.Identity == next.Identity {
					t.Fatal("rollback did not confirm its new original-value reader", restored, err)
				}
			}
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
			record, err := readDesktopNodeMTU(fixture.launch)
			if err != nil || record.Active || record.Failure != "" {
				t.Fatal("final native lease did not drain", record, err)
			}
			want := 1420
			if ending == "commit" {
				want = 1380
			}
			if record.MTU != want || record.Restored != (ending != "commit") {
				t.Fatal("wrong final native readback", record)
			}
			seen := []desktopNodeMTUCommand{}
			for i := 0; i < 3; i++ {
				select {
				case request := <-commands:
					seen = append(seen, request)
				case <-time.After(time.Second):
					t.Fatal("expected captured command was not observed")
				}
			}
			if seen[0].Action != "begin" || seen[1].Action != "set" || seen[2].Action == "begin" {
				t.Fatal("native lifecycle lost command ownership", seen)
			}
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case request := <-commands:
				t.Fatal("idempotent cleanup issued a new command", request)
			default:
			}
		})
	}
}

func TestDesktopNodeMTUFailedBeginRetainsRetryAndBlocksReplacementCapture(t *testing.T) {
	fixture := newDesktopNodeMTUFixture(t)
	a, snapshot := newMTUTransactionFixture(t)
	a.cmd = fixture.launch.command
	desktopNodeOwners.Store(a, fixture.launch)
	t.Cleanup(func() { desktopNodeOwners.Delete(a); mtuLiveOwners.Delete(a) })
	begin := make(chan desktopNodeMTUCommand, 1)
	go func() {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			raw, err := readDesktopRuntimeFile(fixture.launch, "node-mtu-request.json", 4096)
			var command desktopNodeMTUCommand
			if err == nil && decodeRelayControlJSON(raw, &command) == nil {
				record := fixture.base
				record.Generation, record.Request, record.Lease, record.Active = command.Generation, command.Request, strings.Repeat("d", 32), true
				if fixture.publish(record, true) == nil {
					begin <- command
				}
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()
	live := mtuLiveSnapshot{Interface: fixture.base.Interface, Family: 4, OriginalMTU: 1420}
	partial, err := captureMTULiveOwner(a, snapshot, live)
	if err == nil || partial == nil || partial.kernel == nil {
		t.Fatal("ambiguous begin discarded the exact cleanup owner", partial, err)
	}
	var command desktopNodeMTUCommand
	select {
	case command = <-begin:
	case <-time.After(time.Second):
		t.Fatal("failed begin command was not observed")
	}
	native := partial.kernel.(*desktopNodeMTUOwner)
	if retained, _ := mtuLiveOwners.Load(a); retained != partial || native.pending == nil {
		t.Fatal("partial begin was not retained in the application registry")
	}
	if replacement, err := captureMTULiveOwner(a, snapshot, live); err == nil || replacement != nil {
		t.Fatal("another capture bypassed the undrained begin")
	}
	if native.closed || native.pending == nil {
		t.Fatal("failed cleanup lost its retry command")
	}
	ack := fixture.base
	ack.Generation, ack.Request, ack.Lease, ack.Active = command.Generation, command.Request, command.Lease, true
	if err := fixture.publish(ack, true); err != nil {
		t.Fatal(err)
	}
	fixture.base = ack
	commands := startDesktopNodeMTUFixtureChild(t, fixture, nil)
	if err := partial.Close(); err != nil {
		t.Fatal("late matching begin could not be drained and rolled back", err)
	}
	if retained, _ := mtuLiveOwners.Load(a); retained != nil {
		t.Fatal("successful retry retained stale capture")
	}
	select {
	case request := <-commands:
		if request.Action != "rollback" || request.Lease != command.Lease {
			t.Fatal("cleanup followed a different lease", request)
		}
	case <-time.After(time.Second):
		t.Fatal("partial capture did not issue captured rollback")
	}
	final, err := readDesktopNodeMTU(fixture.launch)
	if err != nil || final.Active || !final.Restored || final.MTU != 1420 {
		t.Fatal("partial capture cleanup did not prove original MTU", final, err)
	}
}

func TestDesktopNodeMTUCapturedHTTPBridgeCommitsOrRestoresExactNativeReader(t *testing.T) {
	for _, outcome := range []string{"commit", "restore", "failed-mutation-restore"} {
		t.Run(outcome, func(t *testing.T) {
			fixture := newDesktopNodeMTUFixture(t)
			a, snapshot := newMTUTransactionFixture(t)
			a.cmd = fixture.launch.command
			desktopNodeOwners.Store(a, fixture.launch)
			t.Cleanup(func() { desktopNodeOwners.Delete(a); mtuLiveOwners.Delete(a) })
			startDesktopNodeMTUFixtureChild(t, fixture, func(request desktopNodeMTUCommand, ack *desktopNodeMTURecord) {
				if outcome == "failed-mutation-restore" && request.Action == "set" {
					ack.MTU, ack.Failure = 1420, "native reader returned original MTU after rejection"
				}
			})
			owner, err := captureMTULiveOwner(a, snapshot, mtuLiveSnapshot{Interface: fixture.base.Interface, Family: 4, OriginalMTU: 1420})
			if err != nil || owner == nil {
				t.Fatal("actual native capability capture failed", err)
			}
			t.Cleanup(func() {
				if err := owner.Close(); err != nil {
					t.Error(err)
				}
			})
			code, raw, err := mtuCapabilityCall(context.Background(), owner, http.MethodPost, "", "Bearer "+owner.token, `{"action":"set","mtu":1380}`)
			if err != nil || (code == http.StatusOK) != (outcome != "failed-mutation-restore") {
				t.Fatalf("native HTTP mutation changed its outcome: %d %s %v", code, raw, err)
			}
			if outcome == "commit" {
				if err := owner.ValidateMTU(1380); err != nil {
					t.Fatal(err)
				}
				if err := owner.Commit(); err != nil {
					t.Fatal(err)
				}
			} else if err := owner.Restore(); err != nil {
				t.Fatal("captured native rollback could not drain its actual mailbox", err)
			}
			expected := 1420
			if outcome == "commit" {
				expected = 1380
			}
			if err := owner.ValidateMTU(expected); err != nil {
				t.Fatal("terminal retained reader failed exact readback", err)
			}
			native := owner.kernel.(*desktopNodeMTUOwner)
			if native.record.Active || native.record.Restored != (outcome != "commit") || native.record.Failure != "" || native.state() != owner.current {
				t.Fatal("HTTP controller lost its committed native receipt", native.record, owner.current)
			}
			if _, _, err := mtuCapabilityCall(context.Background(), owner, http.MethodPost, "", "Bearer "+owner.token, `{"action":"set","mtu":1300}`); err == nil {
				t.Fatal("terminal native capability accepted a late mutation")
			}
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDesktopNodeMTUWorkspaceReplacementCannotAcknowledgeOrDelete(t *testing.T) {
	fixture := newDesktopNodeMTUFixture(t)
	owner := fixture.owner(true)
	command, ack := nodeMTUAck(owner, "set", 1380)
	owner.pending = &command
	old := fixture.launch.directory + ".retired"
	if err := os.Rename(fixture.launch.directory, old); err != nil {
		// Windows can deny renaming an open Root handle. That is an actual
		// platform ownership barrier; arbitrary rename failures still fail.
		if runtime.GOOS != "windows" || (!errors.Is(err, syscall.Errno(5)) && !errors.Is(err, syscall.Errno(32))) {
			t.Fatal(err)
		}
		if desktopExternalDirectoryCurrent(fixture.launch) != nil {
			t.Fatal("denied replacement invalidated the original owner")
		}
		return
	}
	if err := os.Mkdir(fixture.launch.directory, 0700); err != nil {
		t.Fatal(err)
	}
	ack.Heartbeat = time.Now().UnixMilli()
	raw, _ := json.Marshal(ack)
	path := filepath.Join(fixture.launch.directory, "node-mtu-status.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	before := owner.record
	if err := owner.drain(); err == nil {
		t.Fatal("replacement directory supplied the retired owner's acknowledgement")
	}
	if err := owner.Close(); err == nil {
		t.Fatal("replacement directory caused unverified old cleanup success")
	}
	actual, err := os.ReadFile(path)
	if err != nil || string(actual) != string(raw) || owner.pending == nil || owner.record != before || owner.closed {
		t.Fatal("retired operation mutated or discarded a replacement", err)
	}
}

func TestNativeNodeMTUEnvironmentStripsInheritedIdentities(t *testing.T) {
	session, config := strings.Repeat("a", 32), strings.Repeat("b", 64)
	actual := nativeNodeMTUEnvironment([]string{"KEEP=untouched", "HOMEVPN_NODE_SESSION=old", "homevpn_node_session=other", "HomeVpn_Node_Config_Sha256=foreign"}, session, config)
	if strings.Join(actual, "\n") != "KEEP=untouched\nHOMEVPN_NODE_SESSION="+session+"\nHOMEVPN_NODE_CONFIG_SHA256="+config {
		t.Fatal("native child inherited another owner's capability", actual)
	}
}
