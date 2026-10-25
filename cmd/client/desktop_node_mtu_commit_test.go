package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func TestDesktopNodeMTULateCommitReceiptRestoresExactLiveAndDurableOwner(t *testing.T) {
	for _, cleanup := range []string{"restore", "close"} {
		t.Run(cleanup, func(t *testing.T) {
			fixture := newDesktopNodeMTUFixture(t)
			a, snapshot := newMTUTransactionFixture(t)
			a.cmd = fixture.launch.command
			desktopNodeOwners.Store(a, fixture.launch)
			t.Cleanup(func() { desktopNodeOwners.Delete(a); mtuLiveOwners.Delete(a) })
			releaseAck := make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(releaseAck) }) }
			defer release()
			committed := make(chan desktopNodeMTUCommand, 1)
			commands := startDesktopNodeMTUFixtureChild(t, fixture, func(request desktopNodeMTUCommand, _ *desktopNodeMTURecord) {
				if request.Action == "commit" {
					committed <- request
					<-releaseAck
				}
			})
			owner, err := captureMTULiveOwner(a, snapshot, mtuLiveSnapshot{Interface: fixture.base.Interface, Family: 4, OriginalMTU: 1420})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				release()
				if err := owner.Close(); err != nil {
					t.Error(err)
				}
			})
			code, _, err := mtuCapabilityCall(context.Background(), owner, http.MethodPost, "", "Bearer "+owner.token, `{"action":"set","mtu":1380}`)
			if err != nil || code != http.StatusOK {
				t.Fatal("captured candidate was not applied", code, err)
			}
			if _, err := persistMTUMeasurement(a, snapshot, testMTUMeasurement()); err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			if err := owner.Commit(); err == nil || time.Since(started) < 11*time.Second {
				t.Fatal("missing commit receipt bypassed the real12-second parent deadline", err)
			}
			native := owner.kernel.(*desktopNodeMTUOwner)
			var commit desktopNodeMTUCommand
			select {
			case commit = <-committed:
			default:
				t.Fatal("native fixture did not consume the proposed commit")
			}
			if native.committed || native.closed || native.pending == nil || native.unconfirmedCommit == nil || native.unconfirmedCommit.Request != commit.Request || !desktopMTURequestPattern.MatchString(commit.RevertToken) {
				t.Fatal("missing receipt lost its private unresolved commit capability")
			}
			if _, err := native.Read(); err == nil {
				t.Fatal("unconfirmed commit was exposed as a confirmed current readback")
			}
			if _, ok := native.CleanupRestored(); ok {
				t.Fatal("unconfirmed commit fabricated a rollback receipt")
			}
			release()
			if cleanup == "restore" {
				if err := owner.Restore(); err != nil {
					t.Fatal("late matching commit did not restore its original native reader", err)
				}
			}
			if err := owner.Close(); err != nil {
				t.Fatal("unconfirmed commit cleanup did not finish its explicit revert", err)
			}
			if err := restoreMTUMeasurementFields(a, snapshot); err != nil {
				t.Fatal("exact durable measurement rollback failed", err)
			}
			state, restored := native.CleanupRestored()
			if !restored || state.MTU != 1420 || owner.current != state || !owner.restored || owner.changed || native.unconfirmedCommit != nil || native.pending != nil || !native.closed {
				t.Fatal("checked late cleanup lost its original-value receipt", state, restored)
			}
			if _, retained := mtuLiveOwners.Load(a); retained {
				t.Fatal("checked rollback kept an already-closed owner")
			}
			raw, err := os.ReadFile(a.cfg.ProfilesFile)
			var saved common.RouterProfileStore
			if err != nil || json.Unmarshal(raw, &saved) != nil || len(saved.Profiles) != 1 || mtuMeasurementFieldsDigest(saved.Profiles[0]) != mtuMeasurementFieldsDigest(snapshot.Profile) {
				t.Fatal("lost commit acknowledgement left durable fields naming the unconfirmed candidate", err)
			}
			var revert desktopNodeMTUCommand
			for i := 0; i < 4; i++ {
				select {
				case request := <-commands:
					if request.Action == "revert-unconfirmed-commit" {
						revert = request
					}
				case <-time.After(time.Second):
					t.Fatal("native lifecycle omitted its captured revert")
				}
			}
			if revert.CommitRequest != commit.Request || revert.CommitGeneration != commit.Generation || revert.RevertToken != commit.RevertToken || revert.Lease != commit.Lease || revert.Reader != commit.Reader || revert.MTU != 1380 || revert.Value != 1420 {
				t.Fatal("late cleanup did not target the original unconfirmed commit and exact candidate reader")
			}
		})
	}
}

func TestDesktopNodeMTUConfirmedCommitDiscardsRevertAuthority(t *testing.T) {
	fixture := newDesktopNodeMTUFixture(t)
	commands := startDesktopNodeMTUFixtureChild(t, fixture, nil)
	kernel, err := openDesktopNodeMTUOwner(fixture.launch, mtuLiveSnapshot{Interface: fixture.base.Interface, Family: 4, OriginalMTU: 1420}, strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	owner := kernel.(*desktopNodeMTUOwner)
	current, err := owner.Read()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = owner.Change(current, 1380); err != nil {
		t.Fatal(err)
	}
	if err := owner.Commit(); err != nil || owner.unconfirmedCommit != nil || !owner.committed {
		t.Fatal("confirmed commit retained a private revert capability", err)
	}
	if _, err := owner.Restore(); err == nil {
		t.Fatal("confirmed inactive commit was later rolled back")
	}
	if err := owner.exchange("revert-unconfirmed-commit", 1420); err == nil || owner.pending != nil {
		t.Fatal("confirmed commit constructed a revert request")
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if _, restored := owner.CleanupRestored(); restored {
		t.Fatal("confirmed candidate was mislabeled as restored")
	}
	for i := 0; i < 3; i++ {
		select {
		case <-commands:
		case <-time.After(time.Second):
			t.Fatal("confirmed commit omitted an expected command")
		}
	}
	select {
	case <-commands:
		t.Fatal("confirmed commit emitted an additional mutation")
	default:
	}
}

func TestDesktopNodeMTUInactiveUnconfirmedOwnerCannotBeDropped(t *testing.T) {
	fixture := newDesktopNodeMTUFixture(t)
	owner := fixture.owner(true)
	owner.record.Active, owner.record.MTU = false, 1380
	if err := fixture.publish(owner.record, false); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err == nil || owner.closed {
		t.Fatal("inactive state alone became successful native cleanup")
	}
}

func TestDesktopNodeMTUFailedCommitRevertRemainsOwned(t *testing.T) {
	fixture := newDesktopNodeMTUFixture(t)
	owner := fixture.owner(true)
	owner.record.Active, owner.record.MTU = false, 1380
	commit := desktopNodeMTUCommand{Action: "commit", Session: owner.record.Session, Config: owner.record.Config, Path: owner.record.Path, Lease: owner.lease, Request: strings.Repeat("d", 32), Generation: owner.record.Generation, RevertToken: strings.Repeat("e", 32)}
	owner.unconfirmedCommit = &commit
	request := desktopNodeMTUCommand{Action: "revert-unconfirmed-commit", Session: owner.record.Session, Config: owner.record.Config, Path: owner.record.Path, Lease: owner.lease, Request: strings.Repeat("f", 32), Generation: owner.record.Generation + 1, Reader: owner.record.Reader, MTU: 1380, Value: 1420, RevertToken: commit.RevertToken, CommitRequest: commit.Request, CommitGeneration: commit.Generation}
	owner.pending = &request
	record := owner.record
	record.Request, record.Generation, record.Failure = request.Request, request.Generation, "revert rejected"
	if err := fixture.publish(record, true); err != nil {
		t.Fatal(err)
	}
	err := owner.drain()
	record.Heartbeat = owner.record.Heartbeat
	if err == nil || owner.pending != nil || owner.unconfirmedCommit == nil || owner.committed || owner.closed || owner.record != record {
		t.Fatal("rejected inactive revert discarded its exact cleanup capability")
	}
	if _, ok := owner.CleanupRestored(); ok {
		t.Fatal("failed native revert claimed a successful rollback")
	}
	if _, err := readDesktopRuntimeFile(fixture.launch, "node-mtu-request.json", 4096); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("fixture did not consume its rejected command", err)
	}
}

func TestDesktopNodeMTUCloseAcceptsOnlyExactExpiryRestoration(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(map[bool]string{false: "last-consumed-command", true: "consumed-pending-commit"}[pending], func(t *testing.T) {
			fixture := newDesktopNodeMTUFixture(t)
			owner := fixture.owner(true)
			owner.record.Reader, owner.record.Index, owner.record.MTU = 2, 8, 1380
			expiry := owner.record
			expiry.Active, expiry.Restored, expiry.Expired = false, true, true
			expiry.Reader, expiry.Index, expiry.MTU = 3, 9, 1420
			expiry.Failure = "captured MTU lease expired; original MTU restored"
			if pending {
				command, _ := nodeMTUAck(owner, "commit", 0)
				command.RevertToken = strings.Repeat("e", 32)
				owner.pending = &command
				capture := command
				owner.unconfirmedCommit = &capture
				raw, _ := json.Marshal(command)
				if err := writeDesktopRuntimeFile(fixture.launch, "node-mtu-request.json", raw, true); err != nil {
					t.Fatal(err)
				}
				expiry.Generation, expiry.Request = command.Generation, command.Request
				expiry.Failure = "captured TUN operation rejected"
			}
			if err := fixture.publish(expiry, true); err != nil {
				t.Fatal(err)
			}
			if err := owner.Close(); err != nil || !owner.closed || owner.pending != nil || owner.unconfirmedCommit != nil {
				t.Fatal("verified native expiry could not retire its exact lease", err)
			}
			state, ok := owner.CleanupRestored()
			if !ok || state.MTU != 1420 || state.Index != 9 || !owner.record.Expired || !owner.record.Restored {
				t.Fatal("native expiry lost its checked original-value reader", state, ok)
			}
		})
	}
	for _, mutation := range []string{"active", "not-restored", "wrong-value", "lease", "session", "config", "path", "request", "generation", "reader", "same-reader-new-index", "failure", "confirmed-commit"} {
		t.Run(mutation, func(t *testing.T) {
			fixture := newDesktopNodeMTUFixture(t)
			owner := fixture.owner(true)
			expiry := owner.record
			expiry.Active, expiry.Restored, expiry.Expired = false, true, true
			expiry.Failure = "captured MTU lease expired; original MTU restored"
			switch mutation {
			case "active":
				expiry.Active = true
			case "not-restored":
				expiry.Restored = false
			case "wrong-value":
				expiry.MTU = 1380
			case "lease":
				expiry.Lease = strings.Repeat("f", 32)
			case "session":
				expiry.Session = strings.Repeat("f", 32)
			case "config":
				expiry.Config = strings.Repeat("f", 64)
			case "path":
				expiry.Path = strings.Repeat("f", 64)
			case "request":
				expiry.Request = strings.Repeat("f", 32)
			case "generation":
				expiry.Generation++
			case "reader":
				expiry.Reader += 3
			case "same-reader-new-index":
				expiry.Index++
			case "failure":
				expiry.Failure = "another operation failed"
			case "confirmed-commit":
				owner.committed, owner.record.Active = true, false
			}
			before := owner.record
			if accepted, err := owner.acceptExpiredRestoration(expiry); err == nil || accepted || owner.record != before || owner.closed {
				t.Fatal("foreign expiry receipt discharged native ownership", mutation, err)
			}
		})
	}
}

func TestDesktopNodeMTUCheckedRuntimeRetirementNeverClaimsNumericRollback(t *testing.T) {
	for _, kind := range []string{"valid", "process-exit-only", "session", "config", "open", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newDesktopNodeMTUFixture(t)
			owner := fixture.owner(true)
			owner.record.Active, owner.record.MTU = false, 1380
			if err := fixture.publish(owner.record, false); err != nil {
				t.Fatal(err)
			}
			if kind != "process-exit-only" {
				closed := desktopExternalStop{Schema: 1, SessionID: fixture.launch.mtuSession, SourceSHA256: fixture.launch.configSHA256, Closed: true}
				switch kind {
				case "session":
					closed.SessionID = strings.Repeat("f", 32)
				case "config":
					closed.SourceSHA256 = strings.Repeat("f", 64)
				case "open":
					closed.Closed = false
				}
				raw, _ := json.Marshal(closed)
				if kind == "duplicate" {
					raw = append(raw[:len(raw)-1], []byte(`,"closed":true}`)...)
				}
				if err := writeDesktopRuntimeFile(fixture.launch, "stopped.json", raw, false); err != nil {
					t.Fatal(err)
				}
			} else {
				fixture.launch.nodeWaitOnce.Do(func() {
					fixture.launch.nodeWaitDone = make(chan struct{})
					close(fixture.launch.nodeWaitDone)
				})
			}
			err := owner.Close()
			if kind == "valid" {
				if err != nil || !owner.closed || !owner.runtimeRetired {
					t.Fatal("exact child close receipt did not discharge the retired TUN", err)
				}
			} else if err == nil || owner.closed || owner.runtimeRetired {
				t.Fatal("process death or foreign close receipt discarded native ownership", kind)
			}
			if _, restored := owner.CleanupRestored(); restored {
				t.Fatal("runtime teardown fabricated an original-MTU readback")
			}
		})
	}
}
