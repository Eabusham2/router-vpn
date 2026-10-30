//go:build windows && routervpn_windows_protection_native

package windowsprotection

import (
	"context"
	"errors"
	"syscall"
	"testing"
	"time"

	"router-vpn/internal/mobiletor"
)

// The real next-slot handle loses write access, while its original retained
// handle remains owned for a checked retry. No pathname replacement or mocked
// flush error supplies this negative case.
func journalAttemptDenyNextWrite(t *testing.T, fixture *journalChannelNative) func() {
	t.Helper()
	file := fixture.store.slots[1-fixture.store.current.Slot]
	original := file.handle
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		t.Fatal(err)
	}
	var limited syscall.Handle
	if err := syscall.DuplicateHandle(process, original, process, &limited, 0x00120089, false, 0); err != nil {
		t.Fatal(err)
	}
	file.handle = limited
	restored := false
	restore := func() {
		if restored {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := fixture.server.Close(ctx); err != nil {
			t.Error("journal attempted write retained its unjoined channel", err)
			return
		}
		file.handle = original
		restored = true
		if err := syscall.CloseHandle(limited); err != nil {
			t.Error("journal attempted write could not close its exact readonly duplicate", err)
		}
	}
	t.Cleanup(restore)
	t.Cleanup(restore)
	return restore
}

func journalAttemptJoin(t *testing.T, fixture *journalChannelNative, child *journalChannelChild) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := fixture.server.Close(ctx); err != nil {
		t.Fatal("journal attempted write did not join its exact channel", err)
	}
	fixture.finish(t, child)
}

func TestWindowsProtectionJournalAttemptPendingDrain(t *testing.T) {
	for _, phase := range []string{"intent", "settled"} {
		t.Run(phase, func(t *testing.T) {
			fixture := newJournalChannelNative(t, nil)
			if record, err := fixture.server.DrainAttempt(fixture.ctx); err == nil || record.Validate() == nil {
				t.Fatal("unused live channel supplied a joined journal attempt", err)
			}
			var child *journalChannelChild
			var failure journalChannelResult
			var report journalChannelReport
			var restore func()
			if phase == "intent" {
				restore = journalAttemptDenyNextWrite(t, fixture)
				child = fixture.launch(t, "client", fixture.server.PipeName())
				fixture.receive(child)
				report = fixture.report(t, child, true)
				failure = fixture.received(t)
				if report.Accepted || report.Replayed || !report.Closed {
					t.Fatal("denied intent write acquired a native acknowledgment", report)
				}
			} else {
				var intent JournalRecord
				child, intent = journalAdmissionStart(t, fixture, "admission-client")
				restore = journalAttemptDenyNextWrite(t, fixture)
				result := journalAdmissionRun(fixture, func(ctx context.Context, target mobiletor.DesktopWindowsProtectionTarget) error {
					if ctx.Err() != nil || target != *intent.Intent.Candidate.Target {
						return errors.New("pending settlement changed its modeled exact prepared target")
					}
					return nil
				})
				report = fixture.report(t, child, true)
				failure = journalAdmissionResult(t, fixture, result)
				journalAdmissionRequireDenied(t, report)
			}
			if !errors.Is(failure.err, syscall.ERROR_ACCESS_DENIED) || failure.record.Validate() == nil || fixture.store.pending == nil {
				t.Fatal("actual failed write did not retain its unacknowledged attempt", phase, failure.err)
			}
			attempted := cloneJournalRecord(fixture.store.pending.record)
			if attempted.Phase != phase || fixture.server.attempted == nil || !journalAdmissionSameRecord(*fixture.server.attempted, attempted) {
				t.Fatal("channel forgot the exact native append before its failed flush", phase)
			}
			before := fixture.store.current.SHA256
			journalAttemptJoin(t, fixture, child)
			if record, err := fixture.server.DrainAttempt(fixture.ctx); !errors.Is(err, syscall.ERROR_ACCESS_DENIED) || record.Validate() == nil || fixture.store.pending == nil || fixture.store.current.SHA256 != before {
				t.Fatal("readonly retry discarded or adopted a different journal attempt", phase, err)
			}
			restore()
			cancelled, cancel := context.WithCancel(context.Background())
			cancel()
			if record, err := fixture.server.DrainAttempt(cancelled); !errors.Is(err, context.Canceled) || record.Validate() == nil || fixture.store.pending == nil {
				t.Fatal("cancelled pending drain changed its retained exact attempt", phase, err)
			}
			durable, err := fixture.server.DrainAttempt(fixture.ctx)
			if err != nil || !journalAdmissionSameRecord(durable, attempted) || fixture.store.pending != nil {
				t.Fatal("joined journal channel could not drain its exact pending append", phase, err)
			}
			selection, err := fixture.store.Snapshot(fixture.ctx)
			if err != nil || selection.Incomplete || !journalAdmissionSameRecord(selection.Record, attempted) {
				t.Fatal("pending drain did not independently read its exact flushed bytes", phase, err)
			}
			again, err := fixture.server.DrainAttempt(fixture.ctx)
			if err != nil || !journalAdmissionSameRecord(again, durable) || fixture.store.current.SHA256 != selection.SHA256 {
				t.Fatal("duplicate attempted drain created or adopted another journal generation", phase, err)
			}
			// Returned values are comparisons, never mutable aliases of the
			// attempt that remains retained for a later cleanup retry.
			if durable.Intent != nil {
				durable.Intent.Candidate.Engine.PID++
			} else {
				durable.Committed.Engine.PID++
			}
			again, err = fixture.server.DrainAttempt(fixture.ctx)
			if err != nil || !journalAdmissionSameRecord(again, attempted) {
				t.Fatal("attempted drain exposed its captured engine through a mutable alias", phase, err)
			}
		})
	}
}

func TestWindowsProtectionJournalAttemptRejectsNewerCheckpoint(t *testing.T) {
	fixture := newJournalChannelNative(t, nil)
	child, intent := journalAdmissionStart(t, fixture, "client")
	report := fixture.report(t, child, true)
	if !report.Accepted || report.Replayed || !report.Closed {
		t.Fatal("completed intent fixture lost its actual acknowledgment", report)
	}
	journalAttemptJoin(t, fixture, child)
	durable, err := fixture.server.DrainAttempt(fixture.ctx)
	if err != nil || !journalAdmissionSameRecord(durable, intent) {
		t.Fatal("closed channel could not re-prove its already flushed intent", err)
	}
	settled, err := DeriveJournalAdmissionSettlement(intent)
	if err != nil {
		t.Fatal(err)
	}
	// The actual test child and its Job joined above. Only the BFE target is
	// an explicit fixture comparison; this writes no native Firewall policy.
	settled.Committed.Engine = nil
	selection, err := fixture.store.Append(fixture.ctx, settled.PreviousSHA256, settled)
	if err != nil || !journalAdmissionSameRecord(selection.Record, settled) {
		t.Fatal("fixture could not retain its later joined comparison checkpoint", err)
	}
	if record, err := fixture.server.DrainAttempt(fixture.ctx); err == nil || record.Validate() == nil {
		t.Fatal("old channel adopted another durable journal generation", err)
	}
	actual, err := fixture.store.Snapshot(fixture.ctx)
	if err != nil || actual.SHA256 != selection.SHA256 || !journalAdmissionSameRecord(actual.Record, settled) {
		t.Fatal("old attempted drain mutated its later exact checkpoint", err)
	}
}

func TestWindowsProtectionJournalAttemptNoWrite(t *testing.T) {
	fixture := newJournalChannelNative(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := fixture.server.Close(ctx); err != nil {
		t.Fatal(err)
	}
	record, err := fixture.server.DrainAttempt(fixture.ctx)
	if err != nil || record.Validate() == nil {
		t.Fatal("unused joined journal channel invented an attempted write", err)
	}
	selection, err := fixture.store.Snapshot(fixture.ctx)
	if err != nil || selection.Record.Sequence != 1 || fixture.store.pending != nil {
		t.Fatal("unused joined channel changed its original journal", err)
	}
}
