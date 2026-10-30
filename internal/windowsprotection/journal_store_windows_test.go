//go:build windows && routervpn_windows_protection_native

package windowsprotection

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"router-vpn/internal/mobiletor"
	"router-vpn/internal/windowscontroller"
)

type journalNativeFixture struct {
	machine string
	data    *os.File
	desktop *windowscontroller.Process
	store   *ProtectionJournal
	reads   int
}

func journalNativeInputs(t *testing.T) *journalNativeFixture {
	t.Helper()
	protectionRequireNative(t)
	fixture := &journalNativeFixture{machine: t.TempDir()}
	dataPath := filepath.Join(t.TempDir(), "Data")
	if err := os.Mkdir(dataPath, 0700); err != nil {
		t.Fatal(err)
	}
	var err error
	fixture.data, err = os.Open(dataPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fixture.data.Close() })
	fixture.desktop, err = windowscontroller.OpenProcess(uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fixture.desktop.Close() })
	return fixture
}

func (fixture *journalNativeFixture) initialRead(_ context.Context, target *mobiletor.DesktopWindowsProtectionTarget) error {
	fixture.reads++
	if target != nil {
		return errors.New("storage fixture only models explicit initial absence")
	}
	return nil
}

func journalNativeCreate(t *testing.T) *journalNativeFixture {
	t.Helper()
	fixture := journalNativeInputs(t)
	store, err := createProtectionJournal(context.Background(), fixture.machine, fixture.desktop, fixture.data, fixture.initialRead)
	fixture.store = store
	if store != nil {
		t.Cleanup(func() {
			if err := store.Close(); err != nil {
				t.Error("journal native creator failed to join its captured handles", err)
			}
		})
	}
	if err != nil || store == nil || fixture.reads != 1 {
		t.Fatal("actual journal file capture and initial durable write failed", err, fixture.reads)
	}
	return fixture
}

func journalNativeOpen(t *testing.T, fixture *journalNativeFixture) (*ProtectionJournal, error) {
	t.Helper()
	store, err := openProtectionJournal(context.Background(), fixture.machine, fixture.desktop, fixture.data)
	if store != nil {
		t.Cleanup(func() {
			if err := store.Close(); err != nil {
				t.Error("journal reopened owner failed to join its captured handles", err)
			}
		})
	}
	return store, err
}

func journalNativeCheckpoint(t *testing.T, store *ProtectionJournal) JournalSelection {
	t.Helper()
	previous, err := store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	next := journalTestNext(t, previous.Record)
	actual, err := store.Append(context.Background(), previous.SHA256, next)
	if err != nil || actual.Record.Sequence != next.Sequence || actual.Slot == previous.Slot || actual.Incomplete {
		t.Fatal("journal did not acknowledge its exact flushed alternate slot", err)
	}
	retained, err := journalReadRetained(store.slots[previous.Slot], JournalRecordLimit)
	if err != nil || !bytes.Equal(retained, journalTestBody(t, previous.Record)) {
		t.Fatal("journal append destroyed its preceding complete slot", err)
	}
	return actual
}

// Only the initial BFE absence reader is an explicit fixture here. File ACLs,
// identities, exclusive sharing, process tokens, writes, flushes and reads are
// real Windows operations. No test opens the production machine journal or
// changes a Firewall/BFE policy; that authority belongs to separate gates.
func TestWindowsProtectionJournalStoreActualLifecycle(t *testing.T) {
	fixture := journalNativeCreate(t)
	store := fixture.store
	initial, err := store.Snapshot(context.Background())
	if err != nil || initial.Record.Controller.PID != uint32(os.Getpid()) || initial.Record.Sequence != 1 || initial.Incomplete || initial.Record.Committed.Target != nil {
		t.Fatal("native journal fabricated its initial controller or absent state", err)
	}
	if store.header.DesktopSID != store.desktopCapture.SID || store.header.Data != journalIdentity(store.data) || store.header.Header != journalIdentity(store.file) {
		t.Fatal("journal did not capture original-user and native file identities")
	}
	header, lock := append([]byte(nil), store.headerBytes...), append([]byte(nil), store.lockBytes...)
	second := journalNativeCheckpoint(t, store)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	for name, expected := range map[string][]byte{journalHeaderName: header, journalLockName: lock} {
		actual, err := os.ReadFile(filepath.Join(store.root.path, name))
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatal("journal close deleted or rewrote its durable native owner", err)
		}
	}
	reopened, err := journalNativeOpen(t, fixture)
	if err != nil {
		t.Fatal("same-controller stable lock could not reopen after checked Close", err)
	}
	read, err := reopened.Snapshot(context.Background())
	if err != nil || read.SHA256 != second.SHA256 || reopened.header != store.header {
		t.Fatal("journal reopen changed its immutable files or acknowledged generation", err)
	}
	third := journalNativeCheckpoint(t, reopened)
	if third.Record.Sequence != 3 {
		t.Fatal("journal did not preserve monotonic durable generations")
	}
	read.Record.Controller.SID = "S-1-5-18"
	if _, err := reopened.Snapshot(context.Background()); err != nil {
		t.Fatal("comparison snapshot mutated the retained native owner", err)
	}
	if _, err := store.Append(context.Background(), second.SHA256, journalTestNext(t, second.Record)); err == nil {
		t.Fatal("closed journal reacquired pathname write authority")
	}
}

func TestWindowsProtectionJournalStoreRejectsUnboundTarget(t *testing.T) {
	t.Run("new-candidate", testWindowsProtectionJournalStoreRejectsUnboundCandidate)
	for _, action := range []string{"release", "off"} {
		t.Run("old-"+action+"-to-absence", func(t *testing.T) {
			fixture := journalNativeCreate(t)
			store := fixture.store
			// Install canonical legacy comparison records into the actual fixed
			// slots after the original native owner has joined. Reopening must
			// preserve their bytes without granting an unbound old target new
			// write authority merely because its next outcome has no target.
			previous := journalTestRetained(t)
			previous.JournalID, previous.Controller = store.header.JournalID, store.controller
			previous.Committed.ProfileRevision = ""
			previous.Committed.Target.Policy = "on-connect"
			pending := journalTestNext(t, previous)
			pending.Phase = "intent"
			pending.Intent = &JournalIntent{Action: action, RequestID: strings.Repeat("c", 32), ProfileID: previous.Committed.ProfileID,
				ProfileRevision: strings.Repeat("f", 64), ResultProfileRevision: strings.Repeat("f", 64)}
			if action == "off" {
				pending.Intent.ResultProfileRevision = strings.Repeat("d", 64)
			}
			next := journalTestSettled(t, pending, JournalState{})
			if err := CheckJournalTransition(pending, next); err != nil {
				t.Fatal("legacy empty settlement must remain valid comparison evidence", err)
			}
			before := [2][]byte{journalTestBody(t, previous), journalTestBody(t, pending)}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			for index, body := range before {
				journalNativeOverwrite(t, store.api, store.slots[index].path, body)
			}
			opened, err := journalNativeOpen(t, fixture)
			if err != nil {
				t.Fatal("legacy intact records must remain readable", err)
			}
			current, err := opened.Snapshot(context.Background())
			if err != nil || current.Record.Sequence != pending.Sequence || current.Incomplete {
				t.Fatal("legacy fixture did not retain its exact old pending intent", err)
			}
			if _, err := opened.Append(context.Background(), current.SHA256, next); err == nil || opened.pending != nil {
				t.Fatal("unbound old intent acquired native empty-settlement authority")
			}
			for index, expected := range before {
				actual, err := journalReadRetained(opened.slots[index], JournalRecordLimit)
				if err != nil || !bytes.Equal(actual, expected) {
					t.Fatal("rejected legacy retirement changed captured journal bytes", err)
				}
			}
		})
	}
}

func testWindowsProtectionJournalStoreRejectsUnboundCandidate(t *testing.T) {
	fixture := journalNativeCreate(t)
	store := fixture.store
	current, err := store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	next := journalTestNext(t, current.Record)
	next.Phase = "intent"
	engine := store.controller
	engine.PID++
	engine.StartTimeUTCTicks++
	candidate := journalTestState("b", false)
	candidate.ProfileRevision, candidate.Engine = "", &engine
	next.Intent = &JournalIntent{Action: "successor", RequestID: strings.Repeat("b", 32), ProfileID: candidate.ProfileID,
		ProfileRevision: strings.Repeat("f", 64), ResultProfileRevision: strings.Repeat("f", 64), Candidate: candidate}
	if err := CheckJournalTransition(current.Record, next); err != nil {
		t.Fatal("legacy unbound record fixture must remain valid comparison evidence", err)
	}
	if _, err := store.Append(context.Background(), current.SHA256, next); err == nil || store.pending != nil {
		t.Fatal("unbound target acquired native journal write authority")
	}
	actual, err := store.Snapshot(context.Background())
	if err != nil || actual.SHA256 != current.SHA256 {
		t.Fatal("rejected unbound write changed the captured native journal", err)
	}
}

func TestWindowsProtectionJournalStoreExclusiveAndNamespace(t *testing.T) {
	fixture := journalNativeCreate(t)
	store := fixture.store
	other, err := journalNativeOpen(t, fixture)
	if err == nil {
		t.Fatal("another journal acquired the live exclusive kernel lock")
	}
	if other != nil {
		if err := other.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for name, attempt := range map[string]func() error{
		"header-write":  func() error { return os.WriteFile(store.file.path, []byte("unrelated"), 0600) },
		"lock-delete":   func() error { return os.Remove(store.lock.path) },
		"slot-rename":   func() error { return os.Rename(store.slots[0].path, store.slots[0].path+".moved") },
		"root-rename":   func() error { return os.Rename(store.root.path, store.root.path+".moved") },
		"parent-rename": func() error { return os.Rename(fixture.machine, fixture.machine+".moved") },
		"data-rename":   func() error { return os.Rename(fixture.data.Name(), fixture.data.Name()+".moved") },
	} {
		t.Run(name, func(t *testing.T) {
			if err := attempt(); err == nil {
				t.Fatal("journal retained namespace allowed a data or directory replacement")
			}
			if _, err := store.Snapshot(context.Background()); err != nil {
				t.Fatal("rejected namespace mutation changed the original journal", err)
			}
		})
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(store.root.path, store.root.path+".moved"); err != nil {
		t.Fatal("journal namespace remained pinned after its actual handles joined", err)
	}
	if err := os.Rename(store.root.path+".moved", store.root.path); err != nil {
		t.Fatal(err)
	}
}

func journalNativeReplaceFile(t *testing.T, api *protectionNativeAPI, path string, body []byte) {
	t.Helper()
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	file, err := createProtectionFile(api, path, false)
	if file != nil {
		defer file.close()
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := journalWriteRetained(file, body); err != nil {
		t.Fatal(err)
	}
	// Move the original outside the strict journal inventory. This tests exact
	// file identity rather than merely an extra-name or inherited-ACL rejection.
	if err := os.Rename(path+".old", filepath.Join(t.TempDir(), "original")); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsProtectionJournalStoreRejectsReplacedFiles(t *testing.T) {
	for _, name := range []string{journalHeaderName, journalLockName, journalSlotNames[0], journalSlotNames[1]} {
		t.Run(name, func(t *testing.T) {
			fixture := journalNativeCreate(t)
			store := fixture.store
			path := filepath.Join(store.root.path, name)
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			journalNativeReplaceFile(t, store.api, path, body)
			opened, err := journalNativeOpen(t, fixture)
			if err == nil || !strings.Contains(err.Error(), "header differs from retained") {
				t.Fatal("journal adopted identical bytes under a replacement native file identity", err)
			}
			if opened != nil {
				if err := opened.Close(); err != nil {
					t.Fatal(err)
				}
			}
			actual, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(actual, body) {
				t.Fatal("rejected reopen changed an unrelated replacement", err)
			}
		})
	}
}

func journalNativeOverwrite(t *testing.T, api *protectionNativeAPI, path string, body []byte) {
	t.Helper()
	file, err := openProtectionObject(path, false, syscall.GENERIC_READ|syscall.GENERIC_WRITE|protectionReadControl, 0)
	if file != nil {
		defer file.close()
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyProtectionSecurity(api, file.handle, false); err != nil {
		t.Fatal(err)
	}
	if err := journalWriteRetained(file, body); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsProtectionJournalStoreOriginalUserAndData(t *testing.T) {
	for _, change := range []string{"desktop-user", "private-directory", "unknown-file"} {
		t.Run(change, func(t *testing.T) {
			fixture := journalNativeCreate(t)
			store := fixture.store
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "desktop-user":
				header := store.header
				header.DesktopSID = "S-1-5-18"
				if header.DesktopSID == store.desktopCapture.SID {
					header.DesktopSID = "S-1-5-20"
				}
				raw, err := canonicalJournalHeader(header)
				if err != nil {
					t.Fatal(err)
				}
				journalNativeOverwrite(t, store.api, store.file.path, raw)
			case "private-directory":
				other, err := os.Open(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				defer other.Close()
				original := fixture.data
				defer func() { fixture.data = original }()
				fixture.data = other
			case "unknown-file":
				if err := os.WriteFile(filepath.Join(store.root.path, "legacy-recovery.json"), []byte("unrelated"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := journalNativeOpen(t, fixture); err == nil {
				t.Fatal("journal adopted another original user, private directory or unknown inventory")
			}
		})
	}
}

func TestWindowsProtectionJournalStoreTornSlotIsReadOnly(t *testing.T) {
	for _, progressed := range []bool{false, true} {
		t.Run(map[bool]string{false: "initial", true: "later"}[progressed], func(t *testing.T) {
			fixture := journalNativeCreate(t)
			store := fixture.store
			if progressed {
				journalNativeCheckpoint(t, store)
			}
			current, err := store.Snapshot(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			next := journalTestNext(t, current.Record)
			raw := journalTestBody(t, next)
			torn := raw[:len(raw)/2]
			path := store.slots[1-current.Slot].path
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			journalNativeOverwrite(t, store.api, path, torn)
			opened, err := journalNativeOpen(t, fixture)
			if err != nil {
				t.Fatal("journal lost its surviving complete comparison slot", err)
			}
			read, err := opened.Snapshot(context.Background())
			if err != nil || !read.Incomplete || read.SHA256 != current.SHA256 {
				t.Fatal("journal guessed an acknowledged generation from a torn slot", err)
			}
			if _, err := opened.Append(context.Background(), read.SHA256, next); err == nil {
				t.Fatal("incomplete journal acquired ordinary append authority")
			}
			actual, err := journalReadRetained(opened.slots[1-read.Slot], JournalRecordLimit)
			if err != nil || !bytes.Equal(actual, torn) {
				t.Fatal("rejected append overwrote unresolved durable state", err)
			}
		})
	}
}

func TestWindowsProtectionJournalStorePendingWriteRetriesSameOwner(t *testing.T) {
	fixture := journalNativeCreate(t)
	store := fixture.store
	current, err := store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	next := journalTestNext(t, current.Record)
	file := store.slots[1-current.Slot]
	original := file.handle
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		t.Fatal(err)
	}
	var limited syscall.Handle
	if err := syscall.DuplicateHandle(process, original, process, &limited, 0x00120089 /* FILE_GENERIC_READ */, false, 0); err != nil {
		t.Fatal(err)
	}
	defer func() {
		file.handle = original
		if limited != 0 {
			_ = syscall.CloseHandle(limited)
		}
	}()
	file.handle = limited
	if _, err := store.Append(context.Background(), current.SHA256, next); err == nil || store.pending == nil {
		t.Fatal("native denied write became an acknowledged journal append", err)
	}
	pending := store.pending
	if _, err := store.Snapshot(context.Background()); err == nil {
		t.Fatal("failed durable append was silently acknowledged by Snapshot")
	}
	// Restore the original actual write handle before either retry. A different
	// request must still fail even though the transient native denial is gone.
	file.handle = original
	if err := syscall.CloseHandle(limited); err != nil {
		t.Fatal(err)
	}
	limited = 0
	wrong := journalTestNext(t, current.Record)
	wrong.Phase = "intent"
	engine := store.controller
	engine.PID++
	engine.StartTimeUTCTicks++
	candidate := journalTestState("b", false)
	candidate.Engine = &engine
	wrong.Intent = &JournalIntent{Action: "successor", RequestID: strings.Repeat("b", 32), ProfileID: candidate.ProfileID,
		ProfileRevision: strings.Repeat("f", 64), ResultProfileRevision: strings.Repeat("f", 64), Candidate: candidate}
	if err := CheckJournalTransition(current.Record, wrong); err != nil {
		t.Fatal("different pending fixture was not a valid comparison record", err)
	}
	if _, err := store.Append(context.Background(), current.SHA256, wrong); err == nil || store.pending != pending {
		t.Fatal("journal failed-write retry adopted another pending operation")
	}
	result, err := store.Append(context.Background(), current.SHA256, next)
	if err != nil || result.Record.Sequence != next.Sequence || store.pending != nil {
		t.Fatal("journal failed write could not join the same retained slot and bytes", err)
	}
}

func TestWindowsProtectionJournalStoreRejectsCreatorAndCancellation(t *testing.T) {
	fixture := journalNativeCreate(t)
	store := fixture.store
	current, err := store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	next := journalTestNext(t, current.Record)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Append(cancelled, current.SHA256, next); err == nil || store.pending != nil {
		t.Fatal("cancelled journal request began a durable write")
	}
	wrong := next
	wrong.Controller.PID++
	if _, err := store.Append(context.Background(), current.SHA256, wrong); err == nil {
		t.Fatal("decoded replacement controller acquired journal write authority")
	}
	if _, err := store.Append(context.Background(), strings.Repeat("f", 64), next); err == nil {
		t.Fatal("stale previous digest acquired journal write authority")
	}
	if err := store.self.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Snapshot(context.Background()); err == nil {
		t.Fatal("retired controller handle retained journal authority")
	}
	if _, err := store.Append(context.Background(), current.SHA256, next); err == nil {
		t.Fatal("retired controller reacquired journal write authority")
	}
}

func TestWindowsProtectionJournalStoreInitialAuthorityAndACL(t *testing.T) {
	for _, fault := range []string{"unproved-absence", "user-owner", "broad-write", "inherited", "legacy-file"} {
		t.Run(fault, func(t *testing.T) {
			fixture := journalNativeInputs(t)
			api, err := protectionNative()
			if err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(fixture.machine, journalDirectoryName)
			read := fixture.initialRead
			if fault == "unproved-absence" {
				read = func(context.Context, *mobiletor.DesktopWindowsProtectionTarget) error {
					return errors.New("unknown native protection")
				}
			} else {
				identity, err := fixture.desktop.Identity()
				if err != nil {
					t.Fatal(err)
				}
				sddl := "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
				if fault == "user-owner" {
					sddl = "O:" + identity.SID + "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
				} else if fault == "broad-write" {
					sddl += "(A;OICI;FA;;;BU)"
				}
				protectionFixtureDirectory(t, api, root, sddl)
				if fault == "inherited" {
					protectionFixtureUnprotect(t, api, root)
				}
				if fault == "legacy-file" {
					if err := os.WriteFile(filepath.Join(root, "legacy.json"), []byte("unrelated"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			store, err := createProtectionJournal(context.Background(), fixture.machine, fixture.desktop, fixture.data, read)
			if store != nil {
				if closeErr := store.Close(); closeErr != nil {
					t.Fatal("rejected journal preparation did not join its retained handles", closeErr)
				}
			}
			if err == nil {
				t.Fatal("journal creation adopted unknown native protection or untrusted storage")
			}
			if _, err := os.Lstat(filepath.Join(root, journalHeaderName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("rejected journal creation wrote a new authority header", err)
			}
		})
	}
}

func TestWindowsProtectionJournalStoreConcurrentClose(t *testing.T) {
	fixture := journalNativeCreate(t)
	var group sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		group.Add(1)
		go func() { defer group.Done(); results <- fixture.store.Close() }()
	}
	group.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal("concurrent close did not join the same journal handles", err)
		}
	}
	if _, err := journalNativeOpen(t, fixture); err != nil {
		t.Fatal("concurrent journal close left its stable lock held", err)
	}
}
