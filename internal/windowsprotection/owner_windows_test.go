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
	"unsafe"

	"router-vpn/internal/windowscontroller"
)

func protectionFixtureCapture() Capture {
	return Capture{SessionID: strings.Repeat("a", 32), SourceSHA256: strings.Repeat("b", 64), ConfigSHA256: strings.Repeat("c", 64),
		NetworkID: strings.Repeat("d", 32), Generation: 1}
}

func protectionRequireNative(t *testing.T) {
	t.Helper()
	identity, err := windowscontroller.CurrentIdentity()
	if err != nil || !identity.Primary || !identity.Elevated || !identity.Administrator {
		t.Fatal("actual Windows protection ownership gate requires an elevated primary token", err)
	}
}

func protectionFixture(t *testing.T) (string, *PreparedOwner) {
	t.Helper()
	protectionRequireNative(t)
	machine := t.TempDir()
	owner, err := createPreparedOwner(context.Background(), machine, protectionFixtureCapture(), "always")
	if owner != nil {
		t.Cleanup(func() {
			if err := owner.Close(); err != nil {
				t.Error("native preparation did not join its captured handles", err)
			}
		})
	}
	if err != nil || owner == nil {
		t.Fatal("actual administrative preparation failed", err)
	}
	return machine, owner
}

func protectionRejectCreation(t *testing.T, machine string) {
	t.Helper()
	owner, err := createPreparedOwner(context.Background(), machine, protectionFixtureCapture(), "always")
	if owner != nil {
		defer owner.Close()
	}
	if err == nil {
		t.Fatal("an existing or untrusted protection owner was adopted")
	}
}

func TestWindowsProtectionPreparedOwnerActualLifecycle(t *testing.T) {
	machine, owner := protectionFixture(t)
	capture := protectionFixtureCapture()
	if err := owner.Verify(context.Background(), capture); err != nil {
		t.Fatal(err)
	}
	record := owner.Record()
	if record.Controller.PID != uint32(os.Getpid()) || record.Capture != capture || record.Policy != "always" || record.OwnerID == capture.SessionID {
		t.Fatal("preparation did not derive its exact controller and independent owner identity", record)
	}
	body, err := CanonicalOwnerRecord(record)
	if err != nil || !bytes.Equal(body, owner.body) {
		t.Fatal("native preparation changed canonical owner bytes", err)
	}
	digest, err := OwnerRecordSHA256(body)
	if err != nil || digest != owner.SHA256() {
		t.Fatal("native preparation changed its record digest", err)
	}
	// Comparison values cannot mutate the retained native capability.
	record.OwnerID, record.Capture.SourceSHA256 = strings.Repeat("e", 32), strings.Repeat("f", 64)
	if err := owner.Verify(context.Background(), capture); err != nil {
		t.Fatal("a returned comparison copy changed the native owner", err)
	}
	path := owner.file.path
	if err := owner.DiscardPrepared(context.Background()); err != nil {
		t.Fatal("exact unstarted preparation was not discarded by handle", err)
	}
	if err := owner.DiscardPrepared(context.Background()); err != nil {
		t.Fatal("joined discard was not idempotent", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("discarded owner record was not absent", err)
	}
	if err := owner.Verify(context.Background(), capture); err == nil {
		t.Fatal("discarded preparation retained live authority")
	}
	second, err := createPreparedOwner(context.Background(), machine, capture, "on-connect")
	if second != nil {
		defer second.Close()
	}
	if err != nil || second == nil || second.Record().OwnerID == owner.Record().OwnerID {
		t.Fatal("new preparation reused an old ownership identity", err)
	}
	if err := second.DiscardPrepared(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsProtectionPreparedOwnerPinsNamespaceAndFile(t *testing.T) {
	machine, owner := protectionFixture(t)
	for name, attempt := range map[string]func() error{
		"record-write":  func() error { return os.WriteFile(owner.file.path, []byte("replacement"), 0600) },
		"record-delete": func() error { return os.Remove(owner.file.path) },
		"record-rename": func() error { return os.Rename(owner.file.path, owner.file.path+".moved") },
		"root-rename":   func() error { return os.Rename(owner.root.path, owner.root.path+".moved") },
		"parent-rename": func() error { return os.Rename(machine, machine+".moved") },
	} {
		t.Run(name, func(t *testing.T) {
			if err := attempt(); err == nil {
				t.Fatal("retained native preparation allowed a namespace or data replacement")
			}
			if err := owner.Verify(context.Background(), owner.Record().Capture); err != nil {
				t.Fatal("a rejected replacement changed the captured owner", err)
			}
		})
	}
	protectionRejectCreation(t, machine)
	if err := owner.DiscardPrepared(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsProtectionPreparedOwnerPreservesRecoveryRecord(t *testing.T) {
	machine, owner := protectionFixture(t)
	path, original := owner.file.path, append([]byte(nil), owner.body...)
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if actual, err := os.ReadFile(path); err != nil || !bytes.Equal(actual, original) {
		t.Fatal("Close discarded or changed the durable owner record", err)
	}
	protectionRejectCreation(t, machine)
	if err := owner.DiscardPrepared(context.Background()); err == nil {
		t.Fatal("closed owner reacquired pathname-based discard authority")
	}
	// Replacing the old pathname after Close cannot give the old object
	// permission to remove a new owner, even when its bytes look valid.
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := owner.DiscardPrepared(context.Background()); err == nil {
		t.Fatal("retired owner discarded a replacement record")
	}
	if actual, err := os.ReadFile(path); err != nil || !bytes.Equal(actual, original) {
		t.Fatal("retired owner modified a replacement record", err)
	}
}

func TestWindowsProtectionPreparedOwnerRejectsChangedIdentity(t *testing.T) {
	_, owner := protectionFixture(t)
	for name, mutate := range map[string]func(*Capture){
		"session":    func(c *Capture) { c.SessionID = strings.Repeat("e", 32) },
		"source":     func(c *Capture) { c.SourceSHA256 = strings.Repeat("e", 64) },
		"config":     func(c *Capture) { c.ConfigSHA256 = strings.Repeat("e", 64) },
		"network":    func(c *Capture) { c.NetworkID = strings.Repeat("e", 32) },
		"generation": func(c *Capture) { c.Generation++ },
	} {
		t.Run(name, func(t *testing.T) {
			capture := owner.Record().Capture
			mutate(&capture)
			if err := owner.Verify(context.Background(), capture); err == nil {
				t.Fatal("another captured connection acquired the native preparation")
			}
		})
	}
	controller := owner.record.Controller
	owner.record.Controller.StartTimeUTCTicks++
	if err := owner.Verify(context.Background(), owner.record.Capture); err == nil {
		t.Fatal("another process creation identity acquired the native preparation")
	}
	owner.record.Controller = controller
	identity := owner.file.identity
	owner.file.identity.FileIndexLow ^= 1
	if err := owner.Verify(context.Background(), owner.record.Capture); err == nil {
		t.Fatal("another retained file identity acquired the native preparation")
	}
	if err := owner.DiscardPrepared(context.Background()); err == nil {
		t.Fatal("changed file identity acquired discard authority")
	}
	owner.file.identity = identity
	if err := owner.DiscardPrepared(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsProtectionPreparedOwnerRejectsChangedRecord(t *testing.T) {
	_, owner := protectionFixture(t)
	original := append([]byte(nil), owner.body...)
	replacement := owner.Record()
	replacement.OwnerID = strings.Repeat("f", 32)
	if replacement.OwnerID == owner.Record().OwnerID {
		replacement.OwnerID = strings.Repeat("e", 32)
	}
	changed, err := CanonicalOwnerRecord(replacement)
	if err != nil || len(changed) != len(original) {
		t.Fatal("changed-record negative did not retain a valid canonical encoding", err)
	}
	write := func(raw []byte) {
		t.Helper()
		if _, err := syscall.Seek(owner.file.handle, 0, 0); err != nil {
			t.Fatal(err)
		}
		var written uint32
		if err := syscall.WriteFile(owner.file.handle, raw, &written, nil); err != nil || int(written) != len(raw) {
			t.Fatal(err)
		}
		if err := syscall.FlushFileBuffers(owner.file.handle); err != nil {
			t.Fatal(err)
		}
	}
	// The retained test handle is the deliberate writer seam. An ordinary
	// second data handle is rejected by the actual sharing test above.
	write(changed)
	if err := owner.Verify(context.Background(), owner.record.Capture); err == nil {
		t.Fatal("changed immutable owner bytes were accepted")
	}
	if err := owner.DiscardPrepared(context.Background()); err == nil {
		t.Fatal("changed immutable owner bytes acquired discard authority")
	}
	write(original)
	if err := owner.DiscardPrepared(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsProtectionPreparedOwnerCancellationAndConcurrentDiscard(t *testing.T) {
	_, owner := protectionFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := owner.Verify(ctx, owner.record.Capture); err == nil || owner.DiscardPrepared(ctx) == nil {
		t.Fatal("cancelled operation retained native preparation authority")
	}
	if err := owner.Verify(context.Background(), owner.record.Capture); err != nil {
		t.Fatal("cancelled read/discard changed the original preparation", err)
	}
	var group sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < cap(results); i++ {
		group.Add(1)
		go func() { defer group.Done(); results <- owner.DiscardPrepared(context.Background()) }()
	}
	group.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal("concurrent discard did not join the same original record", err)
		}
	}
}

func TestWindowsProtectionPreparedOwnerDiscardRetriesSameHandle(t *testing.T) {
	_, owner := protectionFixture(t)
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		t.Fatal(err)
	}
	original := owner.file.handle
	var limited syscall.Handle
	// Duplicate the actual same file object with read/write metadata access but
	// without DELETE. The first disposition must fail at the native access check;
	// no mocked filesystem result supplies this partial-retirement condition.
	if err := syscall.DuplicateHandle(process, original, process, &limited, 0x0012019f, false, 0); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if limited != 0 {
			if owner.file.handle == limited {
				owner.file.handle = original
			}
			_ = syscall.CloseHandle(limited)
		}
	}()
	owner.file.handle = limited
	if err := owner.DiscardPrepared(context.Background()); err == nil || owner.deleteMarked || owner.discarded {
		t.Fatal("failed native disposition was reported as completed discard", err)
	}
	if _, err := os.Lstat(owner.file.path); err != nil {
		t.Fatal("denied disposition changed the original file", err)
	}
	owner.file.handle = original
	if err := syscall.CloseHandle(limited); err != nil {
		t.Fatal(err)
	}
	limited = 0
	if err := owner.DiscardPrepared(context.Background()); err != nil {
		t.Fatal("partial discard could not retry its same retained file", err)
	}
	if _, err := os.Lstat(owner.file.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("retried native discard did not independently prove absence", err)
	}
}

func protectionFixtureDirectory(t *testing.T, api *protectionNativeAPI, path, sddl string) {
	t.Helper()
	value, err := syscall.UTF16PtrFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	security := &protectionSecurity{api: api}
	ok, _, callErr := api.convert.Call(uintptr(unsafe.Pointer(value)), 1, uintptr(unsafe.Pointer(&security.descriptor)), 0)
	if ok == 0 {
		t.Fatal(callErr)
	}
	defer security.close()
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	attributes := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: uintptr(security.descriptor)}
	ok, _, callErr = api.createDirectory.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&attributes)))
	if ok == 0 {
		t.Fatal(callErr)
	}
}

func TestWindowsProtectionPreparedOwnerRejectsUntrustedOrExistingState(t *testing.T) {
	protectionRequireNative(t)
	api, err := protectionNative()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := windowscontroller.CurrentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"foreign-owner", "broad-write", "inherited", "legacy-record", "unknown-journal", "foreign-lock", "linked-parent"} {
		t.Run(fault, func(t *testing.T) {
			machine := t.TempDir()
			root := filepath.Join(machine, protectionDirectoryName)
			sddl := "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
			switch fault {
			case "foreign-owner":
				sddl = "O:" + identity.SID + "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
			case "broad-write":
				sddl += "(A;OICI;FA;;;BU)"
			case "inherited":
				sddl = "O:BAG:BAD:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
			case "linked-parent":
				target := t.TempDir()
				linked := filepath.Join(machine, "redirected")
				if err := os.Symlink(target, linked); err != nil {
					t.Fatal("native reparse negative could not be established", err)
				}
				protectionRejectCreation(t, linked)
				if _, err := os.Lstat(filepath.Join(target, protectionDirectoryName)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("linked parent redirected a protection mutation", err)
				}
				return
			}
			protectionFixtureDirectory(t, api, root, sddl)
			var retained string
			switch fault {
			case "legacy-record":
				retained = filepath.Join(root, protectionRecordName)
			case "unknown-journal":
				retained = filepath.Join(root, "active-owner.json")
			case "foreign-lock":
				retained = filepath.Join(root, protectionLockName)
			}
			if retained != "" {
				if err := os.WriteFile(retained, []byte(`{"schema_version":1,"owner":"foreign"}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			protectionRejectCreation(t, machine)
			if retained != "" {
				actual, err := os.ReadFile(retained)
				if err != nil || string(actual) != `{"schema_version":1,"owner":"foreign"}` {
					t.Fatal("rejected native preparation changed an existing owner", err)
				}
			}
		})
	}
}

func TestWindowsProtectionCapturedObjectsRejectHardlinks(t *testing.T) {
	protectionRequireNative(t)
	directory := t.TempDir()
	original, alias := filepath.Join(directory, "record"), filepath.Join(directory, "alias")
	if err := os.WriteFile(original, []byte("owned test record"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(original, alias); err != nil {
		t.Fatal("native hardlink negative could not be established", err)
	}
	file, err := openProtectionObject(original, false, protectionReadAttributes|protectionReadControl,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE)
	if file != nil {
		defer file.close()
	}
	if err == nil {
		t.Fatal("multiply linked recovery record acquired native file authority")
	}
}

func TestWindowsProtectionCapturedAncestorsRejectRename(t *testing.T) {
	protectionRequireNative(t)
	api, err := protectionNative()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	pins, canonical, err := pinProtectionDirectory(api, directory)
	defer func() {
		for index := len(pins) - 1; index >= 0; index-- {
			if err := pins[index].close(); err != nil {
				t.Error(err)
			}
		}
	}()
	if err != nil || canonical == "" {
		t.Fatal("native ancestry capture failed", err)
	}
	// This case holds no record or descendant. The actual directory handles
	// themselves must prevent replacement, including the canonical volume path.
	for _, path := range []string{directory, canonical} {
		moved := path + ".moved"
		if err := os.Rename(path, moved); err == nil {
			if err := os.Rename(moved, path); err != nil {
				t.Fatal("changed ancestry sharing could not restore its disposable fixture", err)
			}
			t.Fatal("captured protection ancestry allowed a namespace replacement")
		}
	}
}
