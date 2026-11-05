//go:build linux && routervpn_controller_privileged

package standardengine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

func operationTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}
func operationTestClose(t *testing.T, o *OperationFile) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := o.Close(ctx); err != nil {
			t.Error(err)
		}
	})
}
func operationPair(t *testing.T) (context.Context, *OperationFile, *OperationFile) {
	t.Helper()
	ctx := operationTestContext(t)
	parent, err := NewOperationFile()
	if parent != nil {
		operationTestClose(t, parent)
	}
	if err != nil {
		t.Fatal(err)
	}
	capture := SHA256([]byte("exact sealed launch fixture"))
	if err := parent.BindCapture(ctx, capture); err != nil {
		t.Fatal(err)
	}
	device, inode := parent.Identity()
	fd, err := syscall.Dup(int(parent.File().Fd()))
	if err != nil {
		t.Fatal(err)
	}
	child, err := CaptureOperationFile(os.NewFile(uintptr(fd), "original-operation-child"), device, inode, OperationSize, OperationLayout, capture)
	if child != nil {
		operationTestClose(t, child)
	}
	if err != nil {
		t.Fatal(err)
	}
	return ctx, parent, child
}
func operationTestKey(ctx context.Context, capture string, sequence uint64, receipt []byte) OperationKey {
	deadline, _ := ctx.Deadline()
	return OperationKey{capture, fmt.Sprintf("%032x", sequence), sequence, deadline.UnixNano(), ReaderBinding{SHA256([]byte("original native reader")), 1, SHA256(receipt)}}
}
func operationTestReserve(t *testing.T, ctx context.Context, parent *OperationFile, receipt []byte) OperationReservation {
	t.Helper()
	r, err := parent.Reserve(ctx, operationTestKey(ctx, parent.capture, 1, receipt))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestCleanupOperationRawHistoryAndPartialReaders(t *testing.T) {
	ctx, parent, child := operationPair(t)
	if operationHeadersOffset+OperationTransactions*OperationReaders*2*operationHeaderSize != OperationControlSize || OperationSize != 12648448 {
		t.Fatal("fixed operation layout no longer fits")
	}
	// Worst-case raw quote, backslash and non-UTF8 bytes must not be JSON/base64 expanded.
	ready := bytes.Repeat([]byte{'"', '\\', 0xff, 0}, 4096)
	retirement := bytes.Repeat([]byte{'"', '\\', 0xfe}, 16384)
	r := operationTestReserve(t, ctx, parent, ready)
	if err := child.PublishEvidence(ctx, r, OriginalReader, ReadyEvidence, ready); err != nil {
		t.Fatal(err)
	}
	candidate := ReaderBinding{SHA256([]byte("actual partial candidate")), 2, ""}
	rollback := ReaderBinding{SHA256([]byte("actual rollback")), 3, SHA256(ready)}
	for role, binding := range map[OperationRole]ReaderBinding{CandidateReader: candidate, RollbackReader: rollback} {
		if err := child.BindReader(ctx, r, role, binding); err != nil {
			t.Fatal(err)
		}
	}
	if err := child.PublishEvidence(ctx, r, CandidateReader, ReadyEvidence, ready); err == nil {
		t.Fatal("partial constructor fabricated Ready")
	}
	if err := child.PublishEvidence(ctx, r, RollbackReader, ReadyEvidence, ready); err != nil {
		t.Fatal(err)
	}
	for role := OriginalReader; role <= RollbackReader; role++ {
		if err := child.PublishEvidence(ctx, r, role, RetirementEvidence, retirement); err != nil {
			t.Fatal(err)
		}
		got, err := parent.ReadEvidence(ctx, r, role, RetirementEvidence)
		if err != nil || !bytes.Equal(got, retirement) {
			t.Fatal("raw retirement changed", role, err)
		}
	}
	for _, role := range []OperationRole{OriginalReader, RollbackReader} {
		got, err := parent.ReadEvidence(ctx, r, role, ReadyEvidence)
		if err != nil || !bytes.Equal(got, ready) {
			t.Fatal("raw ready changed", role, err)
		}
	}
	if _, err := parent.ReadEvidence(ctx, r, CandidateReader, ReadyEvidence); err == nil {
		t.Fatal("absent Ready admitted")
	}
	if err := child.BindReader(ctx, r, CandidateReader, rollback); err == nil {
		t.Fatal("retained partial reader replaced")
	}
	if err := child.PublishEvidence(ctx, r, OriginalReader, ReadyEvidence, ready); err == nil {
		t.Fatal("committed page reused")
	}
}
func TestCleanupOperationRejectsCorruptOrSubstitutedEvidence(t *testing.T) {
	for _, scenario := range []string{"torn-header", "torn-payload", "nonzero-tail", "wrong-key", "wrong-role", "wrong-reader", "oversized-ready", "oversized-retirement", "missing-binding", "parent-writer"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, parent, child := operationPair(t)
			ready := []byte("actual original Ready")
			r := operationTestReserve(t, ctx, parent, ready)
			switch scenario {
			case "oversized-ready":
				if child.PublishEvidence(ctx, r, OriginalReader, ReadyEvidence, make([]byte, (16<<10)+1)) == nil {
					t.Fatal("oversized Ready accepted")
				}
				return
			case "oversized-retirement":
				if child.PublishEvidence(ctx, r, OriginalReader, RetirementEvidence, make([]byte, (48<<10)+1)) == nil {
					t.Fatal("oversized retirement accepted")
				}
				return
			case "missing-binding":
				if child.PublishEvidence(ctx, r, CandidateReader, RetirementEvidence, []byte("retired")) == nil {
					t.Fatal("unbound reader accepted")
				}
				return
			case "parent-writer":
				if parent.PublishEvidence(ctx, r, OriginalReader, ReadyEvidence, ready) == nil {
					t.Fatal("parent forged child evidence")
				}
				return
			}
			if err := child.PublishEvidence(ctx, r, OriginalReader, ReadyEvidence, ready); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "torn-header":
				changed := make([]byte, 1)
				if _, err := child.file.ReadAt(changed, operationHeadersOffset+20); err != nil {
					t.Fatal(err)
				}
				changed[0] ^= 0xff
				if _, err := child.file.WriteAt(changed, operationHeadersOffset+20); err != nil {
					t.Fatal(err)
				}
			case "torn-payload":
				if _, err := child.file.WriteAt([]byte{0xff}, OperationControlSize); err != nil {
					t.Fatal(err)
				}
			case "nonzero-tail":
				if _, err := child.file.WriteAt([]byte{0xff}, OperationControlSize+OperationPageSize-1); err != nil {
					t.Fatal(err)
				}
			case "wrong-key":
				r.Key.ID = fmt.Sprintf("%032x", 88)
			case "wrong-role":
				r2 := r
				if _, err := parent.ReadEvidence(ctx, r2, CandidateReader, ReadyEvidence); err == nil {
					t.Fatal("page adopted by another role")
				}
				return
			case "wrong-reader":
				header, err := child.read(ctx, 5, operationHeadersOffset, operationHeaderSize)
				if err != nil {
					t.Fatal(err)
				}
				header[40] ^= 1
				if err := child.write(ctx, 5, header, operationHeadersOffset, operationHeaderSize); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := parent.ReadEvidence(ctx, r, OriginalReader, ReadyEvidence); err == nil {
				t.Fatal("corrupt or substituted evidence admitted")
			}
		})
	}
}
func TestCleanupOperationCapacityAndOriginalKey(t *testing.T) {
	ctx, parent, child := operationPair(t)
	ready := []byte("ready")
	first := operationTestReserve(t, ctx, parent, ready)
	if err := parent.Submit(ctx, first); err != nil {
		t.Fatal(err)
	}
	got, err := child.ReadRequest(ctx, 0)
	if err != nil || got != first {
		t.Fatal("original request changed", err)
	}
	if _, err := child.ReadRequest(ctx, 0); err == nil {
		t.Fatal("child re-admitted original request")
	}
	for _, mutate := range []func(*OperationKey){func(k *OperationKey) { k.CaptureSHA256 = SHA256([]byte("foreign")) }, func(k *OperationKey) { k.Original.InitialReceiptSHA256 = "" }, func(k *OperationKey) { k.Original.Generation = 0 }, func(k *OperationKey) { k.DeadlineNS++ }, func(k *OperationKey) { k.Sequence = 1 }} {
		key := operationTestKey(ctx, parent.capture, 2, ready)
		mutate(&key)
		if _, err := parent.Reserve(ctx, key); err == nil {
			t.Fatal("changed original key admitted")
		}
	}

	other, err := parent.Reserve(ctx, operationTestKey(ctx, parent.capture, 2, ready))
	if err != nil {
		t.Fatal(err)
	}
	if err := parent.Cancel(ctx, other); err == nil {
		t.Fatal("unstarted reservation displaced the outstanding cancellation identity")
	}
	constructors := 2
	for sequence := uint64(3); sequence <= OperationTransactions; sequence++ {
		r, err := parent.Reserve(ctx, operationTestKey(ctx, parent.capture, sequence, ready))
		if err != nil {
			t.Fatal(err)
		}
		constructors++
		if err := parent.Submit(ctx, r); err == nil {
			t.Fatal("unjoined outstanding operation overwritten")
		}
	}
	if _, err := parent.Reserve(ctx, operationTestKey(ctx, parent.capture, OperationTransactions+1, ready)); err == nil {
		constructors++
	}
	if constructors != OperationTransactions {
		t.Fatal("constructor reached before capacity reservation")
	}
	if err := child.BindReader(ctx, first, OriginalReader, first.Key.Original); err == nil {
		t.Fatal("original reader rebound")
	}
}
func TestCleanupOperationCancellationHasIndependentExpiredWorkSlot(t *testing.T) {
	ctx, parent, child := operationPair(t)
	work, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	r := operationTestReserve(t, work, parent, []byte("ready"))
	if err := parent.Submit(work, r); err != nil {
		t.Fatal(err)
	}
	<-work.Done()
	// Hold both the same-process work mutex and its actual POSIX region lock.
	unlock, err := child.lock(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := parent.Cancel(ctx, r); err != nil {
		unlock()
		t.Fatal("cancel waited behind expired original work", err)
	}
	cancelled, err := child.Cancelled(ctx, r)
	unlock()
	if err != nil || !cancelled {
		t.Fatal("expired work not cancelled", err)
	}
	if _, err := child.ReadRequest(ctx, 0); err == nil {
		t.Fatal("cancellation renewed original work deadline")
	}
	if err := child.PublishEvidence(ctx, r, OriginalReader, ReadyEvidence, []byte("ready")); err == nil {
		t.Fatal("late work published Ready")
	}
	if err := child.PublishEvidence(ctx, r, OriginalReader, RetirementEvidence, []byte("actual joined retirement")); err != nil {
		t.Fatal("retirement lost separate cleanup budget", err)
	}
	r.Key.ID = fmt.Sprintf("%032x", 99)
	if err := parent.Cancel(ctx, r); err == nil {
		t.Fatal("another work identity cancelled original")
	}
}
func TestCleanupOperationBoundedLocksRetainOriginal(t *testing.T) {
	ctx, parent, _ := operationPair(t)
	for _, scenario := range []string{"work", "cancel", "close"} {
		t.Run(scenario, func(t *testing.T) {
			mutex := &parent.locks.work
			if scenario == "cancel" {
				mutex = &parent.locks.cancel
			}
			mutex.Lock()
			short, cancel := context.WithTimeout(ctx, 15*time.Millisecond)
			defer cancel()
			var err error
			if scenario == "close" {
				err = parent.Close(short)
			} else {
				_, err = parent.lock(short, scenario == "cancel")
			}
			mutex.Unlock()
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("held original mutex did not honor caller deadline", err)
			}
			if err := parent.Current(); err != nil {
				t.Fatal("read expiry retired original operation file", err)
			}
		})
	}
	if _, err := parent.lock(context.Background(), false); err == nil {
		t.Fatal("unbounded operation admitted")
	}
}
func TestCleanupOperationCaptureRetainsRejectedDescriptors(t *testing.T) {
	for _, scenario := range []string{"wrong-inode", "wrong-device", "wrong-size", "wrong-layout", "wrong-capture", "unsealed", "replacement"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, parent, _ := operationPair(t)
			device, inode := parent.Identity()
			size := int64(OperationSize)
			layout := OperationLayout
			capture := parent.capture
			original := parent.file
			switch scenario {
			case "wrong-inode":
				inode++
			case "wrong-device":
				device++
			case "wrong-size":
				size--
			case "wrong-layout":
				layout++
			case "wrong-capture":
				capture = ""
			case "unsealed":
				original = sealedFixture(t, []byte("mutable"), false)
			}
			fd, err := syscall.Dup(int(original.Fd()))
			if err != nil {
				t.Fatal(err)
			}
			partial, err := CaptureOperationFile(os.NewFile(uintptr(fd), "capture-test"), device, inode, size, layout, capture)
			if scenario == "replacement" {
				if err != nil {
					t.Fatal(err)
				}
				foreign := sealedFixture(t, []byte("substituted"), true)
				if _, _, e := syscall.Syscall(syscall.SYS_DUP3, foreign.Fd(), partial.file.Fd(), syscall.O_CLOEXEC); e != 0 {
					t.Fatal(e)
				}
				if partial.Current() == nil || partial.Close(ctx) == nil {
					t.Fatal("replacement accepted or closed")
				} // Restore original before releasing this owned test duplicate.
				if _, _, e := syscall.Syscall(syscall.SYS_DUP3, parent.file.Fd(), partial.file.Fd(), syscall.O_CLOEXEC); e != 0 {
					t.Fatal(e)
				}
			} else if err == nil || partial == nil || partial.File() == nil || partial.Current() == nil {
				t.Fatal("failed capture discarded or admitted partial descriptor", err)
			}
			if err := partial.Close(ctx); err != nil {
				t.Fatal("partial descriptor could not be closed", err)
			}
			if err := parent.Current(); err != nil {
				t.Fatal("partial close lost original parent", err)
			}
		})
	}
}

func TestCleanupOperationInheritedFD11(t *testing.T) {
	if mode := os.Getenv("ROUTERVPN_OPERATION_TEST_CHILD"); mode != "" {
		operationInheritedChild(t, mode)
		return
	}
	for _, scenario := range []string{"original", "substituted"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := operationTestContext(t)
			parent, err := NewOperationFile()
			if parent != nil {
				operationTestClose(t, parent)
			}
			if err != nil {
				t.Fatal(err)
			}
			cleanup, err := NewCleanupFile()
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup.Close()
			device, inode := parent.Identity()
			cleanupDevice, cleanupInode := cleanup.Identity()
			deadline, _ := ctx.Deadline()
			capture := Capture{Schema: 1, Session: strings.Repeat("a", 32), ConfigSHA256: SHA256([]byte("original config")), Mode: "standard-socks5", DeadlineNS: deadline.UnixNano(), CleanupDevice: cleanupDevice, CleanupInode: cleanupInode, OperationDevice: device, OperationInode: inode, OperationSize: OperationSize, OperationLayout: OperationLayout}
			raw, err := capture.Canonical()
			if err != nil {
				t.Fatal(err)
			}
			hash := SHA256(raw)
			if err := parent.BindCapture(ctx, hash); err != nil {
				t.Fatal(err)
			}
			r := operationTestReserve(t, ctx, parent, []byte("inherited actual fixture receipt"))
			if err := parent.Submit(ctx, r); err != nil {
				t.Fatal(err)
			}
			inherited := parent.File()
			if scenario == "substituted" {
				foreign, err := NewOperationFile()
				if foreign != nil {
					operationTestClose(t, foreign)
				}
				if err != nil {
					t.Fatal(err)
				}
				inherited = foreign.File()
			}
			placeholder, err := os.Open(os.DevNull)
			if err != nil {
				t.Fatal(err)
			}
			defer placeholder.Close()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCleanupOperationInheritedFD11$", "-test.v")
			command.Env = append(os.Environ(), "ROUTERVPN_OPERATION_TEST_CHILD="+scenario, "ROUTERVPN_OPERATION_TEST_HASH="+hash)
			command.ExtraFiles = []*os.File{placeholder, placeholder, placeholder, placeholder, placeholder, placeholder, sealedFixture(t, raw, true), cleanup.File(), inherited}
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("actual inherited child failed: %v\n%s", err, output)
			}
			if scenario == "substituted" {
				if !bytes.Contains(output, []byte("EXACT_FD11_SUBSTITUTION_REJECTED")) {
					t.Fatal("missing exact substitution witness", string(output))
				}
				if parent.VerifyLaunch(ctx, "inherited actual fixture receipt") == nil {
					t.Fatal("foreign FD11 acknowledged original launch")
				}
				return
			}
			if err := parent.VerifyLaunch(ctx, "inherited actual fixture receipt"); err != nil {
				t.Fatal(err)
			}
			if _, err := parent.ReadEvidence(ctx, r, OriginalReader, ReadyEvidence); err != nil {
				t.Fatal(err)
			}
			result, err := cleanup.ReadResult(hash)
			if err != nil || !result.Complete || result.Ledger != "original FD10 retirement remains owned" {
				t.Fatal("FD11 changed FD10 cleanup", result, err)
			}
		})
	}
}
func operationInheritedChild(t *testing.T, mode string) {
	ctx := operationTestContext(t)
	raw, err := ReadSealed(os.NewFile(CaptureFD, "original-capture"), 2048)
	if err != nil {
		t.Fatal(err)
	}
	expected := os.Getenv("ROUTERVPN_OPERATION_TEST_HASH")
	capture, err := DecodeCapture(raw, expected)
	if err != nil {
		t.Fatal(err)
	}
	cleanup, err := CaptureCleanupFile(os.NewFile(CleanupFD, "original-cleanup"), capture.CleanupDevice, capture.CleanupInode)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup.Close()
	child, err := CaptureOperationFile(os.NewFile(OperationFD, "original-operations"), capture.OperationDevice, capture.OperationInode, capture.OperationSize, capture.OperationLayout, expected)
	if child != nil {
		operationTestClose(t, child)
	}
	if mode == "substituted" {
		if err == nil || child.Current() == nil {
			t.Fatal("substituted inherited FD11 accepted")
		}
		fmt.Println("EXACT_FD11_SUBSTITUTION_REJECTED")
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, child.File().Fd(), syscall.F_GETFD, 0)
	if errno != 0 || flags&syscall.FD_CLOEXEC == 0 {
		t.Fatal("captured FD11 can escape another exec")
	}
	r, err := child.ReadRequest(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	receipt := []byte("inherited actual fixture receipt")
	if err := child.PublishEvidence(ctx, r, OriginalReader, ReadyEvidence, receipt); err != nil {
		t.Fatal(err)
	}
	if err := child.AcknowledgeLaunch(ctx, string(receipt)); err != nil {
		t.Fatal(err)
	}
	if mode == "held-work" {
		unlock, err := child.lock(ctx, false)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println("EXACT_CHILD_WORK_REGION_HELD")
		var release [1]byte
		if _, err := os.Stdin.Read(release[:]); err != nil {
			unlock()
			t.Fatal(err)
		}
		unlock()
		cancelled, err := child.Cancelled(ctx, r)
		if err != nil || !cancelled {
			t.Fatal("cross-process cancellation lost original key", err)
		}
	}

	now := time.Now()
	if err := cleanup.WriteResult(CleanupResult{Schema: 1, CaptureSHA256: expected, DeadlineNS: now.Add(time.Second).UnixNano(), StartedNS: now.UnixNano(), Authority: "signal", Complete: true, Ledger: "original FD10 retirement remains owned"}); err != nil {
		t.Fatal(err)
	}
}

// A canonical header cannot make partial page contents admissible, even if an
// interrupted writer left plausible length and digest fields from another page.
func TestCleanupOperationRejectsReplayedPageHeader(t *testing.T) {
	ctx, parent, child := operationPair(t)
	receipt := []byte("ready")
	r := operationTestReserve(t, ctx, parent, receipt)
	if err := child.PublishEvidence(ctx, r, OriginalReader, ReadyEvidence, receipt); err != nil {
		t.Fatal(err)
	}
	second, err := parent.Reserve(ctx, operationTestKey(ctx, parent.capture, 2, receipt))
	if err != nil {
		t.Fatal(err)
	}
	header, err := child.rawRead(ctx, operationHeadersOffset, operationHeaderSize)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := child.file.WriteAt(header, int64(operationHeadersOffset+6*operationHeaderSize)); err != nil {
		t.Fatal(err)
	}
	if _, err := parent.ReadEvidence(ctx, second, OriginalReader, ReadyEvidence); err == nil {
		t.Fatal("replayed committed header admitted a different transaction")
	}
	body, err := operationBody(header, 5)
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint32(body, second.Slot)
	if err := child.write(ctx, 5, body, int64(operationHeadersOffset+6*operationHeaderSize), operationHeaderSize); err != nil {
		t.Fatal(err)
	}
	if _, err := parent.ReadEvidence(ctx, second, OriginalReader, ReadyEvidence); err == nil {
		t.Fatal("relabelled committed header lost original key binding")
	}
}

func TestCleanupOperationProcessLockSeparatesCancellation(t *testing.T) {
	ctx := operationTestContext(t)
	parent, err := NewOperationFile()
	if parent != nil {
		operationTestClose(t, parent)
	}
	if err != nil {
		t.Fatal(err)
	}
	cleanup, err := NewCleanupFile()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup.Close()
	device, inode := parent.Identity()
	cd, ci := cleanup.Identity()
	deadline, _ := ctx.Deadline()
	capture := Capture{Schema: 1, Session: strings.Repeat("a", 32), ConfigSHA256: SHA256([]byte("config")), Mode: "standard-socks5", DeadlineNS: deadline.UnixNano(), CleanupDevice: cd, CleanupInode: ci, OperationDevice: device, OperationInode: inode, OperationSize: OperationSize, OperationLayout: OperationLayout}
	raw, err := capture.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	hash := SHA256(raw)
	if err := parent.BindCapture(ctx, hash); err != nil {
		t.Fatal(err)
	}
	r := operationTestReserve(t, ctx, parent, []byte("inherited actual fixture receipt"))
	if err := parent.Submit(ctx, r); err != nil {
		t.Fatal(err)
	}
	placeholder, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer placeholder.Close()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCleanupOperationInheritedFD11$", "-test.v")
	command.Env = append(os.Environ(), "ROUTERVPN_OPERATION_TEST_CHILD=held-work", "ROUTERVPN_OPERATION_TEST_HASH="+hash)
	command.ExtraFiles = []*os.File{placeholder, placeholder, placeholder, placeholder, placeholder, placeholder, sealedFixture(t, raw, true), cleanup.File(), parent.File()}
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(output)
	held := false
	for scanner.Scan() {
		if scanner.Text() == "EXACT_CHILD_WORK_REGION_HELD" {
			held = true
			break
		}
	}
	if !held {
		_ = command.Wait()
		t.Fatal("actual child never held the POSIX work region", stderr.String())
	}
	// An OFD lock would incorrectly succeed here because both descriptors share
	// the same open-file-description. This must fail only at the original deadline.
	short, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	unlock, lockErr := parent.lock(short, false)
	cancel()
	if unlock != nil {
		unlock()
	}
	cancelErr := parent.Cancel(ctx, r)
	_, releaseErr := input.Write([]byte{1})
	for scanner.Scan() {
	}
	waitErr := command.Wait()
	if !errors.Is(lockErr, context.DeadlineExceeded) {
		t.Fatal("shared inherited description bypassed the original process work lock", lockErr)
	}
	if cancelErr != nil || releaseErr != nil || waitErr != nil {
		t.Fatal("independent cancellation or joined child failed", cancelErr, releaseErr, waitErr, stderr.String())
	}
}

func TestCleanupOperationRejectedAdmissionCannotBeRepaired(t *testing.T) {
	ctx := operationTestContext(t)
	file := sealedFixture(t, make([]byte, OperationSize), false)
	if err := file.Chmod(0600); err != nil {
		t.Fatal(err)
	}
	var identity syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &identity); err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Dup(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	partial, err := CaptureOperationFile(os.NewFile(uintptr(fd), "original-rejected-operation"), identity.Dev, identity.Ino, OperationSize, OperationLayout, SHA256([]byte("captured launch")))
	if err == nil || partial == nil {
		t.Fatal("unsealed original admitted")
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, file.Fd(), 1033, 7); errno != 0 {
		t.Fatal(errno)
	}
	if partial.Current() == nil {
		t.Fatal("failed original admission was silently revived")
	}
	if err := partial.Close(ctx); err != nil {
		t.Fatal("failed original descriptor was not retained for close", err)
	}
}
