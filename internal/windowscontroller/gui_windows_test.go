//go:build windows

package windowscontroller

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

type guiFixtureHello struct {
	PID, ParentPID uint32
	ParentHandle   uint64
	ParentAccess   uint32
	Identity       TokenIdentity
}

type guiFixtureTree struct{ GUI, Descendant uint32 }

// Each role is an actual separately created process. Reports contain only
// public kernel identities; the GUI inherits no test output, bearer or Job.
func TestWindowsControllerGUIFixture(t *testing.T) {
	arguments := flag.Args()
	if len(arguments) == 0 {
		return
	}
	if len(arguments) == 1 && arguments[0] == "leaf" {
		time.Sleep(55 * time.Second)
		return
	}
	if len(arguments) != 6 {
		t.Fatal("native GUI fixture requires its fixed public arguments")
	}
	if err := runGUIFixture(t, arguments); err != nil {
		// Normal GUI stdout is deliberately NUL. This new private fixture file
		// preserves an actual child failure without changing inherited handles.
		_ = os.WriteFile(arguments[5], []byte(err.Error()), 0600)
		t.Fatal(err)
	}
}

func runGUIFixture(t *testing.T, arguments []string) error {
	mode, name, parentText, imagePath, handleText := arguments[0], arguments[1], arguments[2], arguments[3], arguments[4]
	if mode != "hold" && mode != "tree" && mode != "blocked-tree" && mode != "owner" {
		return errors.New("native GUI fixture role is invalid")
	}
	selfImage, err := PinCurrentImage()
	if err != nil {
		return fmt.Errorf("actual normalized GUI could not recapture its current executable: %w", err)
	}
	defer selfImage.Close()
	self, err := OpenProcess(uint32(os.Getpid()))
	if err != nil {
		return err
	}
	defer self.Close()
	if err := self.VerifyImage(selfImage); err != nil {
		return fmt.Errorf("actual normalized GUI recaptured another executable: %w", err)
	}
	pid, err := strconv.ParseUint(parentText, 10, 32)
	if err != nil || pid == 0 {
		return errors.New("native GUI fixture parent PID is invalid")
	}
	raw, err := strconv.ParseUint(handleText, 10, 64)
	if err != nil || mode != "owner" && raw == 0 {
		return errors.New("native GUI fixture parent handle is invalid")
	}
	var parent *Process
	var access uint32
	if mode == "owner" {
		// This outer crash fixture intentionally has no production GUI Job.
		// Its child is launched through LaunchGUIChild below; killing only this
		// outer process must exercise that child's own kill-on-close Job.
		parent, err = OpenProcess(uint32(pid))
	} else {
		access, err = guiGrantedAccess(syscall.Handle(raw))
		if err == nil {
			parent, err = adoptProcess(syscall.Handle(raw))
		}
	}
	if err != nil {
		return err
	}
	defer parent.Close()
	if parent.PID() != uint32(pid) {
		return errors.New("GUI inherited a different parent process")
	}
	image, err := PinImage(imagePath)
	if err != nil {
		return err
	}
	defer image.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	pipe, err := DialPipe(ctx, name)
	if err != nil {
		return err
	}
	defer pipe.Close()
	peer, err := pipe.VerifyPeer(parent, image)
	if err != nil {
		return fmt.Errorf("GUI did not authenticate its retained actual parent: %w", err)
	}
	if err := peer.Process.Close(); err != nil {
		return err
	}
	identity, err := CurrentIdentity()
	if err != nil {
		return err
	}
	hello := guiFixtureHello{uint32(os.Getpid()), uint32(pid), raw, access, identity}
	if err := guiWriteJSON(ctx, pipe, hello); err != nil {
		return err
	}
	if mode == "tree" || mode == "blocked-tree" {
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		leaf := exec.Command(executable, "-test.run=^TestWindowsControllerGUIFixture$", "-test.count=1", "-test.timeout=60s", "--", "leaf")
		if err := leaf.Start(); err != nil {
			return err
		}
		joined := make(chan error, 1)
		go func() { joined <- leaf.Wait() }()
		defer func() {
			_ = leaf.Process.Kill()
			select {
			case <-joined:
			case <-time.After(5 * time.Second):
				t.Error("native GUI fixture leaf failed to join")
			}
		}()
		if err := guiWriteJSON(ctx, pipe, guiFixtureTree{uint32(os.Getpid()), uint32(leaf.Process.Pid)}); err != nil {
			return err
		}
		if mode == "blocked-tree" {
			// The owner-death test must independently exercise kernel Job
			// retirement. A cooperative EOF observer would return normally and
			// run the leaf-killing defer even if KILL_ON_JOB_CLOSE were absent.
			// This bounded fixture deliberately stops servicing its UI channel
			// after the authenticated tree report; only the real Job can retire
			// it within the parent's much shorter cleanup bound.
			<-ctx.Done()
			return ctx.Err()
		}
	}
	if mode == "owner" {
		gui, err := startGUIFixture(ctx, "blocked-tree", t.TempDir())
		if gui != nil {
			defer gui.close()
		}
		if err != nil {
			return errors.New("crash fixture could not start its owned GUI: " + err.Error() + "; " + gui.diagnostics())
		}
		var tree guiFixtureTree
		if err := guiReadJSON(ctx, gui.pipe, &tree); err != nil {
			return err
		}
		if tree.GUI != gui.child.PID() || tree.Descendant == 0 || tree.Descendant == tree.GUI {
			return errors.New("owned GUI did not report its distinct actual descendant")
		}
		if err := guiWriteJSON(ctx, pipe, tree); err != nil {
			return err
		}
	}
	if err := pipe.ObserveLifetime(ctx); !errors.Is(err, io.EOF) {
		return fmt.Errorf("GUI fixture did not observe its exact owner closing: %w", err)
	}
	return nil
}

func guiGrantedAccess(handle syscall.Handle) (uint32, error) {
	api, err := native()
	if err != nil {
		return 0, err
	}
	dll, err := syscall.LoadDLL(filepath.Join(api.systemDirectory, "ntdll.dll"))
	if err != nil {
		return 0, err
	}
	defer dll.Release()
	query, err := dll.FindProc("NtQueryObject")
	if err != nil {
		return 0, err
	}
	// Microsoft's documented PUBLIC_OBJECT_BASIC_INFORMATION is 56 bytes on
	// both target architectures; no private object layout or access guess.
	var basic struct {
		Attributes, GrantedAccess, HandleCount, PointerCount uint32
		Reserved                                             [10]uint32
	}
	if unsafe.Sizeof(basic) != 56 {
		return 0, errors.New("native public object information ABI changed")
	}
	var returned uint32
	status, _, _ := query.Call(uintptr(handle), 0, uintptr(unsafe.Pointer(&basic)), unsafe.Sizeof(basic), uintptr(unsafe.Pointer(&returned)))
	if uint32(status) != 0 || returned != 56 {
		return 0, fmt.Errorf("actual inherited-handle rights unavailable: NTSTATUS=0x%x size=%d", uint32(status), returned)
	}
	return basic.GrantedAccess, nil
}

func guiWriteJSON(ctx context.Context, pipe *Pipe, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return pipe.WriteFrame(ctx, append(raw, '\n'))
}

func guiReadJSON(ctx context.Context, pipe *Pipe, value any) error {
	raw, err := pipe.ReadFrame(ctx)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, value)
}

type guiFixture struct {
	child  *GUIChild
	pipe   *Pipe
	image  *Image
	report string
	parent uint64
	hello  guiFixtureHello
}

func guiFixtureEnvironment(directory string) ([]string, error) {
	api, err := native()
	if err != nil {
		return nil, err
	}
	return []string{"SystemRoot=" + filepath.Dir(api.systemDirectory), "TEMP=" + directory,
		"TMP=" + directory, "GORACE=atexit_sleep_ms=0"}, nil
}

func startGUIFixture(ctx context.Context, role, directory string) (*guiFixture, error) {
	f := &guiFixture{report: filepath.Join(directory, "gui-child-diagnostics.txt")}
	var err error
	f.pipe, err = NewPipe()
	if err != nil {
		return f, err
	}
	executable, err := os.Executable()
	if err != nil {
		return f, err
	}
	f.image, err = PinImage(executable)
	if err != nil {
		return f, err
	}
	environment, err := guiFixtureEnvironment(directory)
	if err != nil {
		return f, err
	}
	f.child, err = LaunchGUIChild(ctx, f.image, func(parent uint64) ([]string, error) {
		f.parent = parent
		return []string{"-test.run=^TestWindowsControllerGUIFixture$", "-test.count=1", "-test.timeout=50s", "--",
			role, f.pipe.Name(), strconv.Itoa(os.Getpid()), executable, strconv.FormatUint(parent, 10), f.report}, nil
	}, environment, directory)
	if err != nil {
		return f, err
	}
	if err := f.pipe.Accept(ctx); err != nil {
		return f, err
	}
	if err := guiReadJSON(ctx, f.pipe, &f.hello); err != nil {
		return f, err
	}
	if f.hello.PID != f.child.PID() || f.hello.ParentPID != uint32(os.Getpid()) || f.hello.ParentHandle != f.parent {
		return f, errors.New("GUI public hello changed its actual inherited process capture")
	}
	peer, err := f.child.VerifyPeer(f.pipe, f.image)
	if err != nil {
		return f, err
	}
	return f, peer.Process.Close()
}

func newGUIFixture(t *testing.T, role string) *guiFixture {
	t.Helper()
	directory := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	f, err := startGUIFixture(ctx, role, directory)
	if f != nil {
		t.Cleanup(func() {
			if err := f.close(); err != nil {
				t.Error("native GUI fixture did not retire its exact owners:", err)
			}
		})
	}
	if err != nil {
		t.Fatal("actual native GUI fixture launch/hello failed:", err, f.diagnostics())
	}
	return f
}

func (f *guiFixture) diagnostics() string {
	if f == nil {
		return ""
	}
	data, _ := os.ReadFile(f.report)
	if len(data) > 16384 {
		data = data[len(data)-16384:]
	}
	return string(data)
}

func (f *guiFixture) close() error {
	if f == nil {
		return nil
	}
	var result error
	if f.pipe != nil {
		result = f.pipe.Close()
	}
	if f.child != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := f.child.Close(ctx); err != nil {
			return errors.Join(result, err)
		}
	}
	if f.image != nil {
		result = errors.Join(result, f.image.Close())
	}
	return result
}

func guiCompareAPI(t *testing.T) *syscall.Proc {
	t.Helper()
	api, err := native()
	if err != nil {
		t.Fatal(err)
	}
	dll, err := syscall.LoadDLL(filepath.Join(api.systemDirectory, "kernelbase.dll"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dll.Release() })
	compare, err := dll.FindProc("CompareObjectHandles")
	if err != nil {
		t.Fatal(err)
	}
	return compare
}

func TestWindowsControllerGUIParentRightsAndHandleIsolation(t *testing.T) {
	api, err := native()
	if err != nil {
		t.Fatal(err)
	}
	attributes := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), InheritHandle: 1}
	value, _, callErr := api.event.Call(uintptr(unsafe.Pointer(&attributes)), 1, 0, 0)
	if value == 0 {
		t.Fatal(nativeError("private inheritance control event", callErr))
	}
	unrelated := syscall.Handle(value)
	t.Cleanup(func() { _ = syscall.CloseHandle(unrelated) })
	compare := guiCompareAPI(t)
	var same syscall.Handle
	if err := syscall.DuplicateHandle(^syscall.Handle(0), unrelated, ^syscall.Handle(0), &same, 0, false, syscall.DUPLICATE_SAME_ACCESS); err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(same)
	if identical, _, _ := compare.Call(uintptr(same), uintptr(unrelated)); identical == 0 {
		t.Fatal("actual object comparison failed its independently duplicated positive control")
	}
	f := newGUIFixture(t, "hold")
	if f.hello.ParentAccess != 0x00101000 {
		t.Fatalf("native GUI inherited excess parent authority: 0x%x", f.hello.ParentAccess)
	}
	handle, release, err := f.child.process.borrow()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	var inheritedParent syscall.Handle
	if err := syscall.DuplicateHandle(handle, syscall.Handle(f.parent), ^syscall.Handle(0), &inheritedParent, 0, false, syscall.DUPLICATE_SAME_ACCESS); err != nil {
		t.Fatal("actual GUI parent reference could not be independently read:", err)
	}
	defer syscall.CloseHandle(inheritedParent)
	if identical, _, _ := compare.Call(uintptr(inheritedParent), ^uintptr(0)); identical == 0 {
		t.Fatal("GUI inherited a numeric handle without the exact parent object")
	}
	access, err := guiGrantedAccess(inheritedParent)
	if err != nil || access != 0x00101000 {
		t.Fatal("independent GUI parent-handle rights differ from the child readback", access, err)
	}
	var candidate syscall.Handle
	excludedErr := syscall.DuplicateHandle(handle, unrelated, ^syscall.Handle(0), &candidate, 0, false, syscall.DUPLICATE_SAME_ACCESS)
	if excludedErr == nil {
		defer syscall.CloseHandle(candidate)
	}
	// Capture the original inheritance observation before inserting any test
	// handle. Independently prove this exact Event is a supported cross-process
	// object through the same retained child handle. An unrelated numeric slot
	// can be absent or hold a type that Windows cannot duplicate between
	// processes; neither status is accepted without this actual positive.
	var control syscall.Handle
	if err := syscall.DuplicateHandle(^syscall.Handle(0), unrelated, handle, &control, 0, false, syscall.DUPLICATE_SAME_ACCESS); err != nil {
		t.Fatal("owned Event could not enter its exact GUI process for the duplication control", err)
	}
	defer func() {
		if err := syscall.DuplicateHandle(handle, control, 0, nil, 0, false, syscall.DUPLICATE_CLOSE_SOURCE); err != nil {
			t.Error("owned Event duplication control did not close its exact remote handle", err)
		}
	}()
	var echoed syscall.Handle
	if err := syscall.DuplicateHandle(handle, control, ^syscall.Handle(0), &echoed, 0, false, syscall.DUPLICATE_SAME_ACCESS); err != nil {
		t.Fatal("owned Event could not return through the same GUI process duplication boundary", err)
	}
	defer syscall.CloseHandle(echoed)
	if identical, _, _ := compare.Call(uintptr(echoed), uintptr(unrelated)); identical == 0 {
		t.Fatal("GUI cross-process duplication control did not preserve the actual owned Event identity")
	}
	if excludedErr == nil {
		// A reused numeric slot may name a different runtime object. Compare
		// the actual objects instead of treating that ordinary reuse as a leak.
		if identical, _, _ := compare.Call(uintptr(candidate), uintptr(unrelated)); identical != 0 {
			t.Fatal("native GUI inherited an unrelated inheritable kernel object")
		}
	} else if !errors.Is(excludedErr, syscall.Errno(6) /* ERROR_INVALID_HANDLE */) && !errors.Is(excludedErr, syscall.Errno(50) /* ERROR_NOT_SUPPORTED */) {
		t.Fatal("excluded-handle readback failed before proving object isolation:", excludedErr)
	}
}

func TestWindowsControllerGUIOriginalUserAndPeer(t *testing.T) {
	f := newGUIFixture(t, "hold")
	identity, err := CurrentIdentity()
	if err != nil || !sameOriginalUser(identity, f.hello.Identity) {
		t.Fatal("native GUI changed its actual original-user primary token", err)
	}
	peer, err := f.child.VerifyPeer(f.pipe, f.image)
	if err != nil {
		t.Fatal("native GUI did not prove its actual original-user pipe writer", err)
	}
	defer peer.Process.Close()
	if peer.Identity.Primary || peer.Identity.SID != identity.SID || peer.Identity.AuthenticationID != identity.AuthenticationID ||
		peer.Identity.SessionID != identity.SessionID || peer.Identity.Administrator != identity.Administrator || peer.Identity.Elevated != identity.Elevated {
		t.Fatal("native GUI writer identity differs from the independently read original primary token")
	}
	other := newGUIFixture(t, "hold")
	if wrong, err := f.child.VerifyPeer(other.pipe, f.image); err == nil {
		_ = wrong.Process.Close()
		t.Fatal("native GUI admitted a different live process as its captured pipe writer")
	}
	saved := f.child.identity
	f.child.identity.AuthenticationID ^= 1
	wrong, err := f.child.VerifyPeer(f.pipe, f.image)
	f.child.identity = saved
	if err == nil {
		_ = wrong.Process.Close()
		t.Fatal("native GUI admitted a pipe writer outside its captured original logon identity")
	}
}

func TestWindowsControllerGUIOldCleanupPreservesReplacement(t *testing.T) {
	old, replacement := newGUIFixture(t, "hold"), newGUIFixture(t, "hold")
	retained, err := old.child.RetainProcess()
	if err != nil {
		t.Fatal(err)
	}
	defer retained.Close()
	if retained.PID() != old.child.PID() || retained.VerifyImage(old.image) != nil {
		t.Fatal("retained GUI process differs from the actual suspended launch")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := old.child.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := retained.Wait(ctx); err != nil {
		t.Fatal("old GUI cleanup returned before its exact process joined", err)
	}
	if err := old.child.Close(ctx); err != nil {
		t.Fatal("old GUI cleanup lost idempotent ownership", err)
	}
	if extra, err := old.child.RetainProcess(); err == nil || extra != nil {
		if extra != nil {
			_ = extra.Close()
		}
		t.Fatal("closed GUI admitted another process capture")
	}
	if err := replacement.child.process.Alive(); err != nil {
		t.Fatal("old GUI cleanup terminated a different replacement owner", err)
	}
	peer, err := replacement.child.VerifyPeer(replacement.pipe, replacement.image)
	if err != nil {
		t.Fatal("replacement GUI lost its independent peer ownership", err)
	}
	_ = peer.Process.Close()
}

func TestWindowsControllerGUICancelledCleanupRetainsOwner(t *testing.T) {
	f := newGUIFixture(t, "hold")
	job := f.child.job
	process := f.child.process
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.child.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled GUI drain fabricated joined cleanup", err)
	}
	if f.child.closed || f.child.job != job || f.child.process != process {
		t.Fatal("failed GUI join discarded its captured retry owner")
	}
	handle, release, err := process.borrow()
	if err != nil || handle == 0 {
		t.Fatal("failed GUI join released its retained process handle", err)
	}
	release()
	if peer, err := f.child.VerifyPeer(f.pipe, f.image); err == nil {
		_ = peer.Process.Close()
		t.Fatal("retiring GUI admitted another peer verification")
	}
	retry, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	if err := f.child.Close(retry); err != nil || !f.child.closed || f.child.job != 0 {
		t.Fatal("GUI cleanup could not retry its exact retained owner", err)
	}
}

type guiObservedWaitContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (c *guiObservedWaitContext) Err() error {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Err()
}

func TestWindowsControllerGUIRejectedTerminationJoinsExactProcess(t *testing.T) {
	f := newGUIFixture(t, "hold")
	handle, release, err := f.child.process.borrow()
	if err != nil {
		t.Fatal(err)
	}
	current, err := syscall.GetCurrentProcess()
	if err != nil {
		release()
		t.Fatal(err)
	}
	var queryHandle syscall.Handle
	err = syscall.DuplicateHandle(current, handle, current, &queryHandle, 0x00101000, false, 0)
	release()
	if err != nil {
		t.Fatal(err)
	}
	// The real kernel rejects termination through this independently narrowed
	// handle while still allowing an actual wait on the same captured process.
	// No process DACL, parent token privilege or production API is replaced.
	query, err := adoptProcess(queryHandle)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := query.Close(); err != nil {
			t.Error("actual GUI wait witness did not release its joined process handle", err)
		}
	})
	if rights, err := guiGrantedAccess(queryHandle); err != nil || rights != 0x00101000 || query.PID() != f.child.PID() {
		t.Fatal("GUI termination witness lost the actual query/synchronize-only owner", rights, err)
	}
	terminateErr := syscall.TerminateProcess(queryHandle, 1)
	if !errors.Is(terminateErr, syscall.ERROR_ACCESS_DENIED) || query.Alive() != nil {
		t.Fatal("GUI termination witness did not preserve a live exact process after native access denial", terminateErr)
	}
	startWait := func() (context.CancelFunc, <-chan error) {
		t.Helper()
		bounded, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		observed := &guiObservedWaitContext{Context: bounded, entered: make(chan struct{})}
		result, completed := make(chan error, 1), make(chan struct{})
		go func() {
			result <- joinGUIProcessTermination(observed, query, terminateErr)
			close(completed)
		}()
		t.Cleanup(func() {
			cancel()
			select {
			case <-completed:
			case <-time.After(12 * time.Second):
				t.Error("actual GUI process join did not leave its bounded owner")
			}
		})
		select {
		case <-observed.entered:
		case err := <-result:
			t.Fatal("GUI termination error bypassed the exact live process wait", err)
		case <-time.After(3 * time.Second):
			t.Fatal("actual GUI process join did not enter its bounded wait")
		}
		if err := query.Alive(); err != nil {
			t.Fatal("GUI wait witness lost its live exact process before owner retirement", err)
		}
		select {
		case err := <-result:
			t.Fatal("GUI termination error bypassed the exact live process wait", err)
		default:
		}
		return cancel, result
	}
	cancel, pending := startWait()
	cancel()
	select {
	case err := <-pending:
		if !errors.Is(err, context.Canceled) || !errors.Is(err, syscall.ERROR_ACCESS_DENIED) {
			t.Fatal("bounded GUI join discarded cancellation or its actual termination failure", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled exact GUI wait did not finish")
	}
	if err := query.Alive(); err != nil {
		t.Fatal("cancelled GUI join changed the retained live owner", err)
	}
	stop, pending := startWait()
	defer stop()
	if ok, _, callErr := f.child.api.terminate.Call(uintptr(f.child.job), 1); ok == 0 {
		t.Fatal("actual captured GUI Job could not retire its process", callErr)
	}
	select {
	case err := <-pending:
		if err != nil {
			t.Fatal("actually signaled GUI process retained an earlier termination race as a failed join", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("actual GUI Job termination did not join its exact process")
	}
	joined, stopJoined := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopJoined()
	if _, err := f.child.process.Wait(joined); err != nil {
		t.Fatal("GUI termination helper fabricated a signaled process receipt", err)
	}
	if f.child.closed || f.child.processClosed || f.child.job == 0 {
		t.Fatal("process-only GUI join discarded the independent descendant/Job cleanup owner")
	}
}

func TestWindowsControllerGUIRetirementRevokesBeforeBlockedCleanup(t *testing.T) {
	f := newGUIFixture(t, "hold")
	peer, err := f.child.VerifyPeer(f.pipe, f.image)
	if err != nil {
		t.Fatal("GUI retirement fixture did not first prove its actual live peer", err)
	}
	_ = peer.Process.Close()
	f.child.mu.Lock()
	release := sync.OnceFunc(f.child.mu.Unlock)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	done := make(chan struct{})
	var closeErr error
	go func() { closeErr = f.child.Close(ctx); close(done) }()
	t.Cleanup(func() {
		release()
		defer cancel()
		select {
		case <-done:
			if closeErr != nil {
				t.Error("observed GUI cleanup failed to join", closeErr)
			}
		case <-time.After(12 * time.Second):
			t.Error("observed GUI cleanup did not finish after release")
		}
	})
	deadline := time.Now().Add(3 * time.Second)
	for !f.child.retiring.Load() {
		if time.Now().After(deadline) {
			t.Fatal("GUI cleanup did not revoke admission before waiting for its owner")
		}
		time.Sleep(time.Millisecond)
	}
	if err := f.child.process.Alive(); err != nil {
		t.Fatal("GUI admission test lost the real live child before its blocked cleanup", err)
	}
	if peer, err := f.child.VerifyPeer(f.pipe, f.image); err == nil {
		_ = peer.Process.Close()
		t.Fatal("retiring GUI admitted a live pipe while cleanup was still blocked")
	}
	if err := f.child.Alive(); !errors.Is(err, ErrClosed) {
		t.Fatal("retiring GUI admitted another request while its live process cleanup was blocked", err)
	}
	release()
	select {
	case <-done:
		if closeErr != nil {
			t.Fatal(closeErr)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("released GUI cleanup did not join")
	}
}

func TestWindowsControllerGUIJobCloseFailureCanRetry(t *testing.T) {
	f := newGUIFixture(t, "hold")
	job := f.child.job
	retained, err := f.child.process.retain()
	if err != nil {
		t.Fatal(err)
	}
	defer retained.Close()
	// Protect only this new owned Job handle from CloseHandle. Termination,
	// accounting and process join remain real; no production API is replaced.
	if err := syscall.SetHandleInformation(job, 2 /* PROTECT_FROM_CLOSE */, 2); err != nil {
		t.Fatal(err)
	}
	protected := true
	t.Cleanup(func() {
		if protected {
			if err := syscall.SetHandleInformation(job, 2, 0); err != nil {
				t.Error("owned GUI Job protection could not be removed", err)
			}
		}
	})
	query, err := f.child.api.native.event.Dll.FindProc("GetHandleInformation")
	if err != nil {
		t.Fatal(err)
	}
	var flags uint32
	ok, _, callErr := query.Call(uintptr(job), uintptr(unsafe.Pointer(&flags)))
	if ok == 0 || flags&2 == 0 {
		t.Fatal("private GUI Job close-failure control is not actually protected", callErr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := f.child.Close(ctx); err == nil {
		t.Fatal("GUI cleanup fabricated success after the actual Job close failed")
	}
	if f.child.closed || f.child.job != job || !f.child.processClosed {
		t.Fatal("failed final GUI Job close lost its completed process-close stage")
	}
	if _, err := retained.Wait(ctx); err != nil {
		t.Fatal("protected Job fixture did not actually join its exact GUI process", err)
	}
	if err := syscall.SetHandleInformation(job, 2, 0); err != nil {
		t.Fatal(err)
	}
	protected = false
	if err := f.child.Close(ctx); err != nil || !f.child.closed || f.child.job != 0 {
		t.Fatal("GUI could not retire its retained Job after an actual final-close failure", err)
	}
}

func TestWindowsControllerGUICancelledLaunchRunsNothing(t *testing.T) {
	directory := t.TempDir()
	image, err := PinImage(fixtureExecutable(t))
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	environment, err := guiFixtureEnvironment(directory)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	child, err := LaunchGUIChild(ctx, image, func(uint64) ([]string, error) {
		called = true
		return nil, errors.New("cancelled launch entered its argument builder")
	}, environment, directory)
	if child != nil || !errors.Is(err, context.Canceled) || called {
		t.Fatal("cancelled GUI launch admitted a new native owner or builder", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	child, err = LaunchGUIChild(ctx, image, func(uint64) ([]string, error) {
		cancel()
		return []string{"-test.run=^TestWindowsControllerGUIFixture$", "--", "leaf"}, nil
	}, environment, directory)
	if child != nil {
		t.Cleanup(func() {
			cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			if err := child.Close(cleanup); err != nil {
				t.Error("cancelled native launch left an owned suspended process", err)
			}
		})
	}
	if !errors.Is(err, context.Canceled) || child == nil || !child.closed || child.job != 0 {
		t.Fatal("cancellation during GUI preparation stranded an unjoined creation", err)
	}
}

func TestWindowsControllerGUIRejectsChangedImageBeforeResume(t *testing.T) {
	guiRejectChangedImage(t, true)
}

func TestWindowsControllerGUIRejectsNormalizedImageBeforeCreate(t *testing.T) {
	guiRejectChangedImage(t, false)
}

// The shipping WPF and tray hosts use the actual Windows PowerShell image,
// rather than a PATH-selected process or a copy of this Go fixture. Its system
// path, real file identity, suspended token/Job proofs and exit must all work
// under exactly the same native launch boundary before that host is adopted.
func TestWindowsControllerGUIActualSystemPowerShell(t *testing.T) {
	api, err := native()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(api.systemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe")
	image, err := PinSystemPowerShell()
	if err != nil {
		guiObserveSystemPowerShellImage(t, path)
		t.Fatal("actual system PowerShell could not retain its native executable identity:", err)
	}
	defer image.Close()
	directory := t.TempDir()
	environment, err := guiFixtureEnvironment(directory)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	creationFile := filepath.Join(directory, "actual-creation-ticks.txt")
	child, err := LaunchGUIChild(ctx, image, func(uint64) ([]string, error) {
		command := "[IO.File]::WriteAllText('" + strings.ReplaceAll(creationFile, "'", "''") + "',[Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().Ticks.ToString([Globalization.CultureInfo]::InvariantCulture)); exit 0"
		return []string{"-NoProfile", "-NonInteractive", "-Command", command}, nil
	}, environment, directory)
	if child != nil {
		defer func() {
			cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			if err := child.Close(cleanup); err != nil {
				t.Error("actual system PowerShell did not join its captured native owner:", err)
			}
		}()
	}
	if err != nil || child == nil || child.PID() == 0 {
		t.Fatal("actual system PowerShell did not pass suspended original-user launch proof:", err)
	}
	if exit, err := child.Wait(ctx); err != nil || exit != 0 {
		t.Fatal("actual system PowerShell did not complete its fixed bounded command:", exit, err)
	}
	retained, err := child.RetainProcess()
	if err != nil {
		t.Fatal(err)
	}
	defer retained.Close()
	actual, err := retained.StartTimeUTCTicks()
	content, readErr := os.ReadFile(creationFile)
	want, parseErr := strconv.ParseInt(string(content), 10, 64)
	if err != nil || readErr != nil || parseErr != nil || want <= 0 || actual != want {
		t.Fatal("retained App creation identity differs from actual PowerShell UTC ticks", actual, want, err, readErr, parseErr)
	}
}

// Failure-only readback identifies the exact rejected native component before
// considering any system-runtime-specific policy. It neither retries launch
// nor changes general PinImage rejection, permissions, file contents or links.
func guiObserveSystemPowerShellImage(t *testing.T, path string) {
	t.Helper()
	root, err := executableRoot(path)
	if err != nil {
		t.Log("actual system PowerShell diagnostic path:", err)
		return
	}
	var handles []syscall.Handle
	defer func() {
		for index := len(handles) - 1; index >= 0; index-- {
			if err := syscall.CloseHandle(handles[index]); err != nil {
				t.Error("actual system PowerShell diagnostic handle did not retire:", err)
			}
		}
	}()
	parts := strings.Split(path[len(root):], `\`)
	current := root
	for index := -1; index < len(parts); index++ {
		if index >= 0 {
			current = filepath.Join(current, parts[index])
		}
		last := index == len(parts)-1
		access, share, flags := uint32(0x80), uint32(syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE), uint32(0x00200000|0x02000000)
		if last {
			access, share, flags = syscall.GENERIC_READ, syscall.FILE_SHARE_READ, 0x00200000
		}
		name, err := syscall.UTF16PtrFromString(current)
		if err != nil {
			t.Log("actual system PowerShell diagnostic encoding:", err)
			return
		}
		held, err := syscall.CreateFile(name, access, share, nil, syscall.OPEN_EXISTING, flags, 0)
		if err != nil {
			t.Logf("actual system PowerShell component=%q open=%v", current, err)
			return
		}
		handles = append(handles, held)
		var info syscall.ByHandleFileInformation
		err = syscall.GetFileInformationByHandle(held, &info)
		kind, kindErr := syscall.GetFileType(held)
		t.Logf("actual system PowerShell component=%q last=%t attributes=0x%08x links=%d volume=0x%08x file=0x%08x%08x type=%d read=%v type_read=%v", current, last, info.FileAttributes, info.NumberOfLinks, info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow, kind, err, kindErr)
		if err != nil || kindErr != nil {
			return
		}
	}
}

func guiRejectChangedImage(t *testing.T, afterCreation bool) {
	t.Helper()
	directory := t.TempDir()
	firstPath, secondPath := filepath.Join(directory, "first.exe"), filepath.Join(directory, "second.exe")
	fixtureCopy(t, fixtureExecutable(t), firstPath)
	fixtureCopy(t, fixtureExecutable(t), secondPath)
	first, err := PinImage(firstPath)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := PinImage(secondPath)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if first.identity.FileIndexHigh == second.identity.FileIndexHigh && first.identity.FileIndexLow == second.identity.FileIndexLow {
		t.Fatal("GUI image negative control did not create distinct real files")
	}
	// Both inputs are independently held real files containing identical
	// bytes. The before-create case substitutes only the named target. The
	// suspended case changes this fixture's expected identity only after the
	// actual first process has been created and proved in its exact Job/token.
	// Keeping these cases distinct prevents the earlier guard from masking a
	// regression in the suspended actual-process readback.
	var afterSuspended func()
	observed := false
	if afterCreation {
		afterSuspended = func() {
			observed = true
			first.mu.Lock()
			first.identity = second.identity
			first.mu.Unlock()
		}
	} else {
		first.mu.Lock()
		first.path = second.Path()
		first.mu.Unlock()
	}
	environment, err := guiFixtureEnvironment(directory)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	build := func(uint64) ([]string, error) {
		return []string{"-test.run=^TestWindowsControllerGUIFixture$", "--", "leaf"}, nil
	}
	var child *GUIChild
	if afterCreation {
		child, err = launchGUIChild(ctx, first, build, environment, directory, afterSuspended)
	} else {
		child, err = LaunchGUIChild(ctx, first, build, environment, directory)
	}
	if child != nil {
		t.Cleanup(func() {
			cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			if err := child.Close(cleanup); err != nil {
				t.Error("changed-image GUI negative control did not join", err)
			}
		})
	}
	if err == nil {
		t.Fatal("native GUI resumed a different actual image than its pinned capture")
	}
	if afterCreation && (!observed || child == nil || child.PID() == 0 || !strings.Contains(err.Error(), "different captured file")) {
		t.Fatal("GUI changed-image failure did not prove its intended boundary and joined cleanup", err)
	}
	if !afterCreation && (child == nil || child.PID() != 0 || !strings.Contains(err.Error(), "normalized launch image differs")) {
		t.Fatal("normalized launch replacement reached native creation before exact image proof", err)
	}
	if child == nil || !child.closed || child.job != 0 {
		t.Fatal("GUI changed-image failure did not join its exact native owner", err)
	}
}

func guiRetainFixtureProcess(t *testing.T, pid uint32, image *Image) *Process {
	t.Helper()
	handle, err := syscall.OpenProcess(0x00101001 /* SYNCHRONIZE | QUERY_LIMITED_INFORMATION | TERMINATE */, false, pid)
	if err != nil {
		t.Fatal("native GUI descendant handle could not be retained", err)
	}
	process, err := adoptProcess(handle)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if state, _ := syscall.WaitForSingleObject(handle, 0); state != syscall.WAIT_OBJECT_0 {
			_ = syscall.TerminateProcess(handle, 125)
			if state, err := syscall.WaitForSingleObject(handle, 5000); err != nil || state != syscall.WAIT_OBJECT_0 {
				t.Error("exact GUI descendant negative-control cleanup did not join", err)
				return
			}
		}
		_ = process.Close()
	})
	if err := process.VerifyImage(image); err != nil {
		t.Fatal("reported GUI descendant does not execute the owned fixture image", err)
	}
	return process
}

func TestWindowsControllerGUIJobRetiresDescendants(t *testing.T) {
	f := newGUIFixture(t, "tree")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var tree guiFixtureTree
	if err := guiReadJSON(ctx, f.pipe, &tree); err != nil || tree.GUI != f.child.PID() || tree.Descendant == 0 || tree.Descendant == tree.GUI {
		t.Fatal("owned GUI did not return its actual descendant", err)
	}
	descendant := guiRetainFixtureProcess(t, tree.Descendant, f.image)
	handle, release, err := descendant.borrow()
	if err != nil {
		t.Fatal(err)
	}
	var member uint32
	ok, _, callErr := f.child.api.native.inJob.Call(uintptr(handle), uintptr(f.child.job), uintptr(unsafe.Pointer(&member)))
	release()
	if ok == 0 || member != 1 {
		t.Fatal("GUI descendant escaped the exact creation-time Job", callErr)
	}
	if err := f.child.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := descendant.Wait(ctx); err != nil {
		t.Fatal("GUI cleanup returned before its owned descendant joined", err)
	}
}

func TestWindowsControllerGUIOwnerDeathRetiresOnlyOwnedTree(t *testing.T) {
	control := newGUIFixture(t, "hold")
	directory := t.TempDir()
	pipe, err := NewPipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pipe.Close() })
	image, err := PinImage(fixtureExecutable(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = image.Close() })
	report := filepath.Join(directory, "gui-owner-diagnostics.txt")
	output, err := os.CreateTemp(directory, "owner-output-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = output.Close() })
	command := exec.Command(fixtureExecutable(t), "-test.run=^TestWindowsControllerGUIFixture$", "-test.count=1", "-test.timeout=55s", "--",
		"owner", pipe.Name(), strconv.Itoa(os.Getpid()), fixtureExecutable(t), "0", report)
	command.Stdout, command.Stderr = output, output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	joined := make(chan error, 1)
	go func() { joined <- command.Wait() }()
	t.Cleanup(func() {
		_ = pipe.Close()
		_ = command.Process.Kill()
		select {
		case <-joined:
		case <-time.After(5 * time.Second):
			t.Error("exact outer GUI owner did not join")
		}
	})
	owner, err := OpenProcess(uint32(command.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if err := pipe.Accept(ctx); err != nil {
		t.Fatal(err)
	}
	var hello guiFixtureHello
	if err := guiReadJSON(ctx, pipe, &hello); err != nil || hello.PID != owner.PID() {
		t.Fatal("outer GUI owner hello is invalid", err)
	}
	peer, err := pipe.VerifyPeer(owner, image)
	if err != nil {
		t.Fatal(err)
	}
	_ = peer.Process.Close()
	var tree guiFixtureTree
	if err := guiReadJSON(ctx, pipe, &tree); err != nil || tree.GUI == 0 || tree.Descendant == 0 || tree.GUI == tree.Descendant ||
		tree.GUI == owner.PID() || tree.Descendant == owner.PID() || tree.GUI == control.child.PID() || tree.Descendant == control.child.PID() {
		raw, _ := os.ReadFile(report)
		t.Fatal("outer owner did not retain its distinct GUI tree", err, string(raw))
	}
	gui := guiRetainFixtureProcess(t, tree.GUI, image)
	descendant := guiRetainFixtureProcess(t, tree.Descendant, image)
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Wait(ctx); err != nil {
		t.Fatal("outer GUI owner termination did not join", err)
	}
	cleanup, stop := context.WithTimeout(context.Background(), 4*time.Second)
	defer stop()
	if _, err := gui.Wait(cleanup); err != nil {
		t.Fatal("GUI launcher death left its owned GUI tree alive", err)
	}
	if _, err := descendant.Wait(cleanup); err != nil {
		t.Fatal("GUI launcher death left its owned descendant alive", err)
	}
	if err := control.child.process.Alive(); err != nil {
		t.Fatal("GUI launcher death terminated an unrelated control owner", err)
	}
}

func TestWindowsControllerGUIEnvironmentIsExact(t *testing.T) {
	block, err := guiEnvironment([]string{"b=two", "A=one", "=C:=ignored", "UNICODE=é"})
	if err != nil {
		t.Fatal(err)
	}
	if len(block) < 2 || block[len(block)-1] != 0 || block[len(block)-2] != 0 {
		t.Fatal("native GUI environment is not double terminated")
	}
	var entries []string
	for len(block) > 1 {
		end := 0
		for end < len(block) && block[end] != 0 {
			end++
		}
		if end == len(block) {
			t.Fatal("native GUI environment lost an entry delimiter")
		}
		entries = append(entries, syscall.UTF16ToString(block[:end]))
		block = block[end+1:]
	}
	if strings.Join(entries, "|") != "A=one|b=two|UNICODE=é" {
		t.Fatal("native GUI changed its captured environment values", entries)
	}
	for _, values := range [][]string{{"PATH=a", "path=b"}, {"invalid"}, {"A=bad\x00value"}, {string([]byte{'A', '=', 0xff})}, {"A=" + strings.Repeat("x", 32768)}} {
		if _, err := guiEnvironment(values); err == nil {
			t.Fatal("native GUI accepted ambiguous or unbounded environment input")
		}
	}
}
