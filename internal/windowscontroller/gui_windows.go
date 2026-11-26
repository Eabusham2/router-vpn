//go:build windows

package windowscontroller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"
)

// GUIChild retains an original-user UI process and its private Job. Its native
// creation is suspended and already belongs to that Job before any UI code can
// run. It never borrows the elevated controller's identity or data profile.
type GUIChild struct {
	mu            sync.Mutex
	process       *Process
	job           syscall.Handle
	identity      TokenIdentity
	api           *guiAPI
	closed        bool
	processClosed bool
	retiring      atomic.Bool
	output        *guiSelfTestOutput
}

type guiAPI struct {
	native                                                  *nativeAPI
	initialize, update, delete, resume, terminate, queryJob *syscall.Proc
}

func guiNative() (*guiAPI, error) {
	n, err := native()
	if err != nil {
		return nil, err
	}
	api := &guiAPI{native: n}
	for _, item := range []struct {
		name   string
		target **syscall.Proc
	}{
		{"InitializeProcThreadAttributeList", &api.initialize}, {"UpdateProcThreadAttribute", &api.update},
		{"DeleteProcThreadAttributeList", &api.delete}, {"ResumeThread", &api.resume},
		{"TerminateJobObject", &api.terminate}, {"QueryInformationJobObject", &api.queryJob},
	} {
		*item.target, err = n.event.Dll.FindProc(item.name)
		if err != nil {
			return nil, err
		}
	}
	return api, nil
}

func sameOriginalUser(a, b TokenIdentity) bool {
	return a.Primary && b.Primary && a.SID == b.SID && a.AuthenticationID == b.AuthenticationID && a.SessionID == b.SessionID &&
		a.Elevated == b.Elevated && a.Administrator == b.Administrator
}

// LaunchGUIChild starts only the captured image as the current desktop user.
// build supplies the caller's fixed GUI argv after receiving the public numeric
// value of an inherited parent handle. That handle grants only SYNCHRONIZE and
// PROCESS_QUERY_LIMITED_INFORMATION; no bearer or owner token is put in argv.
// The caller must pin/validate its shipping script and construct fixed flags.
func LaunchGUIChild(ctx context.Context, image *Image, build func(uint64) ([]string, error), environment []string, directory string) (_ *GUIChild, failure error) {
	return launchGUIChild(ctx, image, build, environment, directory, nil)
}

// afterSuspended is a private native test boundary, never an exported launch
// option. The public entry always supplies nil. It runs after real creation,
// Job membership and token proof, and cannot skip the following image readback,
// cancellation guard or Resume ordering.
func launchGUIChild(ctx context.Context, image *Image, build func(uint64) ([]string, error), environment []string, directory string, afterSuspended func()) (_ *GUIChild, failure error) {
	return launchGUIChildWithOutput(ctx, image, build, environment, directory, afterSuspended, false)
}

// LaunchGUIChildSelfTest adds only an anonymous output pipe to the original
// child. It accepts the fixed SelfTest argv/environment, never an output path.
// The pipe and reader remain owned until this exact Job has joined.
func LaunchGUIChildSelfTest(ctx context.Context, image *Image, build func(uint64) ([]string, error), environment []string, directory string) (*GUIChild, error) {
	return launchGUIChildWithOutput(ctx, image, build, environment, directory, nil, true)
}

func launchGUIChildWithOutput(ctx context.Context, image *Image, build func(uint64) ([]string, error), environment []string, directory string, afterSuspended func(), capture bool) (_ *GUIChild, failure error) {
	if ctx == nil || image == nil || build == nil || !filepath.IsAbs(directory) || strings.ContainsRune(directory, 0) {
		return nil, errors.New("the native GUI requires its exact captured launch")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	api, err := guiNative()
	if err != nil {
		return nil, err
	}
	identity, err := CurrentIdentity()
	if err != nil {
		return nil, err
	}
	child := &GUIChild{api: api, identity: identity}
	defer func() {
		if failure != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			failure = errors.Join(failure, child.Close(cleanup))
		}
	}()
	current, err := syscall.GetCurrentProcess()
	if err != nil {
		return child, err
	}
	var parent syscall.Handle
	if err := syscall.DuplicateHandle(current, current, current, &parent, 0x00100000|0x1000, true, 0); err != nil {
		return child, err
	}
	defer syscall.CloseHandle(parent)
	arguments, err := build(uint64(parent))
	if err != nil {
		return child, err
	}
	if len(arguments) == 0 || len(arguments) > 32 {
		return child, errors.New("the native GUI argument set is unbounded")
	}
	var quoted []string
	for _, argument := range arguments {
		if len(argument) > 4096 || !utf8.ValidString(argument) || strings.ContainsAny(argument, "\x00\r\n") {
			return child, errors.New("the native GUI launch argument is invalid")
		}
		quoted = append(quoted, syscall.EscapeArg(argument))
	}
	if len(strings.Join(quoted, " ")) > 16384 {
		return child, errors.New("the native GUI command line is unbounded")
	}
	if capture {
		enabled := false
		for _, value := range environment {
			if value == "ROUTERVPN_CAPTURE_SELF_TEST_LAYOUT=1" {
				enabled = true
			}
		}
		if !enabled || arguments[len(arguments)-1] != "-SelfTest" {
			return child, errors.New("native GUI output is available only for the explicit self-test")
		}
	}
	block, err := guiEnvironment(environment)
	if err != nil {
		return child, err
	}
	nulName, _ := syscall.UTF16PtrFromString("NUL")
	attributes := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), InheritHandle: 1}
	nul, err := syscall.CreateFile(nulName, syscall.GENERIC_READ|syscall.GENERIC_WRITE, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, &attributes, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		return child, err
	}
	defer syscall.CloseHandle(nul)
	if capture {
		child.output = &guiSelfTestOutput{redactions: []string{directory}}
		for i, argument := range arguments[:len(arguments)-1] {
			switch strings.ToLower(argument) {
			case "-controllerpipe":
				child.output.redactions = append(child.output.redactions, arguments[i+1])
			case "-file":
				child.output.redactions = append(child.output.redactions, filepath.Dir(arguments[i+1]))
			}
		}
		for _, entry := range environment {
			name, value, _ := strings.Cut(entry, "=")
			switch strings.ToUpper(name) {
			case "HOMEVPN_ROOT", "HOMEVPN_CLIENT_CONFIG", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP":
				child.output.redactions = append(child.output.redactions, value)
			}
		}
		err = withDescriptor(identity.SID, func(attributes *syscall.SecurityAttributes) error {
			attributes.InheritHandle = 1
			return syscall.CreatePipe(&child.output.read, &child.output.write, attributes, 4096)
		})
		if err != nil {
			return child, err
		}
		if err = syscall.SetHandleInformation(child.output.read, syscall.HANDLE_FLAG_INHERIT, 0); err != nil {
			return child, err
		}
		child.output.done = make(chan struct{})
		go child.output.drain()
	}
	err = withDescriptor(identity.SID, func(attributes *syscall.SecurityAttributes) error {
		value, _, callErr := api.native.createJob.Call(uintptr(unsafe.Pointer(attributes)), 0)
		child.job = syscall.Handle(value)
		if child.job == 0 {
			return nativeError("private GUI Job creation", callErr)
		}
		return nil
	})
	if err != nil {
		return child, err
	}
	limits := jobLimits{Flags: 0x2000 /* KILL_ON_JOB_CLOSE, no breakaway */}
	ok, _, callErr := api.native.setJob.Call(uintptr(child.job), 9, uintptr(unsafe.Pointer(&limits)), unsafe.Sizeof(limits))
	if ok == 0 {
		return child, nativeError("private GUI Job limits", callErr)
	}
	var length uintptr
	ok, _, callErr = api.initialize.Call(0, 2, 0, uintptr(unsafe.Pointer(&length)))
	if ok != 0 || !errors.Is(callErr, syscall.ERROR_INSUFFICIENT_BUFFER) || length == 0 || length > 65536 {
		return child, errors.New("native GUI creation attributes have no bounded shape")
	}
	storage := make([]uintptr, (length+unsafe.Sizeof(uintptr(0))-1)/unsafe.Sizeof(uintptr(0)))
	list := unsafe.Pointer(&storage[0])
	ok, _, callErr = api.initialize.Call(uintptr(list), 2, 0, uintptr(unsafe.Pointer(&length)))
	if ok == 0 {
		return child, nativeError("native GUI creation attributes", callErr)
	}
	defer api.delete.Call(uintptr(list))
	jobs := []syscall.Handle{child.job}
	inherited := []syscall.Handle{parent, nul}
	if child.output != nil {
		inherited = append(inherited, child.output.write)
	}
	for _, attribute := range []struct {
		kind    uintptr
		handles []syscall.Handle
	}{
		{0x0002000d, jobs},      /* PROC_THREAD_ATTRIBUTE_JOB_LIST */
		{0x00020002, inherited}, /* PROC_THREAD_ATTRIBUTE_HANDLE_LIST */
	} {
		ok, _, callErr = api.update.Call(uintptr(list), 0, attribute.kind, uintptr(unsafe.Pointer(&attribute.handles[0])), uintptr(len(attribute.handles))*unsafe.Sizeof(parent), 0, 0)
		if ok == 0 {
			return child, nativeError("exact GUI Job/handle creation attribute", callErr)
		}
	}
	startup := struct {
		Info       syscall.StartupInfo
		Attributes unsafe.Pointer
	}{Attributes: list}
	startup.Info.Cb = uint32(unsafe.Sizeof(startup))
	startup.Info.Flags = syscall.STARTF_USESTDHANDLES
	startup.Info.StdInput, startup.Info.StdOutput, startup.Info.StdErr = nul, nul, nul
	if child.output != nil {
		startup.Info.StdOutput, startup.Info.StdErr = child.output.write, child.output.write
	}
	if unsafe.Sizeof(startup) != 112 || unsafe.Sizeof(limits) != 144 {
		return child, errors.New("native GUI creation ABI changed")
	}
	dir, _ := syscall.UTF16PtrFromString(directory)
	var created syscall.ProcessInformation
	// Keep the exact image path and inode pinned until the OS has created its
	// suspended image section. No mutable DOS alias enters applicationName.
	image.mu.Lock()
	if image.closed || len(image.handles) == 0 {
		image.mu.Unlock()
		return child, ErrClosed
	}
	launchPath, launchImage, err := image.normalizedLaunchNameLocked()
	if err != nil {
		image.mu.Unlock()
		return child, err
	}
	application, _ := syscall.UTF16PtrFromString(launchPath)
	command, _ := syscall.UTF16FromString(syscall.EscapeArg(launchPath) + " " + strings.Join(quoted, " "))
	err = syscall.CreateProcess(application, &command[0], nil, nil, true, 0x00080000|0x00000400|0x00000004|0x08000000,
		&block[0], dir, &startup.Info, &created)
	if child.output != nil {
		err = errors.Join(err, child.output.closeWriter())
	}
	if closeErr := syscall.CloseHandle(launchImage); closeErr != nil {
		image.handles = append(image.handles, launchImage)
		err = errors.Join(err, nativeError("normalized GUI image release", closeErr))
	}
	image.mu.Unlock()
	runtime.KeepAlive(storage)
	runtime.KeepAlive(jobs)
	runtime.KeepAlive(inherited)
	runtime.KeepAlive(block)
	runtime.KeepAlive(command)
	runtime.KeepAlive(application)
	runtime.KeepAlive(dir)
	runtime.KeepAlive(startup)
	if created.Thread != 0 {
		defer syscall.CloseHandle(created.Thread)
	}
	if created.Process != 0 {
		child.process, failure = adoptProcess(created.Process)
		if failure != nil {
			return child, errors.Join(err, failure)
		}
	}
	if err != nil {
		return child, nativeError("original-user GUI suspended CreateProcess", err)
	}
	if child.process == nil || created.Thread == 0 {
		return child, errors.New("native GUI creation returned no exact suspended owner")
	}
	if err := ctx.Err(); err != nil {
		return child, nativeError("GUI operation after suspended process creation", err)
	}
	var member uint32
	handle, release, err := child.process.borrow()
	if err != nil {
		return child, err
	}
	ok, _, callErr = api.native.inJob.Call(uintptr(handle), uintptr(child.job), uintptr(unsafe.Pointer(&member)))
	release()
	if ok == 0 || member != 1 {
		return child, nativeError("GUI creation-time Job membership", callErr)
	}
	actual, err := child.process.Identity()
	if err != nil || !sameOriginalUser(identity, actual) {
		return child, errors.Join(err, errors.New("native GUI did not retain its original desktop identity"))
	}
	if afterSuspended != nil {
		afterSuspended()
	}
	if err := child.process.VerifyImage(image); err != nil {
		return child, nativeError("original-user GUI suspended image readback", err)
	}
	actualParent, err := CurrentIdentity()
	if err != nil || !sameOriginalUser(identity, actualParent) {
		return child, errors.Join(err, errors.New("desktop identity changed during native GUI creation"))
	}
	if err := ctx.Err(); err != nil {
		return child, nativeError("GUI operation after suspended image verification", err)
	}
	previous, _, callErr := api.resume.Call(uintptr(created.Thread))
	if previous != 1 {
		return child, nativeError("owned GUI primary thread resume", callErr)
	}
	if err := ctx.Err(); err != nil {
		return child, nativeError("GUI operation after primary thread resume", err)
	}
	return child, nil
}

func guiEnvironment(values []string) ([]uint16, error) {
	if len(values) > 1024 {
		return nil, errors.New("native GUI environment is unbounded")
	}
	entries := make(map[string]string, len(values))
	for _, value := range values {
		index := strings.IndexByte(value, '=')
		// Drive-current-directory pseudovariables are intentionally omitted;
		// the launcher supplies an explicit absolute working directory.
		if index == 0 {
			continue
		}
		if index < 1 || !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
			return nil, errors.New("native GUI environment contains an invalid entry")
		}
		key := strings.ToUpper(value[:index])
		if _, exists := entries[key]; exists {
			return nil, errors.New("native GUI environment repeats a Windows variable")
		}
		entries[key] = value
	}
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var block []uint16
	for _, key := range keys {
		block = append(block, utf16.Encode([]rune(entries[key]))...)
		block = append(block, 0)
	}
	block = append(block, 0)
	if len(block) == 1 {
		block = append(block, 0)
	}
	if len(block) > 32767 {
		return nil, errors.New("native GUI environment exceeds the Windows limit")
	}
	return block, nil
}

func (child *GUIChild) PID() uint32 {
	if child == nil || child.process == nil {
		return 0
	}
	return child.process.PID()
}

// RetainProcess duplicates the process handle captured by our suspended
// CreateProcess call. It never reopens a public PID. A controller compositor
// uses this read-only abstraction for pipe/TLS identity while the original
// GUIChild continues to own its creation-time Job and checked cleanup.
func (child *GUIChild) RetainProcess() (*Process, error) {
	if child == nil {
		return nil, ErrClosed
	}
	child.mu.Lock()
	defer child.mu.Unlock()
	if child.closed || child.retiring.Load() || child.process == nil {
		return nil, ErrClosed
	}
	return child.process.retain()
}

// Alive checks the retained kernel owner and the GUI's retirement admission.
// A pending Close revokes new requests before asynchronous Job teardown ends.
func (child *GUIChild) Alive() error {
	if child == nil || child.process == nil || child.retiring.Load() {
		return ErrClosed
	}
	if err := child.process.Alive(); err != nil {
		return err
	}
	if child.retiring.Load() {
		return ErrClosed
	}
	return nil
}

func (child *GUIChild) Wait(ctx context.Context) (uint32, error) {
	if child == nil || child.process == nil {
		return 0, ErrClosed
	}
	return child.process.Wait(ctx)
}

// VerifyPeer checks the exact retained GUI process, never whichever process
// happens to claim its public pipe name or inherited-handle number.
func (child *GUIChild) VerifyPeer(pipe *Pipe, image *Image) (*Peer, error) {
	if child == nil || child.process == nil || child.retiring.Load() {
		return nil, ErrClosed
	}
	peer, err := pipe.VerifyPeer(child.process, image)
	if err != nil {
		return nil, err
	}
	want, actual := child.identity, peer.Identity
	if actual.Primary || actual.SID != want.SID || actual.AuthenticationID != want.AuthenticationID || actual.SessionID != want.SessionID || actual.Elevated != want.Elevated || actual.Administrator != want.Administrator {
		return nil, errors.Join(errors.New("native GUI pipe writer changed its captured desktop identity"), peer.Process.Close())
	}
	if child.retiring.Load() {
		return nil, errors.Join(ErrClosed, peer.Process.Close())
	}
	return peer, nil
}

// Close retires this GUI Job and joins its exact process and descendants. A
// failed join keeps all native handles retained so the owner can retry; it is
// never converted into a successful cleanup receipt or PID-based replacement.
func (child *GUIChild) Close(ctx context.Context) error {
	if child == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("native GUI cleanup requires a bounded owner")
	}
	child.retiring.Store(true)
	child.mu.Lock()
	defer child.mu.Unlock()
	if child.closed {
		return nil
	}
	if child.job != 0 {
		ok, _, callErr := child.api.terminate.Call(uintptr(child.job), 1)
		if ok == 0 {
			return nativeError("owned GUI Job termination", callErr)
		}
	}
	if child.process != nil && !child.processClosed {
		// A partial/ambiguous creation must not strand a suspended child even
		// if independent Job membership could not be proved. This handle is
		// the exact process returned by our own CreateProcess call, never a PID
		// reopened from untrusted metadata or another running GUI instance.
		handle, release, err := child.process.borrow()
		if err != nil {
			return err
		}
		status, waitErr := syscall.WaitForSingleObject(handle, 0)
		if waitErr != nil {
			release()
			return waitErr
		}
		var terminateErr error
		if status == syscall.WAIT_TIMEOUT {
			terminateErr = syscall.TerminateProcess(handle, 1)
		} else if status != syscall.WAIT_OBJECT_0 {
			release()
			return errors.New("owned GUI process wait returned an unknown state")
		}
		release()
		if err := joinGUIProcessTermination(ctx, child.process, terminateErr); err != nil {
			return err
		}
	}
	if child.job != 0 {
		for {
			var accounting struct {
				Times                                 [4]int64
				PageFaults, Total, Active, Terminated uint32
			}
			var returned uint32
			ok, _, callErr := child.api.queryJob.Call(uintptr(child.job), 1, uintptr(unsafe.Pointer(&accounting)), unsafe.Sizeof(accounting), uintptr(unsafe.Pointer(&returned)))
			if ok == 0 || returned != uint32(unsafe.Sizeof(accounting)) {
				return nativeError("joined GUI descendant accounting", callErr)
			}
			if accounting.Active == 0 {
				break
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	if child.output != nil {
		if err := child.output.close(ctx); err != nil {
			return err
		}
	}
	if child.process != nil && !child.processClosed {
		if err := child.process.Close(); err != nil {
			return err
		}
		child.processClosed = true
	}
	if child.job != 0 {
		if err := syscall.CloseHandle(child.job); err != nil {
			return err
		}
		child.job = 0
	}
	child.closed = true
	return nil
}

// TerminateJobObject/TerminateProcess initiate asynchronous termination. A
// repeated TerminateProcess can report access denied while that exact process
// is still draining its kernel I/O. Neither that status nor a zero-time wait
// proves exit. Keep its retained handle until the bounded actual wait signals;
// if that join fails, preserve both the termination failure and join failure.
func joinGUIProcessTermination(ctx context.Context, process *Process, terminateErr error) error {
	if _, err := process.Wait(ctx); err != nil {
		return errors.Join(terminateErr, err)
	}
	return nil
}

// guiSelfTestOutput retains only a bounded prefix and a full-stream digest.
// Excess bytes are drained rather than blocking the child's original startup.
type guiSelfTestOutput struct {
	read, write syscall.Handle
	done        chan struct{}
	sample      []byte
	bytes       uint64
	digest      string
	readFailed  bool
	redactions  []string
}

func (output *guiSelfTestOutput) closeWriter() error {
	if output.write == 0 {
		return nil
	}
	if err := syscall.CloseHandle(output.write); err != nil {
		return err
	}
	output.write = 0
	return nil
}

func (output *guiSelfTestOutput) drain() {
	defer close(output.done)
	digest := sha256.New()
	buffer := make([]byte, 4096)
	for {
		var count uint32
		err := syscall.ReadFile(output.read, buffer, &count, nil)
		if count > 0 {
			part := buffer[:count]
			output.bytes += uint64(count)
			_, _ = digest.Write(part)
			if remaining := 16384 - len(output.sample); remaining > 0 {
				output.sample = append(output.sample, part[:min(remaining, len(part))]...)
			}
		}
		if err != nil || count == 0 {
			output.readFailed = err != nil && !errors.Is(err, syscall.ERROR_BROKEN_PIPE) && !errors.Is(err, syscall.ERROR_HANDLE_EOF)
			output.digest = hex.EncodeToString(digest.Sum(nil))
			return
		}
	}
}

// Only called after every process in the captured Job has joined. Failure
// keeps the read handle, goroutine and original Job retained for another Close.
func (output *guiSelfTestOutput) close(ctx context.Context) error {
	if err := output.closeWriter(); err != nil {
		return err
	}
	if output.done != nil {
		select {
		case <-output.done:
		case <-ctx.Done():
			return errors.Join(ctx.Err(), errors.New("native GUI self-test output reader has not joined"))
		}
	}
	if output.read != 0 {
		if err := syscall.CloseHandle(output.read); err != nil {
			return err
		}
		output.read = 0
	}
	return nil
}

// guiSelfTestText decodes only the already bounded prefix. PowerShell can
// write UTF-16 or CLIXML before the App script reaches its own error handler.
func guiSelfTestText(sample []byte) string {
	little, big := false, false
	if len(sample) >= 2 {
		little, big = sample[0] == 0xff && sample[1] == 0xfe, sample[0] == 0xfe && sample[1] == 0xff
		if little || big {
			sample = sample[2:]
		} else {
			even, odd := 0, 0
			for i, value := range sample {
				if value == 0 {
					if i%2 == 0 {
						even++
					} else {
						odd++
					}
				}
			}
			little, big = odd > len(sample)/8 && even == 0, even > len(sample)/8 && odd == 0
		}
	}
	var text string
	if little || big {
		units := make([]uint16, len(sample)/2)
		for i := range units {
			if little {
				units[i] = uint16(sample[2*i]) | uint16(sample[2*i+1])<<8
			} else {
				units[i] = uint16(sample[2*i])<<8 | uint16(sample[2*i+1])
			}
		}
		text = string(utf16.Decode(units))
	} else {
		text = strings.TrimPrefix(strings.ToValidUTF8(string(sample), "\uFFFD"), "\uFEFF")
	}
	if start := strings.Index(text, "<Objs"); start >= 0 {
		decoder := xml.NewDecoder(strings.NewReader(text[start:]))
		var parts []string
		for {
			token, err := decoder.Token()
			if err != nil {
				break
			}
			if value, ok := token.(xml.CharData); ok && strings.TrimSpace(string(value)) != "" {
				parts = append(parts, string(value))
			}
		}
		if len(parts) > 0 {
			text = text[:start] + strings.Join(parts, "\n")
		}
		text = regexp.MustCompile(`_x[0-9A-Fa-f]{4}_`).ReplaceAllStringFunc(text, func(value string) string {
			code, _ := strconv.ParseUint(value[2:6], 16, 16)
			return string(rune(code))
		})
	}
	return strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n")
}

// guiSelfTestExcerpt retains interpreter wording after removing exact private
// launch values and credential-shaped material. It has no independent reader
// or output path: the original SelfTest-only pipe must already have joined.
func guiSelfTestExcerpt(text string, private []string) (string, bool) {
	text = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`).ReplaceAllString(text, "")
	values := append([]string(nil), private...)
	sort.Slice(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
	for _, value := range values {
		if len(value) >= 4 {
			text = regexp.MustCompile("(?i)"+regexp.QuoteMeta(value)).ReplaceAllString(text, "[private-launch-value]")
		}
	}
	for _, rule := range [][2]string{
		{`(?s)-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|$)`, "[private-key]"},
		{`(?i)(-ControllerParentHandle[ \t]+)[0-9]+`, "${1}[private-handle]"},
		{`(?i)(\b(?:password|passwd|pwd|secret|private[_-]?key|preshared[_-]?key|api[_-]?key|(?:(?:access|refresh|auth|api|owner)[_-]?)?token)\b["']?[ \t]*[:=][ \t]*)(?:"[^"]*"|'[^']*'|[^\s,;]+)`, "${1}[credential]"},
		{`(?i)(\b(?:bearer|basic)[ \t]+)[A-Za-z0-9_+/=.-]+`, "${1}[credential]"},
		{`(?i)([a-z][a-z0-9+.-]*://)[^/\s@]+@`, "${1}[credential]@"},
		{`\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`, "[credential]"},
	} {
		text = regexp.MustCompile(rule[0]).ReplaceAllString(text, rule[1])
	}
	text = regexp.MustCompile(`\b[A-Za-z0-9_+/=-]{32,}\b`).ReplaceAllStringFunc(text, func(value string) string {
		switch strings.ToLower(value) {
		case "routervpn-windows-controllertransport", "routervpn-windows-telemetry", "routervpn-windows-product-v2":
			return value
		default:
			return "[opaque-value]"
		}
	})
	text = strings.Map(func(value rune) rune {
		if value < 32 && value != '\n' && value != '\t' || value == 127 {
			return ' '
		}
		return value
	}, text)
	text = strings.TrimSpace(text)
	truncated := len(text) > 4096
	if truncated {
		text = text[:4096]
		for !utf8.ValidString(text) {
			text = text[:len(text)-1]
		}
	}
	return text, truncated
}

// SelfTestOutput returns a bounded sanitized interpreter excerpt, fixed
// classifications and digests only after the original child and reader retire.
func (child *GUIChild) SelfTestOutput() string {
	if child == nil {
		return ""
	}
	child.mu.Lock()
	defer child.mu.Unlock()
	if !child.closed || child.output == nil || child.output.done == nil {
		return ""
	}
	output := child.output
	decoded := guiSelfTestText(output.sample)
	excerpt, excerptTruncated := guiSelfTestExcerpt(decoded, output.redactions)
	text := strings.ToLower(decoded)
	markers := []string{}
	for _, marker := range []string{
		"parameterbinding", "argumenttransformation", "parsererror", "commandnotfound",
		"parentcontainserrorrecord", "methodinvocationexception", "typeinitializationexception",
		"invalidoperation", "invalidcastexception", "securityexception", "unauthorizedaccess",
		"could not load file or assembly", "unable to find type", "cannot find an overload",
		"cannot convert", "cannot bind", "cannot process argument", "access is denied",
		"running scripts is disabled", "malicious content", "not digitally signed",
		"namedparameternotfound", "positionalparameternotfound", "parameterbindingexception",
		"itemnotfoundexception", "providernotfoundexception", "drivenotfoundexception",
		"authorizationmanager", "pssecurityexception", "cannot find path", "cannot find drive",
		"cannot find provider", "does not exist", "not recognized", "unrecognized",
		"parameter cannot be found", "the argument to the -file parameter",
		"import-module", "add-type", "select-object", "convertto-json",
		"controllertransport", "initializeroutervpncontrollertransport", "initialize-routervpncontrollertransport",
		"new-routervpncontrollerclient", "presentationframework", "system.net.http",
	} {
		if strings.Contains(text, marker) {
			markers = append(markers, marker)
		}
	}
	locations := regexp.MustCompile(`(?i)RouterVPN-Windows-(?:App|ControllerTransport|Product-v2|Telemetry|Tray)\.(?:ps1|psm1):[0-9]{1,6}\b(?:[ \t]+char:[0-9]{1,6}\b)?`).FindAllString(text, 8)
	compilerCodes := regexp.MustCompile(`\bcs[0-9]{4}\b`).FindAllString(text, 8)
	sampleDigest := sha256.Sum256(output.sample)
	report, err := json.Marshal(struct {
		Bytes            uint64   `json:"bytes"`
		SHA256           string   `json:"sha256"`
		SampleBytes      int      `json:"sample_bytes"`
		SampleSHA256     string   `json:"sample_sha256"`
		Truncated        bool     `json:"truncated"`
		ReadFailed       bool     `json:"read_failed"`
		ReaderJoined     bool     `json:"reader_joined"`
		Markers          []string `json:"markers"`
		Locations        []string `json:"locations"`
		CompilerCodes    []string `json:"compiler_codes"`
		Excerpt          string   `json:"excerpt"`
		ExcerptTruncated bool     `json:"excerpt_truncated"`
	}{output.bytes, output.digest, len(output.sample), hex.EncodeToString(sampleDigest[:]), output.bytes > uint64(len(output.sample)), output.readFailed, true, markers, locations, compilerCodes, excerpt, excerptTruncated})
	if err != nil {
		return `{"classification_failed":true,"reader_joined":true}`
	}
	return string(report)
}
