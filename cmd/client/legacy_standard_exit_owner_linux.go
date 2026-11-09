//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobiletor"
)

var legacyStandardExitOwners sync.Map // map[*app]*linuxLegacyStandardExitOwner

type linuxLegacyStandardExitOwner struct {
	requestEpoch                                                              *linuxStandardRequestEpoch
	native                                                                    *linuxStandardEngine
	completion                                                                *linuxLegacyExitCompletion
	dns                                                                       *legacyStandardDNS
	protectionPolicy, protectionRoot, protectionProfileID, protectionEndpoint string
	protectionLAN                                                             bool
	protectionFactory                                                         legacyExitProtectionFactory
	protectionAbsence                                                         func(context.Context) error
	protection, offInherited                                                  *legacyExitProtectionSlot
	tunAbsent                                                                 func() error
	processRetired                                                            bool
	closedFiles                                                               map[*os.File]bool
	originalPIDFD                                                             *os.File
	creatorDone                                                               chan struct{}
	runtimeMode, base, routerID                                               string
	pidInfo                                                                   os.FileInfo
	mu                                                                        sync.Mutex
	sourceImage, sourceConfig                                                 *os.File
	offProtectionCheck                                                        func(context.Context) error
	app                                                                       *app
	launch                                                                    *desktopNodeLaunch
	image, config, directory, namespace                                       *os.File
	namespaceInfo                                                             os.FileInfo
	session, digest                                                           string
	command                                                                   *exec.Cmd
	pidfd                                                                     int
	pidFile                                                                   *os.File
	started, registered, workspaceRetired                                     bool
	done                                                                      chan struct{}
	receipt                                                                   *linuxLegacyExitReceipt
}

// Written only by the one creating goroutine before its original done closes.
// Waiting on that channel publishes this exact command's result; no PID lookup
// or replacement command can supply successful cleanup.
type linuxLegacyExitCompletion struct {
	command *exec.Cmd
	done    chan struct{}
	state   *os.ProcessState
	failure error
}

type linuxLegacyExitReceipt struct {
	Schema       int    `json:"schema"`
	Session      string `json:"session"`
	ConfigSHA256 string `json:"config_sha256"`
	PID          int    `json:"pid"`
	Created      bool   `json:"created"`
	Joined       bool   `json:"joined"`
	TUNAbsent    bool   `json:"tun_absent"`
}

func legacyExitTUNAbsent() error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, iface := range interfaces {
		if iface.Name == "router-vpn" {
			return errors.New("legacy standard exit still has a router-vpn TUN; protection retained")
		}
	}
	return nil
}

func prepareLegacyStandardExitOwner(a *app, original *exec.Cmd, runtimeMode, base, routerID string) (legacyStandardExitLaunch, error) {
	preparation := a.connectionOperationContextOrBackground()
	var prepared legacyStandardExitLaunch
	var err error
	if a.localController != nil {
		prepared, err = prepareLegacyStandardExitOwnerMode(a, original, runtimeMode, base, routerID, legacyExitTUNAbsent, physicalNetworkIdentity, false, true)
	} else {
		prepared, err = prepareLegacyStandardExitOwnerWithTUN(a, original, runtimeMode, base, routerID, legacyExitTUNAbsent)
	}
	return finishLegacyStandardExitPreparation(a, preparation, prepared, err)
}

// The route returns immediately on a preparation error. Keep any exact partial
// capture here until an original-budget cleanup or a later serialized Stop
// joins it; it must never replace a retained runtime/protection owner.
func finishLegacyStandardExitPreparation(a *app, preparation context.Context, prepared legacyStandardExitLaunch, failure error) (legacyStandardExitLaunch, error) {
	if prepared == nil {
		return nil, failure
	}
	local, ok := prepared.(*linuxLegacyStandardExitOwner)
	if !ok || local == nil || local.app != a {
		return prepared, errors.Join(failure, errors.New("standard service preparation lost its local source capture"))
	}
	if failure == nil && a.localController == nil {
		return local, nil
	}
	if failure == nil {
		var remote legacyStandardExitLaunch
		remote, failure = prepareLinuxStandardServiceLaunch(a, local)
		if failure == nil {
			return remote, nil
		}
	}
	if cleanup := local.discardContext(preparation); cleanup != nil {
		legacyStandardExitPreparations.Store(local, a)
		return local, errors.Join(failure, cleanup)
	}
	return nil, failure
}

func prepareLegacyStandardExitOwnerWithTUN(a *app, original *exec.Cmd, runtimeMode, base, routerID string, tunAbsent func() error) (legacyStandardExitLaunch, error) {
	return prepareLegacyStandardExitOwnerWithObservers(a, original, runtimeMode, base, routerID, tunAbsent, physicalNetworkIdentity)
}

// Test callers may supply explicit native observation boundaries. Production
// always captures the real physical network before either child is executed.
func prepareLegacyStandardExitOwnerWithObservers(a *app, original *exec.Cmd, runtimeMode, base, routerID string, tunAbsent func() error, network func() string) (legacyStandardExitLaunch, error) {
	return prepareLegacyStandardExitOwnerWithEngine(a, original, runtimeMode, base, routerID, tunAbsent, network, false)
}

func prepareLegacyStandardExitOwnerWithEngine(a *app, original *exec.Cmd, runtimeMode, base, routerID string, tunAbsent func() error, network func() string, native bool) (legacyStandardExitLaunch, error) {
	return prepareLegacyStandardExitOwnerMode(a, original, runtimeMode, base, routerID, tunAbsent, network, native, false)
}

func prepareLegacyStandardExitOwnerMode(a *app, original *exec.Cmd, runtimeMode, base, routerID string, tunAbsent func() error, network func() string, native, requestOnly bool) (result legacyStandardExitLaunch, failure error) {
	return prepareLegacyStandardExitOwnerWithRequestObserver(a, original, runtimeMode, base, routerID, tunAbsent, network, native, requestOnly, openLinuxStandardRequestObserver)
}

func prepareLegacyStandardExitOwnerWithRequestObserver(a *app, original *exec.Cmd, runtimeMode, base, routerID string, tunAbsent func() error, network func() string, native, requestOnly bool, open func(context.Context, context.Context) (linuxStandardStartupObserver, error)) (result legacyStandardExitLaunch, failure error) {
	if requestOnly && (native || a.localController == nil) {
		return nil, errors.New("standard source-only request has no original installed controller")
	}
	// OpenVPN has distinct route/interface cleanup and remains on its separate
	// adapter. Only the existing Linux sing-box wrapper is admitted here.
	if original == nil || len(original.Args) != 6 || filepath.Base(original.Args[1]) != "native-standard-exit-linux.sh" || original.Args[2] != "up" {
		return nil, nil
	}
	// Direct stock exits retain their original process and protection creators.
	// Hopped and custom native-engine paths keep their separate adapters.
	environment := func(key string) string {
		for i := len(original.Env) - 1; i >= 0; i-- {
			if value, ok := strings.CutPrefix(original.Env[i], key+"="); ok {
				return value
			}
		}
		return ""
	}
	if environment("HOMEVPN_PROFILE_ID") != environment("HOMEVPN_POLICY_PROFILE_ID") || environment("HOMEVPN_STANDARD_ENGINE") != "stock" {
		return nil, nil
	}
	a.mu.Lock()
	control, exists := a.profileByIDLocked(environment("HOMEVPN_POLICY_PROFILE_ID"))
	a.mu.Unlock()
	if !exists {
		return nil, errors.New("legacy standard exit lost its captured policy profile")
	}
	policy := strings.ToLower(strings.TrimSpace(control.KillSwitchPolicy))
	if policy == "" {
		if control.KillSwitch {
			policy = "on-connect"
		} else {
			policy = "off"
		}
	}
	if policy != "off" && policy != "on-connect" && policy != "always" {
		return nil, errors.New("standard exit has an invalid captured kill-switch policy")
	}
	launch := &desktopNodeLaunch{}
	if !requestOnly {
		if err := captureDesktopRuntimeDirectory(launch, original.Args[3]); err != nil {
			return nil, err
		}
	}
	owner := &linuxLegacyStandardExitOwner{protectionPolicy: policy, protectionRoot: original.Dir, protectionProfileID: control.ID, protectionEndpoint: original.Args[4], protectionLAN: control.HomeLANAccess, protectionFactory: createLegacyExitNativeProtection, protectionAbsence: mobiletor.ReadDesktopLinuxProtectionAbsence, tunAbsent: tunAbsent, app: a, launch: launch, pidfd: -1, runtimeMode: runtimeMode, base: base, routerID: routerID}
	preparation := a.connectionOperationContextOrBackground()
	failed := true
	defer func() {
		if failed {
			if err := owner.discardContext(preparation); err != nil {
				result, failure = owner, errors.Join(failure, err)
			}
		}
	}()
	if tunAbsent == nil {
		return nil, errors.New("legacy standard exit has no captured TUN readback")
	}
	// Capture and inspect the original network namespace on one thread. The
	// process leader namespace cannot stand in for this worker's native scope.
	var err error
	runtime.LockOSThread()
	owner.namespace, err = os.Open("/proc/thread-self/ns/net")
	if err == nil {
		owner.namespaceInfo, err = owner.namespace.Stat()
	}
	if err == nil && native {
		err = owner.prepareNativeEngine(preparation)
	}
	if err == nil && requestOnly {
		err = owner.openRequestEpoch(preparation, open)
	}
	if err == nil {
		err = owner.tunAbsentInNamespace()
	}
	runtime.UnlockOSThread()
	if err != nil {
		return nil, err
	}
	if requestOnly {
		if err := captureDesktopRuntimeDirectory(launch, original.Args[3]); err != nil {
			return nil, err
		}
	}
	capturedRoot, expectedNamespace := original.Dir, owner.namespaceInfo
	owner.offProtectionCheck = func(ctx context.Context) error {
		return legacyExitVerifyOffProtection(ctx, capturedRoot, expectedNamespace)
	}
	raw, err := readDesktopRuntimeFile(launch, "sing-box.json", 8<<20)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	owner.digest = hex.EncodeToString(sum[:])
	runtime.LockOSThread()
	err = owner.namespaceCurrent()
	if err == nil {
		owner.dns, err = captureLegacyStandardDNS(control, raw, network)
	}
	if err == nil {
		err = owner.namespaceCurrent()
	}
	runtime.UnlockOSThread()
	if err != nil {
		return nil, err
	}
	token := make([]byte, 16)
	if _, err = rand.Read(token); err != nil {
		return nil, err
	}
	owner.session = hex.EncodeToString(token)
	owner.config, err = launch.directoryRoot.Open("sing-box.json")
	if err != nil {
		return nil, err
	}
	configInfo, err := owner.config.Stat()
	if err != nil || !configInfo.Mode().IsRegular() {
		return nil, errors.New("legacy config capture lost its original regular file")
	}
	pinned, err := readDesktopRuntimeFile(launch, "sing-box.json", 8<<20)
	if err != nil || sha256.Sum256(pinned) != sum {
		return nil, errors.New("legacy config changed during capture")
	}
	named, err := launch.directoryRoot.Stat("sing-box.json")
	if err != nil || !os.SameFile(configInfo, named) {
		return nil, errors.New("legacy config inode changed during capture")
	}
	owner.sourceConfig = owner.config
	owner.config, err = sealLegacyExitFile("legacy-standard-config", strings.NewReader(string(raw)), 8<<20)
	if err != nil {
		return nil, err
	}
	owner.dns.source, owner.dns.sealed = owner.sourceConfig, owner.config
	owner.directory, err = launch.directoryRoot.Open(".")
	if err != nil {
		return nil, err
	}
	if requestOnly {
		// This command is an immutable request identity only. The authenticated
		// service independently verifies and checks its actual installed engine.
		// No PATH executable or controller-side child participates in this path.
		owner.command = original
		launch.command = original
		if err := owner.legacyDNSNetworkCurrent(); err != nil {
			return nil, err
		}
		profileDigest, err := linuxStandardProfileDigest(control)
		if err != nil {
			return nil, err
		}
		if err := owner.requestEpoch.bind(preparation, profileDigest); err != nil {
			return nil, err
		}
		failed = false
		return owner, nil
	}
	// The captured stock path needs no shell/helper child. Resolve only its
	// original PATH, then validate and execute exactly the same sealed image.
	imagePath := ""
	if owner.native != nil {
		imagePath = owner.native.imagePath
	}
	for _, directory := range filepath.SplitList(environment("PATH")) {
		if owner.native != nil {
			break
		}
		if !filepath.IsAbs(directory) {
			continue
		}
		candidate := filepath.Join(directory, "sing-box")
		if info, err := os.Lstat(candidate); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			imagePath = candidate
			break
		}
	}
	if imagePath == "" {
		return nil, errors.New("captured stock standard engine is unavailable")
	}
	info, err := os.Lstat(imagePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		return nil, errors.New("legacy selected engine is not a regular executable")
	}
	if owner.native != nil {
		owner.image = owner.native.imageSource
		info = owner.native.imageInfo
	} else {
		owner.image, err = os.Open(imagePath)
		if err != nil {
			return nil, err
		}
	}
	opened, err := owner.image.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("legacy selected engine changed during capture")
	}
	owner.sourceImage = owner.image
	owner.image, err = sealLegacyExitFile("legacy-standard-engine", owner.sourceImage, 512<<20)
	if err != nil {
		return nil, err
	}
	if owner.native != nil {
		if err := owner.native.config(raw); err != nil {
			return nil, err
		}
	}
	makeCommand := func(action string) *exec.Cmd {
		command := exec.Command("/proc/self/fd/3", action, "-D", "/proc/self/fd/5", "-c", "/proc/self/fd/4")
		command.Args[0] = imagePath
		command.Dir = original.Dir
		command.Env = append([]string(nil), original.Env...)
		command.ExtraFiles = []*os.File{owner.image, owner.config, owner.directory}
		if owner.native != nil {
			command.ExtraFiles = append(command.ExtraFiles, owner.native.library)
			command.Env = owner.native.environment(command.Env)
		}
		command.Stdout, command.Stderr = original.Stdout, original.Stderr
		return command
	}
	check := makeCommand("check")
	checkCtx, checkCancel := context.WithTimeout(preparation, 10*time.Second)
	// CommandContext owns cancellation without changing its pinned descriptors.
	checked := exec.CommandContext(checkCtx, check.Path, check.Args[1:]...)
	checked.Args[0] = check.Args[0]
	checked.Dir = check.Dir
	checked.Env = check.Env
	checked.ExtraFiles = check.ExtraFiles
	err = owner.legacyDNSNetworkCurrent()
	if err == nil {
		err = checked.Run()
	}
	checkCancel()
	if err == nil {
		err = owner.legacyDNSNetworkCurrent()
	}
	if err != nil {
		return nil, errors.Join(err, errors.New("pinned legacy engine rejected its captured config"))
	}
	if owner.native != nil {
		if err := owner.native.tracker.CurrentContext(preparation); err != nil {
			return nil, err
		}
	}
	owner.command = makeCommand("run")
	owner.command.SysProcAttr = &syscall.SysProcAttr{PidFD: &owner.pidfd, Pdeathsig: syscall.SIGKILL}
	launch.command = owner.command
	failed = false
	return owner, nil
}

func (o *linuxLegacyStandardExitOwner) Command() *exec.Cmd { return o.command }
func (o *linuxLegacyStandardExitOwner) namespaceCurrent() error {
	now, err := os.Stat("/proc/thread-self/ns/net")
	if err != nil || o.namespaceInfo == nil || !os.SameFile(now, o.namespaceInfo) {
		return errors.New("legacy standard exit network namespace changed")
	}
	return nil
}
func (o *linuxLegacyStandardExitOwner) tunAbsentInNamespace() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := o.namespaceCurrent(); err != nil {
		return err
	}
	if o.tunAbsent == nil {
		return errors.New("legacy standard exit lost its captured TUN readback")
	}
	if err := o.tunAbsent(); err != nil {
		return err
	}
	return o.namespaceCurrent()
}

func (o *linuxLegacyStandardExitOwner) current(command *exec.Cmd) error {
	return o.currentContext(context.Background(), command)
}
func (o *linuxLegacyStandardExitOwner) currentContext(ctx context.Context, command *exec.Cmd) error {
	current, ok := legacyStandardExitOwners.Load(o.app)
	if err := desktopnetwork.LockContext(ctx, &o.app.mu); err != nil {
		return err
	}
	same := o.app.cmd == command
	o.app.mu.Unlock()
	if !ok || current != o || command != o.command || !same {
		return errors.New("legacy standard exit lost its original command; replacement retained")
	}
	if _, present := desktopNodeOwners.Load(o.app); present {
		return errors.New("legacy standard exit cannot share a native node owner")
	}
	if _, present := desktopExternalRetainedLaunches.Load(o.app); present {
		return errors.New("legacy standard exit cannot share a retained external owner")
	}
	if _, present := desktopRelays.Load(o.app); present {
		return errors.New("legacy standard exit cannot release another relay owner")
	}
	if _, present := getActiveMultihopGraph(o.app); present {
		return errors.New("legacy standard exit cannot retire another graph owner")
	}
	return o.namespaceCurrent()
}

func (o *linuxLegacyStandardExitOwner) prepareProtectionLocked(ctx context.Context) error {
	if ctx == nil {
		return errors.New("legacy standard exit launch has no original context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if o.started {
		return errors.New("legacy standard exit launch was reused")
	}
	if err := o.legacyDNSNetworkCurrent(); err != nil {
		return err
	}
	if err := desktopExternalDirectoryCurrent(o.launch); err != nil {
		return err
	}
	if err := o.namespaceCurrent(); err != nil {
		return err
	}
	if err := o.tunAbsentInNamespace(); err != nil {
		return err
	}
	if o.registered {
		actual, present := legacyStandardExitOwners.Load(o.app)
		if !present || actual != o {
			return errors.New("standard guard preparation lost its original registration")
		}
		return o.applyProtection(ctx)
	}
	if err := desktopnetwork.LockContext(ctx, &o.app.mu); err != nil {
		return err
	}
	if o.app.cmd != nil || o.app.checkCapturedConnectionOperationLocked(ctx) != nil || o.app.connectionCancelIntent == ctx {
		o.app.mu.Unlock()
		return errors.New("legacy standard exit cannot replace another command")
	}
	if _, loaded := legacyStandardExitOwners.LoadOrStore(o.app, o); loaded {
		o.app.mu.Unlock()
		return errors.New("legacy standard exit already has an owner")
	}
	o.app.cmd = o.command
	o.app.state.Mode, o.app.state.LogicalMode, o.app.state.RuntimeMode, o.app.state.Base, o.app.state.RouterID = "standard-exit", "standard-exit", o.runtimeMode, o.base, o.routerID
	o.app.state.Connected, o.app.state.Phase, o.app.state.LastError = false, "standard-exit:starting", ""
	o.registered = true
	o.app.mu.Unlock()
	if err := o.applyProtection(ctx); err != nil {
		return err
	}
	return nil
}

func (o *linuxLegacyStandardExitOwner) prepareProtection(ctx context.Context) error {
	if err := desktopnetwork.LockContext(ctx, &o.mu); err != nil {
		return err
	}
	defer o.mu.Unlock()
	return o.prepareProtectionLocked(ctx)
}

func (o *linuxLegacyStandardExitOwner) Start(ctx context.Context) error {
	if err := desktopnetwork.LockContext(ctx, &o.mu); err != nil {
		return err
	}
	defer o.mu.Unlock()
	if err := o.prepareProtectionLocked(ctx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := o.currentContext(ctx, o.command); err != nil {
		return err
	}
	if err := desktopExternalDirectoryCurrent(o.launch); err != nil {
		return err
	}
	o.done = make(chan struct{})
	o.creatorDone = make(chan struct{})
	command, done, creatorDone := o.command, o.done, o.creatorDone
	completion := &linuxLegacyExitCompletion{command: command, done: done}
	o.completion = completion
	started := make(chan error, 1)
	// PR_SET_PDEATHSIG follows the creating thread. Keep that original thread
	// alive until its one child is joined, rather than allowing the Go runtime
	// to retire/reuse it while the standard engine is running.
	go func() {
		runtime.LockOSThread()
		defer close(creatorDone)
		defer runtime.UnlockOSThread()
		err := o.currentContext(ctx, o.command)
		if err == nil {
			err = o.legacyDNSNetworkCurrent()
		}
		lockErr := desktopnetwork.LockContext(ctx, &o.app.mu)
		if lockErr != nil {
			err = errors.Join(err, lockErr)
			started <- err
			completion.failure = err
			close(done)
			return
		}
		if err == nil {
			err = o.app.checkCapturedConnectionOperationLocked(ctx)
		}
		if err == nil && o.app.connectionCancelIntent == ctx {
			err = errConnectionOperationCancelled
		}
		if err == nil && o.app.cmd != o.command {
			err = errors.New("legacy creator admission lost original command")
		}
		if err == nil {
			err = command.Start()
		}
		o.app.mu.Unlock()
		started <- err
		if err == nil {
			completion.failure = command.Wait()
			completion.state = command.ProcessState
		} else {
			completion.failure = err
		}
		close(done)
	}()
	if err := <-started; err != nil {
		<-o.done
		<-o.creatorDone
		return err
	}
	o.started = true
	if o.pidfd < 0 {
		return errors.New("legacy child creation did not return its original pidfd")
	}
	o.pidFile = os.NewFile(uintptr(o.pidfd), "original-legacy-standard-child")
	o.originalPIDFD = o.pidFile
	var err error
	o.pidInfo, err = o.pidFile.Stat()
	if err != nil {
		return err
	}
	return o.currentContext(ctx, o.command)
}

func (o *linuxLegacyStandardExitOwner) Discard() error {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	return o.discardContext(ctx)
}

func (o *linuxLegacyStandardExitOwner) discardContext(ctx context.Context) error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.registered {
		return nil
	} // The published Stop owner, never a defer, owns retry.
	return o.discardLocked(ctx)
}

func (o *linuxLegacyStandardExitOwner) discardLocked(ctx context.Context) error {
	if ctx == nil {
		return errors.New("standard preparation cleanup requires its original budget")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var failures []error
	if err := o.requestEpoch.close(ctx); err != nil {
		return err
	}
	if o.native != nil {
		if err := o.native.close(ctx); err != nil {
			return err
		}
	}
	for _, f := range []*os.File{o.image, o.config, o.sourceImage, o.sourceConfig, o.directory, o.namespace} {
		if f != nil {
			if err := f.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
				failures = append(failures, err)
			}
		}
	}
	if !o.workspaceRetired && o.launch != nil && o.launch.directoryRoot != nil {
		err := cleanupDesktopNodeLaunch(o.launch)
		if err == nil {
			o.workspaceRetired = true
		}
		failures = append(failures, err)
	}
	failures = append(failures, ctx.Err())
	return errors.Join(failures...)
}

type linuxLegacyStandardExitStop struct {
	owner     *linuxLegacyStandardExitOwner
	command   *exec.Cmd
	operation context.Context
}

func captureLegacyStandardExitStop(a *app) (desktopRetainedStopCapture, error) {
	if retained, err := captureLinuxStandardServiceStop(a); retained != nil || err != nil {
		return retained, err
	}
	value, exists := legacyStandardExitOwners.Load(a)
	if !exists {
		return captureLegacyExitDetachedProtectionStop(a)
	}
	owner, ok := value.(*linuxLegacyStandardExitOwner)
	if !ok || owner == nil {
		return nil, errors.New("legacy standard exit has an invalid retained owner")
	}
	a.mu.Lock()
	capture := &linuxLegacyStandardExitStop{owner: owner, command: a.cmd, operation: a.connectionContext}
	a.mu.Unlock()
	return capture, owner.current(capture.command)
}
func (s *linuxLegacyStandardExitStop) current() error {
	if err := s.owner.current(s.command); err != nil {
		return err
	}
	s.owner.app.mu.Lock()
	same := s.owner.app.connectionContext == s.operation
	s.owner.app.mu.Unlock()
	if !same {
		return errors.New("legacy standard Stop lost its original transaction")
	}
	return nil
}

func legacyExitPIDFDState(file *os.File) (bool, error) {
	if file == nil {
		return false, errors.New("legacy child has no retained creation descriptor")
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return false, err
	}
	var result error
	retired := false
	err = raw.Control(func(fd uintptr) {
		type pollFD struct {
			FD              int32
			Events, Revents int16
		}
		p := pollFD{FD: int32(fd), Events: 1}
		zero := syscall.Timespec{}
		var ready uintptr
		var errno syscall.Errno
		for interrupted := 0; interrupted < 16; interrupted++ {
			ready, _, errno = syscall.Syscall6(syscall.SYS_PPOLL, uintptr(unsafe.Pointer(&p)), 1, uintptr(unsafe.Pointer(&zero)), 0, 0, 0)
			if errno != syscall.EINTR {
				break
			}
			// Go preemption or an ordinary caught signal can interrupt even
			// this nonblocking query. Retry only the same retained descriptor
			// and zero timeout; never reopen a PID or renew an owner deadline.
		}
		if errno != 0 {
			result = errno
			return
		}
		if ready == 0 && p.Revents == 0 {
			return
		}
		if ready != 1 || p.Revents&1 == 0 || p.Revents&0x20 != 0 {
			result = errors.New("legacy original process descriptor has an invalid kernel retirement state")
			return
		}
		retired = true
	})
	return retired, errors.Join(err, result)
}
func legacyExitPIDFDRetired(file *os.File) error {
	retired, err := legacyExitPIDFDState(file)
	if err != nil {
		return err
	}
	if !retired {
		return errors.New("original legacy child has not retired in the kernel")
	}
	return nil
}
func (o *linuxLegacyStandardExitOwner) Current(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.currentOperationLocked(ctx); err != nil {
		return err
	}
	return o.currentRuntimeLocked(ctx)
}

// The connection request is required for adoption, but intentionally finishes
// once Connected is published. Later observers retain the same runtime and
// kernel authority without reviving that finished request.
func (o *linuxLegacyStandardExitOwner) currentOperationLocked(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return errors.New("legacy standard exit proof lost its original operation")
	}
	if err := o.current(o.command); err != nil {
		return err
	}
	o.app.mu.Lock()
	admissionErr := o.app.checkCapturedConnectionOperationLocked(ctx)
	if admissionErr == nil && o.app.connectionCancelIntent == ctx {
		admissionErr = errConnectionOperationCancelled
	}
	o.app.mu.Unlock()
	return admissionErr
}

// Caller holds o.mu. All process, workspace and native protection checks are
// shared by activation and the post-activation DNS receipt observer.
func (o *linuxLegacyStandardExitOwner) currentRuntimeLocked(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return errors.New("legacy standard exit observation has no live context")
	}
	if err := o.current(o.command); err != nil {
		return err
	}
	if err := desktopExternalDirectoryCurrent(o.launch); err != nil {
		return err
	}
	if err := o.currentProtection(ctx); err != nil {
		return err
	}
	if !o.started || o.pidFile == nil || o.pidFile != o.originalPIDFD {
		return errors.New("legacy standard exit has no created engine")
	}
	info, err := o.originalPIDFD.Stat()
	if err != nil || o.pidInfo == nil || !os.SameFile(info, o.pidInfo) {
		return errors.New("legacy standard exit proof lost original process descriptor")
	}
	retired, err := legacyExitPIDFDState(o.originalPIDFD)
	if err != nil {
		return err
	}
	if retired {
		return errors.New("legacy standard exit engine retired before public proof adoption")
	}
	if o.native != nil {
		if err := o.native.current(ctx); err != nil {
			return err
		}
	}
	return o.legacyDNSNetworkCurrent()
}

func (s *linuxLegacyStandardExitStop) Retire(ctx context.Context, command *exec.Cmd, release bool) (failure error) {
	o := s.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	defer func() {
		if failure == nil {
			return
		}
		o.app.mu.Lock()
		current, exists := legacyStandardExitOwners.Load(o.app)
		if exists && current == o && o.app.cmd == s.command && o.app.connectionContext == s.operation {
			o.app.state.Connected, o.app.state.Phase, o.app.state.LastError = false, "failed", failure.Error()
		}
		o.app.mu.Unlock()
	}()
	if command != s.command || ctx == nil {
		return errors.New("legacy standard Stop has no current captured command")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.current(); err != nil {
		return err
	}
	if !o.workspaceRetired {
		if err := desktopExternalDirectoryCurrent(o.launch); err != nil {
			return err
		}
	}
	if o.started && !o.processRetired {
		if o.originalPIDFD == nil || o.done == nil || o.creatorDone == nil {
			if o.native != nil {
				return errors.New("native cleanup retains its original child until retirement capability is restored")
			}
			// The original exec.Cmd is still creation authority for emergency join;
			// missing independent retirement evidence never authorizes release.
			if o.command.Process != nil {
				_ = o.command.Process.Kill()
			}
			if o.done != nil {
				select {
				case <-o.done:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			if o.creatorDone != nil {
				select {
				case <-o.creatorDone:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return errors.New("legacy created child lost its exact retirement capability")
		}
		select {
		case <-o.done:
		default:
			if o.native != nil {
				if err := o.native.requestCleanup(ctx); err != nil {
					return err
				}
			}
			if err := o.command.Process.Signal(os.Interrupt); err != nil && !errors.Is(err, os.ErrProcessDone) {
				return err
			}
			if o.native != nil {
				select {
				case <-o.done:
				case <-ctx.Done():
					return ctx.Err()
				}
			} else {
				grace := time.NewTimer(3 * time.Second)
				select {
				case <-o.done:
					stopTimerWithoutBlocking(grace)
				case <-ctx.Done():
					grace.Stop()
					return ctx.Err()
				case <-grace.C:
					if err := s.current(); err != nil {
						return err
					}
					if err := o.command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
						return err
					}
					select {
					case <-o.done:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
			}
		}
		select {
		case <-o.creatorDone:
		case <-ctx.Done():
			return ctx.Err()
		}
		if o.pidFile != o.originalPIDFD {
			return errors.New("legacy child retirement descriptor was replaced")
		}
		info, err := o.originalPIDFD.Stat()
		if err != nil || o.pidInfo == nil || !os.SameFile(info, o.pidInfo) {
			return errors.New("legacy child retirement descriptor was replaced")
		}
		if err := legacyExitPIDFDRetired(o.originalPIDFD); err != nil {
			return err
		}
		o.processRetired = true
	}
	if err := s.current(); err != nil {
		return err
	}
	if err := o.tunAbsentInNamespace(); err != nil {
		return err
	}
	if o.native != nil && o.started {
		if err := o.native.routingRetired(ctx); err != nil {
			return err
		}
	}
	// This is a native creator retirement receipt, not a claimed engine RPC:
	// the original wait has joined, its creation pidfd is readable, and the
	// originally absent TUN is absent in the same captured network namespace.
	if o.receipt == nil {
		pid := 0
		if o.started {
			pid = o.command.Process.Pid
		}
		o.receipt = &linuxLegacyExitReceipt{Schema: 1, Session: o.session, ConfigSHA256: o.digest, PID: pid, Created: o.started, Joined: true, TUNAbsent: true}
		body, _ := json.Marshal(o.receipt)
		if err := writeDesktopRuntimeFile(o.launch, "stopped.json", body, false); err != nil {
			o.receipt = nil
			return err
		}
	}
	if !o.workspaceRetired {
		if err := cleanupDesktopNodeLaunch(o.launch); err != nil {
			return err
		}
		o.workspaceRetired = true
	}
	if err := s.current(); err != nil {
		return err
	}
	if o.native != nil {
		if err := o.native.close(ctx); err != nil {
			return err
		}
	}
	// Only this captured native creator may retire or retain its policy.
	if err := o.retireProtection(ctx, release); err != nil {
		return err
	}
	if err := s.current(); err != nil {
		return err
	}
	o.app.mu.Lock()
	if o.app.cmd != command || o.app.connectionContext != s.operation {
		o.app.mu.Unlock()
		return errors.New("legacy Stop cannot commit over a replacement")
	}
	if o.closedFiles == nil {
		o.closedFiles = make(map[*os.File]bool)
	}
	var closeFailures []error
	for _, file := range []*os.File{o.image, o.config, o.sourceImage, o.sourceConfig, o.directory, o.originalPIDFD, o.namespace} {
		if file == nil || o.closedFiles[file] {
			continue
		}
		if err := file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			closeFailures = append(closeFailures, err)
		} else {
			o.closedFiles[file] = true
		}
	}
	if err := errors.Join(closeFailures...); err != nil {
		o.app.mu.Unlock()
		return err
	}
	if !legacyStandardExitOwners.CompareAndDelete(o.app, o) {
		o.app.mu.Unlock()
		return errors.New("legacy Stop lost its exact owner before commit")
	}
	o.app.cmd = nil
	o.app.state.Mode = "off"
	o.app.state.LogicalMode = ""
	o.app.state.RuntimeMode = ""
	o.app.state.Base = ""
	o.app.state.Connected = false
	o.app.state.Phase = "off"
	o.app.state.LastError = ""
	o.app.mu.Unlock()
	return nil
}

// Called with the app lock held during terminal history/state adoption.
func legacyStandardExitFailureOwned(a *app, expected legacyStandardExitLaunch, retired bool) bool {
	if owned, handled := linuxStandardServiceFailureOwned(a, expected, retired); handled {
		return owned
	}
	current, exists := legacyStandardExitOwners.Load(a)
	if retired {
		return !exists
	}
	return exists && current == expected
}

// Validation and execution consume the same sealed bytes. Keeping only a file
// inode would prevent rename substitution but still allow in-place writes
// between check and Start. No network or dependency lookup chooses this image.
func sealLegacyExitFile(label string, source io.Reader, limit int64) (*os.File, error) {
	var number uintptr
	switch runtime.GOARCH {
	case "amd64":
		number = 319
	case "arm64":
		number = 279
	default:
		return nil, errors.New("legacy captured execution has no validated memfd ABI")
	}
	name, err := syscall.BytePtrFromString(label)
	if err != nil {
		return nil, err
	}
	fd, _, errno := syscall.Syscall(number, uintptr(unsafe.Pointer(name)), 3, 0)
	if errno != 0 {
		return nil, errno
	}
	file := os.NewFile(fd, label)
	valid := false
	defer func() {
		if !valid {
			file.Close()
		}
	}()
	n, err := io.Copy(file, io.LimitReader(source, limit+1))
	if err != nil || n == 0 || n > limit {
		return nil, errors.Join(err, errors.New("captured legacy input exceeds its bounded size"))
	}
	if err = file.Chmod(0500); err != nil {
		return nil, err
	}
	if _, err = file.Seek(0, 0); err != nil {
		return nil, err
	}
	_, _, errno = syscall.Syscall(syscall.SYS_FCNTL, fd, 1033, 15)
	if errno != 0 {
		return nil, errno
	}
	seals, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, 1034, 0)
	if errno != 0 || seals != 15 {
		return nil, errors.New("captured legacy bytes did not retain all write/size/seal locks")
	}
	valid = true
	return file, nil
}
